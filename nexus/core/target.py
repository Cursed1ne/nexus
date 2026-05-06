"""
LLMTarget - Abstraction for any LLM endpoint being tested.
Supports OpenAI-compatible APIs, Anthropic, HuggingFace, local Ollama,
custom HTTP endpoints, and enterprise chatbots (Priceline Penny, etc.).
"""

from __future__ import annotations

import gzip
import time
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class TargetType(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    HUGGINGFACE = "huggingface"
    OLLAMA = "ollama"
    AZURE_OPENAI = "azure_openai"
    CUSTOM = "custom"
    PENNY = "penny"                  # Priceline Penny / gzip-body enterprise chatbot
    # AI framework targets — auto-detected from URL probing
    MLFLOW_GATEWAY = "mlflow_gateway"        # MLflow AI Gateway /gateway/{route}/invocations
    MLFLOW_SERVING = "mlflow_serving"        # MLflow Model Serving /invocations
    TF_SERVING = "tf_serving"                # TensorFlow Serving /v1/models/{model}:predict
    TRITON = "triton"                        # NVIDIA Triton /v2/models/{model}/infer
    TENSORRT_LLM = "tensorrt_llm"            # NVIDIA TensorRT-LLM /v1/chat/completions or /generate
    LANGSERVE = "langserve"                  # LangChain LangServe /{chain}/invoke
    VLLM = "vllm"                            # vLLM /v1/chat/completions
    TGI = "tgi"                              # HuggingFace Text Generation Inference /generate
    LOCALAI = "localai"                      # LocalAI /v1/chat/completions
    HAYSTACK = "haystack"                    # Haystack pipeline /query or /search


@dataclass
class LLMTarget:
    """
    Represents an LLM endpoint under security assessment.

    Inspired by Alias Robotics RSF target modeling — instead of robots,
    we model LLM systems with their API surface, authentication, and
    observable behaviors.
    """

    name: str
    target_type: TargetType = TargetType.OPENAI
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4"
    api_key: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    system_prompt: Optional[str] = None
    temperature: float = 1.0
    max_tokens: int = 2048
    timeout: int = 30
    metadata: Dict[str, Any] = field(default_factory=dict)
    proxy_url: Optional[str] = None  # e.g. "http://127.0.0.1:8080" for Burp

    # Runtime state
    _client: Optional[httpx.Client] = field(default=None, init=False, repr=False)
    _request_count: int = field(default=0, init=False, repr=False)
    _total_latency: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self):
        auth_headers = {}
        if self.api_key:
            if self.target_type == TargetType.ANTHROPIC:
                auth_headers = {
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                }
            elif self.target_type != TargetType.PENNY:
                # Penny uses cookies, not Bearer — skip auth header
                auth_headers = {"Authorization": f"Bearer {self.api_key}"}
        self.headers = {**auth_headers, **self.headers, "Content-Type": "application/json"}

        client_kwargs: Dict[str, Any] = {
            "base_url": self.base_url,
            "headers": self.headers,
            "timeout": self.timeout,
        }
        if self.proxy_url:
            client_kwargs["proxy"] = self.proxy_url
            client_kwargs["verify"] = False  # Burp uses self-signed cert
            logger.info("[%s] All traffic routed through proxy: %s", self.name, self.proxy_url)
        self._client = httpx.Client(**client_kwargs)

    # ------------------------------------------------------------------
    # Core query interface
    # ------------------------------------------------------------------

    def query(self, prompt: str, system_override: Optional[str] = None) -> str:
        """Send a prompt to the target LLM and return the raw text response."""
        start = time.perf_counter()
        try:
            response = self._dispatch(prompt, system_override)
            self._request_count += 1
            self._total_latency += time.perf_counter() - start
            return response
        except httpx.TimeoutException:
            logger.warning("[%s] Request timed out after %ds", self.name, self.timeout)
            return "__TIMEOUT__"
        except Exception as exc:
            logger.error("[%s] Query error: %s", self.name, exc)
            return f"__ERROR__: {exc}"

    def _dispatch(self, prompt: str, system_override: Optional[str]) -> str:
        system = system_override or self.system_prompt

        if self.target_type == TargetType.ANTHROPIC:
            return self._query_anthropic(prompt, system)
        elif self.target_type == TargetType.OLLAMA:
            return self._query_ollama(prompt, system)
        elif self.target_type == TargetType.HUGGINGFACE:
            return self._query_huggingface(prompt)
        elif self.target_type == TargetType.PENNY:
            return self._query_penny(prompt, system)
        # AI Framework targets
        elif self.target_type == TargetType.MLFLOW_GATEWAY:
            return self._query_mlflow_gateway(prompt, system)
        elif self.target_type == TargetType.MLFLOW_SERVING:
            return self._query_mlflow_serving(prompt)
        elif self.target_type == TargetType.TF_SERVING:
            return self._query_tf_serving(prompt)
        elif self.target_type == TargetType.TRITON:
            return self._query_triton(prompt)
        elif self.target_type == TargetType.TENSORRT_LLM:
            return self._query_tensorrt_llm(prompt, system)
        elif self.target_type == TargetType.LANGSERVE:
            return self._query_langserve(prompt)
        elif self.target_type == TargetType.TGI:
            return self._query_tgi(prompt, system)
        elif self.target_type in (TargetType.VLLM, TargetType.LOCALAI):
            return self._query_openai_compat(prompt, system)   # Both are OpenAI-compat
        elif self.target_type == TargetType.HAYSTACK:
            return self._query_haystack(prompt)
        else:
            return self._query_openai_compat(prompt, system)

    # ── Framework-specific query methods ──────────────────────────────

    def _query_mlflow_gateway(self, prompt: str, system: Optional[str]) -> str:
        """MLflow AI Gateway — tries new Deployments API first, falls back to old Gateway API."""
        messages: List[Dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # MLflow 2.9+ Deployments: OpenAI-compat at /v1/chat/completions
        try:
            resp = self._client.post("/v1/chat/completions", json={
                "model": self.model, "messages": messages,
            })
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
        except Exception:
            pass

        # Older MLflow Gateway: /gateway/{route}/invocations
        route = self.metadata.get("route", self.model or "completions")
        resp = self._client.post(f"/gateway/{route}/invocations", json={"messages": messages})
        resp.raise_for_status()
        data = resp.json()
        return (
            data.get("candidates", [{}])[0].get("message", {}).get("content")
            or data.get("choices", [{}])[0].get("message", {}).get("content", str(data))
        )

    def _query_mlflow_serving(self, prompt: str) -> str:
        """MLflow Model Serving /invocations — tries dataframe_records, then instances."""
        field = self.metadata.get("prompt_field", "prompt")
        for payload in [
            {"dataframe_records": [{field: prompt}]},
            {"instances": [prompt]},
            {"inputs": [prompt]},
            {field: prompt},
        ]:
            try:
                resp = self._client.post("/invocations", json=payload)
                if resp.status_code == 200:
                    return self._extract_serving_response(resp.json())
            except Exception:
                continue
        return "__ERROR__: all MLflow serving formats failed"

    def _extract_serving_response(self, data) -> str:
        if isinstance(data, str):
            return data
        if isinstance(data, list) and data:
            item = data[0]
            return item if isinstance(item, str) else json.dumps(item)
        if isinstance(data, dict):
            for key in ("predictions", "output", "response", "text", "generated_text", "choices"):
                if key in data:
                    val = data[key]
                    if isinstance(val, list) and val:
                        if key == "choices":
                            return val[0].get("message", {}).get("content", str(val[0]))
                        return val[0] if isinstance(val[0], str) else json.dumps(val[0])
                    return str(val)
        return json.dumps(data)

    def _query_tf_serving(self, prompt: str) -> str:
        """TensorFlow Serving /v1/models/{model}:predict"""
        model_name = self.model or self.metadata.get("tf_model", "default")
        endpoint = self.metadata.get("tf_endpoint", f"/v1/models/{model_name}:predict")
        # TF Serving expects {"instances": [...]} or {"inputs": {...}}
        for payload in [
            {"instances": [{"input": prompt}]},
            {"instances": [prompt]},
            {"inputs": {"input_ids": [prompt]}},
        ]:
            try:
                resp = self._client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    preds = data.get("predictions", data.get("outputs", [data]))
                    if isinstance(preds, list) and preds:
                        p = preds[0]
                        return p if isinstance(p, str) else json.dumps(p)
                    return json.dumps(data)
            except Exception:
                continue
        return "__ERROR__: TF Serving query failed"

    def _query_triton(self, prompt: str) -> str:
        """NVIDIA Triton Inference Server /v2/models/{model}/infer"""
        model_name = self.model or self.metadata.get("triton_model", "ensemble")
        endpoint = f"/v2/models/{model_name}/infer"
        payload = {
            "inputs": [{
                "name": "text_input",
                "shape": [1, 1],
                "datatype": "BYTES",
                "data": [prompt],
            }],
            "outputs": [{"name": "text_output"}],
        }
        try:
            resp = self._client.post(endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()
            outputs = data.get("outputs", [])
            if outputs:
                out_data = outputs[0].get("data", [])
                return out_data[0] if out_data else json.dumps(data)
            return json.dumps(data)
        except Exception as e:
            return f"__ERROR__: {e}"

    def _query_tensorrt_llm(self, prompt: str, system: Optional[str]) -> str:
        """NVIDIA TensorRT-LLM — tries OpenAI compat first, then /generate."""
        messages: List[Dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # TRT-LLM NIM containers expose /v1/chat/completions
        try:
            resp = self._client.post("/v1/chat/completions", json={
                "model": self.model, "messages": messages, "max_tokens": self.max_tokens,
            })
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
        except Exception:
            pass

        # Older TRT-LLM /generate endpoint
        resp = self._client.post("/generate", json={
            "text_input": prompt,
            "max_tokens": self.max_tokens,
            "bad_words": "",
            "stop_words": "",
        })
        resp.raise_for_status()
        data = resp.json()
        return data.get("text_output", data.get("output", json.dumps(data)))

    def _query_langserve(self, prompt: str) -> str:
        """LangChain LangServe /{chain}/invoke"""
        chain = self.metadata.get("chain", self.model or "chain")
        endpoint = self.metadata.get("langserve_endpoint", f"/{chain}/invoke")
        # LangServe wraps input in {"input": {...}}
        for input_shape in [
            {"input": {"question": prompt}},
            {"input": {"input": prompt}},
            {"input": prompt},
        ]:
            try:
                resp = self._client.post(endpoint, json=input_shape)
                if resp.status_code == 200:
                    data = resp.json()
                    out = data.get("output", data)
                    if isinstance(out, str):
                        return out
                    if isinstance(out, dict):
                        for key in ("answer", "text", "content", "result", "output"):
                            if key in out:
                                return str(out[key])
                    return json.dumps(out)
            except Exception:
                continue
        return "__ERROR__: LangServe query failed"

    def _query_tgi(self, prompt: str, system: Optional[str]) -> str:
        """HuggingFace Text Generation Inference — /generate or /v1/chat/completions"""
        # TGI 2.x supports OpenAI-compat
        try:
            messages: List[Dict] = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            resp = self._client.post("/v1/chat/completions", json={
                "model": "tgi", "messages": messages, "max_tokens": self.max_tokens,
            })
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
        except Exception:
            pass

        # TGI 1.x /generate
        resp = self._client.post("/generate", json={
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": self.max_tokens,
                "temperature": self.temperature,
            },
        })
        resp.raise_for_status()
        return resp.json().get("generated_text", str(resp.json()))

    def _query_haystack(self, prompt: str) -> str:
        """Haystack REST API /query or /search"""
        for endpoint, payload in [
            ("/query", {"query": prompt}),
            ("/search", {"query": prompt}),
            ("/ask", {"query": prompt}),
        ]:
            try:
                resp = self._client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    for key in ("answers", "results", "response", "text"):
                        if key in data:
                            val = data[key]
                            if isinstance(val, list) and val:
                                item = val[0]
                                return item.get("answer", item.get("text", str(item))) if isinstance(item, dict) else str(item)
                            return str(val)
                    return json.dumps(data)
            except Exception:
                continue
        return "__ERROR__: Haystack query failed"

    def _query_openai_compat(self, prompt: str, system: Optional[str]) -> str:
        messages: List[Dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        resp = self._client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    def _query_anthropic(self, prompt: str, system: Optional[str]) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system
        resp = self._client.post("/messages", json=payload)
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]

    def _query_ollama(self, prompt: str, system: Optional[str]) -> str:
        import json as _json
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        if system:
            payload["system"] = system
        resp = self._client.post("/api/generate", json=payload)
        resp.raise_for_status()
        body = resp.text.strip()

        # Some Ollama proxies/gateways ignore stream:false and return NDJSON
        # (Content-Type: application/x-ndjson, one JSON object per token).
        # Detect that case and reassemble the full response.
        if "\n" in body:
            tokens = []
            for line in body.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = _json.loads(line)
                    chunk = obj.get("response", "")
                    if chunk:
                        tokens.append(chunk)
                    if obj.get("done"):
                        break
                except _json.JSONDecodeError:
                    continue
            return "".join(tokens)

        return _json.loads(body)["response"]

    def _query_huggingface(self, prompt: str) -> str:
        payload = {"inputs": prompt, "parameters": {"max_new_tokens": self.max_tokens}}
        resp = self._client.post("", json=payload)
        resp.raise_for_status()
        result = resp.json()
        if isinstance(result, list):
            return result[0].get("generated_text", str(result))
        return str(result)

    def _query_penny(self, prompt: str, system: Optional[str]) -> str:
        """Query Priceline Penny / enterprise chatbots that use gzip-compressed
        JSON bodies.

        Schema decoded from actual Burp capture:
          - pushPrompt: the user message
          - messages[]: array of {role, content}
          - enabledActions: feature flags (shouldUse*/shouldEnable*)
          - hotelPayload: search config
          - cguid: session GUID from PL_CINFO cookie
        """
        messages: List[Dict] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "isSessionActive": True,
            "productId": self.metadata.get("product_id", -1),
            "cguid": self.metadata.get("cguid", ""),
            "cityName": "",
            "countryCode": "",
            "customerName": "",
            "dateToday": "",
            "latitude": "",
            "longitude": "",
            "resolvedClientIP": "",
            "stateCode": "",
            "returnJSONResponse": True,
            "pushPrompt": prompt,
            "hotelPayload": {
                "shouldUseSearchHotelsFeature": True,
                "isHotelSearchDateSelection": True,
                "isShowMoreListingCards": False,
            },
            "enabledActions": {
                "shouldUseFlightListingMarker": True,
                "shouldEnableRoomOptionsMarker": True,
                "shouldUseHotelImages": True,
                "shouldEnableFeedbackIntent": True,
                "shouldEnableInlineLocationMetadata": True,
                "shouldEnableLLMBasedResult": True,
                "shouldEnableSelectedTripQuickActions": True,
                "shouldUseDynamicQuickActionsChips": True,
                "shouldEnableInlineWebSearchResultCitation": True,
                "shouldEnableMarkdownTemplate": True,
                "isPennyAgentEnabled": True,
                "shouldUseRentalCarListingMarker": True,
                "shouldUseAutoCompleteSuggestionChip": False,
            },
            "messages": messages,
        }

        json_bytes = json.dumps(payload).encode("utf-8")
        compressed = gzip.compress(json_bytes)

        resp = self._client.post(
            self.metadata.get("chat_path", "/genai-svc/genai/chat/pennyPortal"),
            content=compressed,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-Model-Version": str(self.metadata.get("model_version", 4)),
                "X-Request-From": self.metadata.get("request_from", "pennyPortalPage"),
                "Cache-Control": "no-cache",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        resp.raise_for_status()

        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}

        # Try to extract text from common response shapes
        if isinstance(data, dict):
            for key in ("response", "text", "answer", "content", "message", "reply",
                        "pushPromptResponse", "pennyResponse"):
                if key in data and isinstance(data[key], str):
                    return data[key]
            if "messages" in data and isinstance(data["messages"], list):
                for msg in reversed(data["messages"]):
                    if msg.get("role") in ("assistant", "bot", "penny"):
                        return msg.get("content", str(msg))
            if "choices" in data:
                return data["choices"][0].get("message", {}).get("content", str(data))

        return resp.text[:2000]

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    @property
    def avg_latency(self) -> float:
        if self._request_count == 0:
            return 0.0
        return self._total_latency / self._request_count

    def stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "model": self.model,
            "type": self.target_type.value,
            "requests": self._request_count,
            "avg_latency_s": round(self.avg_latency, 3),
        }

    def __repr__(self) -> str:
        return f"LLMTarget(name={self.name!r}, model={self.model!r}, type={self.target_type.value})"


# ------------------------------------------------------------------
# Convenience constructors (Aztarna-inspired: quick target discovery)
# ------------------------------------------------------------------

def mlflow_gateway_target(host: str, route: str = "completions", api_key: str = "") -> LLMTarget:
    return LLMTarget(
        name=f"mlflow-gateway:{host}", target_type=TargetType.MLFLOW_GATEWAY,
        base_url=host, model=route, api_key=api_key,
        metadata={"route": route}, timeout=60,
    )

def mlflow_serving_target(host: str, prompt_field: str = "prompt") -> LLMTarget:
    return LLMTarget(
        name=f"mlflow-serving:{host}", target_type=TargetType.MLFLOW_SERVING,
        base_url=host, model="mlflow-model",
        metadata={"prompt_field": prompt_field}, timeout=60,
    )

def tf_serving_target(host: str, model_name: str = "default") -> LLMTarget:
    return LLMTarget(
        name=f"tf-serving:{host}/{model_name}", target_type=TargetType.TF_SERVING,
        base_url=host, model=model_name,
        metadata={"tf_model": model_name}, timeout=60,
    )

def triton_target(host: str, model_name: str = "ensemble") -> LLMTarget:
    return LLMTarget(
        name=f"triton:{host}/{model_name}", target_type=TargetType.TRITON,
        base_url=host, model=model_name, timeout=60,
    )

def tensorrt_llm_target(host: str, model: str = "tensorrt-llm") -> LLMTarget:
    return LLMTarget(
        name=f"tensorrt-llm:{host}", target_type=TargetType.TENSORRT_LLM,
        base_url=host, model=model, timeout=60,
    )

def langserve_target(host: str, chain: str = "chain") -> LLMTarget:
    return LLMTarget(
        name=f"langserve:{host}/{chain}", target_type=TargetType.LANGSERVE,
        base_url=host, model=chain,
        metadata={"chain": chain}, timeout=60,
    )

def vllm_target(host: str, model: str = "") -> LLMTarget:
    return LLMTarget(
        name=f"vllm:{host}", target_type=TargetType.VLLM,
        base_url=host, model=model or "vllm-model", timeout=60,
    )

def tgi_target(host: str) -> LLMTarget:
    return LLMTarget(
        name=f"tgi:{host}", target_type=TargetType.TGI,
        base_url=host, model="tgi", timeout=60,
    )

def openai_target(name: str, model: str = "gpt-4o", api_key: str = "") -> LLMTarget:
    return LLMTarget(
        name=name, target_type=TargetType.OPENAI,
        base_url="https://api.openai.com/v1",
        model=model, api_key=api_key,
    )


def anthropic_target(name: str, model: str = "claude-sonnet-4-6", api_key: str = "") -> LLMTarget:
    return LLMTarget(
        name=name, target_type=TargetType.ANTHROPIC,
        base_url="https://api.anthropic.com/v1",
        model=model, api_key=api_key,
    )


def ollama_target(name: str, model: str = "llama3", host: str = "http://localhost:11434") -> LLMTarget:
    return LLMTarget(
        name=name, target_type=TargetType.OLLAMA,
        base_url=host, model=model,
        timeout=120,  # Local models need more time (14B+ params)
    )


def penny_target(
    name: str = "penny",
    base_url: str = "https://www.priceline.com",
    cookies: str = "",
    cguid: str = "",
    chat_path: str = "/genai-svc/genai/chat/pennyPortal",
    model_version: int = 4,
) -> LLMTarget:
    """Create a target for Priceline Penny or similar enterprise chatbots.

    Usage:
        nexus scan --target penny://www.priceline.com \\
            --api-key "PASTE_FULL_COOKIE_STRING"

    Or from Python:
        target = penny_target(
            cookies="PL_CINFO=xxx; cf_clearance=yyy; ...",
            cguid="fTNMtyk30wBLhel4ko20kZJD8wPDkDVT",
        )
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/146.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": base_url,
        "Referer": f"{base_url}/penny",
        "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    if cookies:
        headers["Cookie"] = cookies

    return LLMTarget(
        name=name,
        target_type=TargetType.PENNY,
        base_url=base_url,
        model="penny-genai",
        headers=headers,
        timeout=30,
        metadata={
            "cguid": cguid,
            "chat_path": chat_path,
            "model_version": model_version,
            "request_from": "pennyPortalPage",
        },
    )
