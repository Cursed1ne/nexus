"""
Centralised settings loaded from environment / .env file.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

_ENV_PATH = Path(__file__).parent.parent / ".env"
load_dotenv(_ENV_PATH)


class Settings:
    # Server
    HOST: str = os.getenv("NEXUS_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("NEXUS_PORT", "8000"))
    DEBUG: bool = os.getenv("NEXUS_DEBUG", "false").lower() == "true"

    # Scanner limits
    MAX_PAGES: int = int(os.getenv("NEXUS_MAX_PAGES", "50"))
    CRAWLER_CONCURRENCY: int = int(os.getenv("NEXUS_CRAWLER_CONCURRENCY", "5"))
    CRAWLER_TIMEOUT: float = float(os.getenv("NEXUS_CRAWLER_TIMEOUT", "10"))
    CHECK_CONCURRENCY: int = int(os.getenv("NEXUS_CHECK_CONCURRENCY", "4"))
    CHECK_TIMEOUT: float = float(os.getenv("NEXUS_CHECK_TIMEOUT", "15"))

    # LLM (optional — Phase 3)
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    # OAST (Phase 2)
    OAST_HOST: str = os.getenv("OAST_HOST", "")
    OAST_PORT: int = int(os.getenv("OAST_PORT", "8888"))

    # DB
    DB_PATH: str = os.getenv("NEXUS_DB_PATH", "nexus_data.db")

    # CORS — frontend origin
    CORS_ORIGINS: list[str] = os.getenv("NEXUS_CORS_ORIGINS", "http://localhost:5173").split(",")


settings = Settings()
