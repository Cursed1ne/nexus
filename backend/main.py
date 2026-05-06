"""
NEXUS — AI Pentesting Platform
Phase 1: working scanner (no LLM required)

Start: uvicorn main:app --reload --port 8000
"""
import logging
import sys
from pathlib import Path

# Ensure backend/ is on sys.path so absolute imports work
_backend = Path(__file__).parent
if str(_backend) not in sys.path:
    sys.path.insert(0, str(_backend))

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import db
from config import settings
from api.routes.scan import router as scan_router
from api.routes.findings import router as findings_router
from api.routes.reports import router as reports_router

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("nexus")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="NEXUS Scanner API",
    description="AI-assisted web application security scanner",
    version="1.0.0-phase1",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(findings_router)
app.include_router(reports_router)


@app.on_event("startup")
async def startup():
    db.init_db()
    logger.info("NEXUS Phase 1 ready — http://%s:%d/docs", settings.HOST, settings.PORT)


@app.get("/health")
async def health():
    return {"status": "ok", "phase": 1}


@app.get("/")
async def root():
    return {
        "name": "NEXUS Scanner",
        "phase": 1,
        "endpoints": {
            "start_scan": "POST /api/scan",
            "poll_scan": "GET /api/scan/{session_id}",
            "list_scans": "GET /api/scans",
            "list_findings": "GET /api/findings",
            "get_finding": "GET /api/findings/{id}",
            "patch_finding": "PATCH /api/findings/{id}",
            "report_json": "GET /api/report/{session_id}",
            "report_html": "GET /api/report/{session_id}?fmt=html",
            "docs": "/docs",
        },
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
