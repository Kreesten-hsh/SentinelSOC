"""SentinelSOC FastAPI Main Application.

Exposes REST APIs for alert triage, autonomous investigations,
and Markdown report generation.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import async_session_factory, init_db
from backend.routes.alerts import router as alerts_router
from backend.services import sentinel_service
from src.scoring.ml_scorer import DEFAULT_MODEL_PATH

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinelsoc.api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup lifecycle: initialize tables, verify ML model, and seed alerts if empty."""
    await init_db()
    # Check ML model status
    is_trained = sentinel_service.agent.severity_scorer.ml_scorer.is_trained
    logger.info(
        "SentinelSOC initialized. ML Scorer Model: %s (Path: %s)",
        "TRAINED" if is_trained else "UNAVAILABLE",
        DEFAULT_MODEL_PATH,
    )
    async with async_session_factory() as session:
        await sentinel_service.seed_alerts(session, force_reload=False)
    yield


app = FastAPI(
    title="SentinelSOC API",
    description="Autonomous SOC Alert Triage, Correlation, and Investigation Engine",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts_router)


@app.get("/api/health")
async def health_check() -> dict[str, Any]:
    ml_scorer = sentinel_service.agent.severity_scorer.ml_scorer
    return {
        "status": "healthy",
        "service": "SentinelSOC",
        "ml_model_loaded": ml_scorer.is_trained,
        "ml_model_path": str(ml_scorer.model_path),
        "pipeline_mode": "deterministic_7_step",
        "llm_mode_available": True,
    }
