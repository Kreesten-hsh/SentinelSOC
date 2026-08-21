"""SentinelSOC FastAPI Main Application.

Exposes REST APIs for alert triage, autonomous investigations,
and Markdown report generation.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import async_session_factory, init_db
from backend.routes.alerts import router as alerts_router
from backend.services import sentinel_service


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup lifecycle: initialize tables and seed alerts if empty."""
    await init_db()
    async with async_session_factory() as session:
        await sentinel_service.seed_alerts(session, force_reload=False)
    yield


app = FastAPI(
    title="SentinelSOC API",
    description="Autonomous AI Agent for SOC Alert Triage, Correlation, and Investigation",
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
async def health_check() -> dict[str, str]:
    return {"status": "healthy", "service": "SentinelSOC"}
