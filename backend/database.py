"""SQLite + SQLAlchemy database layer for SentinelSOC.

Stores:
- Ingested Alerts
- Investigation Results (with full reasoning steps and findings)
- Investigation Reports (JSON + Markdown)
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "sentinelsoc.db"
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session_factory = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class AlertRecord(Base):
    """Database model for ingested alerts."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    scenario_id: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Relationships
    investigation: Mapped[InvestigationRecord | None] = relationship(
        "InvestigationRecord", back_populates="alert", uselist=False, cascade="all, delete-orphan"
    )
    report: Mapped[ReportRecord | None] = relationship(
        "ReportRecord", back_populates="alert", uselist=False, cascade="all, delete-orphan"
    )


class InvestigationRecord(Base):
    """Database model for completed or ongoing investigations."""

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), ForeignKey("alerts.id"), unique=True, nullable=False)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    steps_count: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    alert: Mapped[AlertRecord] = relationship("AlertRecord", back_populates="investigation")


class ReportRecord(Base):
    """Database model for generated investigation reports."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), ForeignKey("alerts.id"), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    executive_summary: Mapped[str] = mapped_column(Text, default="")
    markdown: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    alert: Mapped[AlertRecord] = relationship("AlertRecord", back_populates="report")


async def init_db() -> None:
    """Create all database tables."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for obtaining async DB session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
