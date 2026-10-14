"""Durable database-backed job queue with retries and idempotency.

The queue is backed by PostgreSQL (or SQLite for local tests). Jobs are claimed
atomically. On PostgreSQL we use ``FOR UPDATE SKIP LOCKED`` so multiple workers
can run safely; SQLite uses a conditional UPDATE which is sufficient for the
single-process local development/test scenario.
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, engine
from app.models import Job

logger = logging.getLogger(__name__)

BASE_BACKOFF_SECONDS = 30
MAX_BACKOFF_SECONDS = 3600


def _utcnow() -> datetime:
    return datetime.now(UTC)


def enqueue(
    db: Session,
    *,
    task: str,
    payload: dict | None = None,
    idempotency_key: str | None = None,
    queue: str = "default",
    run_at: datetime | None = None,
    max_attempts: int = 5,
    commit: bool = True,
) -> tuple[Job, bool]:
    """Enqueue a job. With an idempotency_key, re-enqueue is a no-op."""
    if idempotency_key:
        existing = db.execute(
            select(Job).where(Job.idempotency_key == idempotency_key)
        ).scalar_one_or_none()
        if existing is not None:
            return existing, False
    job = Job(
        queue=queue,
        task=task,
        payload=payload or {},
        idempotency_key=idempotency_key,
        run_at=run_at or _utcnow(),
        max_attempts=max_attempts,
    )
    db.add(job)
    if commit:
        try:
            db.commit()
        except Exception:
            db.rollback()
            if idempotency_key:
                existing = db.execute(
                    select(Job).where(Job.idempotency_key == idempotency_key)
                ).scalar_one_or_none()
                if existing is not None:
                    return existing, False
            raise
        db.refresh(job)
    return job, True


def backoff_delay(attempts: int) -> int:
    delay = min(BASE_BACKOFF_SECONDS * (2 ** max(0, attempts - 1)), MAX_BACKOFF_SECONDS)
    return int(delay * (0.5 + random.random() * 0.5))


def claim_next(db: Session, *, worker_id: str, queues: list[str] | None = None) -> Job | None:
    queues = queues or ["default"]
    now = _utcnow()
    dialect = engine.dialect.name
    stmt = (
        select(Job)
        .where(Job.status == "pending", Job.queue.in_(queues), Job.run_at <= now)
        .order_by(Job.run_at.asc())
        .limit(1)
    )
    if dialect == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    job = db.execute(stmt).scalar_one_or_none()
    if job is None:
        return None

    if dialect == "postgresql":
        job.status = "running"
        job.locked_at = now
        job.locked_by = worker_id
        job.attempts += 1
        db.commit()
        db.refresh(job)
        return job

    # SQLite-safe conditional claim.
    result = db.execute(
        update(Job)
        .where(Job.id == job.id, Job.status == "pending")
        .values(status="running", locked_at=now, locked_by=worker_id, attempts=Job.attempts + 1)
    )
    db.commit()
    if result.rowcount != 1:
        return None
    db.refresh(job)
    return job


def complete(db: Session, job: Job) -> None:
    job.status = "succeeded"
    job.finished_at = _utcnow()
    job.last_error = None
    db.commit()


def fail(db: Session, job: Job, error: str) -> Job:
    job.last_error = error[:2000]
    if job.attempts >= job.max_attempts:
        job.status = "failed"
        job.finished_at = _utcnow()
    else:
        job.status = "pending"
        job.run_at = _utcnow() + timedelta(seconds=backoff_delay(job.attempts))
        job.locked_at = None
        job.locked_by = None
    db.commit()
    return job


def reclaim_stale(db: Session, *, older_than_seconds: int = 600) -> int:
    """Return crashed/locked jobs to the pending state."""
    cutoff = _utcnow() - timedelta(seconds=older_than_seconds)
    result = db.execute(
        update(Job)
        .where(Job.status == "running", Job.locked_at < cutoff)
        .values(status="pending", locked_at=None, locked_by=None)
    )
    db.commit()
    return result.rowcount or 0


def worker_id() -> str:
    return f"worker-{uuid.uuid4().hex[:8]}"


def get_session() -> Session:
    return SessionLocal()
