"""Background worker process.

Run with: ``python -m app.jobs.worker``

The worker polls the durable queue, executes registered handlers, retries with
exponential backoff, and requeues stale jobs left behind by crashed workers.
"""

from __future__ import annotations

import logging
import signal
import time

from app.core.config import settings
from app.core.logging import configure_logging
from app.jobs import tasks  # noqa: F401  (registers handlers)
from app.jobs.queue import claim_next, complete, fail, get_session, reclaim_stale, worker_id

logger = logging.getLogger("phishshield.worker")

POLL_INTERVAL = 2.0
STALE_RECLAIM_INTERVAL = 30.0


class Worker:
    def __init__(self, queues: list[str] | None = None):
        self.id = worker_id()
        self.queues = queues or ["default"]
        self._running = True
        self._last_reclaim = 0.0

    def stop(self, *_: object) -> None:
        logger.info("worker %s stopping", self.id)
        self._running = False

    def run(self) -> None:
        logger.info("worker %s started (queues=%s)", self.id, self.queues)
        while self._running:
            now = time.monotonic()
            if now - self._last_reclaim > STALE_RECLAIM_INTERVAL:
                with get_session() as db:
                    reclaimed = reclaim_stale(db)
                    if reclaimed:
                        logger.info("worker %s reclaimed %d stale jobs", self.id, reclaimed)
                self._last_reclaim = now

            processed = self._tick()
            if not processed:
                time.sleep(POLL_INTERVAL)

    def _tick(self) -> bool:
        db = get_session()
        try:
            job = claim_next(db, worker_id=self.id, queues=self.queues)
            if job is None:
                return False
            handler = tasks.REGISTRY.get(job.task)
            if handler is None:
                logger.error("no handler for task %s", job.task)
                fail(db, job, f"no handler registered for task '{job.task}'")
                return True
            try:
                result = handler(db, job.payload or {})
                logger.info("job %s (%s) done: %s", job.id, job.task, result)
                complete(db, job)
            except Exception as exc:  # noqa: BLE001 - record and retry
                logger.exception("job %s (%s) failed", job.id, job.task)
                fail(db, job, str(exc))
            return True
        finally:
            db.close()


def main() -> None:
    configure_logging(settings.log_level, json_logs=settings.is_production)
    worker = Worker()
    signal.signal(signal.SIGINT, worker.stop)
    signal.signal(signal.SIGTERM, worker.stop)
    worker.run()


if __name__ == "__main__":
    main()
