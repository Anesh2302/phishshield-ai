from datetime import UTC, datetime, timedelta

from app.jobs.queue import claim_next, complete, enqueue, fail, reclaim_stale
from app.jobs.tasks import REGISTRY, purge_task
from app.models import Job, Scan


def test_registry_has_core_tasks():
    for name in ("integration.sync_account", "integration.renew",
                 "soc.correlate", "retention.purge"):
        assert name in REGISTRY


def test_enqueue_idempotency(db):
    j1, created1 = enqueue(db, task="noop", idempotency_key="idem-1", queue="q-idem")
    j2, created2 = enqueue(db, task="noop", idempotency_key="idem-1", queue="q-idem")
    assert created1 is True and created2 is False
    assert j1.id == j2.id


def test_claim_and_complete(db):
    enqueue(db, task="noop", queue="q-claim", idempotency_key="claim-1")
    job = claim_next(db, worker_id="w-test", queues=["q-claim"])
    assert job is not None
    assert job.status == "running"
    assert job.attempts == 1
    complete(db, job)
    assert job.status == "succeeded"
    assert db.get(Job, job.id).status == "succeeded"


def test_fail_backoff_then_exhaust(db):
    enqueue(db, task="noop", queue="q-fail", idempotency_key="fail-1", max_attempts=2)
    job = claim_next(db, worker_id="w-test", queues=["q-fail"])
    job = fail(db, job, "boom")
    assert job.status == "pending"
    assert job.run_at > datetime.now(UTC)

    job.run_at = datetime.now(UTC) - timedelta(seconds=1)
    db.commit()
    job = claim_next(db, worker_id="w-test", queues=["q-fail"])
    assert job.attempts == 2
    job = fail(db, job, "boom again")
    assert job.status == "failed"
    assert job.finished_at is not None


def test_reclaim_stale_jobs(db):
    enqueue(db, task="noop", queue="q-stale", idempotency_key="stale-1")
    job = claim_next(db, worker_id="w-test", queues=["q-stale"])
    job.locked_at = datetime.now(UTC) - timedelta(hours=1)
    db.commit()
    reclaimed = reclaim_stale(db, older_than_seconds=60)
    assert reclaimed >= 1
    assert db.get(Job, job.id).status == "pending"


def test_retention_purge_deletes_old_scans(db):
    old = datetime.now(UTC) - timedelta(days=200)
    db.add(Scan(tenant_id="tenant-purge", module="url", target="http://old.example",
                created_at=old))
    db.commit()
    result = purge_task(db, {"tenant_id": "tenant-purge", "days": 90})
    assert result["scans"] >= 1
