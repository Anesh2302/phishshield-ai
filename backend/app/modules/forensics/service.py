"""Digital forensics: evidence register, integrity verification, chain of custody.

We do not claim legal admissibility or forensic soundness. This is a
bookkeeping and integrity tool; validation by a qualified examiner is required
before any evidence is relied upon in a proceeding.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.models import CustodyEvent, EvidenceItem
from app.modules.files.storage import compute_hashes


def register_evidence(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None,
    case_name: str,
    title: str,
    source: str,
    data: bytes | None,
    stored_name: str | None,
    metadata: dict | None = None,
) -> EvidenceItem:
    sha256 = compute_hashes(data)["sha256"] if data is not None else ""
    item = EvidenceItem(
        tenant_id=tenant_id,
        case_name=case_name,
        title=title,
        source=source,
        stored_path=stored_name,
        sha256=sha256,
        size=len(data) if data is not None else 0,
        acquired_by=user_id,
        acquired_at=datetime.now(UTC),
        metadata_json=metadata or {},
    )
    db.add(item)
    db.flush()
    db.add(
        CustodyEvent(
            evidence_id=item.id,
            tenant_id=tenant_id,
            action="registered",
            actor_id=user_id,
            note="Evidence registered",
            hash_snapshot=sha256 or None,
        )
    )
    record_audit(
        db, action="forensics.evidence.register", tenant_id=tenant_id, user_id=user_id,
        resource_type="evidence", resource_id=item.id,
        detail={"case": case_name, "sha256": sha256}, commit=False,
    )
    db.commit()
    db.refresh(item)
    return item


def verify_integrity(db: Session, *, item: EvidenceItem, current_sha256: str,
                     user_id: str | None) -> bool:
    match = bool(item.sha256) and item.sha256 == current_sha256
    db.add(
        CustodyEvent(
            evidence_id=item.id,
            tenant_id=item.tenant_id,
            action="verified",
            actor_id=user_id,
            note=f"Integrity verification {'passed' if match else 'FAILED'}",
            hash_snapshot=current_sha256,
        )
    )
    record_audit(
        db, action="forensics.evidence.verify", tenant_id=item.tenant_id, user_id=user_id,
        resource_type="evidence", resource_id=item.id,
        detail={"match": match}, commit=False,
    )
    db.commit()
    return match


def add_custody(
    db: Session, *, item: EvidenceItem, action: str, actor_id: str | None, note: str
) -> CustodyEvent:
    ev = CustodyEvent(
        evidence_id=item.id,
        tenant_id=item.tenant_id,
        action=action,
        actor_id=actor_id,
        note=note,
        hash_snapshot=item.sha256,
    )
    db.add(ev)
    record_audit(
        db, action=f"forensics.custody.{action}", tenant_id=item.tenant_id, user_id=actor_id,
        resource_type="evidence", resource_id=item.id, detail={"note": note}, commit=False,
    )
    db.commit()
    db.refresh(ev)
    return ev


def build_timeline(db: Session, *, tenant_id: str, case_name: str) -> list[dict]:
    items = db.execute(
        select(EvidenceItem).where(
            EvidenceItem.tenant_id == tenant_id, EvidenceItem.case_name == case_name
        )
    ).scalars().all()
    timeline: list[dict] = []
    for item in items:
        timeline.append(
            {
                "time": item.acquired_at,
                "type": "evidence_registered",
                "evidence_id": item.id,
                "title": item.title,
                "detail": f"sha256={item.sha256}",
            }
        )
        for ev in db.execute(
            select(CustodyEvent).where(CustodyEvent.evidence_id == item.id)
        ).scalars().all():
            timeline.append(
                {
                    "time": ev.created_at,
                    "type": f"custody_{ev.action}",
                    "evidence_id": item.id,
                    "title": item.title,
                    "detail": ev.note,
                }
            )
    timeline.sort(key=lambda r: r["time"])
    return timeline


def report_csv(db: Session, *, tenant_id: str, case_name: str | None = None) -> str:
    stmt = select(EvidenceItem).where(EvidenceItem.tenant_id == tenant_id)
    if case_name:
        stmt = stmt.where(EvidenceItem.case_name == case_name)
    items = db.execute(stmt).scalars().all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "case", "title", "source", "sha256", "size", "acquired_at", "acquired_by"])
    for it in items:
        writer.writerow([it.id, it.case_name, it.title, it.source, it.sha256, it.size,
                         it.acquired_at.isoformat(), it.acquired_by])
    return buf.getvalue()
