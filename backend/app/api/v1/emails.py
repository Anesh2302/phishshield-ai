"""Email phishing analysis endpoints (paste/upload an .eml; detection only)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_csrf
from app.models import EmailScan
from app.modules.email_security.analyzer import analyze_email
from app.schemas import DetectionResult, Page
from app.services.alerts import create_alert
from app.services.scans import persist_detection

router = APIRouter(prefix="/emails", tags=["email-security"])

MAX_EML_BYTES = 2 * 1024 * 1024


class EmailAnalyzeIn(BaseModel):
    raw: str = Field(min_length=1, max_length=2_000_000)
    include_intel: bool = False


class EmailScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    provider: str
    message_id: str
    from_addr: str
    reply_to: str
    subject: str
    score: int
    severity: str
    verdict: str
    created_at: datetime


class EmailAnalyzeOut(BaseModel):
    scan_id: str
    email_scan_id: str
    result: DetectionResult
    alert_created: bool = False


def _persist(db: Session, ctx: AuthContext, raw: str | bytes, *, source: str,
             include_intel: bool) -> EmailAnalyzeOut:
    result = analyze_email(raw, include_intel=include_intel)
    scan = persist_detection(db, tenant_id=ctx.tenant_id, user_id=ctx.user_id, result=result,
                             source=source, commit=False)
    meta = result.metadata
    record = EmailScan(
        tenant_id=ctx.tenant_id, provider="manual", message_id=meta.get("message_id") or scan.id,
        from_addr=meta.get("from", ""), reply_to=meta.get("reply_to", ""),
        subject=meta.get("subject", ""), score=result.score, severity=str(result.severity),
        verdict=result.verdict,
        indicators={"evidence": [e.model_dump(mode="json") for e in result.evidence]},
    )
    db.add(record)
    db.commit()
    db.refresh(scan)
    db.refresh(record)

    alert_created = False
    if result.score >= 65:
        _, alert_created = create_alert(
            db, tenant_id=ctx.tenant_id, source_module="email_security",
            rule_id="email.high_risk_message",
            title=f"High-risk email: {meta.get('subject','(no subject)')[:150]}",
            severity=str(result.severity), category="phishing",
            evidence={"email_scan_id": record.id, "scan_id": scan.id, "score": result.score},
            dedup_key=f"email-manual:{record.id}", scan_id=scan.id,
        )
    record_audit(db, action="email.analyze", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="email_scan", resource_id=record.id,
                 detail={"score": result.score, "severity": str(result.severity)})
    return EmailAnalyzeOut(scan_id=scan.id, email_scan_id=record.id, result=result,
                           alert_created=alert_created)


@router.post("/analyze", response_model=EmailAnalyzeOut, status_code=201)
def analyze(payload: EmailAnalyzeIn, ctx: AuthContext = Depends(require_csrf),
            db: Session = Depends(get_db)) -> EmailAnalyzeOut:
    return _persist(db, ctx, payload.raw, source="api", include_intel=payload.include_intel)


@router.post("/upload", response_model=EmailAnalyzeOut, status_code=201)
async def upload_eml(file: UploadFile = File(...),
                     ctx: AuthContext = Depends(require_csrf),
                     db: Session = Depends(get_db)) -> EmailAnalyzeOut:
    data = await file.read(MAX_EML_BYTES + 1)
    if len(data) > MAX_EML_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Email exceeds 2 MB limit")
    return _persist(db, ctx, data, source="upload", include_intel=False)


@router.get("/scans", response_model=Page[EmailScanOut])
def list_email_scans(severity: str | None = None, page: int = Query(1, ge=1),
                     page_size: int = Query(25, ge=1, le=200),
                     ctx: AuthContext = Depends(get_auth_context),
                     db: Session = Depends(get_db)) -> Page[EmailScanOut]:
    stmt = select(EmailScan).where(EmailScan.tenant_id == ctx.tenant_id)
    if severity:
        stmt = stmt.where(EmailScan.severity == severity)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(EmailScan.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[EmailScanOut.model_validate(r) for r in rows], total=total,
                page=page, page_size=page_size, pages=pages)


@router.get("/scans/{scan_id}")
def get_email_scan(scan_id: str, ctx: AuthContext = Depends(get_auth_context),
                   db: Session = Depends(get_db)) -> dict[str, Any]:
    row = db.get(EmailScan, scan_id)
    if row is None or row.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Email scan not found")
    return {
        "id": row.id, "message_id": row.message_id, "from": row.from_addr,
        "reply_to": row.reply_to, "subject": row.subject, "score": row.score,
        "severity": row.severity, "verdict": row.verdict, "indicators": row.indicators,
        "created_at": row.created_at,
    }
