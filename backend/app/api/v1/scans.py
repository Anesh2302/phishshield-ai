"""Unified scan endpoints. Currently exposes URL scanning; other modules add
their own endpoints but share the same Scan/Alert data model."""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_csrf
from app.models import Scan
from app.modules.phishing.engine import detect_url
from app.schemas import DetectionResult, Page, ScanOut, Severity
from app.services.alerts import create_alert
from app.services.scans import list_scans, persist_detection

router = APIRouter(prefix="/scans", tags=["scans"])


class UrlScanIn(BaseModel):
    url: str = Field(min_length=1, max_length=4000)
    source: str = Field(default="web", max_length=20)
    include_intel: bool = False


class UrlScanOut(BaseModel):
    scan: ScanOut
    result: DetectionResult
    alert_created: bool = False
    alert_id: str | None = None


@router.post("/url", response_model=UrlScanOut, status_code=201)
def scan_url(
    payload: UrlScanIn,
    ctx: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> UrlScanOut:
    result = detect_url(payload.url, include_intel=payload.include_intel)
    scan = persist_detection(
        db,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        result=result,
        source=payload.source,
    )
    alert_id = None
    alert_created = False
    if result.severity in (Severity.high, Severity.critical) or result.score >= 65:
        alert, created = create_alert(
            db,
            tenant_id=ctx.tenant_id,
            source_module="url_scan",
            rule_id="url_scan.high_risk_url",
            title=f"High-risk URL detected: {result.target[:120]}",
            severity=str(result.severity),
            category="phishing",
            asset=result.target[:200],
            evidence={"scan_id": scan.id, "score": result.score, "verdict": result.verdict},
            dedup_key=f"urlscan:{scan.id}",
            scan_id=scan.id,
        )
        alert_id = alert.id
        alert_created = created

    record_audit(
        db,
        action="scan.url",
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        resource_type="scan",
        resource_id=scan.id,
        detail={"score": result.score, "severity": str(result.severity), "source": payload.source},
    )
    return UrlScanOut(
        scan=ScanOut.model_validate(scan), result=result, alert_created=alert_created, alert_id=alert_id
    )


@router.get("", response_model=Page[ScanOut])
def list_my_scans(
    module: str | None = None,
    severity: Severity | None = None,
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> Page[ScanOut]:
    items, total = list_scans(
        db,
        tenant_id=ctx.tenant_id,
        module=module,
        severity=str(severity) if severity else None,
        q=q,
        page=page,
        page_size=page_size,
    )
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(
        items=[ScanOut.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/export.csv")
def export_scans_csv(
    ctx: AuthContext = Depends(get_auth_context), db: Session = Depends(get_db)
) -> Response:
    items, _ = list_scans(db, tenant_id=ctx.tenant_id, page=1, page_size=200)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "module", "target", "score", "severity", "verdict", "source", "created_at"])
    for s in items:
        writer.writerow(
            [s.id, s.module, s.target, s.score, s.severity, s.verdict, s.source, s.created_at.isoformat()]
        )
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scans.csv"},
    )


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> ScanOut:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return ScanOut.model_validate(scan)
