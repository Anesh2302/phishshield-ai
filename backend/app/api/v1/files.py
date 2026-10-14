"""File security & malware-analysis endpoints.

Uploads are stored outside the web root under randomised identifiers. Files are
NEVER executed or rendered. Static analysis is indicative, not proof of safety.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_csrf, require_role
from app.models import FileObject, FileReport
from app.modules.files.analyzer import analyze_bytes
from app.modules.files.storage import FileStorage
from app.schemas import DetectionResult, Page
from app.services.alerts import create_alert
from app.services.scans import persist_detection

router = APIRouter(prefix="/files", tags=["file-security"])

_storage = FileStorage(settings.quarantine_path)
MAX_BYTES = settings.max_upload_mb * 1024 * 1024


class FileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    original_name: str
    size: int
    sha256: str
    detected_type: str
    detected_mime: str
    declared_type: str
    status: str
    severity: str
    score: int
    created_at: datetime


class FileUploadOut(BaseModel):
    file: FileOut
    scan_id: str
    result: DetectionResult
    alert_created: bool = False


@router.post("/upload", response_model=FileUploadOut, status_code=201)
async def upload_file(file: UploadFile = File(...),
                      ctx: AuthContext = Depends(require_csrf),
                      db: Session = Depends(get_db)) -> FileUploadOut:
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"File exceeds {settings.max_upload_mb} MB limit")
    if len(data) == 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty file rejected")

    original_name = (file.filename or "unknown")[:400]
    analysis = analyze_bytes(data, declared_name=original_name)
    stored_name, _path, _size = _storage.save_bytes(data, original_name)

    result = DetectionResult(
        module="file",
        target=analysis.sha256,
        score=analysis.score,
        severity=analysis.severity,
        verdict=_verdict(analysis.score),
        evidence=analysis.evidence,
        recommended_action=_recommendation(str(analysis.severity)),
        metadata=analysis.metadata,
    )
    scan = persist_detection(db, tenant_id=ctx.tenant_id, user_id=ctx.user_id, result=result,
                             source="upload", commit=False)
    record = FileObject(
        tenant_id=ctx.tenant_id, user_id=ctx.user_id, scan_id=scan.id,
        original_name=original_name, stored_path=stored_name, size=analysis.size,
        sha256=analysis.sha256, sha1=analysis.sha1, md5=analysis.md5,
        detected_type=analysis.detected_description, detected_mime=analysis.detected_mime,
        declared_type=analysis.declared_ext, status="quarantined",
        severity=str(analysis.severity), score=analysis.score, metadata_json=analysis.metadata,
    )
    db.add(record)
    db.flush()
    db.add(FileReport(file_id=record.id, tenant_id=ctx.tenant_id, engine="static",
                      findings={"evidence": [e.model_dump(mode="json") for e in analysis.evidence]}))
    db.commit()
    db.refresh(scan)
    db.refresh(record)

    alert_created = False
    if analysis.score >= 65:
        _, alert_created = create_alert(
            db, tenant_id=ctx.tenant_id, source_module="file_analysis",
            rule_id="file.high_risk_file",
            title=f"High-risk file uploaded: {original_name}",
            severity=str(analysis.severity), category="malware",
            evidence={"file_id": record.id, "scan_id": scan.id, "sha256": analysis.sha256,
                      "score": analysis.score},
            dedup_key=f"file:{analysis.sha256}", scan_id=scan.id,
        )
    record_audit(db, action="file.upload", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="file", resource_id=record.id,
                 detail={"sha256": analysis.sha256, "score": analysis.score, "name": original_name})
    return FileUploadOut(file=FileOut.model_validate(record), scan_id=scan.id, result=result,
                         alert_created=alert_created)


@router.get("", response_model=Page[FileOut])
def list_files(severity: str | None = None, q: str | None = None,
               page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
               ctx: AuthContext = Depends(get_auth_context),
               db: Session = Depends(get_db)) -> Page[FileOut]:
    stmt = select(FileObject).where(FileObject.tenant_id == ctx.tenant_id)
    if severity:
        stmt = stmt.where(FileObject.severity == severity)
    if q:
        stmt = stmt.where(FileObject.original_name.ilike(f"%{q}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(FileObject.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[FileOut.model_validate(r) for r in rows], total=total,
                page=page, page_size=page_size, pages=pages)


@router.get("/export.csv")
def export_files_csv(ctx: AuthContext = Depends(get_auth_context),
                     db: Session = Depends(get_db)) -> Response:
    rows = db.execute(select(FileObject).where(FileObject.tenant_id == ctx.tenant_id)
                      .order_by(FileObject.created_at.desc()).limit(500)).scalars().all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "name", "size", "sha256", "detected_type", "severity", "score", "created_at"])
    for r in rows:
        writer.writerow([r.id, r.original_name, r.size, r.sha256, r.detected_type,
                         r.severity, r.score, r.created_at.isoformat()])
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=files.csv"})


def _get(db: Session, file_id: str, ctx: AuthContext) -> FileObject:
    row = db.get(FileObject, file_id)
    if row is None or row.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    return row


@router.get("/{file_id}")
def get_file(file_id: str, ctx: AuthContext = Depends(get_auth_context),
             db: Session = Depends(get_db)) -> dict[str, Any]:
    row = _get(db, file_id, ctx)
    return {
        "id": row.id, "original_name": row.original_name, "size": row.size,
        "sha256": row.sha256, "sha1": row.sha1, "md5": row.md5,
        "detected_type": row.detected_type, "detected_mime": row.detected_mime,
        "declared_type": row.declared_type, "status": row.status,
        "severity": row.severity, "score": row.score, "metadata": row.metadata_json,
        "created_at": row.created_at,
    }


@router.get("/{file_id}/download")
def download_file(file_id: str, ctx: AuthContext = Depends(require_role("admin")),
                  db: Session = Depends(get_db)) -> Response:
    row = _get(db, file_id, ctx)
    data = _storage.read_bytes(row.stored_path, max_bytes=MAX_BYTES)
    record_audit(db, action="file.download", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="file", resource_id=row.id, detail={"sha256": row.sha256})
    return Response(
        content=data, media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file_id}.bin"',
            "X-SHA256": row.sha256,
        },
    )


@router.delete("/{file_id}", status_code=204, response_class=Response)
def delete_file(file_id: str, ctx: AuthContext = Depends(require_csrf),
                db: Session = Depends(get_db)) -> Response:
    row = _get(db, file_id, ctx)
    _storage.delete(row.stored_path)
    db.query(FileReport).filter(FileReport.file_id == row.id).delete()
    db.delete(row)
    record_audit(db, action="file.delete", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="file", resource_id=file_id, detail={"sha256": row.sha256},
                 commit=False)
    db.commit()
    return Response(status_code=204)


def _verdict(score: int) -> str:
    if score >= 65:
        return "malicious"
    if score >= 40:
        return "suspicious"
    if score >= 20:
        return "low_risk"
    return "benign"


def _recommendation(sev: str) -> str:
    if sev in ("high", "critical"):
        return "Do not open or execute this file. Keep it quarantined and escalate to your security team."
    if sev == "medium":
        return "Treat with caution and verify the source before opening."
    return "No strong indicators found, but static analysis is not proof of safety."
