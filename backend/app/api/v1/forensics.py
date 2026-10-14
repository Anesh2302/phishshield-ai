"""Digital forensics endpoints: evidence register, integrity, custody, timeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_csrf
from app.models import CustodyEvent, EvidenceItem
from app.modules.files.storage import FileStorage, compute_hashes
from app.modules.forensics.service import (
    add_custody,
    build_timeline,
    register_evidence,
    report_csv,
    verify_integrity,
)
from app.schemas import Page

router = APIRouter(prefix="/forensics", tags=["forensics"])

_evidence_storage = FileStorage(settings.evidence_path)
MAX_BYTES = settings.max_upload_mb * 1024 * 1024


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    case_name: str
    title: str
    source: str
    sha256: str
    size: int
    status: str
    acquired_by: str | None
    acquired_at: datetime
    metadata_json: dict[str, Any]


class CustodyIn(BaseModel):
    action: str = Field(pattern="^(accessed|transferred|released|verified|registered)$")
    note: str = ""


@router.post("/evidence", response_model=EvidenceOut, status_code=201)
async def create_evidence(
    case_name: str = Form(..., min_length=1, max_length=200),
    title: str = Form(..., min_length=1, max_length=300),
    source: str = Form(default=""),
    file: UploadFile | None = File(default=None),
    ctx: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> EvidenceOut:
    data: bytes | None = None
    stored_name: str | None = None
    metadata: dict[str, Any] = {}
    if file is not None:
        data = await file.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Evidence exceeds size limit")
        if len(data) == 0:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty evidence rejected")
        stored_name, _path, _size = _evidence_storage.save_bytes(data, file.filename or "evidence.bin")
        metadata = {"original_name": file.filename, "content_type": file.content_type}
    item = register_evidence(
        db, tenant_id=ctx.tenant_id, user_id=ctx.user_id, case_name=case_name,
        title=title, source=source, data=data, stored_name=stored_name, metadata=metadata,
    )
    return EvidenceOut.model_validate(item)


@router.get("/evidence", response_model=Page[EvidenceOut])
def list_evidence(case_name: str | None = None, q: str | None = None,
                  page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
                  ctx: AuthContext = Depends(get_auth_context),
                  db: Session = Depends(get_db)) -> Page[EvidenceOut]:
    stmt = select(EvidenceItem).where(EvidenceItem.tenant_id == ctx.tenant_id)
    if case_name:
        stmt = stmt.where(EvidenceItem.case_name == case_name)
    if q:
        stmt = stmt.where(EvidenceItem.title.ilike(f"%{q}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(EvidenceItem.acquired_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[EvidenceOut.model_validate(r) for r in rows], total=total,
                page=page, page_size=page_size, pages=pages)


def _get(db: Session, evidence_id: str, ctx: AuthContext) -> EvidenceItem:
    item = db.get(EvidenceItem, evidence_id)
    if item is None or item.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence not found")
    return item


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str, ctx: AuthContext = Depends(get_auth_context),
                 db: Session = Depends(get_db)) -> dict[str, Any]:
    item = _get(db, evidence_id, ctx)
    custody = db.execute(select(CustodyEvent).where(CustodyEvent.evidence_id == item.id)
                         .order_by(CustodyEvent.created_at)).scalars().all()
    record_audit(db, action="forensics.evidence.access", tenant_id=ctx.tenant_id,
                 user_id=ctx.user_id, resource_type="evidence", resource_id=item.id)
    return {
        "evidence": EvidenceOut.model_validate(item).model_dump(),
        "custody": [{"action": c.action, "actor_id": c.actor_id, "note": c.note,
                     "created_at": c.created_at, "hash_snapshot": c.hash_snapshot} for c in custody],
        "disclaimer": ("This record is a bookkeeping aid. It does not establish legal "
                       "admissibility; independent forensic validation is required."),
    }


@router.post("/evidence/{evidence_id}/verify")
def verify(evidence_id: str, ctx: AuthContext = Depends(require_csrf),
           db: Session = Depends(get_db)) -> dict:
    item = _get(db, evidence_id, ctx)
    if not item.stored_path:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No stored blob to verify")
    data = _evidence_storage.read_bytes(item.stored_path, max_bytes=MAX_BYTES)
    current = compute_hashes(data)["sha256"]
    match = verify_integrity(db, item=item, current_sha256=current, user_id=ctx.user_id)
    return {"match": match, "expected": item.sha256, "actual": current}


@router.post("/evidence/{evidence_id}/custody")
def custody(evidence_id: str, payload: CustodyIn, ctx: AuthContext = Depends(require_csrf),
            db: Session = Depends(get_db)) -> dict:
    item = _get(db, evidence_id, ctx)
    ev = add_custody(db, item=item, action=payload.action, actor_id=ctx.user_id, note=payload.note)
    return {"id": ev.id, "action": ev.action, "created_at": ev.created_at}


@router.get("/cases/{case_name}/timeline")
def case_timeline(case_name: str, ctx: AuthContext = Depends(get_auth_context),
                  db: Session = Depends(get_db)) -> dict:
    return {"case": case_name, "timeline": build_timeline(db, tenant_id=ctx.tenant_id, case_name=case_name)}


@router.get("/report.csv")
def report(case_name: str | None = None, ctx: AuthContext = Depends(get_auth_context),
           db: Session = Depends(get_db)) -> Response:
    content = report_csv(db, tenant_id=ctx.tenant_id, case_name=case_name)
    return Response(content=content, media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=forensics_report.csv"})
