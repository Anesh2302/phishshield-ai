"""Incident response: cases, notes, evidence linking and audit trail."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_csrf, require_role
from app.models import Incident, IncidentLink, IncidentNote
from app.schemas import Page, Severity

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    summary: str = ""
    severity: Severity = Severity.medium
    assignee_id: str | None = None


class IncidentUpdate(BaseModel):
    status: str | None = None
    severity: Severity | None = None
    assignee_id: str | None = None
    summary: str | None = None


class NoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class LinkCreate(BaseModel):
    linked_type: str
    linked_id: str
    reason: str = ""


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    title: str
    summary: str
    severity: str
    status: str
    assignee_id: str | None
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


VALID_STATUS = {"open", "investigating", "contained", "closed"}


@router.post("", response_model=IncidentOut, status_code=201)
def create_incident(payload: IncidentCreate,
                    ctx: AuthContext = Depends(require_csrf),
                    db: Session = Depends(get_db)) -> IncidentOut:
    inc = Incident(
        tenant_id=ctx.tenant_id, title=payload.title, summary=payload.summary,
        severity=str(payload.severity), assignee_id=payload.assignee_id, created_by=ctx.user_id,
    )
    db.add(inc)
    record_audit(db, action="incident.create", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="incident", resource_id=inc.id, detail={"title": payload.title},
                 commit=False)
    db.commit()
    db.refresh(inc)
    return IncidentOut.model_validate(inc)


@router.get("", response_model=Page[IncidentOut])
def list_incidents(status_filter: str | None = Query(None, alias="status"),
                   severity: Severity | None = None,
                   q: str | None = None,
                   page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
                   ctx: AuthContext = Depends(get_auth_context),
                   db: Session = Depends(get_db)) -> Page[IncidentOut]:
    stmt = select(Incident).where(Incident.tenant_id == ctx.tenant_id)
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
    if severity:
        stmt = stmt.where(Incident.severity == str(severity))
    if q:
        stmt = stmt.where(Incident.title.ilike(f"%{q}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(Incident.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[IncidentOut.model_validate(r) for r in rows], total=total,
                page=page, page_size=page_size, pages=pages)


def _get(db: Session, incident_id: str, ctx: AuthContext) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None or inc.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return inc


@router.get("/{incident_id}")
def get_incident(incident_id: str, ctx: AuthContext = Depends(get_auth_context),
                 db: Session = Depends(get_db)) -> dict:
    inc = _get(db, incident_id, ctx)
    notes = db.execute(select(IncidentNote).where(IncidentNote.incident_id == inc.id)
                       .order_by(IncidentNote.created_at)).scalars().all()
    links = db.execute(select(IncidentLink).where(IncidentLink.incident_id == inc.id)).scalars().all()
    return {
        "incident": IncidentOut.model_validate(inc).model_dump(),
        "notes": [{"id": n.id, "author_id": n.author_id, "body": n.body,
                   "created_at": n.created_at} for n in notes],
        "links": [{"id": lnk.id, "type": lnk.linked_type, "linked_id": lnk.linked_id,
                   "reason": lnk.reason, "created_at": lnk.created_at} for lnk in links],
    }


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(incident_id: str, payload: IncidentUpdate,
                    ctx: AuthContext = Depends(require_csrf),
                    db: Session = Depends(get_db)) -> IncidentOut:
    inc = _get(db, incident_id, ctx)
    if payload.status:
        if payload.status not in VALID_STATUS:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid status")
        inc.status = payload.status
        if payload.status == "closed":
            inc.closed_at = datetime.now(UTC)
    if payload.severity:
        inc.severity = str(payload.severity)
    if payload.assignee_id is not None:
        inc.assignee_id = payload.assignee_id
    if payload.summary is not None:
        inc.summary = payload.summary
    record_audit(db, action="incident.update", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="incident", resource_id=inc.id,
                 detail=payload.model_dump(exclude_none=True), commit=False)
    db.commit()
    db.refresh(inc)
    return IncidentOut.model_validate(inc)


@router.post("/{incident_id}/notes", status_code=201)
def add_note(incident_id: str, payload: NoteCreate,
             ctx: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> dict:
    inc = _get(db, incident_id, ctx)
    note = IncidentNote(incident_id=inc.id, author_id=ctx.user_id, body=payload.body)
    db.add(note)
    record_audit(db, action="incident.note", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="incident", resource_id=inc.id, commit=False)
    db.commit()
    db.refresh(note)
    return {"id": note.id, "created_at": note.created_at}


@router.post("/{incident_id}/links", status_code=201)
def add_link(incident_id: str, payload: LinkCreate,
             ctx: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> dict:
    inc = _get(db, incident_id, ctx)
    link = IncidentLink(incident_id=inc.id, linked_type=payload.linked_type,
                        linked_id=payload.linked_id, reason=payload.reason)
    db.add(link)
    record_audit(db, action="incident.link", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="incident", resource_id=inc.id,
                 detail={"type": payload.linked_type, "linked_id": payload.linked_id}, commit=False)
    db.commit()
    db.refresh(link)
    return {"id": link.id}


@router.delete("/{incident_id}", status_code=204, response_class=Response,
               dependencies=[Depends(require_role("admin"))])
def delete_incident(incident_id: str, ctx: AuthContext = Depends(require_role("admin")),
                    db: Session = Depends(get_db)) -> Response:
    inc = _get(db, incident_id, ctx)
    db.delete(inc)
    record_audit(db, action="incident.delete", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="incident", resource_id=incident_id, commit=False)
    db.commit()
    return Response(status_code=204)
