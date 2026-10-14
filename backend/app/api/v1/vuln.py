"""Vulnerability & asset management endpoints.

Active scanning requires explicit authorization and scope; this API only ingests
output from locally run open-source scanners and manages the resulting findings.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.database import get_db
from app.core.deps import AuthContext, get_auth_context, require_csrf, require_role
from app.models import Asset, VulnFinding
from app.modules.vuln.parsers import compute_priority, parse_osv, parse_trivy
from app.schemas import Page, Severity

router = APIRouter(prefix="/vuln", tags=["vulnerability-management"])


class AssetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    kind: str = "host"
    identifier: str = ""
    criticality: str = "medium"
    exposure: str = "internal"
    owner: str = ""
    tags: list[str] = Field(default_factory=list)


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    kind: str
    identifier: str
    criticality: str
    exposure: str
    owner: str
    tags: list[str]
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    asset_id: str | None
    source: str
    cve: str | None
    title: str
    severity: str
    priority: str
    package: str | None
    installed_version: str | None
    fixed_version: str | None
    status: str
    created_at: datetime


class ImportIn(BaseModel):
    tool: str = Field(pattern="^(osv|trivy)$")
    data: dict[str, Any]
    asset_id: str | None = None
    authorized: bool = False
    scope_note: str = ""


class FindingUpdate(BaseModel):
    status: str | None = Field(default=None, pattern="^(open|remediating|resolved|accepted)$")


@router.post("/assets", response_model=AssetOut, status_code=201)
def create_asset(payload: AssetIn, ctx: AuthContext = Depends(require_csrf),
                 db: Session = Depends(get_db)) -> AssetOut:
    exists = db.execute(select(Asset).where(Asset.tenant_id == ctx.tenant_id,
                                            Asset.name == payload.name)).scalar_one_or_none()
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "Asset with this name already exists")
    asset = Asset(tenant_id=ctx.tenant_id, **payload.model_dump())
    db.add(asset)
    record_audit(db, action="asset.create", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="asset", resource_id=asset.id, commit=False)
    db.commit()
    db.refresh(asset)
    return AssetOut.model_validate(asset)


@router.get("/assets", response_model=Page[AssetOut])
def list_assets(q: str | None = None, page: int = Query(1, ge=1),
                page_size: int = Query(25, ge=1, le=200),
                ctx: AuthContext = Depends(get_auth_context),
                db: Session = Depends(get_db)) -> Page[AssetOut]:
    stmt = select(Asset).where(Asset.tenant_id == ctx.tenant_id)
    if q:
        stmt = stmt.where(Asset.name.ilike(f"%{q}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(Asset.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[AssetOut.model_validate(r) for r in rows], total=total,
                page=page, page_size=page_size, pages=pages)


@router.delete("/assets/{asset_id}", status_code=204, response_class=Response,
               dependencies=[Depends(require_role("admin"))])
def delete_asset(asset_id: str, ctx: AuthContext = Depends(require_role("admin")),
                 db: Session = Depends(get_db)) -> Response:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    db.delete(asset)
    record_audit(db, action="asset.delete", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="asset", resource_id=asset_id, commit=False)
    db.commit()
    return Response(status_code=204)


@router.post("/findings/import", status_code=201)
def import_findings(payload: ImportIn, ctx: AuthContext = Depends(require_csrf),
                    db: Session = Depends(get_db)) -> dict:
    if not payload.authorized:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Explicit authorization required. Set authorized=true and provide a scope_note.",
        )
    parsed = parse_osv(payload.data) if payload.tool == "osv" else parse_trivy(payload.data)
    asset = None
    if payload.asset_id:
        asset = db.get(Asset, payload.asset_id)
        if asset is None or asset.tenant_id != ctx.tenant_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    created = 0
    for f in parsed:
        priority = compute_priority(
            f.severity,
            criticality=asset.criticality if asset else "medium",
            exposure=asset.exposure if asset else "internal",
        )
        db.add(VulnFinding(
            tenant_id=ctx.tenant_id, asset_id=payload.asset_id, source=f.source, cve=f.cve,
            title=f.title[:400], severity=f.severity, priority=priority, package=f.package,
            installed_version=f.installed_version, fixed_version=f.fixed_version, raw=f.raw,
        ))
        created += 1
    record_audit(db, action="vuln.import", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 detail={"tool": payload.tool, "count": created, "scope": payload.scope_note},
                 commit=False)
    db.commit()
    return {"imported": created, "tool": payload.tool}


@router.get("/findings", response_model=Page[FindingOut])
def list_findings(severity: Severity | None = None, status_filter: str | None = Query(None, alias="status"),
                  cve: str | None = None, q: str | None = None,
                  page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
                  ctx: AuthContext = Depends(get_auth_context),
                  db: Session = Depends(get_db)) -> Page[FindingOut]:
    stmt = select(VulnFinding).where(VulnFinding.tenant_id == ctx.tenant_id)
    if severity:
        stmt = stmt.where(VulnFinding.severity == str(severity))
    if status_filter:
        stmt = stmt.where(VulnFinding.status == status_filter)
    if cve:
        stmt = stmt.where(VulnFinding.cve == cve)
    if q:
        stmt = stmt.where(VulnFinding.title.ilike(f"%{q}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(VulnFinding.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    pages = max(1, (total + page_size - 1) // page_size)
    return Page(items=[FindingOut.model_validate(r) for r in rows], total=total,
                page=page, page_size=page_size, pages=pages)


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: str, payload: FindingUpdate,
                   ctx: AuthContext = Depends(require_csrf), db: Session = Depends(get_db)) -> FindingOut:
    finding = db.get(VulnFinding, finding_id)
    if finding is None or finding.tenant_id != ctx.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if payload.status:
        finding.status = payload.status
    record_audit(db, action="vuln.update", tenant_id=ctx.tenant_id, user_id=ctx.user_id,
                 resource_type="vuln_finding", resource_id=finding.id,
                 detail={"status": finding.status}, commit=False)
    db.commit()
    db.refresh(finding)
    return FindingOut.model_validate(finding)


@router.get("/scanners")
def scanner_status() -> dict:
    import shutil

    return {
        "scanners": {
            "osv-scanner": bool(shutil.which("osv-scanner")),
            "trivy": bool(shutil.which("trivy")),
        },
        "note": ("Scanners are optional. When absent, run them offline and POST their JSON "
                 "output to /vuln/findings/import. No active scanning is performed by the API."),
    }
