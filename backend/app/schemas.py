"""Shared API contracts: severity scale, evidence, detection results, paging."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_from_score(score: int) -> Severity:
    """Single source of truth mapping a 0-100 risk score to a severity."""
    if score >= 85:
        return Severity.critical
    if score >= 65:
        return Severity.high
    if score >= 40:
        return Severity.medium
    if score >= 20:
        return Severity.low
    return Severity.info


class Evidence(BaseModel):
    """A single explainable piece of detection evidence."""

    rule_id: str
    title: str
    description: str = ""
    weight: int = 0
    severity: Severity = Severity.info
    detail: dict[str, Any] = Field(default_factory=dict)
    source: str = "rules"


class DetectionResult(BaseModel):
    module: str
    target: str
    score: int = 0
    severity: Severity = Severity.info
    verdict: str = "unknown"
    evidence: list[Evidence] = Field(default_factory=list)
    recommended_action: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    model_config = ConfigDict(use_enum_values=True)


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)
    id: str
    tenant_id: str
    user_id: str | None
    module: str
    target: str
    status: str
    score: int
    severity: Severity
    verdict: str
    source: str
    evidence: dict[str, Any]
    created_at: datetime
    updated_at: datetime


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


class PageParams(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=200)
    q: str | None = None
    severity: Severity | None = None
    status: str | None = None
    sort: str = "-created_at"


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    time: datetime
    components: dict[str, Any]
    capabilities: dict[str, Any]


class MessageOut(BaseModel):
    detail: str
