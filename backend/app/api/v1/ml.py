"""Machine-learning model status and prediction endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.deps import AuthContext, get_auth_context, require_csrf
from app.modules.phishing.classifier import get_classifier
from app.modules.phishing.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION

router = APIRouter(prefix="/ml", tags=["ml"])


@router.get("/model")
def model_info(ctx: AuthContext = Depends(get_auth_context)) -> dict:
    clf = get_classifier()
    return {
        "available": clf.available,
        "path": clf.info.path,
        "feature_schema": clf.info.feature_schema or FEATURE_SCHEMA_VERSION,
        "features": FEATURE_NAMES,
        "algorithm": clf.info.algorithm,
        "trained_at": clf.info.trained_at,
        "metrics": clf.info.metrics,
        "error": clf.info.error,
        "fallback": "rules-only" if not clf.available else None,
    }


class PredictIn(BaseModel):
    url: str = Field(min_length=1, max_length=4000)


@router.post("/predict")
def predict(payload: PredictIn, ctx: AuthContext = Depends(require_csrf)) -> dict:
    clf = get_classifier()
    prob = clf.predict_probability(payload.url)
    return {
        "available": clf.available,
        "probability": prob,
        "fallback_used": prob is None,
        "note": "When the model is unavailable the platform uses the rules engine only.",
    }
