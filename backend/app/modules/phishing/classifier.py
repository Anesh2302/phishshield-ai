"""ML classifier wrapper with a strict rules-only fallback.

If the model artifact is missing, incompatible, or fails to load, the detector
still works using the explainable rules engine alone. The model is never the
sole basis for a verdict.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings
from app.modules.phishing.features import FEATURE_SCHEMA_VERSION, feature_vector

logger = logging.getLogger(__name__)


@dataclass
class ModelInfo:
    available: bool
    path: str
    feature_schema: str | None = None
    algorithm: str | None = None
    trained_at: str | None = None
    metrics: dict | None = None
    error: str | None = None


class URLClassifier:
    def __init__(self, model_path: str | None = None):
        self.model_path = Path(model_path or settings.ml_model_path)
        self._artifact: dict | None = None
        self.info = ModelInfo(available=False, path=str(self.model_path))
        if settings.ml_enabled:
            self._load()

    def _load(self) -> None:
        if not self.model_path.exists():
            self.info.error = "model artifact not found; using rules-only fallback"
            logger.info("ML model not found at %s; rules-only fallback active", self.model_path)
            return
        try:
            import joblib

            artifact = joblib.load(self.model_path)
            if not isinstance(artifact, dict) or "pipeline" not in artifact:
                self.info.error = "unexpected artifact format"
                return
            if artifact.get("feature_schema") != FEATURE_SCHEMA_VERSION:
                self.info.error = (
                    f"feature schema mismatch: model={artifact.get('feature_schema')} "
                    f"runtime={FEATURE_SCHEMA_VERSION}"
                )
                return
            self._artifact = artifact
            self.info = ModelInfo(
                available=True,
                path=str(self.model_path),
                feature_schema=artifact.get("feature_schema"),
                algorithm=artifact.get("algorithm"),
                trained_at=artifact.get("trained_at"),
                metrics=artifact.get("metrics"),
            )
            logger.info("Loaded URL model (%s) from %s", self.info.algorithm, self.model_path)
        except Exception as exc:  # pragma: no cover - defensive
            self.info.error = f"failed to load model: {exc}"
            logger.warning("Failed to load ML model: %s", exc)

    @property
    def available(self) -> bool:
        return self._artifact is not None

    def predict_probability(self, url: str) -> float | None:
        if not self.available:
            return None
        try:
            pipeline = self._artifact["pipeline"]
            vec = [feature_vector(url)]
            proba = pipeline.predict_proba(vec)[0]
            # class order chosen at train time: [benign, malicious]
            classes = list(getattr(pipeline, "classes_", [0, 1]))
            idx = classes.index(1) if 1 in classes else len(proba) - 1
            return float(proba[idx])
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Model inference failed: %s", exc)
            return None


_cached: URLClassifier | None = None


def get_classifier() -> URLClassifier:
    global _cached
    if _cached is None:
        _cached = URLClassifier()
    return _cached


def reset_classifier_cache() -> None:
    global _cached
    _cached = None
