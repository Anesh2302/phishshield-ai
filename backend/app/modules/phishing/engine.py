"""Unified URL detection engine: transparent rules + ML + optional threat intel.

The rules engine is always authoritative for *why* something is suspicious. The
ML model contributes a calibrated signal; when it is unavailable only rules are
used. Threat-intelligence hits raise the score but their absence never lowers it.
"""

from __future__ import annotations

from app.modules.phishing.classifier import get_classifier
from app.modules.phishing.url_analyzer import UrlAnalysis, analyze_url
from app.modules.threatintel.service import get_threatintel
from app.schemas import DetectionResult, Evidence, Severity, severity_from_score

# Blend weights when the model is available.
RULE_WEIGHT = 0.7
ML_WEIGHT = 0.3


def detect_url(url: str, *, include_intel: bool = False, intel=None) -> DetectionResult:
    analysis: UrlAnalysis = analyze_url(url)
    evidence = list(analysis.evidence)
    rule_score = min(100, sum(e.weight for e in evidence if e.weight > 0))

    classifier = get_classifier()
    ml_prob = classifier.predict_probability(url)
    ml_score = None
    if ml_prob is not None:
        ml_score = round(ml_prob * 100)
        evidence.append(
            Evidence(
                rule_id="ml.url.classifier",
                title="Statistical model assessment",
                description=(
                    f"The URL classifier estimates a {ml_prob:.0%} probability of phishing "
                    f"(model {classifier.info.algorithm}, schema {classifier.info.feature_schema})."
                ),
                weight=0,
                severity=severity_from_score(ml_score),
                source="ml",
                detail={"probability": round(ml_prob, 4)},
            )
        )

    combined = rule_score
    if ml_score is not None:
        combined = round(RULE_WEIGHT * rule_score + ML_WEIGHT * ml_score)
    combined = max(combined, rule_score) if ml_score is not None else rule_score

    # Optional threat intelligence (raises score on a hit only).
    intel_meta = None
    if include_intel:
        ti = intel if intel is not None else get_threatintel().lookup(url)
        intel_meta = {
            "available": ti.available,
            "providers": [
                {"provider": p.provider, "status": p.status, "detail": p.detail}
                for p in ti.providers
            ],
            "disclaimer": "Absence from a feed does not mean a URL is safe.",
        }
        if ti.any_hit:
            evidence.append(
                Evidence(
                    rule_id="threatintel.hit",
                    title="Matched a threat-intelligence feed",
                    description=f"Indicator(s): {', '.join(ti.indicators)}",
                    weight=0,
                    severity=Severity.critical,
                    source="threatintel",
                    detail={"indicators": ti.indicators},
                )
            )
            combined = min(100, max(combined, 90))

    severity = severity_from_score(combined)
    verdict = analysis.verdict
    if combined >= 65:
        verdict = "malicious"
    elif combined >= 40:
        verdict = "suspicious"
    elif combined >= 20:
        verdict = "low_risk"
    else:
        verdict = "benign"

    meta = dict(analysis.metadata)
    meta["rule_score"] = rule_score
    meta["ml_score"] = ml_score
    meta["ml_available"] = ml_score is not None
    if intel_meta:
        meta["threat_intel"] = intel_meta

    return DetectionResult(
        module="url",
        target=url,
        score=combined,
        severity=severity,
        verdict=verdict,
        evidence=evidence,
        recommended_action=analysis.recommended_action,
        metadata=meta,
    )
