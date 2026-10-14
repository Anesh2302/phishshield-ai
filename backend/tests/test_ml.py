from pathlib import Path

import pytest

ART = Path(__file__).resolve().parents[2] / "ml" / "artifacts" / "url_model.joblib"

pytestmark = pytest.mark.skipif(not ART.exists(), reason="model artifact not trained")


def test_model_artifact_loads(monkeypatch):
    monkeypatch.setattr("app.modules.phishing.classifier.settings.ml_enabled", True)
    from app.modules.phishing.classifier import URLClassifier

    clf = URLClassifier(model_path=str(ART))
    assert clf.available is True
    assert clf.info.feature_schema == "1.0"
    assert clf.info.algorithm == "RandomForestClassifier"
    benign_prob = clf.predict_probability("https://www.python.org/community")
    phish_prob = clf.predict_probability("http://paypal-secure-login.tk/verify/password.exe")
    assert benign_prob is not None
    assert phish_prob is not None
    assert expect_separation(benign_prob, phish_prob)


def expect_separation(benign: float, phish: float) -> bool:
    return benign < 0.5 < phish