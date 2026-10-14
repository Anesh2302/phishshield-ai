"""Train the URL phishing classifier (explainable-feature baseline).

This script produces a supervised model trained on a SYNTHETIC benchmark
dataset generated here. The labels come from our own URL generator, so the
metrics below are only valid on this synthetic benchmark; they are NOT a
statement about real-world traffic. Real-data validation is required before
the model is used in a production decision.

The artifact is loaded by ``app.modules.phishing.classifier.URLClassifier``.
The rules engine remains the primary, always-available detector; the model is
an optional feature-fusion input that is never required for a verdict.

Run from the repository root with the backend venv python:

    backend/.venv/Scripts/python.exe ml/train_url_model.py
"""

from __future__ import annotations

import json
import random
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    classification_report,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from app.modules.phishing.features import FEATURE_SCHEMA_VERSION, feature_vector  # noqa: E402

SEED = 42
ARTIFACT_PATH = ROOT / "ml" / "artifacts" / "url_model.joblib"
METRICS_PATH = ROOT / "ml" / "artifacts" / "url_model_metrics.json"

BENIGN_BRANDS = ["google", "github", "wikipedia", "stackoverflow", "mailchimp", "asana",
                 "mozilla", "duckduckgo", "openstreetmap", "python", "react", "typescript"]
BENIGN_TLDS = ["com", "org", "net", "io", "dev", "app", "co", "info"]
BENIGN_WORDS = ["docs", "blog", "projects", "about", "contact", "releases", "changelog",
                "pricing", "api", "settings", "search", "install", "guides", "tutorial"]

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link",
                   "icu", "country", "stream", "download", "review", "loan", "win", "bid"]
IMPOSTER_BRANDS = ["paypal", "apple", "microsoft", "netflix", "amazon", "dropbox", "linkedin",
                   "instagram", "facebook", "google", "outlook", "mailchimp", "steam", "bankofamerica"]
RISKY_EXTS = ["exe", "scr", "js", "vbs", "bat", "ps1", "jar", "docm", "xlsm", "xll"]
CRED_WORDS = ["password", "login", "verify", "secure", "account", "update", "confirm",
              "billing", "signin", "credential", "authenticate"]
TWO_PART_TLDS = {"co", "com", "org", "net", "gov", "ac", "edu", "xyz"}


def _rng() -> random.Random:
    return random.Random(SEED)


def _benign_url(r: random.Random) -> str:
    brand = r.choice(BENIGN_BRANDS)
    tld = r.choice(BENIGN_TLDS)
    subdomain = r.choice(["www", "mail", "cdn", "static", "blog", ""])
    host = f"{subdomain}.{brand}.{tld}" if subdomain else f"{brand}.{tld}"
    path = "/".join(r.sample(BENIGN_WORDS, r.randint(1, 3)))
    scheme = r.choice(["https", "https"])
    if r.random() < 0.3:
        query = f"?page={r.randint(1, 50)}&lang=en"
    else:
        query = ""
    return f"{scheme}://{host}/{path}{query}"


def _imposter_subdomain(r: random.Random, brand: str) -> str:
    words = [brand + "secure", "secure-" + brand, brand + "-account", "account-" + brand,
             "signin-" + brand, brand + "-verify", "verify-" + brand,
             "login-" + brand, brand + "-login", "support-" + brand]
    return r.choice(words)


def _malicious_url(r: random.Random) -> str:
    brand = r.choice(IMPOSTER_BRANDS)
    tld = r.choice(SUSPICIOUS_TLDS)
    mode = r.random()
    if mode < 0.30:
        host = f"{_imposter_subdomain(r, brand)}.{r.choice(['web','auth','secure','session'])}.{tld}"
    elif mode < 0.45:
        host = f"xn--{brand[:5]}s{''.join(r.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(r.randint(2, 6)))}.com"
    elif mode < 0.60:
        host = f"{r.randint(10, 254)}.{r.randint(0, 254)}.{r.randint(0, 254)}.{r.randint(1, 254)}:{r.randint(1000, 59999)}"
    else:
        host = f"{_imposter_subdomain(r, brand)}.{r.randint(10, 99)}-{r.randint(100, 999)}.{tld}"

    path_words = ["invoice", "update", "verify", "billing", "payment", "document"]
    filename = r.choice([f"invoice{r.randint(10, 999)}.pdf.{r.choice(RISKY_EXTS)}",
                         f"{r.choice(CRED_WORDS)}.exe", f"statement.{r.choice(RISKY_EXTS)}"])
    path = f"{r.choice(CRED_WORDS)}/{filename}"
    if r.random() < 0.7:
        query = f"?{r.choice(['update','token','session','redirect'])}=true&{r.choice(CRED_WORDS)}=1"
    else:
        query = ""
    return f"http://{host}/{path}{query}"


def generate_dataset(r: random.Random, n_benign: int, n_malicious: int) -> tuple[list[str], list[int]]:
    urls: list[str] = []
    labels: list[int] = []
    for _ in range(n_benign):
        urls.append(_benign_url(r))
        labels.append(0)
    for _ in range(n_malicious):
        urls.append(_malicious_url(r))
        labels.append(1)
    return urls, labels


@dataclass
class Artifact:
    pipeline: Pipeline
    classes: list[int]


def main() -> int:
    r = _rng()
    train_urls, train_labels = generate_dataset(r, 6000, 6000)
    eval_urls, eval_labels = generate_dataset(r, 2000, 2000)

    X_train = np.array([feature_vector(u) for u in train_urls])
    X_eval = np.array([feature_vector(u) for u in eval_urls])
    y_train = np.array(train_labels)
    y_eval = np.array(eval_labels)

    X_train_, X_val_, y_train_, y_val_ = train_test_split(
        X_train, y_train, test_size=0.2, random_state=SEED, stratify=y_train
    )

    pipeline = Pipeline([
        ("scale", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=300, max_depth=14, min_samples_leaf=2,
            random_state=SEED, n_jobs=-1,
        )),
    ])
    pipeline.fit(X_train_, y_train_)

    val_proba = pipeline.predict_proba(X_val_)[:, 1]
    val_pred = pipeline.predict(X_val_)
    acc = float(accuracy_score(y_val_, val_pred))
    auc = float(roc_auc_score(y_val_, val_proba))
    prec, rec, f1, _ = precision_recall_fscore_support(y_val_, val_pred, average="binary")

    eval_proba = pipeline.predict_proba(X_eval)[:, 1]
    eval_pred = pipeline.predict(X_eval)
    eval_acc = float(accuracy_score(eval_labels, eval_pred))
    eval_auc = float(roc_auc_score(eval_labels, eval_proba))

    metrics = {
        "algorithm": pipeline.named_steps["clf"].__class__.__name__,
        "feature_schema": FEATURE_SCHEMA_VERSION,
        "dataset": {
            "source": "synthetic (in-repo generator)",
            "train_instances": int(len(X_train_)),
            "validation_instances": int(len(X_val_)),
            "holdout_instances": int(len(X_eval)),
            "classes": {0: "benign", 1: "malicious"},
            "disclaimer": ("Synthetic benchmark only. Not a real-world traffic "
                           "measurement; validate against real data before production use."),
        },
        "validation": {"accuracy": round(acc, 4), "roc_auc": round(auc, 4),
                       "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)},
        "holdout": {"accuracy": round(eval_acc, 4), "roc_auc": round(eval_auc, 4)},
    }

    artifact = {
        "pipeline": pipeline,
        "feature_schema": FEATURE_SCHEMA_VERSION,
        "algorithm": metrics["algorithm"],
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "classes": [0, 1],
        "metrics": metrics,
    }
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, ARTIFACT_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"wrote artifact: {ARTIFACT_PATH}")
    print("validation:", metrics["validation"])
    print("holdout:", metrics["holdout"])
    print(classification_report(y_val_, val_pred, target_names=["benign", "malicious"]))
    print("\nspot checks:")
    import numpy as _np

    for probe in [r.choice(eval_urls) for _ in range(8)]:
        vec = _np.array([feature_vector(probe)])
        proba = pipeline.predict_proba(vec)[0, 1]
        print(f"  p(malicious)={proba:.3f}  {probe[:90]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())