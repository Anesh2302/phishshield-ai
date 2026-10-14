"""Live-server smoke test. Boots uvicorn, exercises the core flow end to end.

Run from the backend directory:

    .venv/Scripts/python.exe scripts/smoke_test.py

Requires the local .env (SQLite) and an available port. Exits non-zero on failure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

BACKEND = Path(__file__).resolve().parents[1]
PORT = int(os.environ.get("SMOKE_PORT", "8099"))
BASE = f"http://127.0.0.1:{PORT}/api/v1"
ENV = dict(os.environ)
ENV.setdefault("PORT", str(PORT))


def wait_ready(url: str, tries: int = 40) -> bool:
    client = httpx.Client(timeout=2)
    for _ in range(tries):
        try:
            if client.get(url).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main() -> int:
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
         "--port", str(PORT)],
        cwd=str(BACKEND),
        env=ENV,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    results: dict = {}
    try:
        if not wait_ready(f"{BASE}/health"):
            print("FAIL server did not become ready")
            return 1
        client = httpx.Client(base_url=BASE, timeout=15)

        health = client.get("/health")
        results["health"] = health.json()["status"]

        bs = client.get("/auth/bootstrap-status").json()
        needs = bs.get("needs_bootstrap")
        if needs:
            boot = client.post("/auth/bootstrap", json={
                "tenant_name": "Smoke Org",
                "email": "smoke@acme-security.com",
                "full_name": "Smoke Tester",
                "password": "Sm0ke-Pass-2026!",
            })
            assert boot.status_code == 201, boot.text
            csrf = boot.json()["csrf_token"]
        else:
            login = client.post("/auth/login", json={
                "email": "smoke@acme-security.com", "password": "Sm0ke-Pass-2026!",
            })
            assert login.status_code == 200, login.text
            csrf = login.json()["csrf_token"]

        headers = {"X-CSRF-Token": csrf}

        me = client.get("/auth/me")
        results["me_role"] = me.json()["role"]

        scan = client.post("/scans/url", json={"url": "http://paypal-verify-account.tk/login"},
                           headers=headers)
        assert scan.status_code == 201, scan.text
        results["scan_verdict"] = scan.json()["result"]["verdict"]

        ml = client.get("/ml/model")
        results["ml_available"] = ml.json()["available"]
        results["ml_algorithm"] = ml.json().get("algorithm")

        addrs = client.post("/integrations/mock_gmail/connect", headers=headers)
        state = addrs.json()["state"]
        cb = client.post("/integrations/mock_gmail/callback-json",
                         json={"code": "smoke@acme-security.com", "state": state},
                         headers=headers)
        results["integration_state"] = cb.json()["state"]

        print(json.dumps(results, indent=2))
        ok = all([
            results["health"] == "ok",
            results["me_role"] == "owner",
            results["scan_verdict"] in {"malicious", "suspicious"},
            results["ml_available"] is True,
            results["integration_state"] in {"monitoring", "connected"},
        ])
        print("SMOKE OK" if ok else "SMOKE FAIL")
        return 0 if ok else 1
    except Exception as exc:  # noqa: BLE001
        print(f"SMOKE FAIL: {exc}")
        return 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())