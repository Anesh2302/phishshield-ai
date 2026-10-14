import pytest

from app.modules.files.analyzer import analyze_bytes
from app.modules.files.storage import FileStorage
from tests.conftest import auth_headers

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def ids(analysis):
    return {e.rule_id for e in analysis.evidence}


def test_eicar_detected_as_critical():
    a = analyze_bytes(EICAR, declared_name="eicar.com")
    assert a.score == 100
    assert str(a.severity) == "critical"
    assert "file.signature.eicar" in ids(a)
    assert a.metadata["note"].startswith("Static analysis")


def test_double_extension_and_mismatch():
    a = analyze_bytes(b"MZ\x90\x00fake-pe", declared_name="invoice.pdf.exe")
    rule = ids(a)
    assert "file.name.double_extension" in rule
    assert "file.name.risky_extension" in rule


def test_pdf_active_content_static():
    a = analyze_bytes(b"%PDF-1.7\n/JavaScript (app.alert('x'))\n", declared_name="doc.pdf")
    assert a.detected_ext == "pdf"
    assert "file.static.suspicious_patterns" in ids(a)


def test_zip_with_risky_member():
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hello")
        zf.writestr("payload.exe", "MZ")
    a = analyze_bytes(buf.getvalue(), declared_name="archive.zip")
    assert "file.archive.risky_members" in ids(a)


def test_storage_path_traversal_blocked(tmp_path):
    storage = FileStorage(tmp_path)
    name, path, size = storage.save_bytes(b"data", "notes.txt")
    assert path.exists()
    assert storage.read_bytes(name) == b"data"
    with pytest.raises(ValueError):
        storage.read_bytes("../../etc/passwd")


def test_upload_api_creates_scan_and_alert(owner):
    client, csrf = owner
    r = client.post(
        "/api/v1/files/upload",
        files={"file": ("eicar.com", EICAR, "application/octet-stream")},
        headers=auth_headers(csrf),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["file"]["severity"] == "critical"
    assert body["alert_created"] is True
    assert body["scan_id"]
    listed = client.get("/api/v1/files")
    assert listed.status_code == 200
    assert listed.json()["total"] >= 1


def test_upload_rejects_empty(owner):
    client, csrf = owner
    r = client.post("/api/v1/files/upload",
                    files={"file": ("empty.bin", b"", "application/octet-stream")},
                    headers=auth_headers(csrf))
    assert r.status_code == 400


def test_files_csv_export(owner):
    client, csrf = owner
    r = client.get("/api/v1/files/export.csv")
    assert r.status_code == 200
    assert "sha256" in r.text
