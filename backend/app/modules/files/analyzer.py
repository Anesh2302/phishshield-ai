"""Static file analysis. Files are NEVER executed, rendered, or opened.

This module performs content-based type detection, hashing, metadata extraction,
extension heuristics, bounded archive inspection, static pattern analysis of
scripts/documents, and optional YARA scanning. Static analysis is indicative,
not proof that a file is safe.
"""

from __future__ import annotations

import io
import logging
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.modules.files.storage import compute_hashes
from app.schemas import Evidence, Severity, severity_from_score

logger = logging.getLogger(__name__)

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

RISKY_EXTS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "msi", "dll", "vbs", "vbe", "js",
    "jse", "wsf", "wsh", "hta", "jar", "apk", "ps1", "psm1", "lnk", "iso", "img",
    "xll", "docm", "xlsm", "pptm", "dotm", "xlam",
}
DOC_EXTS = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "pdf"}
SCRIPT_EXTS = {"js", "vbs", "vbe", "ps1", "psm1", "bat", "cmd", "sh", "py", "wsf", "hta", "jse"}
ARCHIVE_EXTS = {"zip", "gz", "tar", "7z", "rar", "jar", "iso"}

SCRIPT_PATTERNS = [
    (re.compile(rb"powershell[^\n]{0,80}-enc", re.I), "powershell_encoded_command"),
    (re.compile(rb"frombase64string", re.I), "frombase64string"),
    (re.compile(rb"downloadstring|downloadfile|invoke-expression|iex\s*\(", re.I), "download_exec"),
    (re.compile(rb"wscript\.shell|createobject\s*\(\s*[\"']wscript", re.I), "wscript_shell"),
    (re.compile(rb"shell\.application", re.I), "shell_application"),
    (re.compile(rb"cmd\.exe\s*/c|%comspec%", re.I), "cmd_exec"),
    (re.compile(rb"regsvr32|rundll32|mshta|certutil|bitsadmin", re.I), "lolbin"),
    (re.compile(rb"eval\s*\(|atob\s*\(", re.I), "js_eval_atob"),
    (re.compile(rb"new\s+activexobject", re.I), "activexobject"),
]

HTML_PATTERNS = [
    (re.compile(rb"<script[\s>]", re.I), "html_script_tag"),
    (re.compile(rb"onerror\s*=|onload\s*=", re.I), "html_event_handler"),
    (re.compile(rb"javascript:", re.I), "html_javascript_uri"),
    (re.compile(rb"<iframe[\s>]", re.I), "html_iframe"),
    (re.compile(rb"document\.write|unescape\s*\(|eval\s*\(", re.I), "html_obfuscation"),
]

OFFICE_MACRO_MARKERS = [
    (re.compile(rb"AutoOpen|Auto_Open", re.I), "office_autoopen"),
    (re.compile(rb"Workbook_Open|Document_Open", re.I), "office_open_macro"),
    (re.compile(rb"Shell\s*\(|CreateObject", re.I), "office_shell_create"),
    (re.compile(rb"VBA\d|Microsoft VBA", re.I), "office_vba_stream"),
    (re.compile(rb"DDEAUTO|DDE\s", re.I), "office_dde"),
]


@dataclass
class FileAnalysis:
    sha256: str
    sha1: str
    md5: str
    size: int
    detected_mime: str
    detected_ext: str
    declared_ext: str
    detected_description: str
    type_detection_method: str
    score: int = 0
    severity: Severity = Severity.info
    evidence: list[Evidence] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    yara_available: bool = False
    yara_matches: list[str] = field(default_factory=list)
    static_findings: list[str] = field(default_factory=list)


def detect_type(data: bytes) -> tuple[str, str, str, str]:
    """Return (mime, extension, description, method) using content, not name."""
    try:
        import puremagic

        try:
            ext = puremagic.from_string(data)
        except puremagic.PureError:
            ext = ""
        mime = ""
        try:
            matches = puremagic.magic_string(data)
            if matches:
                mime = matches[0].mime_type or ""
                ext = matches[0].extension or ext
        except Exception:
            pass
        if ext:
            return mime or "application/octet-stream", ext.lstrip(".").lower(), "puremagic", "content"
    except ImportError:  # pragma: no cover
        logger.info("puremagic not installed; using signature fallback")
    return _fallback_signature(data)


def _fallback_signature(data: bytes) -> tuple[str, str, str, str]:
    head = data[:4096]
    signatures = [
        (b"%PDF", "application/pdf", "pdf", "pdf"),
        (b"PK\x03\x04", "application/zip", "zip", "zip-ooxml"),
        (b"\x89PNG", "image/png", "png", "png"),
        (b"\xff\xd8\xff", "image/jpeg", "jpg", "jpeg"),
        (b"GIF8", "image/gif", "gif", "gif"),
        (b"\x7fELF", "application/x-executable", "elf", "elf-binary"),
        (b"MZ", "application/x-dosexec", "exe", "pe-binary"),
        (b"Rar!\x1a\x07", "application/x-rar", "rar", "rar"),
        (b"\x1f\x8b", "application/gzip", "gz", "gzip"),
        (b"{\\rtf", "application/rtf", "rtf", "rtf"),
    ]
    for sig, mime, ext, desc in signatures:
        if head.startswith(sig):
            return mime, ext, desc, "signature"
    if head[:2] == b"#!":
        return "text/x-script", "sh", "shebang-script", "signature"
    if all((32 <= b < 127) or b in (9, 10, 13) for b in head) and head:
        return "text/plain", "txt", "plain-text", "heuristic"
    return "application/octet-stream", "", "unknown-binary", "fallback"


def _declared_ext(name: str) -> str:
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def _archive_analysis(data: bytes, evidence: list[Evidence], findings: list[str]) -> dict:
    meta: dict = {}
    if not data.startswith(b"PK\x03\x04"):
        return meta
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            meta["archive_entries"] = len(infos)
            total_uncompressed = sum(i.file_size for i in infos)
            meta["archive_uncompressed_bytes"] = total_uncompressed
            compressed = max(1, sum(i.compress_size for i in infos))
            ratio = total_uncompressed / compressed
            meta["archive_expansion_ratio"] = round(ratio, 2)
            if len(infos) > settings.max_archive_files:
                evidence.append(
                    Evidence(
                        rule_id="file.archive.too_many_entries",
                        title="Archive contains an excessive number of files",
                        description=f"{len(infos)} entries exceed the limit of {settings.max_archive_files}.",
                        weight=30,
                        severity=Severity.high,
                        detail={"entries": len(infos)},
                    )
                )
            if total_uncompressed > settings.max_extract_bytes or ratio > settings.max_archive_expansion_ratio:
                evidence.append(
                    Evidence(
                        rule_id="file.archive.bomb_suspected",
                        title="Potential archive bomb (expansion ratio)",
                        description=(
                            f"Uncompressed {total_uncompressed} bytes at ratio {ratio:.1f}x "
                            f"exceeds safe limits."
                        ),
                        weight=35,
                        severity=Severity.high,
                        detail={"ratio": round(ratio, 2)},
                    )
                )
            nested = [i.filename for i in infos if "." in i.filename and i.filename.rsplit(".", 1)[-1].lower() in RISKY_EXTS]
            if nested:
                evidence.append(
                    Evidence(
                        rule_id="file.archive.risky_members",
                        title="Archive contains executable/script members",
                        description=f"Risky member(s): {nested[:10]}.",
                        weight=25,
                        severity=Severity.high,
                        detail={"members": nested[:10]},
                    )
                )
            findings.append(f"archive:{len(infos)}_entries")
    except zipfile.BadZipFile:
        evidence.append(
            Evidence(
                rule_id="file.archive.malformed",
                title="Malformed archive",
                description="The file has a ZIP header but is corrupt, which can defeat naive scanners.",
                weight=20,
                severity=Severity.medium,
            )
        )
    return meta


def _tar_analysis(data: bytes, evidence: list[Evidence], findings: list[str]) -> dict:
    meta: dict = {}
    if not data[:2] == b"\x1f\x8b" and b"ustar" not in data[:1024]:
        return meta
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            members = tf.getmembers()
            meta["tar_entries"] = len(members)
            total = sum(m.size for m in members)
            meta["tar_uncompressed_bytes"] = total
            if len(members) > settings.max_archive_files or total > settings.max_extract_bytes:
                evidence.append(
                    Evidence(
                        rule_id="file.archive.tar_limits",
                        title="Tar archive exceeds safety limits",
                        description=f"entries={len(members)} total={total}",
                        weight=30,
                        severity=Severity.high,
                    )
                )
            is_traversal = [m.name for m in members if ".." in Path(m.name).parts or m.name.startswith("/")]
            if is_traversal:
                evidence.append(
                    Evidence(
                        rule_id="file.archive.path_traversal",
                        title="Archive contains path traversal names",
                        description=f"Suspicious member(s): {is_traversal[:10]}.",
                        weight=30,
                        severity=Severity.high,
                    )
                )
            findings.append(f"tar:{len(members)}_entries")
    except (tarfile.TarError, ValueError):
        pass
    return meta


def _static_analysis(data: bytes, detected_ext: str, evidence: list[Evidence], findings: list[str]) -> None:
    patterns: list[tuple[re.Pattern, str]] = []
    if detected_ext in SCRIPT_EXTS:
        patterns += SCRIPT_PATTERNS
    if detected_ext in {"html", "htm"}:
        patterns += HTML_PATTERNS
    if detected_ext in DOC_EXTS or detected_ext in {"docm", "xlsm", "pptm", "doc", "xls", "ppt"}:
        patterns += OFFICE_MACRO_MARKERS
    if detected_ext == "pdf":
        patterns.append((re.compile(rb"/JavaScript|/JS\b|/OpenAction|/Launch", re.I), "pdf_active_content"))
        patterns.append((re.compile(rb"/EmbeddedFile", re.I), "pdf_embedded_file"))
    # Always scan for shell/HTML patterns in text-ish content.
    patterns += SCRIPT_PATTERNS if detected_ext in {"txt", ""} else []

    matched = []
    for pattern, name in patterns:
        if pattern.search(data):
            matched.append(name)
    if matched:
        findings.extend(matched)
        weight = 18 + 4 * min(len(matched), 4)
        evidence.append(
            Evidence(
                rule_id="file.static.suspicious_patterns",
                title="Suspicious static patterns found",
                description=f"Matched indicator(s): {sorted(set(matched))}.",
                weight=min(weight, 40),
                severity=Severity.high if len(matched) >= 2 else Severity.medium,
                detail={"patterns": sorted(set(matched))},
            )
        )


def _yara_scan(data: bytes, evidence: list[Evidence], findings: list[str]) -> tuple[bool, list[str]]:
    try:
        import yara  # type: ignore
    except ImportError:
        return False, []
    rules_dir = Path(__file__).parent / "yara_rules"
    rule_files = {p.stem: str(p) for p in rules_dir.glob("*.yar")}
    if not rule_files:
        return True, []
    try:
        rules = yara.compile(filepaths=rule_files)
        matches = rules.match(data=data)
        names = [m.rule for m in matches]
    except yara.YaraError as exc:  # pragma: no cover
        logger.warning("YARA compile/match error: %s", exc)
        return True, []
    if names:
        findings.extend([f"yara:{n}" for n in names])
        evidence.append(
            Evidence(
                rule_id="file.yara.match",
                title="YARA rule match",
                description=f"Matched rule(s): {names}.",
                weight=40,
                severity=Severity.high,
                source="yara",
                detail={"rules": names},
            )
        )
    return True, names


def analyze_bytes(
    data: bytes,
    *,
    declared_name: str = "unknown",
    known_hashes: dict | None = None,
) -> FileAnalysis:
    hashes = compute_hashes(data)
    mime, detected_ext, description, method = detect_type(data)
    declared_ext = _declared_ext(declared_name)
    evidence: list[Evidence] = []
    findings: list[str] = []

    # Known test signature (EICAR) - confirms the pipeline works end to end.
    if EICAR in data[:512]:
        evidence.append(
            Evidence(
                rule_id="file.signature.eicar",
                title="EICAR antivirus test signature detected",
                description="This is the industry-standard harmless antivirus test file.",
                weight=100,
                severity=Severity.critical,
                detail={"test_signature": True},
            )
        )
        findings.append("eicar_test_signature")

    # Content vs declared extension mismatch
    if declared_ext and detected_ext and declared_ext != detected_ext:
        # allow benign equivalences
        equivalent = {
            ("jpg", "jpeg"), ("jpeg", "jpg"), ("htm", "html"), ("html", "htm"),
            ("tgz", "gz"), ("txt", "txt"),
        }
        if (declared_ext, detected_ext) not in equivalent and (detected_ext, declared_ext) not in equivalent:
            evidence.append(
                Evidence(
                    rule_id="file.extension.mismatch",
                    title="Content does not match the file extension",
                    description=(
                        f"Declared '.{declared_ext}' but content looks like '.{detected_ext}' "
                        f"({mime or description})."
                    ),
                    weight=25,
                    severity=Severity.high,
                    detail={"declared": declared_ext, "detected": detected_ext},
                )
            )

    # Double extension
    name_parts = declared_name.lower().split(".")
    if len(name_parts) >= 3 and name_parts[-1] in RISKY_EXTS and name_parts[-2] in {
        "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "mp4", "csv"
    }:
        evidence.append(
            Evidence(
                rule_id="file.name.double_extension",
                title="Double extension disguises an executable",
                description=f"'{declared_name}' ends with a risky extension after a document type.",
                weight=30,
                severity=Severity.high,
                detail={"name": declared_name},
            )
        )

    # Risky extension on its own (informational-to-medium)
    if declared_ext in RISKY_EXTS:
        evidence.append(
            Evidence(
                rule_id="file.name.risky_extension",
                title=f"Risky file type '.{declared_ext}'",
                description="Executable and macro-enabled formats carry higher inherent risk.",
                weight=18,
                severity=Severity.medium,
                detail={"extension": declared_ext},
            )
        )

    meta: dict = {}
    if (
        detected_ext in ARCHIVE_EXTS
        or mime in {"application/zip", "application/x-rar"}
        or data[:4] == b"PK\x03\x04"
        or data[:2] == b"\x1f\x8b"
        or b"ustar" in data[:1024]
    ):
        meta.update(_archive_analysis(data, evidence, findings))
        meta.update(_tar_analysis(data, evidence, findings))

    _static_analysis(data, detected_ext, evidence, findings)
    yara_available, yara_matches = _yara_scan(data, evidence, findings)

    # Reputation lookup only when a provider is configured.
    reputation_status = "not_configured"
    if settings.file_reputation_enabled:
        reputation_status = "unavailable"
        evidence.append(
            Evidence(
                rule_id="file.reputation.unavailable",
                title="File reputation provider configured but not reachable",
                description="No reputation provider responded; this does not mean the file is safe.",
                weight=0,
                severity=Severity.info,
                source="reputation",
            )
        )

    score = min(100, sum(e.weight for e in evidence if e.weight > 0))
    severity = severity_from_score(score)

    return FileAnalysis(
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        size=len(data),
        detected_mime=mime,
        detected_ext=detected_ext,
        declared_ext=declared_ext,
        detected_description=description,
        type_detection_method=method,
        score=score,
        severity=severity,
        evidence=evidence,
        metadata={
            "size": len(data),
            "hashes": hashes,
            "detected_mime": mime,
            "detected_ext": detected_ext,
            "declared_ext": declared_ext,
            "detection_method": method,
            "static_findings": findings,
            "yara_available": yara_available,
            "yara_matches": yara_matches,
            "reputation": reputation_status,
            "note": "Static analysis is indicative only; it is not proof that a file is safe.",
        },
        yara_available=yara_available,
        yara_matches=yara_matches,
        static_findings=findings,
    )
