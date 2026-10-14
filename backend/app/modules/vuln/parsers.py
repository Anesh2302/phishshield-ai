"""Parsers for genuine open-source scanner output (OSV-Scanner, Trivy).

Only real tool output is accepted; we never fabricate findings. If a tool is not
installed the API reports that the scanner is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1}
CRITICALITY_WEIGHT = {"critical": 3, "high": 2, "medium": 1, "low": 0}
EXPOSURE_WEIGHT = {"public": 2, "internal": 0}


@dataclass
class ParsedFinding:
    source: str
    title: str
    severity: str = "unknown"
    cve: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    raw: dict = field(default_factory=dict)


def _norm_severity(value: str | None) -> str:
    if not value:
        return "unknown"
    v = value.strip().lower()
    if v in SEVERITY_WEIGHT:
        return v
    return {
        "moderate": "medium", "important": "high", "negligible": "low", "unknown": "unknown",
    }.get(v, "unknown")


def parse_osv(data: dict) -> list[ParsedFinding]:
    findings: list[ParsedFinding] = []
    for result in data.get("results", []) or []:
        source_path = (result.get("source") or {}).get("path", "")
        for pkg in result.get("packages", []) or []:
            pkg_info = pkg.get("package", {}) or {}
            for vuln in pkg.get("vulnerabilities", []) or []:
                aliases = vuln.get("aliases", []) or []
                cve = next((a for a in aliases if str(a).upper().startswith("CVE-")), None)
                severity = "unknown"
                for sev in vuln.get("severity", []) or []:
                    severity = _cvss_to_severity(sev.get("score"))
                database_specific = vuln.get("database_specific", {}) or {}
                if database_specific.get("severity"):
                    severity = _norm_severity(database_specific["severity"])
                findings.append(
                    ParsedFinding(
                        source="osv",
                        title=vuln.get("summary") or vuln.get("id", "OSV finding"),
                        severity=severity,
                        cve=cve,
                        package=pkg_info.get("name"),
                        installed_version=pkg_info.get("version"),
                        fixed_version=None,
                        raw={"id": vuln.get("id"), "path": source_path, "aliases": aliases},
                    )
                )
    return findings


def parse_trivy(data: dict) -> list[ParsedFinding]:
    findings: list[ParsedFinding] = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                ParsedFinding(
                    source="trivy",
                    title=vuln.get("Title") or vuln.get("VulnerabilityID", "Trivy finding"),
                    severity=_norm_severity(vuln.get("Severity")),
                    cve=vuln.get("VulnerabilityID"),
                    package=vuln.get("PkgName"),
                    installed_version=vuln.get("InstalledVersion"),
                    fixed_version=vuln.get("FixedVersion"),
                    raw={"target": target, "cvss": vuln.get("CVSS", {})},
                )
            )
    return findings


def _cvss_to_severity(score: str | float | None) -> str:
    try:
        s = float(score) if score is not None else None
    except (TypeError, ValueError):
        s = None
    if s is None:
        return "unknown"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "unknown"


def compute_priority(severity: str, criticality: str = "medium", exposure: str = "internal",
                     exploit_available: bool = False) -> str:
    score = SEVERITY_WEIGHT.get(severity, 1) * 2
    score += CRITICALITY_WEIGHT.get(criticality, 1)
    score += EXPOSURE_WEIGHT.get(exposure, 0)
    if exploit_available:
        score += 3
    if score >= 12:
        return "critical"
    if score >= 9:
        return "high"
    if score >= 6:
        return "medium"
    return "low"
