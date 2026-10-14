"""Explainable URL phishing analyzer.

Every decision is expressed as named evidence with a weight and a plain-language
description so users can understand *why* a URL was flagged. The analyzer never
contacts the target URL and never follows links.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote

from app.modules.phishing.features import (
    BRANDS,
    IP_HOST_RE,
    SHORTENER_HOSTS,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_TLDS,
    extract_features,
    registered_domain,
    shannon_entropy,
    split_host,
)
from app.schemas import Evidence, Severity, severity_from_score

CREDENTIAL_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "passwd", "credential", "banking", "wallet",
    "billing", "invoice", "unlock", "recover", "auth", "session",
}
REDIRECT_PARAMS = {"url", "redirect", "next", "dest", "destination", "goto", "continue", "target"}


@dataclass
class UrlAnalysis:
    url: str
    score: int
    severity: Severity
    verdict: str
    evidence: list[Evidence]
    recommended_action: str
    metadata: dict = field(default_factory=dict)

    @property
    def rule_score(self) -> int:
        return min(100, sum(e.weight for e in self.evidence if e.weight > 0))


def _dangerous_scheme(scheme: str) -> Evidence | None:
    if scheme in {"javascript", "data", "vbscript"}:
        return Evidence(
            rule_id="url.scheme.dangerous",
            title=f"Dangerous URL scheme '{scheme}:'",
            description=(
                "The link uses a scheme that can execute code or embed content "
                "instead of linking to a normal web page."
            ),
            weight=45,
            severity=Severity.high,
            source="rules",
            detail={"scheme": scheme},
        )
    return None


def analyze_url(url: str) -> UrlAnalysis:
    url = (url or "").strip()
    evidence: list[Evidence] = []
    scheme, host, path, query = split_host(url)
    full = url
    labels = [lab for lab in host.split(".") if lab]
    tld = labels[-1] if labels else ""
    reg = registered_domain(host)

    d = _dangerous_scheme(scheme)
    if d:
        evidence.append(d)

    if (not scheme or not host) and not d:
        return UrlAnalysis(
            url=url,
            score=0,
            severity=Severity.info,
            verdict="invalid",
            evidence=[
                Evidence(
                    rule_id="url.parse.invalid",
                    title="Could not parse a hostname",
                    description="The input is not a well-formed absolute URL.",
                    weight=0,
                    severity=Severity.info,
                )
            ],
            recommended_action="Treat as untrusted; the input could not be validated.",
        )

    # 1. IP-literal host
    if IP_HOST_RE.match(host):
        evidence.append(
            Evidence(
                rule_id="url.host.ip_literal",
                title="Hostname is a raw IP address",
                description="Legitimate services rarely link to raw IP addresses.",
                weight=30,
                severity=Severity.high,
                detail={"host": host},
            )
        )

    # 2. Userinfo trick (user@host)
    if "@" in full.split("://", 1)[-1].split("/", 1)[0]:
        evidence.append(
            Evidence(
                rule_id="url.userinfo.at",
                title="'@' used to disguise the real host",
                description=(
                    "Everything before '@' is ignored by browsers, so the visible "
                    "text can be made to look like a trusted domain."
                ),
                weight=28,
                severity=Severity.high,
            )
        )

    # 3. Punycode / IDN homograph
    if "xn--" in host:
        evidence.append(
            Evidence(
                rule_id="url.host.punycode",
                title="Punycode / internationalised look-alike domain",
                description="Encoded characters can mimic a trusted brand visually.",
                weight=25,
                severity=Severity.high,
                detail={"host": host},
            )
        )

    # 4. Brand impersonation: brand appears in host but not the registrable domain
    impersonated = [b for b in BRANDS if b in host and b not in reg]
    if impersonated:
        evidence.append(
            Evidence(
                rule_id="url.host.brand_impersonation",
                title="Trusted brand name appears outside the real domain",
                description=(
                    f"The host contains the brand name(s) {sorted(set(impersonated))} "
                    f"but the registrable domain is '{reg}'."
                ),
                weight=32,
                severity=Severity.high,
                detail={"brands": sorted(set(impersonated)), "registered_domain": reg},
            )
        )

    # 5. Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        evidence.append(
            Evidence(
                rule_id="url.tld.suspicious",
                title=f"High-abuse top-level domain '.{tld}'",
                description="This TLD is disproportionately used in phishing campaigns.",
                weight=15,
                severity=Severity.medium,
                detail={"tld": tld},
            )
        )

    # 6. Excessive subdomains
    if len(labels) - 2 >= 3:
        evidence.append(
            Evidence(
                rule_id="url.host.subdomain_depth",
                title="Unusually deep subdomain chain",
                description="Long subdomain chains are used to push the real domain out of view.",
                weight=14,
                severity=Severity.medium,
                detail={"subdomains": labels[:-2]},
            )
        )

    # 7. Shortener
    if reg in SHORTENER_HOSTS or host in SHORTENER_HOSTS:
        evidence.append(
            Evidence(
                rule_id="url.host.shortener",
                title="URL shortener hides the destination",
                description="The real destination cannot be verified without resolving the link.",
                weight=15,
                severity=Severity.medium,
                detail={"shortener": host},
            )
        )

    # 8. Length
    if len(full) > 100:
        evidence.append(
            Evidence(
                rule_id="url.length.long",
                title="Very long URL",
                description="Excessive length is often used to hide the true destination.",
                weight=10 if len(full) < 160 else 15,
                severity=Severity.low,
                detail={"length": len(full)},
            )
        )

    # 9. Hyphens in host
    host_hyphens = host.count("-")
    if host_hyphens >= 2:
        evidence.append(
            Evidence(
                rule_id="url.host.hyphens",
                title="Multiple hyphens in the hostname",
                description="Hyphenated look-alike hostnames are a common phishing pattern.",
                weight=10,
                severity=Severity.low,
                detail={"hyphens": host_hyphens},
            )
        )

    # 10. Credential/urgency keywords in path or query
    haystack = unquote(f"{path}?{query}").lower()
    hits = sorted({k for k in CREDENTIAL_KEYWORDS if k in haystack})
    if hits:
        evidence.append(
            Evidence(
                rule_id="url.path.credential_keywords",
                title="Credential/urgency keywords in path or query",
                description=(
                    "The URL mentions login/verification terms, which phishing pages "
                    "commonly do to appear legitimate."
                ),
                weight=15 if len(hits) == 1 else 22,
                severity=Severity.medium,
                detail={"keywords": hits},
            )
        )

    # 11. Redirect parameters (potential open redirect abuse)
    params = parse_qs(query)
    redir = sorted(set(params) & REDIRECT_PARAMS)
    if redir:
        evidence.append(
            Evidence(
                rule_id="url.query.redirect_param",
                title="URL carries a redirect parameter",
                description="Redirect parameters can be abused to bounce to a malicious site.",
                weight=12,
                severity=Severity.low,
                detail={"parameters": redir},
            )
        )

    # 12. Suspicious file extension / double extension
    path_exts = re.findall(r"\.[a-z0-9]{1,5}(?=[.?#/]|$)", path.lower())
    sus = sorted(set(path_exts) & SUSPICIOUS_EXTENSIONS)
    if sus:
        evidence.append(
            Evidence(
                rule_id="url.path.suspicious_extension",
                title="Link points to an executable/script file",
                description=f"Downloadable extension(s): {sus}.",
                weight=25,
                severity=Severity.high,
                detail={"extensions": sus},
            )
        )
    if len(path_exts) >= 2 and (set(path_exts) & SUSPICIOUS_EXTENSIONS):
        evidence.append(
            Evidence(
                rule_id="url.path.double_extension",
                title="Double file extension",
                description="e.g. invoice.pdf.exe - a classic disguise technique.",
                weight=28,
                severity=Severity.high,
                detail={"extensions": path_exts},
            )
        )

    # 13. Not HTTPS
    if scheme == "http":
        evidence.append(
            Evidence(
                rule_id="url.scheme.http",
                title="Not encrypted (http://)",
                description="Credentials submitted over http are sent in clear text.",
                weight=10,
                severity=Severity.low,
            )
        )

    # 14. Non-standard port
    netloc = full.split("://", 1)[-1].split("/", 1)[0]
    if re.search(r":\d{2,5}$", netloc.split("@")[-1]):
        port = netloc.rsplit(":", 1)[-1]
        if port not in {"80", "443"}:
            evidence.append(
                Evidence(
                    rule_id="url.port.nonstandard",
                    title=f"Non-standard port :{port}",
                    description="Unusual ports can indicate a proxied or temporary attacker service.",
                    weight=14,
                    severity=Severity.medium,
                    detail={"port": port},
                )
            )

    # 15. High host entropy
    ent = shannon_entropy(host)
    if ent > 4.0 and len(host) > 20:
        evidence.append(
            Evidence(
                rule_id="url.host.entropy",
                title="Random-looking hostname",
                description="High character entropy suggests an automatically generated domain.",
                weight=10,
                severity=Severity.low,
                detail={"entropy": round(ent, 2)},
            )
        )

    # 16. Encoded characters
    hex_escapes = len(re.findall(r"%[0-9a-fA-F]{2}", full))
    if hex_escapes >= 4:
        evidence.append(
            Evidence(
                rule_id="url.encoding.heavy",
                title="Heavily percent-encoded URL",
                description="Heavy encoding can obfuscate the true destination.",
                weight=10,
                severity=Severity.low,
                detail={"escapes": hex_escapes},
            )
        )

    # 17. Embedded credentials in URL (http://user:pass@host)
    userinfo = netloc.split("@")[0] if "@" in netloc else ""
    if userinfo and ":" in userinfo:
        evidence.append(
            Evidence(
                rule_id="url.userinfo.credentials",
                title="Embedded credentials in the link",
                description="A username/password pair is embedded in the URL.",
                weight=20,
                severity=Severity.high,
            )
        )

    score = min(100, sum(e.weight for e in evidence))
    severity = severity_from_score(score)
    verdict = _verdict(score)
    action = _recommendation(severity, verdict)

    return UrlAnalysis(
        url=url,
        score=score,
        severity=severity,
        verdict=verdict,
        evidence=evidence,
        recommended_action=action,
        metadata={
            "scheme": scheme,
            "host": host,
            "registered_domain": reg,
            "features": extract_features(url),
        },
    )


def _verdict(score: int) -> str:
    if score >= 65:
        return "malicious"
    if score >= 40:
        return "suspicious"
    if score >= 20:
        return "low_risk"
    return "benign"


def _recommendation(severity: Severity, verdict: str) -> str:
    if severity in (Severity.critical, Severity.high):
        return "Do not visit this link or enter any information. Report it to your security team."
    if severity == Severity.medium:
        return "Treat with caution. Verify the sender through a separate, trusted channel before acting."
    if severity == Severity.low:
        return "Low risk, but avoid entering credentials unless you are certain of the destination."
    return "No strong phishing indicators were found. Stay alert and verify unexpected requests."
