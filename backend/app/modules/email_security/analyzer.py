"""Transparent email phishing detection.

Combines sender/reply-to analysis, authentication results, subject and body
linguistic signals, attachment-name risk and URL analysis. It never modifies the
message: PhishShield detects and alerts only.
"""

from __future__ import annotations

import re

from app.modules.email_security.parser import ParsedEmail, parse_email
from app.modules.phishing.features import BRANDS, registered_domain, split_host
from app.modules.phishing.url_analyzer import analyze_url
from app.schemas import DetectionResult, Evidence, Severity, severity_from_score

URGENCY_TERMS = {
    "urgent", "immediately", "act now", "verify your account", "suspended",
    "unusual activity", "within 24 hours", "final warning", "expires", "limited time",
    "your account will be", "click below", "confirm your identity", "security alert",
}
CREDENTIAL_TERMS = {
    "password", "login", "sign in", "username", "credit card", "ssn", "social security",
    "bank account", "routing number", "pin", "one-time", "otp", "verification code",
    "update your payment", "confirm your password",
}
PAYMENT_TERMS = {
    "wire transfer", "gift card", "bitcoin", "crypto", "invoice attached", "payment failed",
    "bank details have changed", "update banking", "remit payment", "purchase order",
}
RISKY_ATTACHMENT_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".wsf", ".hta", ".jar",
    ".msi", ".ps1", ".lnk", ".iso", ".img", ".docm", ".xlsm", ".pptm", ".html", ".htm",
}


def analyze_email(raw: str | bytes, *, include_intel: bool = False) -> DetectionResult:
    parsed = parse_email(raw)
    return analyze_parsed_email(parsed, include_intel=include_intel)


def analyze_parsed_email(parsed: ParsedEmail, *, include_intel: bool = False) -> DetectionResult:
    evidence: list[Evidence] = []

    sender_domain = split_host(f"http://{parsed.from_addr}")[1] if parsed.from_addr else ""
    from_reg = registered_domain(sender_domain) if sender_domain else ""

    # 1. Display-name impersonation
    if parsed.from_display and parsed.from_addr:
        display_lower = parsed.from_display.lower()
        brand_in_display = [b for b in BRANDS if b in display_lower]
        if brand_in_display and not all(b in from_reg for b in brand_in_display):
            evidence.append(
                Evidence(
                    rule_id="email.sender.display_name_impersonation",
                    title="Display name impersonates a trusted brand",
                    description=(
                        f"The display name mentions {sorted(set(brand_in_display))} but the "
                        f"sending domain is '{from_reg or parsed.from_addr}'."
                    ),
                    weight=30,
                    severity=Severity.high,
                    detail={"display": parsed.from_display, "from": parsed.from_addr},
                )
            )
        if "@" in parsed.from_display:
            evidence.append(
                Evidence(
                    rule_id="email.sender.display_is_address",
                    title="Display name itself looks like an email address",
                    description="A common trick to make a foreign address look legitimate.",
                    weight=12,
                    severity=Severity.low,
                    detail={"display": parsed.from_display},
                )
            )

    # 2. Reply-To mismatch
    if parsed.reply_to and parsed.from_addr:
        _, reply_host, _, _ = split_host(f"http://{_bare_addr(parsed.reply_to)}")
        reply_reg = registered_domain(reply_host) if reply_host else ""
        if reply_reg and from_reg and reply_reg != from_reg:
            evidence.append(
                Evidence(
                    rule_id="email.replyto.mismatch",
                    title="Reply-To domain differs from the sender domain",
                    description=(
                        f"Replies would go to '{reply_reg}', not the sending domain '{from_reg}'."
                    ),
                    weight=22,
                    severity=Severity.high,
                    detail={"reply_to": parsed.reply_to, "from": parsed.from_addr},
                )
            )

    # 3. Return-Path mismatch
    if parsed.return_path and parsed.from_addr:
        rp = _bare_addr(parsed.return_path)
        rp_host = split_host(f"http://{rp}")[1]
        rp_reg = registered_domain(rp_host) if rp_host else ""
        if rp_reg and from_reg and rp_reg != from_reg:
            evidence.append(
                Evidence(
                    rule_id="email.returnpath.mismatch",
                    title="Return-Path differs from the From domain",
                    description="A mismatch can indicate spoofing or a compromised relay.",
                    weight=16,
                    severity=Severity.medium,
                    detail={"return_path": parsed.return_path, "from": parsed.from_addr},
                )
            )

    # 4. Authentication results
    auth = parsed.auth_results or {}
    for mech in ("spf", "dkim", "dmarc"):
        val = auth.get(mech)
        if val in {"fail", "softfail", "permerror", "temperror"}:
            sev = Severity.high if mech == "dmarc" else Severity.medium
            evidence.append(
                Evidence(
                    rule_id=f"email.auth.{mech}_fail",
                    title=f"{mech.upper()} authentication {val}",
                    description=f"The message failed {mech.upper()} checks reported by the receiving server.",
                    weight=25 if mech == "dmarc" else 18,
                    severity=sev,
                    detail={"mechanism": mech, "result": val},
                )
            )
    if not auth:
        evidence.append(
            Evidence(
                rule_id="email.auth.missing",
                title="No authentication results available",
                description=(
                    "SPF/DKIM/DMARC results were not present in the message headers; "
                    "this is informational and does not by itself indicate phishing."
                ),
                weight=0,
                severity=Severity.info,
                source="rules",
            )
        )

    # 5. Subject urgency / credential terms
    subject_lower = parsed.subject.lower()
    subj_urgent = sorted({t for t in URGENCY_TERMS if t in subject_lower})
    if subj_urgent:
        evidence.append(
            Evidence(
                rule_id="email.subject.urgency",
                title="Urgency language in the subject",
                description=f"Urgency phrases found: {subj_urgent}.",
                weight=14,
                severity=Severity.medium,
                detail={"terms": subj_urgent},
            )
        )

    body_lower = parsed.text_body.lower()
    cred_hits = sorted({t for t in CREDENTIAL_TERMS if t in body_lower})
    if cred_hits:
        evidence.append(
            Evidence(
                rule_id="email.body.credential_request",
                title="Requests credentials or sensitive personal data",
                description=f"Credential-related phrases found: {cred_hits}.",
                weight=22,
                severity=Severity.high,
                detail={"terms": cred_hits},
            )
        )
    pay_hits = sorted({t for t in PAYMENT_TERMS if t in body_lower})
    if pay_hits:
        evidence.append(
            Evidence(
                rule_id="email.body.payment_scam",
                title="Payment/fraud language detected",
                description=f"Payment-scam phrases found: {pay_hits}.",
                weight=20,
                severity=Severity.high,
                detail={"terms": pay_hits},
            )
        )
    body_urgent = sorted({t for t in URGENCY_TERMS if t in body_lower})
    if body_urgent and not subj_urgent:
        evidence.append(
            Evidence(
                rule_id="email.body.urgency",
                title="Urgency language in the message body",
                description=f"Urgency phrases found: {body_urgent}.",
                weight=12,
                severity=Severity.medium,
                detail={"terms": body_urgent},
            )
        )

    # 6. Risky attachments (names only)
    risky = [a for a in parsed.attachment_names if any(a.lower().endswith(e) for e in RISKY_ATTACHMENT_EXTS)]
    if risky:
        evidence.append(
            Evidence(
                rule_id="email.attachment.risky_type",
                title="Attachment with a risky file type",
                description=f"Attachment name(s): {risky[:10]}.",
                weight=28,
                severity=Severity.high,
                detail={"attachments": risky[:10]},
            )
        )

    # 7. URL analysis (aggregate worst URL)
    url_scores: list[dict] = []
    worst = 0
    for u in parsed.urls[:50]:
        a = analyze_url(u)
        url_scores.append({"url": u, "score": a.score, "verdict": a.verdict})
        worst = max(worst, a.score)
    if parsed.urls:
        evidence.append(
            Evidence(
                rule_id="email.urls.analyzed",
                title=f"Analyzed {len(parsed.urls)} embedded link(s)",
                description=f"Highest link risk score: {worst}/100.",
                weight=0,
                severity=severity_from_score(worst),
                detail={"top": sorted(url_scores, key=lambda d: -d["score"])[:10]},
                source="rules",
            )
        )
        if worst >= 40:
            evidence.append(
                Evidence(
                    rule_id="email.urls.suspicious",
                    title="Contains suspicious link(s)",
                    description="At least one embedded URL matched phishing indicators.",
                    weight=min(30, worst // 2),
                    severity=severity_from_score(worst),
                    detail={"worst_score": worst},
                )
            )
    if include_intel and parsed.urls:
        from app.modules.threatintel.service import get_threatintel

        ti = get_threatintel()
        hits = []
        for u in parsed.urls[:10]:
            res = ti.lookup(u)
            if res.any_hit:
                hits.append(u)
        if hits:
            evidence.append(
                Evidence(
                    rule_id="email.urls.threatintel",
                    title="Link matches a threat-intelligence feed",
                    description=f"Indicator(s) found for {len(hits)} link(s).",
                    weight=0,
                    severity=Severity.critical,
                    source="threatintel",
                    detail={"urls": hits},
                )
            )

    score = min(100, sum(e.weight for e in evidence if e.weight > 0))
    if any(e.rule_id == "email.urls.threatintel" for e in evidence):
        score = max(score, 90)
    severity = severity_from_score(score)
    verdict = _verdict(score)

    return DetectionResult(
        module="email",
        target=f"{parsed.from_addr} | {parsed.subject[:120]}",
        score=score,
        severity=severity,
        verdict=verdict,
        evidence=evidence,
        recommended_action=_recommendation(severity),
        metadata={
            "message_id": parsed.message_id,
            "from": parsed.from_addr,
            "reply_to": parsed.reply_to,
            "subject": parsed.subject,
            "urls": parsed.urls,
            "attachment_names": parsed.attachment_names,
            "auth_results": parsed.auth_results,
            "body_stored": False,
        },
    )


def _bare_addr(value: str) -> str:
    m = re.search(r"<([^>]+)>", value)
    if m:
        return m.group(1).strip().lower()
    return value.strip().lower()


def _verdict(score: int) -> str:
    if score >= 65:
        return "malicious"
    if score >= 40:
        return "suspicious"
    if score >= 20:
        return "low_risk"
    return "benign"


def _recommendation(severity: Severity) -> str:
    if severity in (Severity.critical, Severity.high):
        return (
            "Do not click links, open attachments, or reply. Report this message to your "
            "security team. PhishShield does not modify your mailbox automatically."
        )
    if severity == Severity.medium:
        return "Verify the sender via a separate trusted channel before acting on this message."
    return "No strong phishing indicators found. Still confirm unexpected requests independently."
