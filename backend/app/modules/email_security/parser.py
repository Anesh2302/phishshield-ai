"""Safe email parsing.

We parse RFC 822 messages with the standard library only. HTML bodies are
flattened to text with the standard parser; nothing is rendered, executed, or
fetched. Attachment *names* are inspected, but attachment contents are only
analysed when the caller explicitly hands them to the file module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser, Parser
from email.utils import getaddresses
from html.parser import HTMLParser

MAX_BODY_CHARS = 20_000
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.links: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style"}:
            self._skip = True
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v and v.lower().startswith(("http://", "https://")):
                    self.links.append(v)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)

    @property
    def text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.parts)).strip()


@dataclass
class ParsedEmail:
    message_id: str = ""
    from_addr: str = ""
    from_display: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    date: str = ""
    auth_results: dict = field(default_factory=dict)
    text_body: str = ""
    urls: list[str] = field(default_factory=list)
    attachment_names: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)


def _header(msg: Message, name: str) -> str:
    val = msg.get(name)
    return str(val).strip() if val else ""


def _parse_auth_results(value: str) -> dict:
    """Extract spf/dkim/dmarc results from an Authentication-Results header.

    This is a best-effort parse of a header we did not generate; it is used as
    a signal, not as proof, and the raw header is preserved in evidence.
    """
    result: dict = {"raw": value[:500]}
    for mechanism in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mechanism}\s*=\s*([a-z]+)", value, re.IGNORECASE)
        if m:
            result[mechanism] = m.group(1).lower()
    return result


def parse_email(raw: str | bytes) -> ParsedEmail:
    if isinstance(raw, str):
        msg: Message = Parser(policy=policy.default).parsestr(raw)
    else:
        msg = BytesParser(policy=policy.default).parsebytes(raw)

    parsed = ParsedEmail()
    parsed.message_id = _header(msg, "Message-ID")
    parsed.reply_to = _header(msg, "Reply-To")
    parsed.return_path = _header(msg, "Return-Path")
    parsed.subject = _header(msg, "Subject")[:500]
    parsed.date = _header(msg, "Date")

    from_hdr = msg.get("From")
    if from_hdr is not None:
        pairs = getaddresses([str(from_hdr)])
        if pairs:
            name, addr = pairs[0]
            parsed.from_display = (name or "").strip()
            parsed.from_addr = (addr or "").strip().lower()

    auth = _header(msg, "Authentication-Results")
    parsed.auth_results = _parse_auth_results(auth) if auth else {}
    parsed.headers = {
        k.lower(): str(msg.get(k))[:400]
        for k in ("Received-SPF", "DKIM-Signature", "ARC-Authentication-Results")
        if msg.get(k)
    }

    text_parts: list[str] = []
    html_parts: list[str] = []
    urls: set[str] = set()

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            if filename:
                parsed.attachment_names.append(filename[:255])
                continue
            if "attachment" in disp.lower():
                continue
            if ctype == "text/plain":
                text_parts.append(_decode(part))
            elif ctype == "text/html":
                html_parts.append(_decode(part))
    else:
        if msg.get_content_type() == "text/html":
            html_parts.append(_decode(msg))
        else:
            text_parts.append(_decode(msg))

    body_text = "\n".join(text_parts).strip()
    if not body_text and html_parts:
        extractor = _TextExtractor()
        for hp in html_parts:
            extractor.feed(hp)
        body_text = extractor.text
        for link in extractor.links:
            urls.add(link)

    body_text = body_text[:MAX_BODY_CHARS]
    for u in _URL_RE.findall(body_text):
        urls.add(u.rstrip(".,;)"))
    for hp in html_parts:
        for u in _URL_RE.findall(hp):
            urls.add(u.rstrip(".,;)"))

    parsed.text_body = body_text
    parsed.urls = sorted(urls)[:100]
    return parsed


def _decode(part: EmailMessage) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else str(content)
    except Exception:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload.decode("utf-8", errors="replace")
        return ""
