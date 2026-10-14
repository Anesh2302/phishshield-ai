"""Deterministic URL feature extraction shared by the rules engine and the ML
classifier. The feature schema is versioned so model artifacts can be checked
for compatibility.
"""

from __future__ import annotations

import math
import re
from urllib.parse import parse_qs, urlsplit

FEATURE_SCHEMA_VERSION = "1.0"

FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_subdomains",
    "num_slashes",
    "num_at",
    "num_percent",
    "has_ip_host",
    "has_port",
    "is_https",
    "has_punycode",
    "num_suspicious_tld",
    "num_brand_hits",
    "entropy_host",
    "num_query_params",
    "has_double_extension",
    "has_suspicious_extension",
    "num_hex_escapes",
    "path_depth",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click",
    "link", "country", "stream", "download", "review", "loan", "win", "bid",
    "men", "party", "gdn", "icu", "cyou", "rest", "quest", "monster", "sbs",
}

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "lnkd.in",
}

BRANDS = [
    "google", "gmail", "microsoft", "outlook", "office365", "apple", "icloud",
    "paypal", "amazon", "facebook", "instagram", "whatsapp", "netflix", "bank",
    "chase", "wellsfargo", "hsbc", "barclays", "santander", "github", "dropbox",
    "linkedin", "twitter", "coinbase", "binance", "steam", "spotify", "adobe",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".dll", ".vbs",
    ".js", ".jse", ".wsf", ".hta", ".jar", ".apk", ".ps1", ".lnk", ".iso",
    ".img", ".xll", ".docm", ".xlsm", ".pptm",
}

IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def split_host(url: str) -> tuple[str, str, str, str]:
    """Return (scheme, host, path, query) lowercased where appropriate."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", "", "", ""
    return (
        parts.scheme.lower(),
        (parts.hostname or "").lower(),
        parts.path or "",
        parts.query or "",
    )


def registered_domain(host: str) -> str:
    """Best-effort registrable domain (last two labels). Not a public-suffix
    implementation; documented limitation.
    """
    labels = [lab for lab in host.split(".") if lab]
    if len(labels) <= 2:
        return host
    # handle common multi-part suffixes co.uk, com.au, etc.
    two_part = {"co", "com", "org", "net", "gov", "ac", "edu"}
    if len(labels) >= 3 and labels[-2] in two_part and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def extract_features(url: str) -> dict[str, float]:
    scheme, host, path, query = split_host(url)
    full = url
    labels = [lab for lab in host.split(".") if lab]
    tld = labels[-1] if labels else ""
    exts = re.findall(r"\.[a-z0-9]{1,5}(?=[.?#/]|$)", path.lower())
    has_double_ext = any(
        SUSPICIOUS_EXTENSIONS & {exts[i], exts[i + 1]} for i in range(len(exts) - 1)
    ) if len(exts) >= 2 else False
    brand_hits = sum(1 for b in BRANDS if b in host)
    reg = registered_domain(host)
    # brand in subdomain but not the registrable domain => impersonation signal
    brand_in_host_not_reg = sum(1 for b in BRANDS if b in host and b not in reg)

    feats = {
        "url_length": float(len(full)),
        "host_length": float(len(host)),
        "path_length": float(len(path)),
        "num_dots": float(full.count(".")),
        "num_hyphens": float(full.count("-")),
        "num_digits": float(sum(c.isdigit() for c in full)),
        "num_subdomains": float(max(0, len(labels) - 2)),
        "num_slashes": float(full.count("/")),
        "num_at": float(full.count("@")),
        "num_percent": float(full.count("%")),
        "has_ip_host": 1.0 if IP_HOST_RE.match(host) else 0.0,
        "has_port": 1.0 if re.search(r":\d{2,5}(/|$)", full.split("://", 1)[-1]) else 0.0,
        "is_https": 1.0 if scheme == "https" else 0.0,
        "has_punycode": 1.0 if "xn--" in host else 0.0,
        "num_suspicious_tld": 1.0 if tld in SUSPICIOUS_TLDS else 0.0,
        "num_brand_hits": float(brand_in_host_not_reg or brand_hits),
        "entropy_host": shannon_entropy(host),
        "num_query_params": float(len(parse_qs(query))),
        "has_double_extension": 1.0 if has_double_ext else 0.0,
        "has_suspicious_extension": 1.0 if (set(exts) & SUSPICIOUS_EXTENSIONS) else 0.0,
        "num_hex_escapes": float(len(re.findall(r"%[0-9a-fA-F]{2}", full))),
        "path_depth": float(len([p for p in path.split("/") if p])),
    }
    # keep declared order
    return {k: feats[k] for k in FEATURE_NAMES}


def feature_vector(url: str) -> list[float]:
    f = extract_features(url)
    return [f[name] for name in FEATURE_NAMES]
