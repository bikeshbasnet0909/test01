"""Local-only email parsing and deterministic phishing triage indicators.

This module never resolves DNS, opens URLs, executes attachments, or calls AI.
Email headers and body are untrusted evidence and must not be treated as commands.
"""
from __future__ import annotations

from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit
import re

MAX_EMAIL_BYTES = 2 * 1024 * 1024
URL_RE = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>\"']{1,2048}")
EMAIL_RE = re.compile(r"(?i)^[^\s@<>]+@([^\s@<>]+)$")
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly",
    "cutt.ly", "shorturl.at", "rb.gy",
}
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd",
    ".ps1", ".hta", ".iso", ".img", ".lnk", ".jar", ".msi", ".dll",
}

class _HTMLLinkParser(HTMLParser):
    """Extract href values without rendering or executing HTML."""
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self.links.append(value[:2048])


def _addresses(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        from email.utils import getaddresses
        return [address.strip().lower() for _, address in getaddresses([value]) if address]
    except (TypeError, ValueError):
        return []


def _domain(address: str) -> str | None:
    match = EMAIL_RE.match(address.strip())
    return match.group(1).rstrip(".").lower() if match else None


def _safe_url(raw: str) -> dict[str, Any]:
    value = raw.strip().rstrip(".,);]}")
    normalized = value
    if normalized.lower().startswith("hxxp://"):
        normalized = "http://" + normalized[7:]
    elif normalized.lower().startswith("hxxps://"):
        normalized = "https://" + normalized[8:]
    elif normalized.lower().startswith("www."):
        normalized = "http://" + normalized
    try:
        parts = urlsplit(normalized)
        host = (parts.hostname or "").rstrip(".").lower()
        ip_literal = False
        if host:
            import ipaddress
            try:
                ipaddress.ip_address(host)
                ip_literal = True
            except ValueError:
                pass
        return {
            "url": value[:2048],
            "scheme": parts.scheme.lower() or None,
            "host": host or None,
            "has_userinfo": parts.username is not None or parts.password is not None,
            "ip_literal_host": ip_literal,
            "is_shortener": host in SHORTENER_DOMAINS,
        }
    except (ValueError, UnicodeError):
        return {
            "url": value[:2048], "scheme": None, "host": None,
            "has_userinfo": False, "ip_literal_host": False, "is_shortener": False,
        }


def analyze_email(raw: bytes) -> dict[str, Any]:
    """Analyze raw RFC 5322 email bytes and return JSON-serializable findings."""
    if not raw:
        raise ValueError("Email content is empty.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError(f"Email exceeds the {MAX_EMAIL_BYTES // (1024 * 1024)} MiB limit.")

    digest = sha256(raw).hexdigest()
    message = BytesParser(policy=policy.default).parsebytes(raw)

    from_values = _addresses(str(message.get("From", "")))
    reply_values = _addresses(str(message.get("Reply-To", "")))
    return_values = _addresses(str(message.get("Return-Path", "")))
    from_domains = sorted({d for d in (_domain(a) for a in from_values) if d})
    reply_domains = sorted({d for d in (_domain(a) for a in reply_values) if d})
    return_domains = sorted({d for d in (_domain(a) for a in return_values) if d})

    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        content_type = part.get_content_type().lower()
        if filename or part.get_content_disposition() == "attachment":
            safe_name = (filename or "unnamed").replace("\\", "/").split("/")[-1][:255]
            suffix = ("." + safe_name.rsplit(".", 1)[-1].lower()) if "." in safe_name else ""
            attachments.append({
                "filename": safe_name,
                "content_type": content_type,
                "size_bytes": len(payload),
                "sha256": sha256(payload).hexdigest(),
                "suspicious_extension": suffix in SUSPICIOUS_EXTENSIONS,
            })
            continue
        if content_type in {"text/plain", "text/html"}:
            try:
                content = part.get_content()
                if not isinstance(content, str):
                    content = str(content)
            except (LookupError, UnicodeError, ValueError):
                content = payload[:100_000].decode("utf-8", errors="replace")
            content = content[:200_000]
            if content_type == "text/html":
                body_html_parts.append(content)
            else:
                body_text_parts.append(content)

    plain_text = "\n".join(body_text_parts)
    html_text = "\n".join(body_html_parts)
    html_parser = _HTMLLinkParser()
    try:
        html_parser.feed(html_text)
    except Exception:
        pass

    candidates = URL_RE.findall(plain_text + "\n" + html_text) + html_parser.links
    seen: set[str] = set()
    urls: list[dict[str, Any]] = []
    for candidate in candidates:
        key = candidate.strip()
        if key and key not in seen:
            seen.add(key)
            urls.append(_safe_url(key))
        if len(urls) >= 200:
            break

    auth_headers = []
    for header in ("Authentication-Results", "Received-SPF", "ARC-Authentication-Results"):
        for value in message.get_all(header, []):
            auth_headers.append({"header": header, "value": str(value)[:2000]})

    findings: list[dict[str, str]] = []
    score = 0
    def add(code: str, severity: str, points: int, evidence: str, explanation: str) -> None:
        nonlocal score
        findings.append({
            "code": code, "severity": severity,
            "evidence": evidence[:1000], "explanation": explanation,
        })
        score += points

    if not from_values:
        add("MISSING_FROM", "medium", 15, str(message.get("From", "")), "No usable From address was parsed.")
    if from_domains and reply_domains and not set(from_domains).intersection(reply_domains):
        add("REPLY_TO_DOMAIN_MISMATCH", "high", 25,
            f"From domains: {from_domains}; Reply-To domains: {reply_domains}",
            "The reply destination uses a different domain. This can be legitimate, but warrants verification.")
    if from_domains and return_domains and not set(from_domains).intersection(return_domains):
        add("RETURN_PATH_DOMAIN_MISMATCH", "low", 8,
            f"From domains: {from_domains}; Return-Path domains: {return_domains}",
            "The envelope return path differs from the visible sender domain; mailing services can cause this legitimately.")
    if not auth_headers:
        add("AUTH_RESULTS_NOT_PRESENT", "info", 0, "No Authentication-Results, Received-SPF, or ARC-Authentication-Results header found.",
            "Authentication cannot be assessed from the supplied message alone. Pasted or forwarded email may omit transport headers.")
    else:
        auth_text = " ".join(item["value"] for item in auth_headers).lower()
        if re.search(r"\b(spf|dkim|dmarc)\s*=\s*fail\b", auth_text):
            add("AUTH_FAILURE_REPORTED", "high", 25, "Supplied authentication-result header contains a fail result.",
                "A supplied header reports SPF, DKIM, or DMARC failure. Header authenticity and trusted receiving infrastructure are not verified here.")
        elif re.search(r"\b(spf|dkim|dmarc)\s*=\s*(none|softfail|temperror|permerror)\b", auth_text):
            add("AUTH_RESULT_NEEDS_REVIEW", "medium", 10, "Supplied authentication-result header contains a non-pass result.",
                "A supplied header reports a non-pass authentication result; confirm it against trusted mail-gateway logs.")

    for item in urls:
        if item["has_userinfo"]:
            add("URL_USERINFO", "high", 20, item["url"], "URL contains user-info before the host, a pattern sometimes used to disguise the actual destination.")
        if item["ip_literal_host"]:
            add("URL_IP_LITERAL", "high", 20, item["url"], "URL host is an IP address rather than a domain name.")
        if item["is_shortener"]:
            add("URL_SHORTENER", "medium", 10, item["url"], "URL uses a known link-shortening domain; destination is not resolved by this tool.")
        if item["scheme"] == "http":
            add("URL_CLEAR_TEXT_HTTP", "low", 5, item["url"], "URL uses HTTP rather than HTTPS; this alone does not prove maliciousness.")

    for attachment in attachments:
        if attachment["suspicious_extension"]:
            add("RISKY_ATTACHMENT_EXTENSION", "high", 25, attachment["filename"],
                "Attachment has an executable or script-capable extension. It has not been opened or executed.")

    subject = str(message.get("Subject", ""))[:500]
    body_lower = (plain_text + "\n" + html_text).lower()
    urgency_terms = ("urgent", "immediately", "verify your account", "password expires",
                     "account suspended", "wire transfer", "payment overdue", "confidential",
                     "mfa", "one-time password", "otp")
    matches = [term for term in urgency_terms if term in (subject + "\n" + body_lower).lower()]
    if matches:
        add("URGENCY_OR_CREDENTIAL_LANGUAGE", "low", 5, ", ".join(matches[:10]),
            "Urgency or credential-related language was detected. Review in context; legitimate messages can use these terms.")

    score = min(score, 100)
    level = "high" if score >= 50 else "medium" if score >= 20 else "low"
    return {
        "schema_version": "1.0",
        "analysis_mode": "deterministic_local_only",
        "evidence": {
            "sha256": digest,
            "size_bytes": len(raw),
            "message_id": str(message.get("Message-ID", ""))[:500] or None,
            "date": str(message.get("Date", ""))[:200] or None,
            "from": str(message.get("From", ""))[:1000] or None,
            "reply_to": str(message.get("Reply-To", ""))[:1000] or None,
            "subject": subject or None,
            "from_domains": from_domains,
            "reply_to_domains": reply_domains,
            "authentication_headers": auth_headers,
        },
        "indicators": {"urls": urls, "attachments": attachments},
        "risk_assessment": {
            "score": score, "level": level,
            "meaning": "Heuristic triage score, not a probability or definitive verdict.",
        },
        "findings": findings,
        "limitations": [
            "Supplied authentication-result headers are not independently verified and may be forged.",
            "No DNS queries, URL visits, reputation lookups, attachment execution, or AI calls were performed.",
            "A low score does not establish that an email is safe; analyst review is required.",
        ],
    }
