from __future__ import annotations

import ipaddress
import joblib
import os
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser, Parser
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

# Regular expression to extract HTTP / HTTPS URLs from raw text
URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# High-risk top level domains known for abuse, disposability, or test abuse
HIGH_RISK_TLDS = {".invalid", ".top", ".xyz", ".biz", ".info"}

# Urgency and phishing lure keywords (+15 points per matched keyword)
SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "password",
    "account",
    "suspended",
    "reset",
    "alert",
    "immediately",
    "action required",
    "unauthorized",
    "compromised",
    "security",
    "confirm",
    "login",
]

# Pattern to extract a potential domain from displayed anchor text
DOMAIN_IN_TEXT_RE = re.compile(
    r"(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)",
    re.IGNORECASE,
)

# AI Model path
MODEL_PATH = Path(__file__).parent / "phishing_model.joblib"
_ai_model = None
_model_loaded = False


def load_ai_model() -> bool:
    """Load the trained phishing ML model from disk.

    Returns:
        True if model loaded successfully, False otherwise.
    """
    global _ai_model, _model_loaded

    if _model_loaded:
        return True

    try:
        if MODEL_PATH.exists():
            _ai_model = joblib.load(MODEL_PATH)
            _model_loaded = True
            print(f"[AI] Phishing model loaded from {MODEL_PATH}")
            return True
        else:
            print(f"[AI] Model file not found at {MODEL_PATH}. AI scoring disabled.")
            return False
    except Exception as e:
        print(f"[AI] Failed to load model: {e}. AI scoring disabled.")
        return False


def get_ai_score(text: str) -> int:
    """Get AI-based phishing probability score (0-100).

    Args:
        text: Email text to analyze.

    Returns:
        Phishing probability percentage (0-100). Returns 0 if model not loaded.
    """
    global _ai_model, _model_loaded

    if not _model_loaded:
        load_ai_model()

    if not _model_loaded or _ai_model is None:
        return 0

    try:
        # Get phishing probability (probability of class 1)
        proba = _ai_model.predict_proba([text])[0][1]
        return int(proba * 100)
    except Exception as e:
        print(f"[AI] Error getting AI score: {e}")
        return 0


class HTMLAnchorExtractor(HTMLParser):
    """HTML parser to extract hyperlinks and their visible anchor text."""

    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[tuple[str, str]] = []  # list of (href, anchor_text)
        self._current_href: Optional[str] = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "a":
            attr_dict = dict(attrs)
            href = attr_dict.get("href")
            if href:
                self._current_href = href.strip()
                self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            anchor_text = " ".join("".join(self._current_text).split())
            self.anchors.append((self._current_href, anchor_text))
            self._current_href = None
            self._current_text = []


def clean_url(raw_url: str) -> str:
    """Trim trailing punctuation characters commonly attached to URLs in prose."""
    return raw_url.rstrip(".,;:!?)]}\"'")


def extract_urls(text: str) -> list[str]:
    """Extract and deduplicate all HTTP/HTTPS URLs from plain or HTML text."""
    urls: list[str] = []
    for match in URL_REGEX.findall(text):
        cleaned = clean_url(match)
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls


def extract_anchors(html_text: str) -> list[tuple[str, str]]:
    """Extract (href, anchor_text) pairs from HTML content using HTMLParser with regex fallback."""
    parser = HTMLAnchorExtractor()
    try:
        parser.feed(html_text)
        parser.close()
        anchors = parser.anchors
    except Exception:
        anchors = []

    # Regex fallback for unclosed or malformed tags
    regex_anchors = re.findall(
        r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_text, re.IGNORECASE | re.DOTALL
    )
    for href, raw_text in regex_anchors:
        cleaned_text = re.sub(r"<[^>]+>", "", raw_text).strip()
        pair = (href.strip(), cleaned_text)
        if pair not in anchors:
            anchors.append(pair)

    return anchors


def is_ip_hostname(hostname: Optional[str]) -> bool:
    """Check if a hostname is an IPv4 or IPv6 address (e.g., http://192.168.1.1/login)."""
    if not hostname:
        return False
    # Strip port if present or brackets for IPv6 [::1]
    cleaned = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def extract_domain_from_text(text: str) -> Optional[str]:
    """Extract a domain name from display text if present."""
    match = DOMAIN_IN_TEXT_RE.search(text.strip())
    if match:
        domain = match.group(1).lower()
        return domain.split("/")[0].split(":")[0]
    return None


def detect_anchor_mismatches(anchors: list[tuple[str, str]]) -> list[dict[str, str]]:
    """Detect deceptive links where the visible anchor text displays a domain that differs from the target URL."""
    mismatches: list[dict[str, str]] = []

    for href, anchor_text in anchors:
        if not anchor_text:
            continue

        displayed_domain = extract_domain_from_text(anchor_text)
        if not displayed_domain:
            continue

        try:
            parsed_target = urlsplit(href)
        except Exception:
            continue

        target_host = (parsed_target.hostname or "").lower()
        if not target_host:
            continue

        # If target is an IP, any domain displayed in anchor text is an immediate mismatch
        if is_ip_hostname(target_host):
            mismatches.append({
                "anchor_text": anchor_text,
                "displayed_domain": displayed_domain,
                "target_url": href,
                "target_hostname": target_host,
            })
            continue

        # Domain comparison: check exact match or subdomain relationship
        displayed_domain = displayed_domain.lower()
        if (
            target_host != displayed_domain
            and not target_host.endswith("." + displayed_domain)
            and not displayed_domain.endswith("." + target_host)
        ):
            mismatches.append({
                "anchor_text": anchor_text,
                "displayed_domain": displayed_domain,
                "target_url": href,
                "target_hostname": target_host,
            })

    return mismatches


def extract_message_payload(msg: Any) -> tuple[str, str, str, str, str]:
    """Extract subject, sender, recipient, plain text body, and HTML body from email."""
    subject = str(msg.get("subject", "") or "")
    sender = str(msg.get("from", "") or "")
    recipient = str(msg.get("to", "") or "")

    plain_chunks: list[str] = []
    html_chunks: list[str] = []

    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue

        ctype = part.get_content_type()
        payload = b""
        try:
            content = part.get_content()
            if isinstance(content, str):
                if ctype == "text/html":
                    html_chunks.append(content)
                else:
                    plain_chunks.append(content)
                continue
        except Exception:
            pass

        try:
            payload = part.get_payload(decode=True) or b""
            decoded_text = payload.decode("utf-8", errors="replace")
            if ctype == "text/html":
                html_chunks.append(decoded_text)
            else:
                plain_chunks.append(decoded_text)
        except Exception:
            pass

    return subject, sender, recipient, "\n".join(plain_chunks), "\n".join(html_chunks)


def calculate_email_score(headers: dict[str, str], body: str) -> dict[str, Any]:
    """Calculate composite email score combining AI and heuristic analysis.

    Combines:
      - AI probability score (weight ~40%)
      - URL inspection, suspicious TLD checks, keyword heuristics (weight ~60%)

    Final score 0-100:
      - Score < 35: ALLOW
      - 35-69: QUARANTINE
      - 70+: BLOCK

    Args:
        headers: Email headers as dict.
        body: Email body text.

    Returns:
        Dict with score, decision, reasons, and component scores.
    """
    # Prepare combined text for AI analysis
    subject = headers.get("subject", "")
    combined_text = f"{subject}\n{body}".strip()

    # 1. Get AI score (40% weight)
    ai_score = get_ai_score(combined_text)
    ai_weight = 0.4

    # 2. Calculate heuristic score (60% weight)
    heuristic_score = 0
    heuristic_reasons: list[str] = []

    # URL-based heuristics
    urls = extract_urls(body)
    combined_body_lower = body.lower()

    # High-risk TLDs
    high_risk_tld_links: list[str] = []
    for url in urls:
        try:
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower()
            if any(hostname.endswith(tld) for tld in HIGH_RISK_TLDS):
                if url not in high_risk_tld_links:
                    high_risk_tld_links.append(url)
        except Exception:
            pass

    if high_risk_tld_links:
        heuristic_score += 30
        heuristic_reasons.append(
            f"High-risk TLD detected in links ({', '.join(high_risk_tld_links)}): +30."
        )

    # IP-address hostnames
    ip_links: list[str] = []
    for url in urls:
        try:
            parsed = urlsplit(url)
            if is_ip_hostname(parsed.hostname):
                if url not in ip_links:
                    ip_links.append(url)
        except Exception:
            pass

    if ip_links:
        heuristic_score += 30
        heuristic_reasons.append(f"URL uses IP-address hostname ({', '.join(ip_links)}): +30.")

    # Suspicious keywords
    matched_keywords: list[str] = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined_body_lower:
            matched_keywords.append(kw)
            heuristic_score += 15
            heuristic_reasons.append(f"Urgency/phishing keyword matched ('{kw}'): +15.")

    # HTTP (non-HTTPS) links
    http_links = [u for u in urls if u.startswith("http://")]
    if http_links:
        heuristic_score += 10
        heuristic_reasons.append(f"Non-HTTPS links detected ({len(http_links)}): +10.")

    # Cap heuristic score at 100
    heuristic_score = min(heuristic_score, 100)
    heuristic_weight = 0.6

    # 3. Combine scores
    combined_score = int((ai_score * ai_weight) + (heuristic_score * heuristic_weight))
    combined_score = min(combined_score, 100)

    # Build reasons list
    reasons: list[str] = []
    if ai_score > 0:
        reasons.append(f"AI Model phishing probability: {ai_score}% (weight: {ai_weight*100}%).")
    reasons.extend(heuristic_reasons)

    if not reasons:
        reasons.append("No threat indicators or suspicious patterns detected.")

    # Determine verdict
    if combined_score >= 70:
        decision = "BLOCK"
    elif combined_score >= 35:
        decision = "QUARANTINE"
    else:
        decision = "ALLOW"

    return {
        "score": combined_score,
        "threat_score": combined_score,
        "risk_score": combined_score,
        "decision": decision,
        "verdict": decision,
        "reasons": reasons,
        "ai_score": ai_score,
        "heuristic_score": heuristic_score,
        "subject": subject or "(No Subject)",
        "urls": urls,
        "ip_links": ip_links,
        "high_risk_tld_links": high_risk_tld_links,
        "matched_keywords": matched_keywords,
    }


def analyse_email(raw_or_parsed: bytes | str | EmailMessage) -> dict[str, Any]:
    """Execute heuristic security analysis on an email.

    Detection Rules:
      1. Detect IP-address hostnames in links (+30 points)
      2. Detect anchor-text mismatches (+35 points)
      3. Flag high-risk TLDs (.invalid, .top, .xyz, .biz, .info) (+30 points)
      4. Score urgency/phishing keywords (+15 points per match)
      5. Cap total score at 100:
         - Score < 35: ALLOW
         - 35 - 69: QUARANTINE
         - 70+: BLOCK

    Note: For composite AI+heuristic scoring, use calculate_email_score() instead.
    """
    if isinstance(raw_or_parsed, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(raw_or_parsed)
    elif isinstance(raw_or_parsed, str):
        msg = Parser(policy=policy.default).parsestr(raw_or_parsed)
    else:
        msg = raw_or_parsed

    subject, sender, recipient, plain_body, html_body = extract_message_payload(msg)
    combined_body = f"{plain_body}\n{html_body}".strip()
    combined_text = f"{subject}\n{combined_body}".lower()

    # 1. URL Extraction using urllib.parse and regex
    extracted_urls = extract_urls(combined_body)
    anchors = extract_anchors(html_body) if html_body else []
    for href, _ in anchors:
        cleaned_href = clean_url(href)
        if cleaned_href.startswith(("http://", "https://")) and cleaned_href not in extracted_urls:
            extracted_urls.append(cleaned_href)

    score = 0
    reasons: list[str] = []

    # 2. Detect IP-address hostnames in links
    ip_links: list[str] = []
    for url in extracted_urls:
        try:
            parsed = urlsplit(url)
            if is_ip_hostname(parsed.hostname):
                if url not in ip_links:
                    ip_links.append(url)
        except Exception:
            pass

    if ip_links:
        score += 30
        reasons.append(f"URL uses IP-address hostname ({', '.join(ip_links)}): +30.")

    # 3. Detect anchor-text mismatches
    anchor_mismatches = detect_anchor_mismatches(anchors)
    if anchor_mismatches:
        score += 35
        for m in anchor_mismatches:
            reasons.append(
                f"Anchor-text mismatch: displays '{m['anchor_text']}' but points to '{m['target_url']}': +35."
            )

    # 4. Flag high-risk TLDs (.invalid, .top, .xyz, .biz, .info)
    high_risk_tld_links: list[str] = []
    for url in extracted_urls:
        try:
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower()
            if any(hostname.endswith(tld) for tld in HIGH_RISK_TLDS):
                if url not in high_risk_tld_links:
                    high_risk_tld_links.append(url)
        except Exception:
            pass

    if high_risk_tld_links:
        score += 30
        reasons.append(
            f"High-risk TLD detected in links ({', '.join(high_risk_tld_links)}): +30."
        )

    # 5. Score urgency/phishing keywords (+15 per match)
    matched_keywords: list[str] = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined_text:
            matched_keywords.append(kw)
            score += 15
            reasons.append(f"Urgency/phishing keyword matched ('{kw}'): +15.")

    # 6. Score Capping & Verdict Decision
    total_score = min(score, 100)
    if total_score >= 70:
        decision = "BLOCK"
    elif total_score >= 35:
        decision = "QUARANTINE"
    else:
        decision = "ALLOW"

    # Compute AI score for text payload
    ai_score = get_ai_score(combined_text)

    if not reasons:
        reasons.append("No threat indicators or suspicious patterns detected.")

    return {
        "score": total_score,
        "threat_score": total_score,
        "ai_score": ai_score,
        "risk_score": total_score,  # Alias for compatibility with existing tests
        "decision": decision,
        "verdict": decision,
        "reasons": reasons,
        "subject": subject or "(No Subject)",
        "sender": sender,
        "recipient": recipient,
        "urls": extracted_urls,
        "ip_links": ip_links,
        "high_risk_tld_links": high_risk_tld_links,
        "anchor_mismatches": anchor_mismatches,
        "matched_keywords": matched_keywords,
    }

