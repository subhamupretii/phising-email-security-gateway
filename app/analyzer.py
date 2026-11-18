from __future__ import annotations

import base64
import ipaddress
import os
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlsplit

import requests

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SUSPICIOUS_URL_TERMS = {
    "login", "verify", "password", "account", "update", "confirm", "signin"
}
URGENCY_TERMS = {"urgent", "immediately", "suspended", "verify now", "action required"}

# Threat Intelligence API Configuration
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv(
    "GOOGLE_SAFE_BROWSING_API_KEY", 
    "AIzaSyCslRDsqfEwPhZEqIq0gye2kyeXthwb7tI"
)
VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY", 
    "c2123c98ffdc021f0612cf43a74c5f6d92c72041991d2fe0766ffb7c51e6a629"
)
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"


def extract_text(message) -> str:
    chunks: list[str] = []
    parts = message.walk() if message.is_multipart() else [message]

    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
            if isinstance(content, str):
                chunks.append(content)
        except (LookupError, UnicodeDecodeError, AttributeError):
            payload = part.get_payload(decode=True) or b""
            chunks.append(payload.decode("utf-8", errors="replace"))

    return "\n".join(chunks)


def extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for match in URL_RE.findall(text):
        cleaned = match.rstrip(".,;:!?)]}")
        if cleaned and cleaned not in found:
            found.append(cleaned)
    return found


def check_header_anomalies(message) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    from_header = str(message.get("From", "")).lower()
    reply_to = str(message.get("Reply-To", "")).lower()

    if reply_to and from_header and (reply_to not in from_header and from_header not in reply_to):
        score += 25
        reasons.append(f"Header Anomaly: 'Reply-To' ({reply_to}) does not match 'From' ({from_header}): +25.")

    if not message.get("Message-ID"):
        score += 10
        reasons.append("Header Anomaly: Missing standard 'Message-ID' header: +10.")

    return score, reasons


def check_google_safe_browsing(urls: list[str]) -> tuple[int, list[str]]:
    if not GOOGLE_SAFE_BROWSING_API_KEY or not urls:
        return 0, []

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "csdf-gateway", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data and len(data["matches"]) > 0:
                matched_count = len(data["matches"])
                return 40, [f"Google Safe Browsing ALERT: {matched_count} malicious URL match(es) detected: +40."]
            return 0, ["Google Safe Browsing: Clean (No threat matches detected)."]
        return 0, [f"Google Safe Browsing lookup returned HTTP {response.status_code}."]
    except requests.RequestException:
        return 0, ["Google Safe Browsing: Service unreachable (Offline / lab mode)."]


def check_virustotal(urls: list[str]) -> tuple[int, list[str]]:
    if not VIRUSTOTAL_API_KEY or not urls:
        return 0, []

    score = 0
    reasons: list[str] = []
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    for url in urls[:2]:  # Check first 2 URLs to avoid API quota limits
        try:
            # VirusTotal v3 URL ID is base64 encoded URL without trailing '='
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            response = requests.get(endpoint, headers=headers, timeout=4)
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                if malicious > 0 or suspicious > 0:
                    added_score = min(40, (malicious * 10) + (suspicious * 5))
                    score += added_score
                    reasons.append(
                        f"VirusTotal ALERT: URL '{url}' flagged by {malicious} engine(s) as malicious: +{added_score}."
                    )
            elif response.status_code == 404:
                reasons.append(f"VirusTotal: URL '{url}' not yet seen in VT database.")
        except requests.RequestException:
            reasons.append("VirusTotal API: Service unreachable (Offline / lab mode).")
            break

    return score, reasons


def check_openphish(urls: list[str]) -> tuple[int, list[str]]:
    if not urls:
        return 0, []

    try:
        response = requests.get(OPENPHISH_FEED_URL, timeout=4)
        if response.status_code == 200:
            feed_urls = set(response.text.splitlines())
            matches = [u for u in urls if u in feed_urls]
            if matches:
                return 35, [f"OpenPhish ALERT: {len(matches)} URL(s) match active community phishing feed: +35."]
            return 0, ["OpenPhish: Clean (No feed matches found)."]
        return 0, [f"OpenPhish feed returned HTTP {response.status_code}."]
    except requests.RequestException:
        return 0, ["OpenPhish: Community feed unreachable (Offline / lab mode)."]


def analyse_email(raw_message: bytes) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    subject = str(message.get("subject", ""))
    body = extract_text(message)
    combined_text = f"{subject}\n{body}".lower()
    urls = extract_urls(body)

    score = 0
    reasons: list[str] = []

    # 1. Header Anomaly Analysis
    header_score, header_reasons = check_header_anomalies(message)
    score += header_score
    reasons.extend(header_reasons)

    # 2. Local Heuristic URL Checks
    if not urls:
        reasons.append("No URL was found in the extracted message body.")

    for url in urls:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        matching_terms = sorted(term for term in SUSPICIOUS_URL_TERMS if term in url.lower())

        if matching_terms:
            points = min(30, 10 * len(matching_terms))
            score += points
            reasons.append(
                f"URL contains suspicious terms ({', '.join(matching_terms)}): +{points}."
            )

        if parsed.scheme.lower() == "http":
            score += 5
            reasons.append("URL uses HTTP rather than HTTPS: +5.")

        if hostname.startswith("xn--") or ".xn--" in hostname:
            score += 15
            reasons.append("URL hostname contains an internationalised/punycode label: +15.")

        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            score += 30
            reasons.append("URL uses an IP address as its hostname: +30.")

    # 3. Threat Intelligence APIs (Google Safe Browsing, VirusTotal v3, OpenPhish)
    if urls:
        gsb_score, gsb_reasons = check_google_safe_browsing(urls)
        score += gsb_score
        reasons.extend(gsb_reasons)

        vt_score, vt_reasons = check_virustotal(urls)
        score += vt_score
        reasons.extend(vt_reasons)

        op_score, op_reasons = check_openphish(urls)
        score += op_score
        reasons.extend(op_reasons)

    # 4. Urgency Wording Analysis
    matching_urgency = sorted(term for term in URGENCY_TERMS if term in combined_text)
    if matching_urgency:
        points = min(10, 5 * len(matching_urgency))
        score += points
        reasons.append(
            f"Message contains urgency-related wording ({', '.join(matching_urgency)}): +{points}."
        )

    score = min(score, 100)
    if score >= 40:
        decision = "BLOCK"
    elif score >= 20:
        decision = "QUARANTINE"
    else:
        decision = "ALLOW"

    if not reasons:
        reasons.append("No indicators in this rule set were triggered.")

    return {
        "subject": subject,
        "urls": urls,
        "risk_score": score,
        "decision": decision,
        "reasons": reasons,
    }
