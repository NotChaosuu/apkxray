# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
scan extracted APK strings for secrets, API keys, endpoints, and sensitive data.
"""

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class Secret:
    type: str = ""
    value: str = ""
    severity: str = ""   # critical, high, medium, low, info
    context: str = ""


# patterns organized by severity
SECRET_PATTERNS = {
    # --- critical ---
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "critical"),
    "AWS Secret Key": (r"(?:aws_secret|secret_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "critical"),
    "Google API Key": (r"AIza[0-9A-Za-z_\-]{35}", "critical"),
    "Google OAuth Client ID": (r"\d+-[a-z0-9]+\.apps\.googleusercontent\.com", "high"),
    "Firebase URL": (r"https?://[a-zA-Z0-9_\-]+\.firebaseio\.com", "high"),
    "Firebase API Key": (r"(?:firebase|FIREBASE).*?['\"]([A-Za-z0-9_\-]{39})['\"]", "critical"),
    "Private Key": (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "critical"),
    "GitHub Token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", "critical"),
    "Slack Token": (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}", "critical"),
    "Slack Webhook": (r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "critical"),
    "Stripe Key": (r"[sr]k_live_[0-9a-zA-Z]{24,}", "critical"),
    "Stripe Test Key": (r"[sr]k_test_[0-9a-zA-Z]{24,}", "medium"),
    "Twilio API Key": (r"SK[a-f0-9]{32}", "high"),
    "SendGrid API Key": (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "critical"),
    "Mailgun API Key": (r"key-[0-9a-zA-Z]{32}", "high"),

    # --- high ---
    "JWT Token": (r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", "high"),
    "Bearer Token": (r"[Bb]earer\s+[a-zA-Z0-9_\-\.]{20,}", "high"),
    "Basic Auth (base64)": (r"[Bb]asic\s+[A-Za-z0-9+/=]{10,}", "high"),
    "Hardcoded Password": (r"""(?:password|passwd|pwd|pass)\s*[:=]\s*['"]?([^'"\s,;]{4,})['"]?""", "high"),
    "Hardcoded Secret": (r"""(?:secret|api_?secret|client_?secret|app_?secret)\s*[:=]\s*['"]?([^'"\s,;]{8,})['"]?""", "high"),
    "Hardcoded API Key": (r"""(?:api_?key|apikey|API[_ ]Key)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{8,})['"]?""", "high"),
    "Hardcoded Username": (r"""(?:user_?name|username|API[_ ]User[_ ]?name)\s*[:=]\s*['"]?([^'"\s,;]{3,})['"]?""", "medium"),
    "Hardcoded Credential": (r"""(?:credential|cred|auth_token|access_token)\s*[:=]\s*['"]?([^'"\s,;]{6,})['"]?""", "high"),
    "Telegram Bot Token": (r"\d{8,10}:[a-zA-Z0-9_\-]{35}", "high"),
    "Discord Bot Token": (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}", "high"),
    "Mapbox Token": (r"pk\.[a-zA-Z0-9]{60,}", "high"),

    # --- medium ---
    "S3 Bucket": (r"[a-zA-Z0-9._\-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9._\-]+", "medium"),
    "Content Provider URI": (r"content://[a-zA-Z0-9._\-]+/[a-zA-Z0-9._\-/]*", "medium"),
    "SQL Statement": (r"(?:CREATE\s+TABLE|INSERT\s+INTO|SELECT\s+.+\s+FROM)\s+\w+", "medium"),
    "Internal IP": (r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:/]", "medium"),
    "Localhost URL": (r"https?://(?:localhost|127\.0\.0\.1)[:/][\w/\-?=&]*", "medium"),
    "Staging/Dev URL": (r"https?://(?:staging|dev|test|debug|sandbox|uat|preprod)\.[a-zA-Z0-9._\-]+", "medium"),
    "Shared Preferences": (r"""getSharedPreferences\s*\(\s*['"]([^'"]+)['"]""", "medium"),
    "Database Name": (r"""(?:openOrCreateDatabase|SQLiteDatabase\.openDatabase)\s*\(\s*['"]([^'"]+)['"]""", "medium"),

    # --- low / info ---
    "Email Address": (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "info"),
    "IP Address": (r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "info"),
}

# API endpoint patterns
ENDPOINT_PATTERNS = [
    r"https?://[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9._\-/{}%?=&]+)",
    r"""(?:"|'|`)(/(?:api|v[0-9]|rest|graphql|auth|user|admin)[a-zA-Z0-9/_\-\.{}]*?)(?:"|'|`)""",
]

# URLs to always skip (noise)
SKIP_URL_PATTERNS = [
    r"schemas\.android\.com",
    r"www\.w3\.org",
    r"schemas\.google\.com",
    r"xmlpull\.org",
    r"ns\.adobe\.com",
    r"apache\.org",
    r"example\.com",
    r"xml\.org",
    r"json\.org",
    r"mozilla\.org/MPL",
    r"opensource\.org",
    r"creativecommons\.org",
    r"play\.google\.com",
    r"developer\.android\.com",
    r"github\.com/[a-zA-Z]+$",  # bare github profile links
    r"schema\.org",             # structured-data vocab, not endpoints
    r"goo\.gl/",                # google shortlinks, rarely useful
    r"ogp\.me",
    r"purl\.org",
    r"svg\.com",
    r"fonts\.googleapis\.com",
    r"fonts\.gstatic\.com",
    r"maps\.google\.com/maps",
    r"issuetracker\.google\.com",
    r"stackoverflow\.com",
    r"pexels\.com/photos",      # stock images used as placeholders
    r"^https?://hostname",      # placeholder string
    r"googleads\.g\.doubleclick\.net",
    r"csi\.gstatic\.com",
    r"www\.googleapis\.com/auth/",  # OAuth scope identifiers, not endpoints
    r"www\.googletagmanager\.com",
    r"firebaselogging\.googleapis\.com",
    r"clientservices\.googleapis\.com",
]


def scan_secrets(strings: List[str]) -> List[Secret]:
    """scan a list of strings for secrets and sensitive data."""
    found = []
    seen = set()

    for s in strings:
        for name, (pattern, severity) in SECRET_PATTERNS.items():
            matches = re.findall(pattern, s)
            for match in matches:
                value = match if isinstance(match, str) else match[0]
                # deduplicate
                key = f"{name}:{value[:50]}"
                if key in seen:
                    continue
                seen.add(key)

                # skip obvious false positives
                if name == "Email Address" and ("@example" in value or "@test" in value):
                    continue
                if name == "IP Address" and value.startswith("0."):
                    continue

                found.append(Secret(
                    type=name,
                    value=value[:120],
                    severity=severity,
                    context=s[:150] if len(s) > len(value) + 5 else "",
                ))

    return found


def scan_endpoints(strings: List[str]) -> List[str]:
    """extract API endpoints and URLs from strings."""
    endpoints = set()

    for s in strings:
        for pattern in ENDPOINT_PATTERNS:
            matches = re.findall(pattern, s)
            for match in matches:
                url = match.strip()

                # skip noise
                skip = False
                for skip_pattern in SKIP_URL_PATTERNS:
                    if re.search(skip_pattern, url, re.IGNORECASE):
                        skip = True
                        break
                if skip:
                    continue

                # skip very short paths
                if len(url) < 10:
                    continue

                endpoints.add(url)

    return sorted(endpoints)
