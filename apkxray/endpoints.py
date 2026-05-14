# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
Endpoint extraction. Pulls URLs, API paths, and operation definitions from:

  - Retrofit / OkHttp / Volley annotations in smali (rich attribution)
  - String concatenation of BASE_URL + path patterns
  - res/values/strings.xml resource strings
  - assets/* text content (HTML, JS, JSON, GraphQL, proto)
  - AndroidManifest <meta-data> URLs
  - DEX strings (fallback / what we had before)

Outputs structured Endpoint records with source attribution + classification
+ template-deduplication. Use scan(info) to run everything; the Endpoint
list is sorted, deduplicated, and ready for display or JSON output.
"""

import os
import re
import json
from dataclasses import dataclass, field
from typing import List, Optional

from .unpacker import APKInfo, get_smali_text


# ── data ────────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    url: str                       # the full URL or path
    method: str = ""               # HTTP method when known (GET / POST / etc)
    source: str = ""               # short tag: "retrofit" / "smali" / "asset:<file>" / "manifest" / "resource" / "dex"
    location: str = ""             # class.method context when known
    category: str = "public"       # auth / admin / payment / upload / webhook / internal / graphql / websocket / cdn / analytics / public
    confidence: str = "medium"     # high / medium / low
    template: str = ""             # /api/user/{id} (computed)

    @property
    def key(self):
        return (self.method, self.url)


# ── regexes ─────────────────────────────────────────────────────────────

# Retrofit / OkHttp / Volley annotation patterns in smali.
# Smali form:
#   .annotation runtime Lretrofit2/http/POST;
#       value = "api/v2/login"
#   .end annotation
_RETROFIT_ANNOTATION = re.compile(
    r"\.annotation runtime Lretrofit2/http/(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP);"
    r"\s*value\s*=\s*\"([^\"]+)\"",
    re.MULTILINE,
)

# OkHttp Request.Builder pattern: .url("...")
_OKHTTP_URL = re.compile(
    r"invoke-(?:virtual|direct|static)[^\n]*?Lokhttp3/Request\$Builder;->url\(Ljava/lang/String;\)",
    re.IGNORECASE,
)

# Generic full URL extraction (used on every text source).
_FULL_URL = re.compile(
    r"https?://[A-Za-z0-9._~\-]+(?::\d+)?(/[A-Za-z0-9._~\-/{}%?=&:+@!$',;*]+)?",
    re.IGNORECASE,
)
_WS_URL = re.compile(
    r"wss?://[A-Za-z0-9._~\-]+(?::\d+)?(/[A-Za-z0-9._~\-/{}%?=&:+@!$',;*]+)?",
    re.IGNORECASE,
)

# Relative API path. Quotes optional — DEX strings come unwrapped, smali
# strings come in literal quotes. Word-boundary on the leading side prevents
# matching inside an absolute URL or arbitrary text.
_REL_PATH = re.compile(
    r"""(?:^|["'`\s])(/(?:api|v[0-9]|rest|graphql|gql|auth|user|admin|oauth|payment|"""
    r"""checkout|upload|webhook|callback|hook|account|profile|settings|wallet|"""
    r"""order|cart|search|product|catalog|inventory|track|telemetry|sso|saml|jwks)"""
    r"""[A-Za-z0-9/_\-.{}:]*)"""
)

# GraphQL operations (loose match — works on smali, assets, resources)
_GQL_OP = re.compile(
    r"\b(?:query|mutation|subscription)\s+(\w+)\s*[\(\{]",
    re.IGNORECASE,
)

# Smali const-string with method context — extract via line-by-line walk.
_SMALI_CLASS = re.compile(r"^\.class[^\n]*\s+L([^\s;]+);", re.MULTILINE)
_SMALI_METHOD = re.compile(r"^\.method[^\n]*\s+(\w+)\(", re.MULTILINE)
_SMALI_CONST_STRING = re.compile(r'const-string\s+v\d+,\s*"([^"]+)"')

# Skip-list — well-known noise from libraries / docs / schemas.
_SKIP_HOSTS = (
    "schemas.android.com", "www.w3.org", "schemas.google.com", "xmlpull.org",
    "ns.adobe.com", "apache.org", "example.com", "xml.org", "json.org",
    "mozilla.org/MPL", "opensource.org", "creativecommons.org",
    "play.google.com", "developer.android.com", "schema.org", "ogp.me",
    "purl.org", "fonts.googleapis.com", "fonts.gstatic.com",
    "stackoverflow.com", "goo.gl/", "issuetracker.google.com",
)
_SKIP_PATTERNS = (
    re.compile(r"^https?://(?:www\.)?googleapis\.com/auth/"),  # OAuth scopes
    re.compile(r"^https?://hostname"),                          # placeholder
    re.compile(r"^https?://localhost(:|/|$)"),                 # local dev (still surface separately if needed)
    re.compile(r"\.pexels\.com/photos"),
    re.compile(r"images\.unsplash\.com"),
    re.compile(r"^https?://github\.com/[a-zA-Z]+$"),            # bare github profile links
)


# ── helpers ────────────────────────────────────────────────────────────

def _looks_like_noise(url: str) -> bool:
    low = url.lower()
    for h in _SKIP_HOSTS:
        if h in low:
            return True
    for p in _SKIP_PATTERNS:
        if p.search(low):
            return True
    return False


def _path_of(url: str) -> str:
    """Return just the path portion of a URL/path. Strips host so we don't
    misclassify e.g. 'http://payatu.com' as payment because the host has 'pay'."""
    low = url.lower()
    if low.startswith(("http://", "https://", "ws://", "wss://")):
        # find first slash after the scheme://
        scheme_end = low.find("://") + 3
        slash = low.find("/", scheme_end)
        if slash == -1:
            return ""
        return low[slash:]
    return low


def _classify(url: str, method: str = "") -> str:
    low = url.lower()
    if low.startswith(("ws://", "wss://")):
        return "websocket"
    path = _path_of(url)
    if "/graphql" in path or "/gql" in path:
        return "graphql"
    if any(k in path for k in ("/auth", "/login", "/signin", "/signup", "/oauth",
                               "/token", "/jwks", "/saml", "/sso", "/2fa", "/verify",
                               "/password", "/forgot", "/reset")):
        return "auth"
    if any(k in path for k in ("/admin", "/superuser", "/backoffice", "/staff",
                               "/dashboard/admin")):
        return "admin"
    if any(k in path for k in ("/payment", "/billing", "/charge", "/checkout",
                               "/subscription", "/stripe", "/paypal", "/refund",
                               "/pay/", "/wallet")):
        return "payment"
    if any(k in path for k in ("/upload", "/file", "/attachment", "/media", "/avatar")):
        return "upload"
    if any(k in path for k in ("/webhook", "/callback", "/hook")):
        return "webhook"
    if any(k in path for k in ("/internal", "/private", "/debug", "/dev/",
                               "/staging", "/test/", "/qa/")):
        return "internal"
    if any(k in path for k in ("/analytics", "/track", "/pixel", "/telemetry",
                               "/metric", "/event")):
        return "analytics"
    if any(k in low for k in (".cloudfront.net", ".s3.amazonaws.com", ".cdn.",
                              ".akamaized.net", ".fastly.net", "cdn-",
                              "://cdn.", "://static.", "://assets.")):
        return "cdn"
    return "public"


# patterns used to build URL templates
_TEMPLATE_RULES = [
    # already a Retrofit-style template, keep as-is
    (re.compile(r"\{[a-zA-Z_]+\}"), None),
    # UUID
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
     "{uuid}"),
    # 32+ char hex (md5/sha-ish)
    (re.compile(r"\b[0-9a-fA-F]{24,}\b"), "{hash}"),
    # email-like
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "{email}"),
    # all-digit segments of length 3+
    (re.compile(r"(?<=/)\d{3,}(?=/|$|\?|#)"), "{id}"),
]


def _to_template(url: str) -> str:
    out = url
    for pat, repl in _TEMPLATE_RULES:
        if repl is None:
            continue
        out = pat.sub(repl, out)
    return out


def _shorten_class(fqcn: str) -> str:
    """com/target/app/api/UserClient -> UserClient (or last 2 parts if collisiony)."""
    parts = fqcn.split("/")
    if len(parts) <= 1:
        return fqcn
    return parts[-1]


# ── scanners ───────────────────────────────────────────────────────────

def _scan_retrofit_smali(smali_text: str) -> List[Endpoint]:
    """Find @GET/@POST/etc annotations and their path argument."""
    out = []
    for m in _RETROFIT_ANNOTATION.finditer(smali_text):
        method = m.group(1).upper()
        path = m.group(2).strip()
        if not path:
            continue
        if not path.startswith("/") and not path.startswith("http"):
            path = "/" + path
        out.append(Endpoint(
            url=path,
            method=method,
            source="retrofit",
            confidence="high",
            category=_classify(path, method),
        ))
    return out


def _scan_smali_const_strings(info: APKInfo, per_file_class: dict) -> List[Endpoint]:
    """Pull URL-like const-strings from smali with class+method context.
    per_file_class is filled as we go: file -> last seen class."""
    out = []
    if not info.smali_files:
        return out
    seen = set()
    for path in info.smali_files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        # class + method tracking
        klass = ""
        method = ""
        m = _SMALI_CLASS.search(text)
        if m:
            klass = m.group(1)
            per_file_class[path] = klass
        for line in text.splitlines():
            mm = _SMALI_METHOD.match(line)
            if mm:
                method = mm.group(1)
                continue
            cs = _SMALI_CONST_STRING.search(line)
            if not cs:
                continue
            val = cs.group(1)
            if len(val) < 7:
                continue
            for url in _extract_urls(val):
                key = (klass, url)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Endpoint(
                    url=url,
                    source="smali",
                    location=f"{_shorten_class(klass)}.{method}" if klass else "",
                    confidence="medium",
                    category=_classify(url),
                ))
    return out


def _extract_urls(text: str) -> List[str]:
    """Pull URL candidates from a text blob: full URLs, ws URLs, and api-ish relative paths."""
    out = []
    for m in _FULL_URL.finditer(text):
        url = m.group(0).rstrip(".,;:'\"")
        if not _looks_like_noise(url):
            out.append(url)
    for m in _WS_URL.finditer(text):
        url = m.group(0).rstrip(".,;:'\"")
        if not _looks_like_noise(url):
            out.append(url)
    for m in _REL_PATH.finditer(text):
        out.append(m.group(1))
    return out


def _scan_assets(info: APKInfo) -> List[Endpoint]:
    """Scan text-like assets for URLs + GraphQL operations."""
    out = []
    if not info.asset_files:
        return out
    decoded_root = info.decoded_dir or ""
    for path in info.asset_files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(2 * 1024 * 1024)  # 2 MB cap per file
        except OSError:
            continue
        rel = os.path.relpath(path, decoded_root) if decoded_root else os.path.basename(path)
        for url in _extract_urls(text):
            out.append(Endpoint(
                url=url,
                source=f"asset:{rel}",
                confidence="high" if url.startswith("http") else "medium",
                category=_classify(url),
            ))
        # GraphQL operations: pull operation names + the .graphql payloads
        if path.lower().endswith((".graphql", ".gql")):
            for m in _GQL_OP.finditer(text):
                out.append(Endpoint(
                    url=f"graphql:{m.group(1)}",
                    method="OP",
                    source=f"asset:{rel}",
                    confidence="high",
                    category="graphql",
                ))
        # JSON config — extract anything that looks like a URL field
        if path.lower().endswith(".json"):
            try:
                blob = json.loads(text)
                for url in _walk_json_urls(blob):
                    if not _looks_like_noise(url):
                        out.append(Endpoint(
                            url=url,
                            source=f"asset:{rel}",
                            confidence="high",
                            category=_classify(url),
                        ))
            except (ValueError, json.JSONDecodeError):
                pass
    return out


def _walk_json_urls(node, depth=0):
    """Yield URL-shaped strings from a parsed JSON tree."""
    if depth > 6:
        return
    if isinstance(node, dict):
        for v in node.values():
            yield from _walk_json_urls(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_json_urls(v, depth + 1)
    elif isinstance(node, str):
        if node.startswith(("http://", "https://", "ws://", "wss://")):
            yield node


def _scan_resources(info: APKInfo) -> List[Endpoint]:
    """Scan res/values/*.xml resource strings."""
    out = []
    for s in info.resource_strings:
        for url in _extract_urls(s):
            out.append(Endpoint(
                url=url,
                source="resource",
                confidence="high" if url.startswith("http") else "medium",
                category=_classify(url),
            ))
    return out


def _scan_manifest_metadata(info: APKInfo) -> List[Endpoint]:
    """Scan AndroidManifest <meta-data> values for URLs."""
    out = []
    for name, value in (info.meta_data or {}).items():
        if not isinstance(value, str):
            continue
        for url in _extract_urls(value):
            out.append(Endpoint(
                url=url,
                source="manifest",
                location=name,
                confidence="high",
                category=_classify(url),
            ))
    return out


def _scan_dex_strings(info: APKInfo) -> List[Endpoint]:
    """Fallback: scan DEX strings. Used regardless of apktool — catches things
    that don't make it into smali (string-table-only entries)."""
    out = []
    for s in info.dex_strings:
        for url in _extract_urls(s):
            out.append(Endpoint(
                url=url,
                source="dex",
                confidence="low" if url.startswith("/") else "medium",
                category=_classify(url),
            ))
    return out


# ── top-level entry point ───────────────────────────────────────────────

def scan(info: APKInfo) -> List[Endpoint]:
    """Run every scanner, dedupe, classify, template, return sorted list."""
    out: List[Endpoint] = []

    if info.apktool_used and info.smali_files:
        smali_text = get_smali_text(info)
        out.extend(_scan_retrofit_smali(smali_text))
        out.extend(_scan_smali_const_strings(info, {}))

    out.extend(_scan_assets(info))
    out.extend(_scan_resources(info))
    out.extend(_scan_manifest_metadata(info))
    out.extend(_scan_dex_strings(info))

    # dedupe — same (method, url) wins to highest-confidence + best-attributed entry
    confidence_rank = {"high": 3, "medium": 2, "low": 1, "": 0}
    best: dict = {}
    for ep in out:
        key = ep.key
        if key not in best:
            best[key] = ep
            continue
        prev = best[key]
        if confidence_rank.get(ep.confidence, 0) > confidence_rank.get(prev.confidence, 0):
            best[key] = ep
            continue
        # tiebreak: prefer entries with class/method context
        if ep.location and not prev.location:
            best[key] = ep

    deduped = list(best.values())

    # compute templates
    for ep in deduped:
        ep.template = _to_template(ep.url)

    # sort: category-priority, then method, then url
    cat_order = {"auth": 0, "admin": 1, "payment": 2, "upload": 3, "webhook": 4,
                 "graphql": 5, "websocket": 6, "internal": 7, "analytics": 8,
                 "cdn": 9, "public": 10}
    deduped.sort(key=lambda e: (cat_order.get(e.category, 99), e.method, e.url))
    return deduped


def group_by_template(endpoints: List[Endpoint]) -> List[dict]:
    """Collapse endpoints into template-rows for display.
    Returns list of {template, method, count, sample, category, source, location}."""
    groups: dict = {}
    for ep in endpoints:
        key = (ep.method, ep.template or ep.url)
        if key not in groups:
            groups[key] = {
                "method": ep.method,
                "template": ep.template or ep.url,
                "category": ep.category,
                "source": ep.source,
                "location": ep.location,
                "count": 0,
                "samples": [],
            }
        groups[key]["count"] += 1
        if len(groups[key]["samples"]) < 3:
            groups[key]["samples"].append(ep.url)
        # keep the strongest source per group
        if ep.source.startswith("retrofit"):
            groups[key]["source"] = ep.source
            groups[key]["location"] = ep.location
    return list(groups.values())
