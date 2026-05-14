# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
Deep link / intent-filter analysis.

For every exported component with an intent-filter, surface:
  - the scheme(s), host(s), and path patterns it accepts
  - whether it's a custom scheme (e.g. myapp://...) → often handles untrusted URIs
  - whether host has a wildcard (*) — open redirect risk
  - whether it's an https universal link
  - the activity / receiver / service name

Findings get severity bumps for known-dangerous patterns: wildcard host on
a payment-shaped path, custom-scheme into a WebView, etc.
"""

from dataclasses import dataclass, field
from typing import List

from .unpacker import APKInfo


@dataclass
class DeepLink:
    component: str         # fqcn of the activity/receiver/service
    component_kind: str    # "activity" | "receiver" | "service"
    exported: bool
    scheme: str
    host: str
    port: str = ""
    path: str = ""         # combined of path / pathPrefix / pathPattern
    mime: str = ""
    severity: str = "info"
    notes: list = field(default_factory=list)


_CUSTOM_SCHEMES_OK = {"http", "https"}
_SUSPICIOUS_PATH_HINTS = ("payment", "checkout", "auth", "login", "oauth",
                         "redirect", "callback", "return", "next", "continue",
                         "verify", "reset", "wallet")


def scan(info: APKInfo) -> List[DeepLink]:
    out: List[DeepLink] = []
    for f in info.intent_filters or []:
        component = f.get("component", "")
        kind = f.get("component_kind", "activity")
        exported = (f.get("exported", "false") or "false").lower() == "true"
        actions = f.get("actions") or []
        # only intent-filters with an ACTION_VIEW make a real deep link target
        if "android.intent.action.VIEW" not in actions:
            continue
        for data in f.get("data") or []:
            scheme = (data.get("scheme") or "").strip().lower()
            host = (data.get("host") or "").strip()
            port = (data.get("port") or "").strip()
            path = (data.get("path") or data.get("pathPrefix") or data.get("pathPattern") or "").strip()
            mime = (data.get("mimeType") or "").strip()
            if not scheme and not host and not path and not mime:
                continue
            dl = DeepLink(
                component=component,
                component_kind=kind,
                exported=exported,
                scheme=scheme,
                host=host,
                port=port,
                path=path,
                mime=mime,
            )

            # severity / notes
            if not exported and kind == "activity" and "android.intent.category.BROWSABLE" in (f.get("categories") or []):
                # browsable activities are effectively exported via the browser
                dl.notes.append("BROWSABLE category → reachable from web links even if exported=false")
                exported = True
                dl.exported = True

            # custom-scheme without HTTPS = often a webview handler
            if scheme and scheme not in _CUSTOM_SCHEMES_OK:
                dl.notes.append(f"custom scheme '{scheme}://' — verify it doesn't load attacker URLs into a WebView")
                dl.severity = "medium"

            # wildcard host
            if "*" in host:
                dl.notes.append("wildcard host — open-redirect / domain-spoof risk")
                dl.severity = "high"

            # suspicious path keyword
            low_path = path.lower()
            if any(h in low_path for h in _SUSPICIOUS_PATH_HINTS):
                dl.notes.append("payment/auth-shaped path — test for unvalidated return parameters")
                if dl.severity == "info":
                    dl.severity = "medium"
                elif dl.severity == "medium":
                    dl.severity = "high"

            # https universal links without an asset-statements check = recon worthy
            if scheme in ("http", "https") and host and "*" not in host:
                if dl.severity == "info":
                    dl.notes.append(f"universal link to {host} — verify /.well-known/assetlinks.json is locked down")

            out.append(dl)
    return out


def to_findings(deeplinks: List[DeepLink]):
    """Convert into SecurityFinding-shaped dicts (compatible with analyzer output)."""
    findings = []
    for dl in deeplinks:
        if dl.severity == "info":
            continue
        title = f"Deep link: {dl.scheme}://{dl.host}{dl.path}".rstrip("/")
        if len(title) > 90:
            title = title[:87] + "..."
        detail = f"{dl.component} ({dl.component_kind}) — " + "; ".join(dl.notes)
        findings.append({
            "title": title,
            "severity": dl.severity,
            "category": "deeplink",
            "detail": detail[:200],
        })
    return findings
