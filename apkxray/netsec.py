# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
network_security_config.xml parser. Surfaces cleartext-traffic exceptions,
custom trust anchors, debug overrides, and pinned-cert configurations —
the four common ways a "secure" app actually accepts MITM.

Only available when apktool decoded the APK (the binary XML in the APK
itself isn't human-parseable without it).
"""

import re
from dataclasses import dataclass, field
from typing import List
from xml.etree import ElementTree as ET

from .unpacker import APKInfo


@dataclass
class NetSecFinding:
    title: str
    severity: str
    detail: str = ""


def scan(info: APKInfo) -> List[NetSecFinding]:
    if not info.netsec_xml:
        return []
    out: List[NetSecFinding] = []
    try:
        root = ET.fromstring(info.netsec_xml)
    except ET.ParseError:
        return out

    # <base-config> — global defaults
    for base in root.findall("base-config"):
        if (base.get("cleartextTrafficPermitted") or "").lower() == "true":
            out.append(NetSecFinding(
                title="Global cleartext-traffic permitted",
                severity="high",
                detail="<base-config cleartextTrafficPermitted=\"true\"> — every HTTP target accepted unencrypted",
            ))
        for ta in base.findall("trust-anchors/certificates"):
            src = (ta.get("src") or "").strip()
            if src == "user":
                out.append(NetSecFinding(
                    title="User CA trusted globally",
                    severity="high",
                    detail="<base-config> trusts user-installed CAs → MITM via planted cert is allowed",
                ))

    # <domain-config> — per-domain rules
    for dc in root.findall("domain-config"):
        domains = [d.text.strip() for d in dc.findall("domain") if d.text]
        clear = (dc.get("cleartextTrafficPermitted") or "").lower() == "true"
        if clear and domains:
            out.append(NetSecFinding(
                title=f"Cleartext allowed for {', '.join(domains[:5])}" + (f" (+{len(domains)-5} more)" if len(domains) > 5 else ""),
                severity="medium",
                detail="Per-domain cleartextTrafficPermitted=\"true\" — verify these hosts aren't sensitive",
            ))
        for ta in dc.findall("trust-anchors/certificates"):
            src = (ta.get("src") or "").strip()
            if src == "user" and domains:
                out.append(NetSecFinding(
                    title=f"User CA trusted for {', '.join(domains[:3])}",
                    severity="medium",
                    detail="<domain-config> trusts user CAs → MITM allowed on these hosts",
                ))

    # <debug-overrides> in what is presumably a release APK is suspicious
    debug_overrides = root.find("debug-overrides")
    if debug_overrides is not None:
        for ta in debug_overrides.findall("trust-anchors/certificates"):
            src = (ta.get("src") or "").strip()
            if src == "user":
                out.append(NetSecFinding(
                    title="<debug-overrides> with user-CA trust shipped",
                    severity="low",
                    detail="Debug-only override present in release APK — only active if android:debuggable=true (and we flag that separately)",
                ))

    # find missing pin-set declarations on domains that ARE sensitive — info-only
    sensitive_pat = re.compile(r"(api|auth|payment|wallet|login|account|admin)", re.IGNORECASE)
    for dc in root.findall("domain-config"):
        domains = [d.text.strip() for d in dc.findall("domain") if d.text]
        pinset = dc.find("pin-set")
        for dom in domains:
            if sensitive_pat.search(dom) and pinset is None:
                out.append(NetSecFinding(
                    title=f"No certificate pinning on {dom}",
                    severity="info",
                    detail="Sensitive-looking domain without <pin-set> — TLS cert is the only attack barrier",
                ))

    return out


def to_findings(items: List[NetSecFinding]):
    """Convert to dicts compatible with analyzer's SecurityFinding."""
    return [
        {"title": x.title, "severity": x.severity, "category": "netsec", "detail": x.detail}
        for x in items
    ]
