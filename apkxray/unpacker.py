# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
unpack APK files using androguard for proper binary XML and DEX parsing.
"""

import os
import re
import sys
import logging
import zipfile
from dataclasses import dataclass, field

# suppress androguard debug spam
logging.getLogger("androguard").setLevel(logging.ERROR)
logging.getLogger("androguard.core").setLevel(logging.ERROR)
try:
    from loguru import logger as _loguru
    _loguru.disable("androguard")
except ImportError:
    pass

from androguard.core.apk import APK
from androguard.core.dex import DEX


@dataclass
class APKInfo:
    path: str = ""
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: list = field(default_factory=list)
    activities: list = field(default_factory=list)
    services: list = field(default_factory=list)
    receivers: list = field(default_factory=list)
    providers: list = field(default_factory=list)
    exported_components: list = field(default_factory=list)
    intent_filters: list = field(default_factory=list)
    meta_data: dict = field(default_factory=dict)
    files: list = field(default_factory=list)
    dex_strings: list = field(default_factory=list)
    raw_manifest: str = ""
    debuggable: bool = False
    allow_backup: bool = True
    cleartext_traffic: bool = False
    has_network_config: bool = False


def unpack(apk_path, quiet=False):
    """unpack an APK and extract all analyzable content."""
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    def status(msg):
        if not quiet:
            sys.stderr.write(msg)

    info = APKInfo(path=apk_path)
    status(f"  unpacking {os.path.basename(apk_path)}...\n")

    # parse APK with androguard
    a = APK(apk_path)

    # basic info
    info.package = a.get_package() or ""
    info.version_name = a.get_androidversion_name() or ""
    info.version_code = a.get_androidversion_code() or ""
    info.min_sdk = a.get_min_sdk_version() or ""
    info.target_sdk = a.get_target_sdk_version() or ""
    status(f"  package: {info.package}\n")

    # permissions
    info.permissions = list(a.get_permissions())
    status(f"  permissions: {len(info.permissions)}\n")

    # components
    ns = "{http://schemas.android.com/apk/res/android}"
    manifest = a.get_android_manifest_xml()
    app_elem = manifest.find("application") if manifest is not None else None

    # application flags
    if app_elem is not None:
        info.debuggable = app_elem.get(f"{ns}debuggable", "false").lower() == "true"
        info.allow_backup = app_elem.get(f"{ns}allowBackup", "true").lower() != "false"
        info.cleartext_traffic = app_elem.get(f"{ns}usesCleartextTraffic", "false").lower() == "true"
        info.has_network_config = app_elem.get(f"{ns}networkSecurityConfig") is not None

    # activities
    for act_name in a.get_activities():
        exported = "false"
        if app_elem is not None:
            for act_elem in app_elem.findall("activity"):
                if act_elem.get(f"{ns}name") == act_name:
                    exported = act_elem.get(f"{ns}exported", "false")
                    # activities with intent-filters are implicitly exported
                    if exported != "true" and act_elem.findall("intent-filter"):
                        exported = "true"
                    break
        info.activities.append({"name": act_name, "exported": exported})

    # services
    for svc_name in a.get_services():
        exported = "false"
        if app_elem is not None:
            for svc_elem in app_elem.findall("service"):
                if svc_elem.get(f"{ns}name") == svc_name:
                    exported = svc_elem.get(f"{ns}exported", "false")
                    if exported != "true" and svc_elem.findall("intent-filter"):
                        exported = "true"
                    break
        info.services.append({"name": svc_name, "exported": exported})

    # receivers
    for rec_name in a.get_receivers():
        exported = "false"
        if app_elem is not None:
            for rec_elem in app_elem.findall("receiver"):
                if rec_elem.get(f"{ns}name") == rec_name:
                    exported = rec_elem.get(f"{ns}exported", "false")
                    if exported != "true" and rec_elem.findall("intent-filter"):
                        exported = "true"
                    break
        info.receivers.append({"name": rec_name, "exported": exported})

    # providers
    for prov_name in a.get_providers():
        exported = "false"
        if app_elem is not None:
            for prov_elem in app_elem.findall("provider"):
                if prov_elem.get(f"{ns}name") == prov_name:
                    exported = prov_elem.get(f"{ns}exported", "false")
                    break
        info.providers.append({"name": prov_name, "exported": exported})

    # exported components
    for comp_list in [info.activities, info.services, info.receivers, info.providers]:
        for comp in comp_list:
            if comp.get("exported", "false").lower() == "true":
                info.exported_components.append(comp["name"])

    # intent filters
    if app_elem is not None:
        for act_elem in app_elem.findall("activity"):
            act_name = act_elem.get(f"{ns}name", "")
            for intent_filter in act_elem.findall("intent-filter"):
                actions = [a_elem.get(f"{ns}name", "") for a_elem in intent_filter.findall("action")]
                categories = [c_elem.get(f"{ns}name", "") for c_elem in intent_filter.findall("category")]
                data_elems = []
                for d_elem in intent_filter.findall("data"):
                    scheme = d_elem.get(f"{ns}scheme", "")
                    host = d_elem.get(f"{ns}host", "")
                    if scheme or host:
                        data_elems.append(f"{scheme}://{host}" if scheme else host)
                info.intent_filters.append({
                    "activity": act_name,
                    "actions": actions,
                    "categories": categories,
                    "data": data_elems,
                })

    # meta-data
    if app_elem is not None:
        for meta in app_elem.findall("meta-data"):
            name = meta.get(f"{ns}name", "")
            value = meta.get(f"{ns}value", "")
            if name:
                info.meta_data[name] = value

    # generate raw manifest text for pattern matching
    from xml.etree.ElementTree import tostring
    if manifest is not None:
        try:
            info.raw_manifest = tostring(manifest, encoding="unicode")
        except Exception:
            info.raw_manifest = ""

    # file list
    try:
        with zipfile.ZipFile(apk_path) as zf:
            info.files = zf.namelist()
    except Exception:
        info.files = []

    # DEX string extraction via androguard
    status("  extracting DEX strings...\n")
    try:
        with zipfile.ZipFile(apk_path) as zf:
            dex_files = [f for f in info.files if f.endswith(".dex")]
            for dex_name in dex_files:
                dex_data = zf.read(dex_name)
                d = DEX(dex_data)
                for s in d.get_strings():
                    # skip android/java framework noise
                    if s.startswith("Ljava/") or s.startswith("Landroid/") or s.startswith("Ldalvik/"):
                        continue
                    if s.startswith("Lcom/google/android/") or s.startswith("Landroidx/"):
                        continue
                    if len(s) >= 4:
                        info.dex_strings.append(s)
    except Exception as e:
        status(f"  DEX parse error: {e}\n")
        # fallback: raw byte extraction
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for dex_name in [f for f in info.files if f.endswith(".dex")]:
                    data = zf.read(dex_name)
                    for match in re.findall(b'([\x20-\x7e]{6,})', data):
                        info.dex_strings.append(match.decode("ascii", errors="ignore"))
        except Exception:
            pass

    status(f"  found {len(info.dex_strings)} strings, {len(info.exported_components)} exported components\n")
    return info
