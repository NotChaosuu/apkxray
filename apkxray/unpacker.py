# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
APK unpacker. Uses androguard for AndroidManifest + DEX strings (always),
and optionally shells out to apktool for full decoded resources + smali sources
(huge upgrade for endpoint extraction). apktool is detected automatically;
if not installed, falls back to androguard-only mode.

Also transparently unwraps APKPure/APKMirror/Bundletool bundles:
.xapk, .apkm, .apks — they're all zips containing base.apk + splits.
"""

import os
import re
import sys
import json
import shutil
import logging
import zipfile
import tempfile
import subprocess
from dataclasses import dataclass, field
from typing import Optional

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
    network_security_config_name: str = ""  # value of android:networkSecurityConfig
    # v0.2 additions — populated when apktool is available
    decoded_dir: Optional[str] = None  # path to apktool's decoded output dir
    apktool_used: bool = False
    smali_files: list = field(default_factory=list)  # absolute paths to .smali files
    asset_files: list = field(default_factory=list)  # absolute paths to text-like assets
    resource_strings: list = field(default_factory=list)  # values from res/values/*.xml
    netsec_xml: str = ""  # raw text of network_security_config.xml if present
    # bundle metadata — populated when input was .xapk/.apkm/.apks
    bundle_format: str = ""  # "xapk" | "apkm" | "apks" | ""
    bundle_source: str = ""  # original bundle path (for display)
    split_apks: list = field(default_factory=list)  # names of split apks found in bundle
    _bundle_tmpdir: Optional[str] = None  # tempdir holding the extracted base apk
    # cached smali aggregate (lazy-loaded by endpoints scanner)
    _smali_text_cache: Optional[str] = None


def detect_apktool(override_path: Optional[str] = None) -> Optional[str]:
    """Return path to apktool executable, or None if not found."""
    if override_path and os.path.isfile(override_path):
        return override_path
    return shutil.which("apktool")


# names that indicate a split APK, not the base — these get skipped when
# picking the entry point of a bundle.
_SPLIT_PREFIXES = ("config.", "split_", "split.")


def is_bundle(apk_path: str) -> bool:
    """Return True if the file is an APK bundle (.xapk/.apkm/.apks) rather than
    a plain .apk. Detection is extension-first, then a zip content sniff for
    extensions like .zip or unknown."""
    low = apk_path.lower()
    if low.endswith((".xapk", ".apkm", ".apks")):
        return True
    if low.endswith(".apk"):
        return False
    # unknown extension — peek inside
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    has_meta = any(n in ("manifest.json", "info.json", "toc.pb") for n in names)
    inner_apks = [n for n in names if n.lower().endswith(".apk") and "/" not in n]
    return has_meta and len(inner_apks) >= 1


def _bundle_format(apk_path: str) -> str:
    low = apk_path.lower()
    if low.endswith(".xapk"):
        return "xapk"
    if low.endswith(".apkm"):
        return "apkm"
    if low.endswith(".apks"):
        return "apks"
    return "bundle"


def _pick_base_apk(names, manifest_pkg: Optional[str]) -> Optional[str]:
    """Choose the base APK from a bundle's file list. Priority:
    1. literal base.apk
    2. <package>.apk when manifest told us the package name
    3. first .apk that doesn't look like a split
    """
    top_apks = [n for n in names if n.lower().endswith(".apk") and "/" not in n]
    if not top_apks:
        # some bundlers nest in splits/ — try one level deep
        top_apks = [n for n in names if n.lower().endswith(".apk")]
    for n in top_apks:
        if n.lower() == "base.apk":
            return n
    if manifest_pkg:
        target = f"{manifest_pkg}.apk".lower()
        for n in top_apks:
            if os.path.basename(n).lower() == target:
                return n
    for n in top_apks:
        base = os.path.basename(n).lower()
        if not any(base.startswith(p) for p in _SPLIT_PREFIXES):
            return n
    return top_apks[0] if top_apks else None


def _read_bundle_manifest(zf: zipfile.ZipFile) -> dict:
    """Pull package_name / version info from manifest.json (xapk) or info.json (apkm)."""
    for cand in ("manifest.json", "info.json"):
        try:
            data = zf.read(cand)
        except KeyError:
            continue
        try:
            return json.loads(data.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
    return {}


def _extract_bundle(apk_path: str, status) -> tuple:
    """Extract the base APK from a bundle to a tempdir.
    Returns (extracted_apk_path, tmpdir, manifest_dict, split_apk_names)."""
    tmpdir = tempfile.mkdtemp(prefix="apkxray-bundle-")
    with zipfile.ZipFile(apk_path) as zf:
        names = zf.namelist()
        manifest = _read_bundle_manifest(zf)
        pkg = manifest.get("package_name") or manifest.get("pname")
        base_name = _pick_base_apk(names, pkg)
        if not base_name:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise RuntimeError(f"no base APK found inside bundle {os.path.basename(apk_path)}")
        # extract just the base apk, preserving filename
        target = os.path.join(tmpdir, os.path.basename(base_name))
        with zf.open(base_name) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)
        splits = [n for n in names
                  if n.lower().endswith(".apk") and n != base_name]
    status(f"  bundle: extracted {os.path.basename(base_name)} "
           f"({len(splits)} splits ignored)\n")
    return target, tmpdir, manifest, splits


def unpack(apk_path, quiet=False, use_apktool=True, apktool_path=None):
    """Unpack an APK or APK bundle (.xapk/.apkm/.apks). apktool used when
    available unless use_apktool=False."""
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    def status(msg):
        if not quiet:
            sys.stderr.write(msg)

    # bundle unwrap — happens before everything else so the rest of the
    # pipeline only ever sees a single .apk
    bundle_format = ""
    bundle_source = ""
    bundle_tmpdir = None
    split_apks: list = []
    if is_bundle(apk_path):
        bundle_format = _bundle_format(apk_path)
        bundle_source = apk_path
        status(f"  detected {bundle_format} bundle, unwrapping...\n")
        extracted, bundle_tmpdir, _manifest, split_apks = _extract_bundle(apk_path, status)
        apk_path = extracted

    info = APKInfo(path=apk_path)
    info.bundle_format = bundle_format
    info.bundle_source = bundle_source
    info._bundle_tmpdir = bundle_tmpdir
    info.split_apks = split_apks
    status(f"  unpacking {os.path.basename(apk_path)}...\n")

    a = APK(apk_path)
    info.package = a.get_package() or ""
    info.version_name = a.get_androidversion_name() or ""
    info.version_code = a.get_androidversion_code() or ""
    info.min_sdk = a.get_min_sdk_version() or ""
    info.target_sdk = a.get_target_sdk_version() or ""
    status(f"  package: {info.package}\n")

    info.permissions = list(a.get_permissions())
    status(f"  permissions: {len(info.permissions)}\n")

    ns = "{http://schemas.android.com/apk/res/android}"
    manifest = a.get_android_manifest_xml()
    app_elem = manifest.find("application") if manifest is not None else None

    if app_elem is not None:
        info.debuggable = app_elem.get(f"{ns}debuggable", "false").lower() == "true"
        info.allow_backup = app_elem.get(f"{ns}allowBackup", "true").lower() != "false"
        info.cleartext_traffic = app_elem.get(f"{ns}usesCleartextTraffic", "false").lower() == "true"
        nsc = app_elem.get(f"{ns}networkSecurityConfig")
        info.has_network_config = nsc is not None
        if nsc:
            # androguard returns either the resource name or the resource id
            info.network_security_config_name = str(nsc)

    for act_name in a.get_activities():
        exported = "false"
        if app_elem is not None:
            for act_elem in app_elem.findall("activity"):
                if act_elem.get(f"{ns}name") == act_name:
                    exported = act_elem.get(f"{ns}exported", "false")
                    if exported != "true" and act_elem.findall("intent-filter"):
                        exported = "true"
                    break
        info.activities.append({"name": act_name, "exported": exported})

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

    for prov_name in a.get_providers():
        exported = "false"
        if app_elem is not None:
            for prov_elem in app_elem.findall("provider"):
                if prov_elem.get(f"{ns}name") == prov_name:
                    exported = prov_elem.get(f"{ns}exported", "false")
                    break
        info.providers.append({"name": prov_name, "exported": exported})

    for comp_list in [info.activities, info.services, info.receivers, info.providers]:
        for comp in comp_list:
            if comp.get("exported", "false").lower() == "true":
                info.exported_components.append(comp["name"])

    # intent filters — captured for deep-link analysis
    if app_elem is not None:
        for kind in ("activity", "receiver", "service"):
            for elem in app_elem.findall(kind):
                comp_name = elem.get(f"{ns}name", "")
                exported = elem.get(f"{ns}exported", "false")
                for intent_filter in elem.findall("intent-filter"):
                    actions = [a_elem.get(f"{ns}name", "") for a_elem in intent_filter.findall("action")]
                    categories = [c_elem.get(f"{ns}name", "") for c_elem in intent_filter.findall("category")]
                    data_specs = []
                    for d_elem in intent_filter.findall("data"):
                        data_specs.append({
                            "scheme": d_elem.get(f"{ns}scheme", ""),
                            "host": d_elem.get(f"{ns}host", ""),
                            "port": d_elem.get(f"{ns}port", ""),
                            "path": d_elem.get(f"{ns}path", ""),
                            "pathPrefix": d_elem.get(f"{ns}pathPrefix", ""),
                            "pathPattern": d_elem.get(f"{ns}pathPattern", ""),
                            "mimeType": d_elem.get(f"{ns}mimeType", ""),
                        })
                    if intent_filter.findall("intent-filter") or actions or data_specs:
                        info.intent_filters.append({
                            "component": comp_name,
                            "component_kind": kind,
                            "exported": exported,
                            "actions": actions,
                            "categories": categories,
                            "data": data_specs,
                        })

    if app_elem is not None:
        for meta in app_elem.findall("meta-data"):
            name = meta.get(f"{ns}name", "")
            value = meta.get(f"{ns}value", "")
            if name:
                info.meta_data[name] = value

    from xml.etree.ElementTree import tostring
    if manifest is not None:
        try:
            info.raw_manifest = tostring(manifest, encoding="unicode")
        except Exception:
            info.raw_manifest = ""

    try:
        with zipfile.ZipFile(apk_path) as zf:
            info.files = zf.namelist()
    except Exception:
        info.files = []

    # DEX strings (always — works without apktool)
    status("  extracting DEX strings...\n")
    try:
        with zipfile.ZipFile(apk_path) as zf:
            dex_files = [f for f in info.files if f.endswith(".dex")]
            for dex_name in dex_files:
                dex_data = zf.read(dex_name)
                d = DEX(dex_data)
                for s in d.get_strings():
                    if s.startswith("Ljava/") or s.startswith("Landroid/") or s.startswith("Ldalvik/"):
                        continue
                    if s.startswith("Lcom/google/android/") or s.startswith("Landroidx/"):
                        continue
                    if len(s) >= 4:
                        info.dex_strings.append(s)
    except Exception as e:
        status(f"  DEX parse error: {e}\n")
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for dex_name in [f for f in info.files if f.endswith(".dex")]:
                    data = zf.read(dex_name)
                    for match in re.findall(b'([\x20-\x7e]{6,})', data):
                        info.dex_strings.append(match.decode("ascii", errors="ignore"))
        except Exception:
            pass

    status(f"  found {len(info.dex_strings)} strings, {len(info.exported_components)} exported components\n")

    # apktool — optional deep decode
    apktool_bin = detect_apktool(apktool_path) if use_apktool else None
    if apktool_bin:
        status(f"  decoding with apktool ({apktool_bin})...\n")
        try:
            decoded = _run_apktool(apktool_bin, apk_path, quiet=quiet)
            info.decoded_dir = decoded
            info.apktool_used = True
            _gather_decoded_artifacts(info, decoded, status)
        except Exception as e:
            status(f"  apktool failed: {e} — continuing with androguard-only mode\n")
            info.apktool_used = False
    elif use_apktool:
        status("  apktool not found on PATH — install for full endpoint/SDK analysis\n")
        status("    https://ibotpeaches.github.io/Apktool/install/\n")

    return info


def _run_apktool(apktool_bin: str, apk_path: str, quiet: bool = False) -> str:
    """Run apktool d on the APK. Returns the decoded output directory."""
    out_dir = tempfile.mkdtemp(prefix="apkxray-")
    target_dir = os.path.join(out_dir, "decoded")
    cmd = [apktool_bin, "d", "-f", "-q", "-o", target_dir, apk_path]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            err = (result.stderr or b"").decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"apktool exited {result.returncode}: {err}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("apktool timed out after 300s")
    if not os.path.isdir(target_dir):
        raise RuntimeError(f"apktool didn't produce expected dir: {target_dir}")
    return target_dir


def _gather_decoded_artifacts(info: APKInfo, decoded_dir: str, status):
    """Walk apktool's output and collect smali files, asset paths, resource strings,
    and the network security config XML if present."""
    smali_count = 0
    for root, dirs, files in os.walk(decoded_dir):
        rel_root = os.path.relpath(root, decoded_dir)
        # smali sources
        if rel_root.split(os.sep)[0].startswith("smali"):
            for fn in files:
                if fn.endswith(".smali"):
                    info.smali_files.append(os.path.join(root, fn))
                    smali_count += 1
        # assets — capture text-y file paths only
        elif rel_root.split(os.sep)[0] == "assets":
            for fn in files:
                low = fn.lower()
                if any(low.endswith(ext) for ext in (".json", ".html", ".htm", ".js", ".css", ".xml",
                                                     ".graphql", ".gql", ".proto", ".txt", ".env",
                                                     ".cfg", ".conf", ".ini", ".yaml", ".yml", ".properties")):
                    info.asset_files.append(os.path.join(root, fn))

    # resource strings (res/values/*.xml)
    res_values = os.path.join(decoded_dir, "res", "values")
    if os.path.isdir(res_values):
        for fn in os.listdir(res_values):
            if fn.endswith(".xml"):
                fpath = os.path.join(res_values, fn)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                # crude but effective: pull every <string>...</string> body
                for m in re.finditer(r"<string[^>]*>([^<]+)</string>", text):
                    val = m.group(1).strip()
                    if val:
                        info.resource_strings.append(val)
                # also catch <item>http...</item>
                for m in re.finditer(r"<item[^>]*>(https?://[^<]+)</item>", text):
                    info.resource_strings.append(m.group(1).strip())

    # network security config — try the manifest-declared name first
    nsc_paths = []
    cfg_name = info.network_security_config_name
    if cfg_name:
        # cfg_name is usually like "@xml/network_security_config" or "0x7f..."
        m = re.search(r"@xml/(\w+)", cfg_name)
        if m:
            nsc_paths.append(os.path.join(decoded_dir, "res", "xml", m.group(1) + ".xml"))
    # fall back to the standard locations
    nsc_paths.extend([
        os.path.join(decoded_dir, "res", "xml", "network_security_config.xml"),
        os.path.join(decoded_dir, "res", "xml", "nsc.xml"),
    ])
    for nsc_path in nsc_paths:
        if os.path.isfile(nsc_path):
            try:
                with open(nsc_path, "r", encoding="utf-8", errors="replace") as fh:
                    info.netsec_xml = fh.read()
                break
            except OSError:
                continue

    status(f"  apktool decoded: {smali_count} smali, "
           f"{len(info.asset_files)} text assets, "
           f"{len(info.resource_strings)} resource strings"
           f"{' + netsec_config' if info.netsec_xml else ''}\n")


def get_smali_text(info: APKInfo, max_bytes: int = 50 * 1024 * 1024) -> str:
    """Return concatenated smali content (cached). Capped to avoid runaway memory."""
    if info._smali_text_cache is not None:
        return info._smali_text_cache
    chunks = []
    total = 0
    for f in info.smali_files:
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                data = fh.read()
        except OSError:
            continue
        chunks.append(data)
        total += len(data)
        if total > max_bytes:
            break
    info._smali_text_cache = "\n".join(chunks)
    return info._smali_text_cache


def cleanup(info: APKInfo):
    """Remove apktool's decoded directory and any bundle-extraction tmpdir."""
    if info.decoded_dir and os.path.isdir(info.decoded_dir):
        parent = os.path.dirname(info.decoded_dir)
        try:
            shutil.rmtree(parent, ignore_errors=True)
        except Exception:
            pass
    if info._bundle_tmpdir and os.path.isdir(info._bundle_tmpdir):
        try:
            shutil.rmtree(info._bundle_tmpdir, ignore_errors=True)
        except Exception:
            pass
