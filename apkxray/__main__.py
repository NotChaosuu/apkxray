#!/usr/bin/env python3
# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
apkxray - x-ray your APK.

  apkxray app.apk
  apkxray app.apk -v --no-apktool
  apkxray app.apk --endpoints-only | jq .
  apkxray app.apk --min-severity high --exit-code    # CI
"""

import argparse
import json
import os
import sys

# force utf-8 on stdout/stderr so box-drawing chars don't blow up on Windows cp1252
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from . import __version__
from .unpacker import unpack, cleanup
from .secrets import scan_secrets
from .analyzer import analyze_permissions, analyze_components, calculate_risk_score, SecurityFinding
from . import endpoints as endpoints_mod
from . import sdks as sdks_mod
from . import deeplinks as deeplinks_mod
from . import netsec as netsec_mod


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _use_color():
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stderr.isatty() and sys.stdout.isatty()


_COLOR = _use_color()
BOLD   = "\033[1m"  if _COLOR else ""
DIM    = "\033[2m"  if _COLOR else ""
RESET  = "\033[0m"  if _COLOR else ""
GREEN  = "\033[92m" if _COLOR else ""
YELLOW = "\033[93m" if _COLOR else ""
RED    = "\033[91m" if _COLOR else ""
CYAN   = "\033[96m" if _COLOR else ""
MAGENTA = "\033[95m" if _COLOR else ""

SEV_COLORS = {
    "critical": RED,
    "high": RED,
    "medium": YELLOW,
    "low": CYAN,
    "info": DIM,
}

BANNER = f"""{BOLD}
   ┌─┐┌─┐┬┌─ ─ ┬─┐┌─┐┬ ┬
   ├─┤├─┘├┴┐ x ├┬┘├─┤└┬┘
   ┴ ┴┴  ┴ ┴ ─ ┴└─┴ ┴ ┴  v{__version__}
{RESET}{DIM}  x-ray your APK{RESET}
"""


def _sev_badge(severity):
    color = SEV_COLORS.get(severity, DIM)
    return f"{color}{BOLD}{severity.upper()}{RESET}"


def _divider(width=58):
    return f"{DIM}{'─' * width}{RESET}"


def _filter_by_severity(items, min_severity):
    if not min_severity:
        return items
    try:
        cutoff = SEVERITY_ORDER.index(min_severity)
    except ValueError:
        return items
    return [x for x in items if SEVERITY_ORDER.index(x.severity) <= cutoff]


def print_results(apk_info, secrets, eps, sec_findings, sdk_hits, risk_score, risk_grade, verbose=False):
    print()
    print(_divider())
    print(f"  {BOLD}APK X-Ray Report{RESET}")
    print(_divider())

    # app info
    print()
    print(f"  Package:    {apk_info.package or 'unknown'}")
    if apk_info.version_name:
        print(f"  Version:    {apk_info.version_name} ({apk_info.version_code})")
    if apk_info.min_sdk:
        print(f"  SDK:        min={apk_info.min_sdk} target={apk_info.target_sdk}")
    if apk_info.bundle_format:
        bundle_label = apk_info.bundle_format.upper()
        split_n = len(apk_info.split_apks)
        print(f"  Bundle:     {bundle_label} ({split_n} split APK{'s' if split_n != 1 else ''} ignored)")
    print(f"  Files:      {len(apk_info.files)}")
    if apk_info.apktool_used:
        print(f"  Decoded:    apktool → {len(apk_info.smali_files)} smali, {len(apk_info.asset_files)} assets")
    else:
        print(f"  Decoded:    androguard (install apktool for full analysis)")

    gc = GREEN if risk_grade in ("A", "B") else YELLOW if risk_grade == "C" else RED
    print()
    print(f"  Risk:       {gc}{BOLD}{risk_grade}{RESET} ({risk_score}/100)")

    crit = sum(1 for f in sec_findings if f.severity == "critical") + \
           sum(1 for s in secrets if s.severity == "critical")
    high = sum(1 for f in sec_findings if f.severity == "high") + \
           sum(1 for s in secrets if s.severity == "high")

    grouped = endpoints_mod.group_by_template(eps)
    print(f"  Findings:   {len(sec_findings)} sec issues, {len(secrets)} secrets, "
          f"{len(grouped)} endpoint templates ({len(eps)} raw), {len(sdk_hits)} SDKs")
    if crit + high > 0:
        if crit:
            print(f"              {RED}{crit} critical{RESET}", end="")
        if high:
            if crit:
                print(",", end="")
            print(f" {YELLOW}{high} high{RESET}", end="")
        print()

    # secrets
    if secrets:
        print()
        print(f"  {BOLD}Secrets Found{RESET}")
        print()
        for sev in SEVERITY_ORDER:
            sev_secrets = [s for s in secrets if s.severity == sev]
            if not sev_secrets:
                continue
            for s in sev_secrets[:10 if not verbose else 50]:
                badge = _sev_badge(s.severity)
                val = s.value[:60] + "..." if len(s.value) > 60 else s.value
                print(f"    {badge}  {s.type}")
                print(f"    {DIM}{val}{RESET}")
                if verbose and s.context:
                    print(f"    {DIM}ctx: {s.context[:80]}{RESET}")
                print()

    # SDKs
    if sdk_hits:
        print(f"  {BOLD}SDKs Detected ({len(sdk_hits)}){RESET}")
        print()
        # sort by severity then name
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for hit in sorted(sdk_hits, key=lambda h: (sev_rank.get(h.severity, 9), h.name)):
            if not verbose and hit.severity == "info":
                continue
            badge = _sev_badge(hit.severity)
            print(f"    {badge}  {hit.name}")
            print(f"    {DIM}{hit.attack_surface}{RESET}")
            if hit.api_key:
                print(f"    {CYAN}key:{RESET} {hit.api_key[:80]}")
            if verbose:
                print(f"    {DIM}signals: {', '.join(hit.signals[:3])}{RESET}")
            print()
        info_count = sum(1 for h in sdk_hits if h.severity == "info")
        if info_count and not verbose:
            print(f"    {DIM}+ {info_count} info-level SDKs (use -v){RESET}")
            print()

    # security findings
    if sec_findings:
        print(f"  {BOLD}Security Issues{RESET}")
        print()
        for sev in SEVERITY_ORDER:
            items = [f for f in sec_findings if f.severity == sev]
            if not items:
                continue
            if not verbose and sev == "info":
                print(f"    {DIM}+ {len(items)} informational findings (use -v){RESET}")
                continue
            for f in items:
                badge = _sev_badge(f.severity)
                print(f"    {badge}  {f.title}")
                if verbose and f.detail:
                    print(f"    {DIM}{f.detail}{RESET}")
            print()

    # endpoints — grouped by template, by category
    if grouped:
        print(f"  {BOLD}Endpoints ({len(grouped)} templates, {len(eps)} raw){RESET}")
        print()
        cat_order = ["auth", "admin", "payment", "upload", "webhook", "graphql",
                     "websocket", "internal", "analytics", "cdn", "public"]
        for cat in cat_order:
            in_cat = [g for g in grouped if g["category"] == cat]
            if not in_cat:
                continue
            in_cat.sort(key=lambda g: (g["method"], g["template"]))
            label = cat.upper()
            print(f"    {CYAN}{label}{RESET}  ({len(in_cat)})")
            for g in (in_cat[:8] if not verbose else in_cat[:50]):
                m = g["method"] or "-"
                tmpl = g["template"]
                if len(tmpl) > 72:
                    tmpl = tmpl[:69] + "..."
                count_note = f" {DIM}x{g['count']}{RESET}" if g["count"] > 1 else ""
                src = g["source"]
                if g["location"]:
                    src = f"{src} @ {g['location']}"
                print(f"      {m:6} {tmpl}{count_note}")
                if verbose:
                    print(f"             {DIM}{src}{RESET}")
            if len(in_cat) > 8 and not verbose:
                print(f"      {DIM}+ {len(in_cat) - 8} more (use -v){RESET}")
            print()

    # permissions summary
    if apk_info.permissions:
        print(f"  {BOLD}Permissions ({len(apk_info.permissions)} total){RESET}")
        print()
        for p in sorted(apk_info.permissions)[:10 if not verbose else 100]:
            short = p.replace("android.permission.", "")
            print(f"    {short}")
        if len(apk_info.permissions) > 10 and not verbose:
            print(f"    {DIM}... +{len(apk_info.permissions) - 10} more{RESET}")
        print()

    print(_divider())
    print()


def save_report(apk_info, secrets, eps, sec_findings, sdk_hits, risk_score, risk_grade, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    src_basename = os.path.basename(apk_info.bundle_source or apk_info.path)
    pkg = apk_info.package or os.path.splitext(src_basename)[0]
    safe_name = pkg.replace(".", "_")
    grouped = endpoints_mod.group_by_template(eps)

    lines = []
    lines.append(f"# APK X-Ray: {pkg}")
    if apk_info.bundle_source:
        lines.append(f"**File:** {os.path.basename(apk_info.bundle_source)} "
                     f"({apk_info.bundle_format.upper()} bundle)  ")
    else:
        lines.append(f"**File:** {os.path.basename(apk_info.path)}  ")
    lines.append(f"**Risk:** {risk_grade} ({risk_score}/100)  ")
    lines.append(f"**Tool:** apkxray v{__version__}  ")
    lines.append("")

    lines.append("## App Info")
    lines.append("| Property | Value |")
    lines.append("|----------|-------|")
    lines.append(f"| Package | {pkg} |")
    lines.append(f"| Version | {apk_info.version_name} ({apk_info.version_code}) |")
    lines.append(f"| Min SDK | {apk_info.min_sdk} |")
    lines.append(f"| Target SDK | {apk_info.target_sdk} |")
    lines.append(f"| Files | {len(apk_info.files)} |")
    lines.append(f"| Permissions | {len(apk_info.permissions)} |")
    lines.append(f"| Decoded via | {'apktool' if apk_info.apktool_used else 'androguard only'} |")
    lines.append("")

    if secrets:
        lines.append("## Secrets")
        lines.append("| Severity | Type | Value |")
        lines.append("|----------|------|-------|")
        for s in secrets:
            val = s.value[:60] + "..." if len(s.value) > 60 else s.value
            lines.append(f"| {s.severity} | {s.type} | `{val}` |")
        lines.append("")

    if sdk_hits:
        lines.append("## SDKs Detected")
        lines.append("| Severity | SDK | Attack Surface | Key/ID |")
        lines.append("|----------|-----|----------------|--------|")
        for h in sdk_hits:
            key_short = (h.api_key[:60] + "...") if len(h.api_key) > 60 else (h.api_key or "")
            lines.append(f"| {h.severity} | {h.name} | {h.attack_surface[:80]} | `{key_short}` |")
        lines.append("")

    if sec_findings:
        lines.append("## Security Issues")
        lines.append("| Severity | Category | Finding | Detail |")
        lines.append("|----------|----------|---------|--------|")
        for f in sec_findings:
            lines.append(f"| {f.severity} | {f.category} | {f.title} | {f.detail[:80]} |")
        lines.append("")

    if grouped:
        lines.append(f"## Endpoints ({len(grouped)} templates, {len(eps)} raw)")
        cat_order = ["auth", "admin", "payment", "upload", "webhook", "graphql",
                     "websocket", "internal", "analytics", "cdn", "public"]
        for cat in cat_order:
            in_cat = [g for g in grouped if g["category"] == cat]
            if not in_cat:
                continue
            in_cat.sort(key=lambda g: (g["method"], g["template"]))
            lines.append(f"### {cat} ({len(in_cat)})")
            lines.append("| Method | Template | Count | Source |")
            lines.append("|--------|----------|-------|--------|")
            for g in in_cat:
                src = g["source"]
                if g["location"]:
                    src = f"{src} @ {g['location']}"
                lines.append(f"| {g['method'] or '-'} | `{g['template']}` | {g['count']} | {src} |")
            lines.append("")

    if apk_info.permissions:
        lines.append(f"## Permissions ({len(apk_info.permissions)})")
        lines.append("```")
        for p in sorted(apk_info.permissions):
            lines.append(p)
        lines.append("```")

    md_path = os.path.join(output_dir, f"{safe_name}_xray.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    json_data = {
        "tool": "apkxray",
        "tool_version": __version__,
        "package": pkg,
        "version": apk_info.version_name,
        "risk_score": risk_score,
        "risk_grade": risk_grade,
        "apktool_used": apk_info.apktool_used,
        "secrets": [{"type": s.type, "value": s.value, "severity": s.severity} for s in secrets],
        "sdks": [{"name": h.name, "severity": h.severity, "confidence": h.confidence,
                  "attack_surface": h.attack_surface, "api_key": h.api_key,
                  "signals": h.signals} for h in sdk_hits],
        "security_issues": [{"title": f.title, "severity": f.severity, "category": f.category,
                             "detail": f.detail} for f in sec_findings],
        "endpoints": [{"method": e.method, "url": e.url, "template": e.template,
                       "category": e.category, "source": e.source,
                       "location": e.location, "confidence": e.confidence} for e in eps],
        "endpoint_templates": grouped,
        "permissions": apk_info.permissions,
        "exported_components": apk_info.exported_components,
    }
    json_path = os.path.join(output_dir, f"{safe_name}_xray.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)

    return md_path, json_path


def main():
    parser = argparse.ArgumentParser(
        prog="apkxray",
        description="X-ray an APK for secrets, SDKs, deep links, endpoints, and security issues.",
    )
    parser.add_argument("apk", help="Path to APK or bundle (.apk / .xapk / .apkm / .apks)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show all findings with details")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress banner and progress messages")
    parser.add_argument("-o", "--output", default="./apkxray_output",
                        help="output directory (default: ./apkxray_output)")
    parser.add_argument("--json", action="store_true",
                        help="emit full JSON report to stdout (implies -q, --no-save)")
    parser.add_argument("--endpoints-only", action="store_true",
                        help="print just the endpoint list (one per line, method+url) for piping into nuclei/ffuf/burp")
    parser.add_argument("--no-save", action="store_true",
                        help="don't write report files to disk")
    parser.add_argument("--no-apktool", action="store_true",
                        help="skip apktool even if it's installed (androguard-only mode)")
    parser.add_argument("--apktool", default=None, metavar="PATH",
                        help="explicit path to apktool binary")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default=None,
                        help="only show findings at or above this severity")
    parser.add_argument("--exit-code", action="store_true",
                        help="exit non-zero if any critical/high findings (for CI)")
    parser.add_argument("--version", action="version", version=f"apkxray {__version__}")

    args = parser.parse_args()

    quiet = args.quiet or args.json or args.endpoints_only

    def status(msg):
        if not quiet:
            sys.stderr.write(msg)

    if not quiet:
        sys.stderr.write(BANNER)
        sys.stderr.write(f"\n  target: {args.apk}\n\n")

    apk_info = unpack(
        args.apk,
        quiet=quiet,
        use_apktool=not args.no_apktool,
        apktool_path=args.apktool,
    )

    try:
        status("  scanning for secrets...\n")
        secrets = scan_secrets(apk_info.dex_strings)

        status("  extracting endpoints...\n")
        eps = endpoints_mod.scan(apk_info)

        status("  fingerprinting SDKs...\n")
        sdk_hits = sdks_mod.scan(apk_info)

        status("  analyzing security...\n")
        sec_findings = []
        sec_findings.extend(analyze_permissions(apk_info.permissions))
        sec_findings.extend(analyze_components(apk_info))

        # deep link analysis
        dls = deeplinks_mod.scan(apk_info)
        for d in deeplinks_mod.to_findings(dls):
            sec_findings.append(SecurityFinding(**d))

        # network security config (only when apktool decoded)
        nsec = netsec_mod.scan(apk_info)
        for d in netsec_mod.to_findings(nsec):
            sec_findings.append(SecurityFinding(**d))

        # SDK hits feed into risk too (severity-weighted)
        risk_inputs = (
            sec_findings
            + [type("F", (), {"severity": s.severity})() for s in secrets]
            + [type("F", (), {"severity": h.severity})() for h in sdk_hits if h.severity != "info"]
        )
        risk_score, risk_grade = calculate_risk_score(risk_inputs)

        # filter views
        shown_secrets = _filter_by_severity(secrets, args.min_severity)
        shown_findings = _filter_by_severity(sec_findings, args.min_severity)
        shown_sdks = _filter_by_severity(sdk_hits, args.min_severity)

        # --endpoints-only mode (clean pipe-able output)
        if args.endpoints_only:
            seen = set()
            for ep in eps:
                line = f"{ep.method or '-'} {ep.url}"
                if line in seen:
                    continue
                seen.add(line)
                print(line)
            return

        # output
        if args.json:
            json_data = {
                "tool": "apkxray",
                "tool_version": __version__,
                "package": apk_info.package,
                "version": apk_info.version_name,
                "risk_score": risk_score,
                "risk_grade": risk_grade,
                "apktool_used": apk_info.apktool_used,
                "secrets": [{"type": s.type, "value": s.value, "severity": s.severity} for s in shown_secrets],
                "sdks": [{"name": h.name, "severity": h.severity, "confidence": h.confidence,
                          "attack_surface": h.attack_surface, "api_key": h.api_key,
                          "signals": h.signals} for h in shown_sdks],
                "security_issues": [{"title": f.title, "severity": f.severity, "category": f.category,
                                     "detail": f.detail} for f in shown_findings],
                "endpoints": [{"method": e.method, "url": e.url, "template": e.template,
                               "category": e.category, "source": e.source,
                               "location": e.location, "confidence": e.confidence} for e in eps],
                "permissions": apk_info.permissions,
                "exported_components": apk_info.exported_components,
            }
            print(json.dumps(json_data, indent=2, ensure_ascii=False))
        else:
            print_results(apk_info, shown_secrets, eps, shown_findings, shown_sdks,
                          risk_score, risk_grade, verbose=args.verbose)

        if not args.no_save and not args.json:
            md_path, json_path = save_report(apk_info, secrets, eps, sec_findings, sdk_hits,
                                             risk_score, risk_grade, args.output)
            if not quiet:
                sys.stderr.write(f"\n  report: {md_path}\n")
                sys.stderr.write(f"  data:   {json_path}\n\n")

        if args.exit_code:
            has_serious = any(f.severity in ("critical", "high") for f in sec_findings) or \
                          any(s.severity in ("critical", "high") for s in secrets) or \
                          any(h.severity in ("critical", "high") for h in sdk_hits)
            if has_serious:
                sys.exit(1)
    finally:
        cleanup(apk_info)


if __name__ == "__main__":
    main()
