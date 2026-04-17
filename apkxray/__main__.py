#!/usr/bin/env python3
# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
apkxray - x-ray your APK for secrets, permissions, and security issues.

Usage:
    apkxray app.apk
    apkxray app.apk -v
    apkxray app.apk --json
    apkxray app.apk -o results/
    apkxray app.apk --min-severity high --exit-code    # CI usage
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
from .unpacker import unpack
from .secrets import scan_secrets, scan_endpoints
from .analyzer import analyze_permissions, analyze_components, calculate_risk_score


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# color handling — disable if not a TTY or NO_COLOR is set
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
    """keep only items at or above min_severity."""
    if not min_severity:
        return items
    try:
        cutoff = SEVERITY_ORDER.index(min_severity)
    except ValueError:
        return items
    return [x for x in items if SEVERITY_ORDER.index(x.severity) <= cutoff]


def print_results(apk_info, secrets, endpoints, sec_findings, risk_score, risk_grade, verbose=False):
    """display results in terminal."""
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
    print(f"  Files:      {len(apk_info.files)}")
    print(f"  Strings:    {len(apk_info.dex_strings)}")

    # risk score
    gc = GREEN if risk_grade in ("A", "B") else YELLOW if risk_grade == "C" else RED
    print()
    print(f"  Risk:       {gc}{BOLD}{risk_grade}{RESET} ({risk_score}/100)")

    # stats
    crit_count = sum(1 for f in sec_findings if f.severity == "critical")
    high_count = sum(1 for f in sec_findings if f.severity == "high")
    crit_secrets = sum(1 for s in secrets if s.severity == "critical")
    high_secrets = sum(1 for s in secrets if s.severity == "high")

    print(f"  Findings:   {len(sec_findings)} security issues, {len(secrets)} secrets, {len(endpoints)} endpoints")
    if crit_count + crit_secrets > 0:
        print(f"              {RED}{crit_count + crit_secrets} critical{RESET}", end="")
        if high_count + high_secrets > 0:
            print(f", {YELLOW}{high_count + high_secrets} high{RESET}", end="")
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

    # security findings
    if sec_findings:
        print(f"  {BOLD}Security Issues{RESET}")
        print()
        for sev in SEVERITY_ORDER:
            sev_findings = [f for f in sec_findings if f.severity == sev]
            if not sev_findings:
                continue
            if not verbose and sev == "info":
                print(f"    {DIM}+ {len(sev_findings)} informational findings (use -v){RESET}")
                continue
            for f in sev_findings:
                badge = _sev_badge(f.severity)
                print(f"    {badge}  {f.title}")
                if verbose and f.detail:
                    print(f"    {DIM}{f.detail}{RESET}")
            print()

    # endpoints
    if endpoints:
        print(f"  {BOLD}Endpoints ({len(endpoints)}){RESET}")
        print()
        show = endpoints[:15] if not verbose else endpoints[:50]
        for ep in show:
            print(f"    {ep}")
        if len(endpoints) > len(show):
            print(f"    {DIM}... +{len(endpoints) - len(show)} more (use -v or check report){RESET}")
        print()

    # permissions summary
    if apk_info.permissions:
        print(f"  {BOLD}Permissions ({len(apk_info.permissions)} total){RESET}")
        print()
        if verbose:
            for p in sorted(apk_info.permissions):
                short = p.replace("android.permission.", "")
                print(f"    {short}")
        else:
            for p in sorted(apk_info.permissions)[:10]:
                short = p.replace("android.permission.", "")
                print(f"    {short}")
            if len(apk_info.permissions) > 10:
                print(f"    {DIM}... +{len(apk_info.permissions) - 10} more{RESET}")
        print()

    print(_divider())
    print()


def save_report(apk_info, secrets, endpoints, sec_findings, risk_score, risk_grade, output_dir):
    """save markdown + json reports."""
    os.makedirs(output_dir, exist_ok=True)
    pkg = apk_info.package or os.path.basename(apk_info.path).replace(".apk", "")
    safe_name = pkg.replace(".", "_")

    # markdown
    lines = []
    lines.append(f"# APK X-Ray: {pkg}")
    lines.append(f"**File:** {os.path.basename(apk_info.path)}  ")
    lines.append(f"**Risk:** {risk_grade} ({risk_score}/100)  ")
    lines.append(f"**Tool:** apkxray v{__version__}  ")
    lines.append("")

    lines.append("## App Info")
    lines.append(f"| Property | Value |")
    lines.append(f"|----------|-------|")
    lines.append(f"| Package | {pkg} |")
    lines.append(f"| Version | {apk_info.version_name} ({apk_info.version_code}) |")
    lines.append(f"| Min SDK | {apk_info.min_sdk} |")
    lines.append(f"| Target SDK | {apk_info.target_sdk} |")
    lines.append(f"| Files | {len(apk_info.files)} |")
    lines.append(f"| Permissions | {len(apk_info.permissions)} |")
    lines.append("")

    if secrets:
        lines.append("## Secrets")
        lines.append(f"| Severity | Type | Value |")
        lines.append(f"|----------|------|-------|")
        for s in secrets:
            val = s.value[:60] + "..." if len(s.value) > 60 else s.value
            lines.append(f"| {s.severity} | {s.type} | `{val}` |")
        lines.append("")

    if sec_findings:
        lines.append("## Security Issues")
        lines.append(f"| Severity | Category | Finding | Detail |")
        lines.append(f"|----------|----------|---------|--------|")
        for f in sec_findings:
            lines.append(f"| {f.severity} | {f.category} | {f.title} | {f.detail[:60]} |")
        lines.append("")

    if endpoints:
        lines.append(f"## Endpoints ({len(endpoints)})")
        lines.append("```")
        for ep in endpoints:
            lines.append(ep)
        lines.append("```")
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

    # json
    json_data = {
        "package": pkg,
        "version": apk_info.version_name,
        "risk_score": risk_score,
        "risk_grade": risk_grade,
        "secrets": [{"type": s.type, "value": s.value, "severity": s.severity} for s in secrets],
        "security_issues": [{"title": f.title, "severity": f.severity, "category": f.category, "detail": f.detail} for f in sec_findings],
        "endpoints": endpoints,
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
        description="X-ray an APK for secrets, permissions, endpoints, and security issues.",
    )
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show all findings with details")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress banner and progress messages")
    parser.add_argument("-o", "--output", default="./apkxray_output",
                        help="output directory for reports (default: ./apkxray_output)")
    parser.add_argument("--json", action="store_true",
                        help="output JSON to stdout only (no pretty report, implies -q)")
    parser.add_argument("--no-save", action="store_true",
                        help="don't write report files to disk")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default=None,
                        help="only show findings at or above this severity")
    parser.add_argument("--exit-code", action="store_true",
                        help="exit with non-zero status if any critical/high findings (for CI)")
    parser.add_argument("--version", action="version", version=f"apkxray {__version__}")

    args = parser.parse_args()

    quiet = args.quiet or args.json

    def status(msg):
        if not quiet:
            sys.stderr.write(msg)

    if not quiet:
        sys.stderr.write(BANNER)
        sys.stderr.write(f"\n  target: {args.apk}\n\n")

    # unpack
    apk_info = unpack(args.apk, quiet=quiet)

    # scan secrets
    status("  scanning for secrets...\n")
    secrets = scan_secrets(apk_info.dex_strings)
    endpoints = scan_endpoints(apk_info.dex_strings)

    # security analysis
    status("  analyzing security...\n")
    sec_findings = []
    sec_findings.extend(analyze_permissions(apk_info.permissions))
    sec_findings.extend(analyze_components(apk_info))

    # risk uses the unfiltered view
    risk_inputs = sec_findings + [
        type("F", (), {"severity": s.severity})() for s in secrets
    ]
    risk_score, risk_grade = calculate_risk_score(risk_inputs)

    # filter views for display (not for risk/report)
    shown_secrets = _filter_by_severity(secrets, args.min_severity)
    shown_findings = _filter_by_severity(sec_findings, args.min_severity)

    # output
    if args.json:
        json_data = {
            "package": apk_info.package,
            "version": apk_info.version_name,
            "risk_score": risk_score,
            "risk_grade": risk_grade,
            "secrets": [{"type": s.type, "value": s.value, "severity": s.severity} for s in shown_secrets],
            "security_issues": [{"title": f.title, "severity": f.severity, "category": f.category, "detail": f.detail} for f in shown_findings],
            "endpoints": endpoints,
            "permissions": apk_info.permissions,
            "exported_components": apk_info.exported_components,
        }
        print(json.dumps(json_data, indent=2))
    else:
        print_results(apk_info, shown_secrets, endpoints, shown_findings, risk_score, risk_grade, verbose=args.verbose)

    # save reports (uses unfiltered data — reports are the source of truth)
    if not args.no_save:
        md_path, json_path = save_report(apk_info, secrets, endpoints, sec_findings, risk_score, risk_grade, args.output)
        if not quiet:
            sys.stderr.write(f"\n  report: {md_path}\n")
            sys.stderr.write(f"  data:   {json_path}\n\n")

    # exit code for CI
    if args.exit_code:
        has_serious = any(f.severity in ("critical", "high") for f in sec_findings) or \
                      any(s.severity in ("critical", "high") for s in secrets)
        if has_serious:
            sys.exit(1)


if __name__ == "__main__":
    main()
