# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
security analysis of APK manifest and configuration.
checks permissions, exported components, backup settings, debuggable flag, etc.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class SecurityFinding:
    title: str = ""
    severity: str = ""     # critical, high, medium, low, info
    category: str = ""     # permission, component, config, crypto, network
    detail: str = ""


# dangerous permissions that indicate high-risk capabilities
DANGEROUS_PERMISSIONS = {
    # location
    "android.permission.ACCESS_FINE_LOCATION": ("Location (precise)", "medium", "App can track exact GPS location"),
    "android.permission.ACCESS_COARSE_LOCATION": ("Location (approximate)", "low", "App can access approximate location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("Background location", "high", "App tracks location even when closed"),
    # camera/mic
    "android.permission.CAMERA": ("Camera access", "medium", "App can use the camera"),
    "android.permission.RECORD_AUDIO": ("Microphone access", "medium", "App can record audio"),
    # contacts/calendar
    "android.permission.READ_CONTACTS": ("Read contacts", "medium", "App can read your contact list"),
    "android.permission.WRITE_CONTACTS": ("Write contacts", "high", "App can modify your contacts"),
    "android.permission.READ_CALENDAR": ("Read calendar", "medium", "App can read calendar events"),
    # phone/sms
    "android.permission.READ_PHONE_STATE": ("Phone state", "medium", "App can read phone number, IMEI, call state"),
    "android.permission.CALL_PHONE": ("Make calls", "high", "App can make phone calls without user interaction"),
    "android.permission.READ_CALL_LOG": ("Read call log", "high", "App can read your call history"),
    "android.permission.SEND_SMS": ("Send SMS", "critical", "App can send SMS messages (premium SMS risk)"),
    "android.permission.READ_SMS": ("Read SMS", "critical", "App can read your text messages"),
    "android.permission.RECEIVE_SMS": ("Receive SMS", "high", "App can intercept incoming SMS"),
    # storage
    "android.permission.READ_EXTERNAL_STORAGE": ("Read storage", "medium", "App can read files on device"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Write storage", "medium", "App can write files to device storage"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("Full storage access", "high", "App has unrestricted storage access"),
    # other
    "android.permission.INSTALL_PACKAGES": ("Install apps", "critical", "App can install other applications"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Request install", "high", "App can request to install other apps"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Overlay permission", "high", "App can draw over other apps (tapjacking risk)"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("Accessibility", "critical", "App can read screen content and simulate input"),
    "android.permission.BIND_DEVICE_ADMIN": ("Device admin", "critical", "App can lock/wipe device"),
    "android.permission.READ_PHONE_NUMBERS": ("Read phone number", "medium", "App can read your phone number"),
    "android.permission.ACCESS_WIFI_STATE": ("WiFi state", "low", "App can see WiFi connection info"),
    "android.permission.CHANGE_WIFI_STATE": ("Change WiFi", "medium", "App can change WiFi settings"),
    "android.permission.BLUETOOTH_CONNECT": ("Bluetooth", "low", "App can connect to Bluetooth devices"),
    "android.permission.POST_NOTIFICATIONS": ("Notifications", "info", "App can show notifications"),
    "android.permission.USE_BIOMETRIC": ("Biometrics", "info", "App uses fingerprint/face auth"),
}

# suspicious permission combinations
SUSPICIOUS_COMBOS = [
    (
        ["android.permission.SEND_SMS", "android.permission.INTERNET"],
        "SMS + Internet", "critical",
        "Can send SMS and transmit data — premium SMS fraud risk"
    ),
    (
        ["android.permission.READ_SMS", "android.permission.INTERNET"],
        "Read SMS + Internet", "critical",
        "Can read SMS and send data out — OTP/2FA interception risk"
    ),
    (
        ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
        "Camera + Mic + Internet", "high",
        "Can capture audio/video and transmit — surveillance capability"
    ),
    (
        ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET", "android.permission.ACCESS_BACKGROUND_LOCATION"],
        "Background location tracking", "high",
        "Can continuously track and transmit location"
    ),
    (
        ["android.permission.READ_CONTACTS", "android.permission.INTERNET"],
        "Contacts + Internet", "medium",
        "Can exfiltrate contact list"
    ),
]


def analyze_permissions(permissions: List[str]) -> List[SecurityFinding]:
    """analyze permissions for security issues."""
    findings = []

    # check individual dangerous permissions
    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            title, severity, detail = DANGEROUS_PERMISSIONS[perm]
            findings.append(SecurityFinding(
                title=f"Dangerous permission: {title}",
                severity=severity,
                category="permission",
                detail=f"{perm} — {detail}",
            ))

    # check suspicious combinations
    perm_set = set(permissions)
    for combo_perms, name, severity, detail in SUSPICIOUS_COMBOS:
        if all(p in perm_set for p in combo_perms):
            findings.append(SecurityFinding(
                title=f"Suspicious combo: {name}",
                severity=severity,
                category="permission",
                detail=detail,
            ))

    # count stats
    dangerous_count = sum(1 for p in permissions if p in DANGEROUS_PERMISSIONS)
    total = len(permissions)
    if dangerous_count > 8:
        findings.append(SecurityFinding(
            title="Excessive dangerous permissions",
            severity="high",
            category="permission",
            detail=f"{dangerous_count} dangerous permissions out of {total} total — app is over-permissioned",
        ))

    return findings


def analyze_components(apk_info) -> List[SecurityFinding]:
    """analyze exported components, intent filters, and manifest config."""
    findings = []

    # exported components without permission protection
    if apk_info.exported_components:
        for comp in apk_info.exported_components:
            findings.append(SecurityFinding(
                title=f"Exported component: {comp.split('.')[-1]}",
                severity="medium",
                category="component",
                detail=f"{comp} is exported and accessible to other apps",
            ))

        if len(apk_info.exported_components) > 5:
            findings.append(SecurityFinding(
                title="Many exported components",
                severity="high",
                category="component",
                detail=f"{len(apk_info.exported_components)} exported components — large attack surface",
            ))

    # deep links / URL schemes
    for intent_filter in apk_info.intent_filters:
        if intent_filter.get("data"):
            for data_uri in intent_filter["data"]:
                if data_uri and "://" in data_uri:
                    findings.append(SecurityFinding(
                        title=f"Deep link: {data_uri}",
                        severity="info",
                        category="component",
                        detail=f"Activity {intent_filter.get('activity', '?')} handles {data_uri}",
                    ))

    # content providers (data exposure risk)
    if apk_info.providers:
        exported_providers = [p for p in apk_info.providers if p.get("exported", "").lower() == "true"]
        if exported_providers:
            for p in exported_providers:
                findings.append(SecurityFinding(
                    title=f"Exported content provider",
                    severity="high",
                    category="component",
                    detail=f"{p['name']} — exported provider can leak app data to other apps",
                ))

    # meta-data checks
    meta = apk_info.meta_data
    if meta:
        # firebase
        for key in meta:
            if "firebase" in key.lower():
                findings.append(SecurityFinding(
                    title=f"Firebase config: {key}",
                    severity="info",
                    category="config",
                    detail=f"Value: {meta[key][:80]}" if meta[key] else "",
                ))
            if "api_key" in key.lower() or "apikey" in key.lower():
                findings.append(SecurityFinding(
                    title=f"API key in manifest: {key}",
                    severity="high",
                    category="config",
                    detail=f"Value: {meta[key][:40]}..." if len(meta.get(key, "")) > 40 else f"Value: {meta.get(key, '')}",
                ))

    # check manifest for insecure settings
    if apk_info.debuggable:
        findings.append(SecurityFinding(
            title="App is debuggable",
            severity="critical",
            category="config",
            detail="android:debuggable=true — anyone can attach a debugger and inspect app data",
        ))

    if apk_info.allow_backup:
        findings.append(SecurityFinding(
            title="Backup enabled",
            severity="medium",
            category="config",
            detail="android:allowBackup=true (or not set) — app data can be extracted via ADB backup",
        ))

    if apk_info.cleartext_traffic:
        findings.append(SecurityFinding(
            title="Cleartext traffic allowed",
            severity="high",
            category="network",
            detail="App allows unencrypted HTTP traffic — MITM risk",
        ))

    if not apk_info.has_network_config:
        findings.append(SecurityFinding(
            title="No network security config",
            severity="medium",
            category="network",
            detail="No custom network security configuration — using platform defaults",
        ))

    # SDK version checks
    if apk_info.min_sdk:
        try:
            min_ver = int(apk_info.min_sdk)
            if min_ver < 21:
                findings.append(SecurityFinding(
                    title=f"Very old minimum SDK: {min_ver}",
                    severity="high",
                    category="config",
                    detail=f"minSdkVersion {min_ver} (Android 4.x) — missing modern security features",
                ))
            elif min_ver < 26:
                findings.append(SecurityFinding(
                    title=f"Old minimum SDK: {min_ver}",
                    severity="medium",
                    category="config",
                    detail=f"minSdkVersion {min_ver} — consider raising for better security defaults",
                ))
        except ValueError:
            pass

    return findings


def calculate_risk_score(findings: List[SecurityFinding]) -> tuple:
    """calculate overall risk score 0-100 from all findings."""
    score = 0
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}

    for f in findings:
        score += weights.get(f.severity, 0)

    score = min(100, score)

    if score >= 75:
        grade = "F"
    elif score >= 55:
        grade = "D"
    elif score >= 35:
        grade = "C"
    elif score >= 15:
        grade = "B"
    else:
        grade = "A"

    return score, grade
