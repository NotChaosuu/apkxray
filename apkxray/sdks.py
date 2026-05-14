# -*- coding: utf-8 -*- | src: chaosuu | t.me/chaosuudev
"""
SDK fingerprinting. Walks the APK's class namespace + manifest meta-data
and identifies third-party SDKs the app embeds. Each SDK detection carries
an attack-surface hint so a bug-bounty hunter knows what to test next.

Detection signals:
  - smali class path prefix (e.g. Lcom/onesignal/ or Lio/branch/)
  - characteristic strings in DEX
  - manifest <meta-data> keys / values
  - well-known asset file names

A match is high-confidence when 2+ signals coincide; otherwise medium.
"""

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .unpacker import APKInfo


@dataclass
class SDKHit:
    name: str
    severity: str           # critical / high / medium / low / info
    confidence: str         # high / medium
    attack_surface: str     # one-line hint for what to probe
    api_key: str = ""       # extracted API key/ID when available
    signals: list = field(default_factory=list)   # which signals fired


# Each entry:
#   name             : display name
#   class_prefixes   : list of Java package prefixes (with / separators, no L/;)
#   string_markers   : list of strings to grep DEX for
#   manifest_keys    : list of <meta-data> keys we'd see when the SDK is integrated
#   key_extract_re   : optional regex (vs DEX strings) that yields the SDK's API key
#   severity         : default severity when matched
#   attack_surface   : one-liner shown in the report
_SDK_DB = [
    {
        "name": "Firebase / Google Mobile Services",
        "class_prefixes": ["com/google/firebase/", "com/google/android/gms/measurement/"],
        "string_markers": ["firebase_database_url", "google_app_id", "firebaseio.com",
                           "googleapis.com/identitytoolkit", "FirebaseInstanceId"],
        "manifest_keys": ["com.google.android.gms.version", "firebase_database_url",
                          "google_app_id", "firebase_messaging_auto_init_enabled"],
        "key_extract_re": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        "severity": "high",
        "attack_surface": "Open RW on Firebase RTDB / Firestore — visit <db>.firebaseio.com/.json to test",
    },
    {
        "name": "Crashlytics",
        "class_prefixes": ["com/crashlytics/", "com/google/firebase/crashlytics/"],
        "string_markers": ["com.crashlytics.android.beta", "io.fabric.ApiKey", "crashlytics.com"],
        "manifest_keys": ["io.fabric.ApiKey", "com.crashlytics.RequireBuildId",
                          "com.google.firebase.crashlytics.unity.version"],
        "key_extract_re": None,
        "severity": "low",
        "attack_surface": "Leaks stack traces; rarely exploitable but useful for recon",
    },
    {
        "name": "OneSignal",
        "class_prefixes": ["com/onesignal/"],
        "string_markers": ["onesignal.com", "OneSignalDbHelper", "ONESIGNAL_APP_ID"],
        "manifest_keys": ["onesignal_app_id", "onesignal_google_project_number"],
        "key_extract_re": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        "severity": "medium",
        "attack_surface": "App ID leaked → push notification abuse / spoofing if REST API key also leaks",
    },
    {
        "name": "Branch.io (deep links)",
        "class_prefixes": ["io/branch/"],
        "string_markers": ["api.branch.io", "BranchSDK", "branch_key"],
        "manifest_keys": ["io.branch.sdk.BranchKey", "io.branch.sdk.TestMode",
                          "io.branch.sdk.BranchKey.test"],
        "key_extract_re": re.compile(r"key_(?:live|test)_[a-zA-Z0-9]{32}"),
        "severity": "high",
        "attack_surface": "Branch key gives deep-link hijack + analytics access — test in Branch dashboard",
    },
    {
        "name": "Adjust",
        "class_prefixes": ["com/adjust/sdk/"],
        "string_markers": ["app.adjust.com", "AdjustConfig", "AdjustReferrerReceiver"],
        "manifest_keys": ["com.adjust.preinstall.MetaDataReader"],
        "key_extract_re": re.compile(r"\b[a-z0-9]{12}\b"),  # adjust app tokens — noisy, low conf
        "severity": "medium",
        "attack_surface": "Adjust app token → can attribute attacker installs / spoof events",
    },
    {
        "name": "AppsFlyer",
        "class_prefixes": ["com/appsflyer/"],
        "string_markers": ["appsflyersdk.com", "AppsFlyerLib", "AF_PRELOADED"],
        "manifest_keys": ["AppsFlyerDevKey", "AF_PRE_INSTALL_NAME"],
        "key_extract_re": re.compile(r"AppsFlyerDevKey[^A-Za-z0-9]*[\"']([A-Za-z0-9]{16,})"),
        "severity": "medium",
        "attack_surface": "Dev key → attribution / install-event spoofing in AppsFlyer dashboard",
    },
    {
        "name": "Sentry",
        "class_prefixes": ["io/sentry/"],
        "string_markers": ["sentry.io/api/", "@sentry/android", "sentry-dsn"],
        "manifest_keys": ["io.sentry.dsn", "io.sentry.environment", "io.sentry.sample-rate"],
        "key_extract_re": re.compile(r"https?://[a-f0-9]+@(?:o\d+\.ingest\.)?sentry\.io/\d+"),
        "severity": "medium",
        "attack_surface": "Sentry DSN gives event-injection access → flood / fake-report abuse",
    },
    {
        "name": "Bugsnag",
        "class_prefixes": ["com/bugsnag/"],
        "string_markers": ["bugsnag.com", "BugsnagApiKey"],
        "manifest_keys": ["com.bugsnag.android.API_KEY"],
        "key_extract_re": re.compile(r"\b[a-f0-9]{32}\b"),
        "severity": "medium",
        "attack_surface": "API key allows event injection in the Bugsnag dashboard",
    },
    {
        "name": "Mixpanel",
        "class_prefixes": ["com/mixpanel/android/"],
        "string_markers": ["api.mixpanel.com", "MixpanelAPI", "mp_lib"],
        "manifest_keys": [],
        "key_extract_re": re.compile(r"\b[a-f0-9]{32}\b"),
        "severity": "low",
        "attack_surface": "Project token → analytics event spoofing",
    },
    {
        "name": "Amplitude",
        "class_prefixes": ["com/amplitude/"],
        "string_markers": ["api.amplitude.com", "AmplitudeClient"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "low",
        "attack_surface": "API key → event injection / cohort spoofing",
    },
    {
        "name": "Segment",
        "class_prefixes": ["com/segment/analytics/"],
        "string_markers": ["api.segment.io", "Segment.io"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "medium",
        "attack_surface": "Write key sends events to every Segment downstream — high impact if leaked",
    },
    {
        "name": "RevenueCat",
        "class_prefixes": ["com/revenuecat/"],
        "string_markers": ["api.revenuecat.com", "PurchasesAPI"],
        "manifest_keys": [],
        "key_extract_re": re.compile(r"appl_[A-Za-z0-9]{32}|goog_[A-Za-z0-9]{32}"),
        "severity": "high",
        "attack_surface": "Public API key — check for missing user-id validation in entitlement endpoints",
    },
    {
        "name": "Stripe",
        "class_prefixes": ["com/stripe/android/"],
        "string_markers": ["api.stripe.com", "Stripe-Version"],
        "manifest_keys": [],
        "key_extract_re": re.compile(r"\bpk_(?:live|test)_[A-Za-z0-9]{24,}"),
        "severity": "high",
        "attack_surface": "Publishable key (pk_*) → check for restricted-key misuse; pk_live=production payments",
    },
    {
        "name": "PayPal",
        "class_prefixes": ["com/paypal/"],
        "string_markers": ["paypal.com/v1/oauth", "paypal-sdk"],
        "manifest_keys": [],
        "key_extract_re": re.compile(r"A[A-Za-z0-9_\-]{79,80}"),  # PayPal client IDs are 80 chars
        "severity": "high",
        "attack_surface": "Client ID may pair with a hardcoded secret elsewhere — grep DEX for matching secret",
    },
    {
        "name": "Facebook SDK",
        "class_prefixes": ["com/facebook/"],
        "string_markers": ["graph.facebook.com", "FacebookSdk", "fb_app_id"],
        "manifest_keys": ["com.facebook.sdk.ApplicationId", "com.facebook.sdk.ClientToken",
                          "com.facebook.sdk.AutoLogAppEventsEnabled"],
        "key_extract_re": re.compile(r"(?:^|[^A-Za-z0-9])(\d{14,17})(?:[^A-Za-z0-9]|$)"),
        "severity": "medium",
        "attack_surface": "FB App ID + Client Token → test login flow / app event injection",
    },
    {
        "name": "Google Mobile Ads (AdMob)",
        "class_prefixes": ["com/google/android/gms/ads/"],
        "string_markers": ["AdMob", "googleads.g.doubleclick.net"],
        "manifest_keys": ["com.google.android.gms.ads.APPLICATION_ID"],
        "key_extract_re": re.compile(r"ca-app-pub-\d{16}~\d{10}"),
        "severity": "low",
        "attack_surface": "App ID extractable; click-fraud testing if rev share is interesting",
    },
    {
        "name": "Google Maps",
        "class_prefixes": ["com/google/android/gms/maps/"],
        "string_markers": ["maps.googleapis.com"],
        "manifest_keys": ["com.google.android.geo.API_KEY", "com.google.android.maps.v2.API_KEY"],
        "key_extract_re": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        "severity": "medium",
        "attack_surface": "If API key isn't restricted by SHA-1 + package, you can burn Maps quota → billing impact",
    },
    {
        "name": "Stripe Identity / Onfido / Persona",
        "class_prefixes": ["com/onfido/android/sdk/", "withpersona/"],
        "string_markers": ["onfido.com", "withpersona.com"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "high",
        "attack_surface": "KYC flow — investigate webhooks + verification-bypass on the backend",
    },
    {
        "name": "Datadog RUM",
        "class_prefixes": ["com/datadog/android/"],
        "string_markers": ["browser-intake-datadoghq.com", "rum-http-intake.logs"],
        "manifest_keys": [],
        "key_extract_re": re.compile(r"\bpub[a-f0-9]{32}\b"),
        "severity": "low",
        "attack_surface": "RUM client token → can flood the customer's Datadog ingestion",
    },
    {
        "name": "New Relic",
        "class_prefixes": ["com/newrelic/agent/android/"],
        "string_markers": ["mobile-collector.newrelic.com"],
        "manifest_keys": [],
        "key_extract_re": re.compile(r"AA[a-f0-9]{40}"),
        "severity": "low",
        "attack_surface": "Mobile token leaked — event injection",
    },
    {
        "name": "Auth0",
        "class_prefixes": ["com/auth0/android/"],
        "string_markers": ["auth0.com", "Auth0AuthenticationAPIClient"],
        "manifest_keys": ["com.auth0.android.auth0.ClientId", "com.auth0.android.auth0.Domain"],
        "key_extract_re": None,
        "severity": "high",
        "attack_surface": "Client ID + domain — check OIDC misconfig / open redirects on the Auth0 tenant",
    },
    {
        "name": "Okta",
        "class_prefixes": ["com/okta/oidc/"],
        "string_markers": [".okta.com", "/idp/idx/"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "high",
        "attack_surface": "Okta tenant exposed — test OIDC flows + look for app-level token bypass",
    },
    {
        "name": "Cognito (AWS Amplify)",
        "class_prefixes": ["com/amazonaws/mobile/auth/", "com/amplifyframework/"],
        "string_markers": ["cognito-identity.amazonaws.com", "cognito-idp.us-"],
        "manifest_keys": [],
        "key_extract_re": re.compile(r"us-[a-z]+-\d:[a-f0-9\-]{36}"),  # identity pool ID
        "severity": "high",
        "attack_surface": "Identity pool ID + region → test for unauthenticated role permissions (classic AWS bb)",
    },
    {
        "name": "Salesforce Marketing Cloud",
        "class_prefixes": ["com/salesforce/marketingcloud/"],
        "string_markers": ["mcsubdomain", "etmc.com"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "medium",
        "attack_surface": "MC subdomain exposed → check push abuse",
    },
    {
        "name": "Realm (DB)",
        "class_prefixes": ["io/realm/"],
        "string_markers": ["realm.io"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "info",
        "attack_surface": "Local Realm DB — root the device + grep for keys; nothing live-server-side",
    },
    {
        "name": "Retrofit",
        "class_prefixes": ["retrofit2/"],
        "string_markers": ["retrofit2.HttpUrl"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "info",
        "attack_surface": "API client — endpoints in @GET/@POST annotations (use --endpoints-only)",
    },
    {
        "name": "OkHttp",
        "class_prefixes": ["okhttp3/"],
        "string_markers": [],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "info",
        "attack_surface": "HTTP client — check for cert-pinning bypass (TrustManager / pinned cert configs)",
    },
    {
        "name": "Kasada client SDK",
        "class_prefixes": ["com/kasada/"],
        "string_markers": ["kpsdk", "kasada.io", "/ips.js"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "info",
        "attack_surface": "Bot-management client embedded — endpoints behind Kasada gating",
    },
    {
        "name": "DataDome client SDK",
        "class_prefixes": ["co/datadome/"],
        "string_markers": ["datadome.co", "DataDomeSDK"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "info",
        "attack_surface": "Bot-management client embedded — endpoints behind DataDome gating",
    },
    {
        "name": "PerimeterX / HUMAN MOBILE SDK",
        "class_prefixes": ["com/perimeterx/", "com/humansecurity/"],
        "string_markers": ["px-client.net", "perimeterx.com"],
        "manifest_keys": [],
        "key_extract_re": None,
        "severity": "info",
        "attack_surface": "Bot-management client embedded — endpoints behind PX gating",
    },
]


def scan(info: APKInfo) -> List[SDKHit]:
    """Run all SDK fingerprints. Each gets one SDKHit per match."""
    hits = []
    # build a haystack of class paths from smali (when apktool ran) + dex strings
    class_haystack = ""
    if info.smali_files:
        # We don't need the full smali text — class names are in the filename path.
        if info.decoded_dir:
            for path in info.smali_files:
                rel = os.path.relpath(path, info.decoded_dir)
                # smali/com/onesignal/Foo.smali → com/onesignal/Foo
                class_haystack += rel.replace(os.sep, "/") + "\n"
    # also fold in DEX strings — they include class refs like Lcom/onesignal/...;
    for s in info.dex_strings:
        if s.startswith("L"):
            class_haystack += s[1:].rstrip(";") + "\n"

    dex_haystack = "\n".join(info.dex_strings[:50000])
    manifest_keys_set = set(info.meta_data.keys())

    for sdk in _SDK_DB:
        signals = []

        # class-prefix match
        for prefix in sdk["class_prefixes"]:
            if prefix in class_haystack:
                signals.append(f"class:{prefix}")
                break

        # string markers
        for marker in sdk["string_markers"]:
            if marker in dex_haystack:
                signals.append(f"string:{marker}")
                break

        # manifest meta-data keys
        for key in sdk["manifest_keys"]:
            if key in manifest_keys_set:
                signals.append(f"manifest:{key}")
                break

        if not signals:
            continue

        # extract API key/ID if pattern provided
        api_key = ""
        if sdk["key_extract_re"]:
            for s in info.dex_strings:
                m = sdk["key_extract_re"].search(s)
                if m:
                    api_key = m.group(0)
                    break
            # also try manifest values
            if not api_key:
                for v in info.meta_data.values():
                    if isinstance(v, str):
                        m = sdk["key_extract_re"].search(v)
                        if m:
                            api_key = m.group(0)
                            break

        confidence = "high" if len(signals) >= 2 else "medium"
        hits.append(SDKHit(
            name=sdk["name"],
            severity=sdk["severity"],
            confidence=confidence,
            attack_surface=sdk["attack_surface"],
            api_key=api_key,
            signals=signals,
        ))

    return hits
