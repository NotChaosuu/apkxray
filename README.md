# apkxray

Static APK triage. Point it at any Android `.apk` (or `.xapk` / `.apkm` / `.apks` bundle from APKPure, APKMirror, or bundletool) and it prints back a risk-graded report covering hardcoded secrets, exported components, deep links, third-party SDKs, and the API endpoints the app talks to. Markdown + JSON output ready to paste into a HackerOne report or pipe into nuclei/ffuf.

```
$ apkxray app.apk

──────────────────────────────────────────────────────────
  APK X-Ray Report
──────────────────────────────────────────────────────────

  Package:    com.example.banking
  Version:    3.2.1 (42)
  SDK:        min=23 target=33
  Files:      847
  Decoded:    apktool → 4218 smali, 31 assets

  Risk:       F (92/100)
  Findings:   12 sec issues, 4 secrets, 47 endpoint templates (213 raw), 6 SDKs
              1 critical, 5 high

  Secrets Found
    CRITICAL  Firebase API Key
    AIzaSyD...kE8xQ...
    HIGH      Hardcoded Password
    password = "admin123"

  SDKs Detected (6)
    HIGH    Firebase / Google Mobile Services
    Open RW on Firebase RTDB / Firestore — visit <db>.firebaseio.com/.json to test
    key:    AIzaSyD...kE8xQ...
    HIGH    Branch.io (deep links)
    Branch key gives deep-link hijack + analytics access — test in Branch dashboard
    key:    key_live_abc...

  Security Issues
    CRITICAL  App is debuggable
    HIGH      Cleartext traffic allowed
    HIGH      Deep link: https://*.example.com/payment
    MEDIUM    Backup enabled

  Endpoints (47 templates, 213 raw)
    AUTH    (3)
      POST   /api/v2/auth/login
      POST   /api/v2/auth/refresh
      DELETE /api/v2/sessions/{uuid}
    PAYMENT (5)
      POST   /api/v2/payment/charge
      GET    /api/v2/payment/methods
    ...
```

## Install

```bash
pip install git+https://github.com/NotChaosuu/apkxray.git
```

Python 3.9+. Required dep: `androguard`. Optional but **strongly recommended**: install [apktool](https://ibotpeaches.github.io/Apktool/install/) on your PATH — that's what unlocks smali-aware endpoint extraction (Retrofit annotation scraping, string concat tracing, asset scanning). Without apktool, you still get the DEX-string fallback, just shallower.

## Usage

```bash
apkxray app.apk                          # full scan
apkxray app.apk -v                       # verbose: everything
apkxray app.apk --endpoints-only         # one endpoint per line, pipe into nuclei/ffuf
apkxray app.apk --json --no-save | jq    # full report to stdout
apkxray app.apk --exit-code --min-severity high   # CI gate
apkxray app.apk --no-apktool             # skip apktool even if installed
apkxray reddit.xapk                      # APKPure bundle — base APK is unwrapped, split APKs ignored
```

Run `apkxray --help` for the full flag list.

## Bundle formats

Most APKs you download from public mirrors aren't plain APKs anymore — they're bundles:

- `.xapk` — APKPure. ZIP of `<package>.apk` + locale/density/ABI splits + `manifest.json`.
- `.apkm` — APKMirror. ZIP of `base.apk` + `split_*.apk` + `info.json`.
- `.apks` — Bundletool output. ZIP of `base.apk` + `splits/*.apk` + `toc.pb`.

apkxray detects all three by extension (or by zip-content sniff for weird filenames) and transparently unwraps the base APK before scanning. Split APKs are ignored — they carry locale strings and architecture-specific native libs, not new code paths. The report header shows the bundle format + how many splits were skipped.

## What it actually pulls out

**Endpoints.** When apktool is on PATH, apkxray reads the decoded smali sources and scrapes Retrofit `@GET/@POST/@PUT/@DELETE/@PATCH` annotations directly — that's the API contract sitting in plain sight inside every interface. It also walks `const-string` instructions with class+method context, scans `res/values/strings.xml`, walks `assets/*` for JSON/HTML/JS/GraphQL config files, and pulls URLs out of `AndroidManifest.xml` meta-data. The results get classified (auth / admin / payment / upload / webhook / graphql / websocket / internal / cdn / analytics / public) and collapsed by template (`/api/user/{id}` instead of 50 separate `/api/user/123` lines).

Without apktool the endpoint pass falls back to DEX strings only. Catches the obvious stuff, misses anything built via string concatenation.

**SDKs.** Fingerprints 25+ third-party SDKs from class-namespace prefixes + DEX strings + manifest meta-data. Each detection comes with an attack-surface hint, and when the SDK ships an API key with a recognizable shape (Firebase `AIza…`, Branch `key_live_…`, Stripe `pk_live_…`, etc), apkxray extracts and prints it. Common targets: Firebase, Crashlytics, OneSignal, Branch, Adjust, AppsFlyer, Sentry, Bugsnag, Mixpanel, Amplitude, Segment, RevenueCat, Stripe, PayPal, Facebook, AdMob, Maps, Auth0, Okta, Cognito.

**Secrets.** 30+ regex patterns tuned to cut false positives — AWS keys, Google API keys, JWTs, Bearer tokens, hardcoded passwords, GitHub tokens, Slack tokens & webhooks, Stripe/Twilio/SendGrid/Mailgun keys, Telegram & Discord bot tokens, Mapbox tokens, SQL statements, content provider URIs, internal IPs, staging URLs.

**Deep links.** For every exported activity/receiver/service with an `<intent-filter>` declaring `ACTION_VIEW`, apkxray maps the scheme/host/path it accepts and flags risky shapes — custom schemes (`myapp://` getting fed to WebViews), wildcard hosts (open-redirect / domain-spoof risk), payment/auth-shaped paths, BROWSABLE activities effectively exported via the browser even when `exported=false`.

**Security misconfigs.** `android:debuggable=true`, `android:allowBackup=true`, cleartext traffic permitted, missing network security config, exported components, dangerous permission combos (`READ_SMS + INTERNET`, `CAMERA + RECORD_AUDIO + INTERNET`, etc.), stale `minSdkVersion`, API keys in manifest meta-data.

**Network security config.** When apktool decodes the APK, apkxray also parses `res/xml/network_security_config.xml` for cleartext exceptions, user-CA trust, debug-overrides shipped in release builds, and missing pin-set declarations on sensitive-looking domains.

## Output

Each scan writes `apkxray_output/<package>_xray.md` and `<package>_xray.json`. The Markdown copy-pastes well into bug bounty reports. The JSON has the full structured data for downstream tooling — every endpoint with its source attribution, every SDK hit with signals + API key, every security finding with severity + category. Use `--no-save` to skip writing, `--endpoints-only` for a clean list piping into other tools.

## For bug bounty

Common quick wins this surfaces:
- Firebase `AIza…` keys → check `<host>.firebaseio.com/.json` for open read/write
- Branch `key_live_…` → log in to Branch dashboard, inspect deep-link config + analytics
- Stripe `pk_live_…` → look for matching restricted-key misuse elsewhere
- Wildcard host on deep links → open redirect into WebView
- Staging/internal URLs left in production builds → softer auth
- Exported activities → `adb shell am start -n com.target/.InternalActivity` to launch directly
- Content providers → `content://...` reads without permission checks

## How it works

1. Parse `AndroidManifest.xml` with androguard.
2. Extract DEX strings with class-prefix noise filtering.
3. If `apktool` is on PATH, shell out to it for a full decode (smali sources + resources + assets + decoded XML configs). Tmpdir gets cleaned up on exit.
4. Run the endpoint scanner against every artifact we have (Retrofit, smali const-strings, assets, resources, manifest meta-data, DEX fallback). Dedupe by `(method, url)`. Compute templates. Classify by path.
5. Run the SDK fingerprinter across class paths + DEX strings + manifest. Extract keys when shape-matchable.
6. Walk intent-filters for deep links; tag risk based on scheme, host wildcards, path keywords.
7. Parse `network_security_config.xml` if present.
8. Roll everything into a weighted A–F risk grade.

## Limitations

- Without apktool, endpoint extraction is limited to what's in the DEX strings table. URLs built via runtime concatenation (`BASE_URL + "/api/v1/" + path`) won't be reconstructed.
- SDK API-key extraction is shape-based — false positives are possible when an SDK's regex collides with an unrelated string. The SDK match itself is usually solid; double-check the key in context before reporting.
- Native libraries (`lib/*/*.so`) aren't scanned for strings yet.
- HTTP/2 / gRPC service definitions in proto files only matched on the literal protocol descriptor — full service introspection isn't implemented.
- For bundles, only the base APK is scanned. Split APKs (locales / ABI / density) aren't analyzed individually — the assumption is that secrets and code live in the base, and splits carry resources. If you hit a target where the bug is hiding in a split, run apkxray against that split directly.

## Extended version

apkxray is the static recon layer. There's a private extended build that does the next step — spins the APK up on an emulator, attaches Frida, takes valid credentials, walks the app authenticated, and runs BOLA / IDOR / auth-shape misconfig probes against the live API. Driven by a local LLM so it makes its own decisions about what to try next. Not open source.

If you want access — bug bounty team, appsec consultancy, or a serious solo hunter — DM on Telegram: [t.me/chaosuudev](https://t.me/chaosuudev).

## License

MIT

## Author

Chaosuu — t.me/chaosuudev. More tools at github.com/NotChaosuu.
