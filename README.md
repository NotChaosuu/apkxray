# apkxray

**X-ray any Android APK in one command.** No apktool, no jadx, no Java install — just `pip install` and go. Finds hardcoded secrets, scores security risk A–F, flags exported components, extracts endpoints, and kicks out a Markdown + JSON report fit for HackerOne / Bugcrowd submission.

```
$ apkxray target.apk

   ┌─┐┌─┐┬┌─ ─ ┬─┐┌─┐┬ ┬
   ├─┤├─┘├┴┐ x ├┬┘├─┤└┬┘
   ┴ ┴┴  ┴ ┴ ─ ┴└─┴ ┴ ┴  v0.1.0
  x-ray your APK

  target: target.apk

──────────────────────────────────────────────────────────
  APK X-Ray Report
──────────────────────────────────────────────────────────

  Package:    com.example.banking
  Version:    3.2.1 (42)
  SDK:        min=23 target=33
  Files:      847
  Strings:    12,340

  Risk:       F (92/100)
  Findings:   8 security issues, 3 secrets, 47 endpoints
              1 critical, 3 high

  Secrets Found

    CRITICAL  Firebase API Key
    AIzaSyD...kE8xQ...

    HIGH      Hardcoded Password
    password = "admin123"

    HIGH      JWT Token
    eyJhbGci...

  Security Issues

    CRITICAL  App is debuggable
    HIGH      Cleartext traffic allowed
    HIGH      Exported content provider
    MEDIUM    Backup enabled

  Endpoints (47)
    https://api.example.com/v2/auth/login
    https://api.example.com/v2/user/profile
    https://staging.example.com/debug/...
    ... +44 more

──────────────────────────────────────────────────────────

  report: ./apkxray_output/com_example_banking_xray.md
  data:   ./apkxray_output/com_example_banking_xray.json
```

## Install

```bash
pip install git+https://github.com/NotChaosuu/apkxray.git
```

Python 3.9+. One dependency (`androguard`). Works on Linux, macOS, Windows.

## Usage

```bash
# basic scan
apkxray app.apk

# everything in detail
apkxray app.apk -v

# JSON to stdout, no disk writes — great for piping
apkxray app.apk --json --no-save | jq '.secrets[] | select(.severity=="critical")'

# CI mode: fail build on critical/high findings
apkxray app.apk -q --no-save --exit-code --min-severity high

# custom output directory
apkxray app.apk -o ./reports
```

### Flags

| Flag | What it does |
|---|---|
| `-v, --verbose` | Show every finding with detail + full endpoint list |
| `-q, --quiet` | Suppress banner and progress lines |
| `--json` | JSON to stdout only (implies `-q`) |
| `--no-save` | Don't write markdown/json reports to disk |
| `--min-severity LEVEL` | Only show findings at or above `critical \| high \| medium \| low \| info` |
| `--exit-code` | Exit non-zero if any critical/high found (CI-friendly) |
| `-o DIR` | Output directory (default `./apkxray_output/`) |

## What it finds

**Secrets** — 30+ patterns, tuned to cut false positives:
AWS access keys, Google API keys, Firebase URLs/keys, RSA/EC private keys, GitHub tokens, Slack tokens & webhooks, Stripe live/test keys, Twilio, SendGrid, Mailgun, Telegram bot tokens, Discord tokens, Mapbox tokens, JWTs, Bearer tokens, Basic Auth, hardcoded passwords, hardcoded API keys/secrets, S3 buckets, internal IPs, localhost URLs, staging/dev URLs, SQL statements, content provider URIs.

**Security misconfigs:**
- `android:debuggable=true` — anyone can attach a debugger
- `android:allowBackup=true` — app data extractable via `adb backup`
- Cleartext HTTP traffic allowed (MITM risk)
- Missing network security config
- Exported activities / services / receivers / providers (attack surface)
- Dangerous permissions + suspicious combinations (e.g. `READ_SMS + INTERNET` → OTP interception)
- Stale `minSdkVersion` (missing modern security defaults)
- API keys sitting in `AndroidManifest.xml` meta-data
- Deep links / custom URL schemes

**Endpoints:** `/api/`, `/v1/`, `/graphql/`, `/auth/` etc extracted from DEX bytecode. Noise URLs (schema.org, shortlinks, OAuth scopes, stock-image hosts) are filtered out — what you see is what you can probe.

**Risk score:** weighted 0–100, graded A (clean) to F (burning). Computed from every finding so the score moves with real severity, not just count.

## Output

Every scan writes two files to `./apkxray_output/`:

| File | Use it for |
|---|---|
| `<package>_xray.md` | Markdown report — paste into HackerOne / Bugcrowd |
| `<package>_xray.json` | Structured data — feed into automation, dashboards, diffing |

Skip file-writing with `--no-save`.

## For bug bounty

Point it at any APK pulled from a program's mobile target. The quickest wins:
- Hardcoded API keys in DEX strings → access backend without auth
- Firebase URLs → check for open Firebase databases (`<url>/.json`)
- Staging / internal URLs → often dev environments with weaker auth
- Exported activities → launch internal screens via `adb shell am start`
- Content providers → read app data over `content://` URIs
- `debuggable=true` on a production build → attach JDB, dump heap

## How it works

1. **Unpack** — androguard parses the binary `AndroidManifest.xml` (no apktool needed)
2. **Extract DEX strings** — every readable string from every `classes*.dex`, framework strings filtered out
3. **Scan secrets** — 30+ regexes, deduplicated, false-positives trimmed
4. **Parse security flags** — debuggable, backup, cleartext, SDK versions, network security config
5. **Analyze components** — activities/services/receivers/providers, `exported` flag + implicit export via `<intent-filter>`
6. **Score risk** — weighted severity sum, grade A–F
7. **Write reports** — Markdown for humans, JSON for machines

## How it compares

| | apkleaks | MobSF | **apkxray** |
|---|---|---|---|
| Install | `pip` (needs jadx) | Docker + 2 GB + web UI | `pip`, zero external deps |
| Secret scanning | ✅ | ✅ | ✅ (30+ patterns, dedup, noise-filtered) |
| Manifest security | ❌ | ✅ | ✅ |
| Risk scoring | ❌ | ✅ | ✅ (A–F) |
| CI-friendly (`--exit-code`, `--json`) | partial | awkward | ✅ |
| Time to first report | ~20s | minutes | **~5s** |
| Offline | ✅ | ✅ | ✅ |

**When to use MobSF instead:** you need dynamic analysis, malware detection, full decompilation, or a team dashboard.
**When to use apkxray:** you want fast static triage from the command line, in CI, or as a first pass before hitting MobSF.

## Part of the Chaosuu security toolkit

- [tlsprint](https://github.com/NotChaosuu/tlsprint) — TLS JA3/JA4 fingerprint analyzer
- [authmap](https://github.com/NotChaosuu/authmap) — auth flow mapper + vuln scanner
- **apkxray** — APK security analyzer (you are here)

## License

MIT

## Author

**Chaosuu** — [Telegram](https://t.me/chaosuudev) · [GitHub](https://github.com/NotChaosuu)
