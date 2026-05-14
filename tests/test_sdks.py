# -*- coding: utf-8 -*-
"""Tests for SDK fingerprinting."""

from apkxray.sdks import scan
from apkxray.unpacker import APKInfo


def test_firebase_detected_via_class_prefix():
    info = APKInfo()
    info.dex_strings = ["Lcom/google/firebase/database/FirebaseDatabase;"]
    hits = scan(info)
    names = [h.name for h in hits]
    assert any("Firebase" in n for n in names)


def test_firebase_high_confidence_when_two_signals():
    info = APKInfo()
    info.dex_strings = [
        "Lcom/google/firebase/database/FirebaseDatabase;",
        "https://my-app-default-rtdb.firebaseio.com",
    ]
    hits = scan(info)
    firebase = next(h for h in hits if "Firebase" in h.name)
    assert firebase.confidence == "high"


def test_firebase_api_key_extracted():
    info = APKInfo()
    info.dex_strings = [
        "Lcom/google/firebase/FirebaseApp;",
        "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567",
    ]
    hits = scan(info)
    firebase = next((h for h in hits if "Firebase" in h.name), None)
    assert firebase is not None
    assert firebase.api_key == "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567"


def test_onesignal_from_manifest():
    info = APKInfo()
    info.meta_data = {"onesignal_app_id": "12345678-1234-1234-1234-123456789012"}
    hits = scan(info)
    osi = next((h for h in hits if "OneSignal" in h.name), None)
    assert osi is not None
    # API key is extracted from manifest value
    assert "12345678" in osi.api_key


def test_branch_io_via_manifest_key():
    info = APKInfo()
    info.meta_data = {"io.branch.sdk.BranchKey": "key_live_abc123def456ghi789jkl012mno345pq"}
    hits = scan(info)
    branch = next((h for h in hits if "Branch.io" in h.name), None)
    assert branch is not None
    assert branch.api_key.startswith("key_live_")


def test_stripe_via_pk_live_token():
    info = APKInfo()
    info.dex_strings = [
        "Lcom/stripe/android/PaymentSession;",
        "pk_live_51HABCDEFGabcdefghijklmnopqrstuvwxyz0123456789",
    ]
    hits = scan(info)
    stripe = next((h for h in hits if "Stripe" in h.name), None)
    assert stripe is not None
    assert stripe.api_key.startswith("pk_live_")
    assert stripe.severity == "high"


def test_no_false_positive_on_empty_info():
    info = APKInfo()
    hits = scan(info)
    assert hits == []


def test_okhttp_info_only():
    info = APKInfo()
    info.dex_strings = ["Lokhttp3/OkHttpClient;"]
    hits = scan(info)
    okhttp = next((h for h in hits if "OkHttp" == h.name), None)
    assert okhttp is not None
    assert okhttp.severity == "info"
