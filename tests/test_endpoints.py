# -*- coding: utf-8 -*-
"""Tests for the endpoint extractor."""

import os
import pytest

from apkxray.endpoints import (
    Endpoint,
    _classify,
    _to_template,
    _looks_like_noise,
    _scan_retrofit_smali,
    group_by_template,
    scan,
)
from apkxray.unpacker import APKInfo


def test_classify_payment_path_not_host():
    # the bug we shipped a fix for — "payatu.com" was classified as payment
    assert _classify("http://payatu.com") == "public"
    assert _classify("https://api.example.com/payment/charge") == "payment"
    assert _classify("https://wallet.example.com/wallet/balance") == "payment"


def test_classify_categories():
    assert _classify("https://api.example.com/v1/auth/login") == "auth"
    assert _classify("https://api.example.com/v1/admin/users") == "admin"
    assert _classify("https://api.example.com/v1/upload") == "upload"
    assert _classify("https://api.example.com/v1/webhook") == "webhook"
    assert _classify("https://api.example.com/graphql") == "graphql"
    assert _classify("wss://realtime.example.com/socket") == "websocket"
    assert _classify("https://media.example.com/static/img.png") == "public"
    assert _classify("https://api.example.com/internal/dev/debug") == "internal"
    assert _classify("https://api.example.com/analytics/track") == "analytics"
    assert _classify("https://cdn.example.com/x.js") == "cdn"
    assert _classify("https://x.cloudfront.net/x.js") == "cdn"


def test_template_extraction():
    # numeric IDs → {id}
    assert _to_template("/api/user/123/profile") == "/api/user/{id}/profile"
    # multiple numeric segments
    assert _to_template("/v1/order/456/item/789") == "/v1/order/{id}/item/{id}"
    # UUIDs
    assert _to_template("/api/session/550e8400-e29b-41d4-a716-446655440000") == "/api/session/{uuid}"
    # SHA-style hashes
    assert _to_template("/api/file/d41d8cd98f00b204e9800998ecf8427e/download") == "/api/file/{hash}/download"
    # emails
    assert _to_template("/api/user/john@example.com") == "/api/user/{email}"
    # already templated → leave alone
    assert _to_template("/api/user/{id}") == "/api/user/{id}"


def test_noise_filter():
    assert _looks_like_noise("https://schemas.android.com/apk/res/android")
    assert _looks_like_noise("https://www.w3.org/2000/svg")
    assert _looks_like_noise("https://www.googleapis.com/auth/userinfo.email")
    assert _looks_like_noise("https://www.example.com/api")
    assert _looks_like_noise("http://hostname/x")
    # legit endpoint — should NOT be flagged
    assert not _looks_like_noise("https://api.target.com/v1/users")


def test_retrofit_annotation_scraping():
    smali = """
.class public abstract Lcom/target/app/api/AuthApi;
.method public abstract login()V
    .annotation runtime Lretrofit2/http/POST;
        value = "/api/v2/auth/login"
    .end annotation
.end method
.method public abstract getProfile()V
    .annotation runtime Lretrofit2/http/GET;
        value = "/api/v2/users/{id}/profile"
    .end annotation
.end method
.method public abstract delete()V
    .annotation runtime Lretrofit2/http/DELETE;
        value = "/api/v2/users/{id}"
    .end annotation
.end method
"""
    eps = _scan_retrofit_smali(smali)
    assert len(eps) == 3
    methods = {e.method for e in eps}
    assert methods == {"POST", "GET", "DELETE"}
    urls = {e.url for e in eps}
    assert "/api/v2/auth/login" in urls
    assert "/api/v2/users/{id}/profile" in urls
    # confidence is high for Retrofit hits
    assert all(e.confidence == "high" for e in eps)
    # auth path correctly classified
    auth = next(e for e in eps if e.url == "/api/v2/auth/login")
    assert auth.category == "auth"


def test_retrofit_handles_path_without_leading_slash():
    smali = """
    .annotation runtime Lretrofit2/http/GET;
        value = "users/me"
    .end annotation
"""
    eps = _scan_retrofit_smali(smali)
    assert len(eps) == 1
    assert eps[0].url == "/users/me"


def test_group_by_template_dedupes():
    eps = [
        Endpoint(url="/api/user/123", method="GET", template="/api/user/{id}", category="public"),
        Endpoint(url="/api/user/456", method="GET", template="/api/user/{id}", category="public"),
        Endpoint(url="/api/user/789", method="GET", template="/api/user/{id}", category="public"),
        Endpoint(url="/api/order/1", method="POST", template="/api/order/{id}", category="public"),
    ]
    groups = group_by_template(eps)
    assert len(groups) == 2
    user_group = next(g for g in groups if g["template"] == "/api/user/{id}" and g["method"] == "GET")
    assert user_group["count"] == 3
    assert len(user_group["samples"]) == 3


def test_scan_empty_apkinfo():
    """scan() on an empty APKInfo should not crash and should return []."""
    info = APKInfo()
    result = scan(info)
    assert result == []


def test_scan_uses_dex_strings_when_no_apktool():
    info = APKInfo()
    info.dex_strings = [
        "https://api.target.com/v1/users",
        "/api/v2/auth/login",
        "noise without any URL",
        "https://schemas.android.com/apk/res/android",  # should be filtered
    ]
    result = scan(info)
    urls = {e.url for e in result}
    assert "https://api.target.com/v1/users" in urls
    assert "/api/v2/auth/login" in urls
    # noise filtered
    assert "https://schemas.android.com/apk/res/android" not in urls
