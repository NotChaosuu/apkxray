# -*- coding: utf-8 -*-
"""Tests for deep link / intent filter analysis."""

from apkxray.deeplinks import scan, to_findings
from apkxray.unpacker import APKInfo


def _make_info(intent_filters):
    info = APKInfo()
    info.intent_filters = intent_filters
    return info


def test_no_intent_filters_no_findings():
    info = APKInfo()
    assert scan(info) == []


def test_view_required():
    """Intent filters without ACTION_VIEW should not produce a deep link."""
    info = _make_info([{
        "component": "com.target.app.Foo",
        "component_kind": "activity",
        "exported": "true",
        "actions": ["android.intent.action.MAIN"],
        "categories": [],
        "data": [{"scheme": "myapp", "host": "x.com"}],
    }])
    assert scan(info) == []


def test_custom_scheme_medium():
    info = _make_info([{
        "component": "com.target.app.WebActivity",
        "component_kind": "activity",
        "exported": "true",
        "actions": ["android.intent.action.VIEW"],
        "categories": ["android.intent.category.DEFAULT"],
        "data": [{"scheme": "myapp", "host": "open"}],
    }])
    dls = scan(info)
    assert len(dls) == 1
    assert dls[0].severity == "medium"
    assert any("custom scheme" in n for n in dls[0].notes)


def test_wildcard_host_high():
    info = _make_info([{
        "component": "com.target.app.Universal",
        "component_kind": "activity",
        "exported": "true",
        "actions": ["android.intent.action.VIEW"],
        "categories": ["android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"],
        "data": [{"scheme": "https", "host": "*.target.com", "path": "/login"}],
    }])
    dls = scan(info)
    assert len(dls) == 1
    # wildcard + auth path → high
    assert dls[0].severity == "high"


def test_browsable_implies_exported():
    info = _make_info([{
        "component": "com.target.app.X",
        "component_kind": "activity",
        "exported": "false",
        "actions": ["android.intent.action.VIEW"],
        "categories": ["android.intent.category.BROWSABLE"],
        "data": [{"scheme": "https", "host": "target.com"}],
    }])
    dls = scan(info)
    assert dls[0].exported is True


def test_findings_skip_info_severity():
    info = _make_info([{
        "component": "com.target.app.X",
        "component_kind": "activity",
        "exported": "true",
        "actions": ["android.intent.action.VIEW"],
        "categories": [],
        "data": [{"scheme": "https", "host": "static.target.com", "path": "/help"}],
    }])
    dls = scan(info)
    findings = to_findings(dls)
    # info-level findings aren't surfaced to the security report
    assert findings == []
