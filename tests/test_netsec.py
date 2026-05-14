# -*- coding: utf-8 -*-
"""Tests for network_security_config parsing."""

from apkxray.netsec import scan
from apkxray.unpacker import APKInfo


def _info_with_nsc(xml):
    info = APKInfo()
    info.netsec_xml = xml
    return info


def test_no_xml_no_findings():
    assert scan(APKInfo()) == []


def test_global_cleartext_high():
    xml = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
    </trust-anchors>
  </base-config>
</network-security-config>"""
    findings = scan(_info_with_nsc(xml))
    assert any(f.severity == "high" and "Global cleartext" in f.title for f in findings)


def test_per_domain_cleartext_medium():
    xml = """<?xml version="1.0"?>
<network-security-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">internal.target.com</domain>
  </domain-config>
</network-security-config>"""
    findings = scan(_info_with_nsc(xml))
    assert any(f.severity == "medium" and "Cleartext allowed" in f.title for f in findings)


def test_user_ca_trust_high():
    xml = """<?xml version="1.0"?>
<network-security-config>
  <base-config>
    <trust-anchors>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
</network-security-config>"""
    findings = scan(_info_with_nsc(xml))
    assert any(f.severity == "high" and "User CA" in f.title for f in findings)


def test_malformed_xml_returns_empty():
    findings = scan(_info_with_nsc("<<<bad xml"))
    assert findings == []


def test_missing_pinning_on_sensitive_domain_info():
    xml = """<?xml version="1.0"?>
<network-security-config>
  <domain-config>
    <domain>api.payments.target.com</domain>
  </domain-config>
</network-security-config>"""
    findings = scan(_info_with_nsc(xml))
    assert any(f.severity == "info" and "pinning" in f.title.lower() for f in findings)
