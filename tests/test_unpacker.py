# -*- coding: utf-8 -*-
"""Tests for the bundle-format unwrap path (.xapk / .apkm / .apks)."""

import io
import json
import os
import zipfile

import pytest

from apkxray import unpacker


# tiny "APK-shaped" bytes — not a real APK, just enough to verify extraction
# preserves the bytes we put in.
_FAKE_APK_BYTES = b"PK\x03\x04fake-apk-payload-" + b"x" * 64


def _make_xapk(tmp_path, base_name="com.example.app.apk", manifest=None, splits=None, dest_name="sample.xapk"):
    """Build a synthetic .xapk: manifest.json + one base apk + N splits."""
    path = tmp_path / dest_name
    splits = splits or ["config.en.apk", "config.armeabi_v7a.apk"]
    with zipfile.ZipFile(path, "w") as zf:
        if manifest is not None:
            zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr(base_name, _FAKE_APK_BYTES)
        for s in splits:
            zf.writestr(s, b"split-payload")
    return str(path)


def _make_apkm(tmp_path):
    path = tmp_path / "sample.apkm"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("info.json", json.dumps({"pname": "com.example.app"}))
        zf.writestr("base.apk", _FAKE_APK_BYTES)
        zf.writestr("split_config.en.apk", b"split")
    return str(path)


def _make_apks(tmp_path):
    path = tmp_path / "sample.apks"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("toc.pb", b"\x00\x01\x02")
        zf.writestr("base.apk", _FAKE_APK_BYTES)
        zf.writestr("splits/split_config.en.apk", b"split")
    return str(path)


def test_is_bundle_detects_xapk_by_extension(tmp_path):
    p = _make_xapk(tmp_path, manifest={"package_name": "com.example.app"})
    assert unpacker.is_bundle(p) is True


def test_is_bundle_detects_apkm_by_extension(tmp_path):
    p = _make_apkm(tmp_path)
    assert unpacker.is_bundle(p) is True


def test_is_bundle_detects_apks_by_extension(tmp_path):
    p = _make_apks(tmp_path)
    assert unpacker.is_bundle(p) is True


def test_is_bundle_rejects_plain_apk(tmp_path):
    p = tmp_path / "plain.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("classes.dex", b"dx")
    assert unpacker.is_bundle(str(p)) is False


def test_is_bundle_content_sniff_on_unknown_ext(tmp_path):
    """If the extension is .zip but the contents look like an xapk, detect it."""
    p = tmp_path / "weird.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("manifest.json", "{}")
        zf.writestr("base.apk", _FAKE_APK_BYTES)
    assert unpacker.is_bundle(str(p)) is True


def test_pick_base_prefers_literal_base_apk():
    names = ["config.en.apk", "base.apk", "config.armeabi_v7a.apk"]
    assert unpacker._pick_base_apk(names, None) == "base.apk"


def test_pick_base_uses_manifest_package_name():
    names = ["com.reddit.frontpage.apk", "config.en.apk"]
    assert unpacker._pick_base_apk(names, "com.reddit.frontpage") == "com.reddit.frontpage.apk"


def test_pick_base_skips_split_prefixes_when_no_hint():
    names = ["config.en.apk", "split_arm64.apk", "the_real_one.apk"]
    assert unpacker._pick_base_apk(names, None) == "the_real_one.apk"


def test_pick_base_returns_none_when_no_apks():
    assert unpacker._pick_base_apk(["manifest.json", "icon.png"], None) is None


def test_extract_bundle_writes_base_apk_to_tempdir(tmp_path):
    p = _make_xapk(tmp_path, manifest={"package_name": "com.example.app"})

    def _noop(_):
        pass

    extracted, tmpdir, manifest, splits = unpacker._extract_bundle(p, _noop)
    try:
        assert os.path.isfile(extracted)
        with open(extracted, "rb") as fh:
            assert fh.read() == _FAKE_APK_BYTES
        assert manifest["package_name"] == "com.example.app"
        assert len(splits) == 2
        assert os.path.dirname(extracted) == tmpdir
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_extract_bundle_raises_when_no_base_apk(tmp_path):
    p = tmp_path / "broken.xapk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("manifest.json", "{}")
        zf.writestr("icon.png", b"\x89PNG\r\n")

    def _noop(_):
        pass

    with pytest.raises(RuntimeError, match="no base APK"):
        unpacker._extract_bundle(str(p), _noop)


def test_bundle_format_label():
    assert unpacker._bundle_format("foo.xapk") == "xapk"
    assert unpacker._bundle_format("foo.XAPK") == "xapk"
    assert unpacker._bundle_format("foo.apkm") == "apkm"
    assert unpacker._bundle_format("foo.apks") == "apks"
    assert unpacker._bundle_format("foo.zip") == "bundle"


def test_cleanup_removes_bundle_tmpdir(tmp_path):
    info = unpacker.APKInfo(path=str(tmp_path / "x.apk"))
    fake_tmp = tmp_path / "apkxray-bundle-xxx"
    fake_tmp.mkdir()
    (fake_tmp / "base.apk").write_bytes(b"x")
    info._bundle_tmpdir = str(fake_tmp)

    unpacker.cleanup(info)
    assert not fake_tmp.exists()
