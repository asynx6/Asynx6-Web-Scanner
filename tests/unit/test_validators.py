"""Tests for core.validators."""

from __future__ import annotations

import pytest

from asynx6.core.validators import (
    extract_domain,
    is_high_entropy_secret,
    is_internal_ip,
    is_junk_secret,
    mask_secret,
    normalize_url,
    safe_filename,
    shannon_entropy,
)


class TestNormalizeUrl:
    def test_adds_http_when_missing(self):
        assert normalize_url("example.com") == "http://example.com"

    def test_preserves_https(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_preserves_http(self):
        assert normalize_url("http://example.com") == "http://example.com"


class TestExtractDomain:
    def test_strips_scheme_and_path(self):
        assert extract_domain("https://example.com/x") == "example.com"

    def test_strips_port(self):
        assert extract_domain("http://example.com:8080/") == "example.com"


class TestIsInternalIp:
    @pytest.mark.parametrize("ip", ["10.0.0.1", "172.16.5.5", "192.168.1.1"])
    def test_private(self, ip: str):
        assert is_internal_ip(ip)

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "172.15.255.255"])
    def test_public(self, ip: str):
        assert not is_internal_ip(ip)


class TestIsJunkSecret:
    @pytest.mark.parametrize("v", ["init", "reset", "getElementById",
                                    "createElement"])
    def test_junk(self, v: str):
        assert is_junk_secret(v)

    @pytest.mark.parametrize("v", ["AKIAEXAMPLE0000000000",
                                    "sk_test_PLACEHOLDER000000000000",
                                    "ghp_PLACEHOLDER0000000000000000000000"])
    def test_real(self, v: str):
        assert not is_junk_secret(v)


class TestMaskSecret:
    def test_short(self):
        assert mask_secret("abc") == "*******"

    def test_long(self):
        assert mask_secret("abcdefghijklmnop") == "abcd****mnop"


class TestEntropy:
    def test_empty(self):
        assert shannon_entropy("") == 0.0

    def test_high_entropy_random(self):
        # 16 distinct characters, all different
        assert shannon_entropy("aB3$kL9!mN2@pQ7&xY") > 3.5
        # Pure random long string is much higher
        assert shannon_entropy("aZbY3$kL9!mN2@pQ7&xY9wV0eR8tU") > 4.0

    def test_low_entropy_repeat(self):
        assert shannon_entropy("aaaaaa") < 1.0


class TestIsHighEntropySecret:
    def test_random_token(self):
        assert is_high_entropy_secret("aZbY3$kL9!mN2@pQ7&xY9wV0eR8tU")

    def test_short_or_low_entropy(self):
        assert not is_high_entropy_secret("aaaa")
        assert not is_high_entropy_secret("abcdef")


class TestSafeFilename:
    def test_basic(self):
        assert safe_filename("https://example.com/path/file.txt") \
            == "https___example_com_path_file_txt"

    def test_empty(self):
        assert safe_filename("") == "index.html"