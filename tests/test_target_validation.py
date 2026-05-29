from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "apps" / "api"))

from app.services.target_validation import normalize_target  # noqa: E402


def test_domain_normalization_accepts_accidental_url_paste():
    normalized = normalize_target("HTTPS://WWW.Example.COM/path?q=1", "domain")
    assert normalized.type == "domain"
    assert normalized.value == "www.example.com"


def test_url_normalization_adds_https_and_lowercases_host():
    normalized = normalize_target("Api.Example.COM:8443/v1", "url")
    assert normalized.type == "url"
    assert normalized.value == "https://api.example.com:8443/v1"


def test_ip_and_cidr_are_canonicalized():
    assert normalize_target("127.0.0.1", "ip").value == "127.0.0.1"
    assert normalize_target("10.0.0.4/24", "cidr").value == "10.0.0.0/24"


@pytest.mark.parametrize("value,target_type", [
    ("not_a_domain", "domain"),
    ("ftp://example.com", "url"),
    ("999.1.1.1", "ip"),
    ("10.0.0.1/99", "cidr"),
    ("example.com", "banana"),
])
def test_invalid_targets_raise_clean_value_error(value: str, target_type: str):
    with pytest.raises(ValueError):
        normalize_target(value, target_type)
