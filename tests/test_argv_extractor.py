"""Argv parser used by the ROE guard to feed port / method / rps to the
engine. Plain-function tests; no DB."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "apps" / "api"))

from app.services.argv_extractor import extract, effective_argv  # noqa: E402


# ----- Ports ----------------------------------------------------------------

@pytest.mark.parametrize("argv,expected", [
    (["-p", "80"], {80}),
    (["-p", "80,443,8080"], {80, 443, 8080}),
    (["--port=80"], {80}),
    (["--ports", "80,443"], {80, 443}),
    (["-port", "8000-8005"], {8000, 8001, 8002, 8003, 8004, 8005}),
    # Non-port flags untouched
    (["-v", "-d", "example.com"], set()),
])
def test_explicit_ports(argv, expected):
    assert extract(argv).ports == expected


def test_port_range_too_wide_marks_broad_not_ports():
    s = extract(["-p", "1-65535"])
    assert s.ports == set()
    assert s.broad_port_scan is True


def test_top_ports_flag_marks_broad_without_listing_ports():
    s = extract(["nmap", "--top-ports", "1000", "example.com"])
    assert s.ports == set()
    assert s.broad_port_scan is True


def test_short_top_ports_flag():
    s = extract(["naabu", "-top-ports", "100"])
    assert s.broad_port_scan is True


def test_explicit_dash_dash_p_all_ports():
    s = extract(["nmap", "-p-", "example.com"])
    assert s.broad_port_scan is True


def test_invalid_port_value_silently_ignored():
    """A typo like `-p http` shouldn't crash the parser."""
    s = extract(["-p", "http"])
    assert s.ports == set()
    assert s.broad_port_scan is False


# ----- HTTP methods --------------------------------------------------------

@pytest.mark.parametrize("argv,expected", [
    (["-X", "DELETE"], {"DELETE"}),
    (["-X", "delete"], {"DELETE"}),  # upper-cased to match engine policy form
    (["--method=POST"], {"POST"}),
    (["-method", "GET,POST"], {"GET", "POST"}),
    (["-X", "TRACE", "-X", "OPTIONS"], {"TRACE", "OPTIONS"}),
])
def test_methods(argv, expected):
    assert extract(argv).methods == expected


# ----- Rate-limit ---------------------------------------------------------

@pytest.mark.parametrize("argv,expected", [
    (["-rate-limit", "5"], 5.0),
    (["--rate-limit=10"], 10.0),
    (["-rl", "20"], 20.0),
    (["-rate", "100"], 100.0),
    (["--rate", "0.5"], 0.5),
])
def test_rate_limit(argv, expected):
    assert extract(argv).rps == pytest.approx(expected)


def test_invalid_rate_silently_ignored():
    assert extract(["-rate-limit", "fast"]).rps is None


# ----- Mixed argv ---------------------------------------------------------

def test_mixed_flags_produce_full_signal_set():
    s = extract([
        "httpx", "-silent", "-ports", "80,443", "-rate-limit", "5",
        "-method", "GET,POST",
    ])
    assert s.ports == {80, 443}
    assert s.methods == {"GET", "POST"}
    assert s.rps == 5.0
    assert s.broad_port_scan is False


def test_no_flags_means_empty_signals():
    s = extract(["subfinder", "-d", "example.com"])
    assert s.is_empty()


def test_flag_value_then_flag_doesnt_swallow_next_flag():
    """`-p -X DELETE` shouldn't pull `-X` into the port value or swallow
    the method flag — both should still be detected."""
    s = extract(["-p", "-X", "DELETE"])
    # `-p` had no value (next token is a flag); methods still parsed
    assert s.ports == set()
    assert s.methods == {"DELETE"}


# ----- effective_argv (resolves the step's argv_replace / argv_extra) -----

def test_effective_argv_passthrough_with_no_step():
    assert effective_argv(["nmap", "-p", "80"], None) == ["nmap", "-p", "80"]


def test_argv_replace_overrides_entirely():
    assert effective_argv(["nmap"], {"argv_replace": ["nmap", "-p", "22"]}) == ["nmap", "-p", "22"]


def test_argv_extra_appends_to_default():
    assert effective_argv(
        ["nmap", "example.com"],
        {"argv_extra": ["-p", "22"]},
    ) == ["nmap", "example.com", "-p", "22"]


def test_argv_extra_appends_after_replace():
    """Replace then extra — operators wire both fields to express
    'use a different base, then add some flags on top'."""
    assert effective_argv(
        ["nmap", "default"],
        {"argv_replace": ["nmap"], "argv_extra": ["-p", "22"]},
    ) == ["nmap", "-p", "22"]
