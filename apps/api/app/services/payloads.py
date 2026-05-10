"""Payload library + encoding service.

Loads category/file pairs from PAYLOAD_DIR (defaults to packages/payloads/)
and serves them via the API. Each payload file is a plain `.txt` where
blank lines and `# comment` lines are dropped from `payload` lists but
preserved in the raw `body` view.

Encodings supported (URL param `encoding`):

  raw       no transform (default)
  url       single application/x-www-form-urlencoded encode
  url2      double-URL encode (the URL-encoded output, encoded again)
  base64    standard base64 of the UTF-8 bytes
  hex       lower-case hex of the UTF-8 bytes
  html      HTML entity escape (text-context safe; matches html.escape)
  unicode   each code point rendered as \\uXXXX (or \\UXXXXXXXX for >0xFFFF)
"""
from __future__ import annotations

import base64
import binascii
import html
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable
from urllib.parse import quote


SUPPORTED_ENCODINGS = ("raw", "url", "url2", "base64", "hex", "html", "unicode")


@dataclass(frozen=True)
class PayloadFile:
    category: str
    name: str
    description: str
    payload_count: int
    raw_lines: int
    path: str


def _payload_dir() -> Path:
    """Resolve PAYLOAD_DIR, defaulting to packages/payloads at the repo root.
    The settings module is intentionally not used here so payloads stay
    drop-in even in environments that don't load .env."""
    explicit = os.getenv("PAYLOAD_DIR")
    if explicit:
        return Path(explicit)
    # apps/api/app/services/payloads.py -> repo root is parents[4]
    return Path(__file__).resolve().parents[4] / "packages" / "payloads"


def _strip_comments(body: str) -> list[str]:
    """Filter the body of a payload file down to actionable lines.
    Empty lines and lines starting with `#` are dropped; everything else
    survives verbatim (whitespace inside a payload is significant)."""
    out: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append(line)
    return out


def _description(body: str) -> str:
    """First `# …` comment in a file becomes its short description."""
    for line in body.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
        if line.startswith("#"):
            return line[1:].strip()
        if line.strip():
            break
    return ""


@lru_cache(maxsize=1)
def _index() -> tuple[Path, dict[tuple[str, str], PayloadFile]]:
    """Walk PAYLOAD_DIR once, build {(category, name): PayloadFile}."""
    root = _payload_dir()
    out: dict[tuple[str, str], PayloadFile] = {}
    if not root.exists():
        return root, out
    for entry in sorted(root.glob("*/*.txt")):
        category = entry.parent.name
        name = entry.stem
        body = entry.read_text(encoding="utf-8")
        payloads = _strip_comments(body)
        out[(category, name)] = PayloadFile(
            category=category,
            name=name,
            description=_description(body),
            payload_count=len(payloads),
            raw_lines=len(body.splitlines()),
            path=str(entry.relative_to(root.parent.parent)),
        )
    return root, out


def reset_cache() -> None:
    """Drop the cached index — useful for tests that monkeypatch PAYLOAD_DIR."""
    _index.cache_clear()


def list_payloads() -> list[PayloadFile]:
    return sorted(_index()[1].values(), key=lambda f: (f.category, f.name))


def categories() -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in _index()[1].values():
        counts[f.category] = counts.get(f.category, 0) + 1
    return dict(sorted(counts.items()))


def get_payload(category: str, name: str) -> tuple[PayloadFile, str, list[str]]:
    """Returns (meta, full body, payload-only lines). 404s via KeyError."""
    if "/" in category or "/" in name or ".." in category or ".." in name:
        raise KeyError("invalid path component")
    info = _index()[1].get((category, name))
    if not info:
        raise KeyError(f"unknown payload: {category}/{name}")
    body = (Path(_index()[0]) / category / f"{name}.txt").read_text(encoding="utf-8")
    return info, body, _strip_comments(body)


# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def _encode_unicode(text: str) -> str:
    """\\uXXXX form. Code points above 0xFFFF use the \\UXXXXXXXX form so
    the output is unambiguous when fed back into a Python-style decoder."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp <= 0xFFFF:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(f"\\U{cp:08x}")
    return "".join(out)


def encode_line(text: str, encoding: str) -> str:
    if encoding == "raw":
        return text
    if encoding == "url":
        return quote(text, safe="")
    if encoding == "url2":
        return quote(quote(text, safe=""), safe="")
    if encoding == "base64":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if encoding == "hex":
        return binascii.hexlify(text.encode("utf-8")).decode("ascii")
    if encoding == "html":
        return html.escape(text, quote=True)
    if encoding == "unicode":
        return _encode_unicode(text)
    raise ValueError(f"unsupported encoding: {encoding}")


def encode_lines(lines: Iterable[str], encoding: str) -> list[str]:
    if encoding not in SUPPORTED_ENCODINGS:
        raise ValueError(f"unsupported encoding: {encoding}")
    return [encode_line(line, encoding) for line in lines]
