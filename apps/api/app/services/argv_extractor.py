"""Argv signal extraction for ROE preflight.

Pulls policy-relevant signals out of a tool's effective argv so the ROE
engine can decide on them at run-creation. The shape we extract:

  - explicit ports (`-p 22`, `--port=22`, `-p 22,443`, `-p 8000-8010`)
  - broad-port-scan intent (`--top-ports 1000`, `-p-`, `--all-ports`)
  - HTTP methods (`-X DELETE`, `--method=POST`)
  - rate limit (`-rate-limit 5`, `-rl 5`, `-rate 5`)

Tier-1 design choices (each documented inline):
  - Port ranges larger than 100 are flagged as "broad" rather than
    expanded (avoids inflating the engine eval set into the thousands).
  - `--top-ports` / `-Pn` / `-p-` are signals without explicit ports;
    the engine evaluates them by probing a representative high-blast-
    radius port (22 / SSH) so a policy that allowlists 80/443 will
    refuse them.
  - Tools without explicit port flags are not gated — there's no signal
    to act on. The operator's allowlist should still cover them at the
    network layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Flags that name a specific port / port list.
PORT_FLAGS = {"-p", "--port", "-port", "-ports", "--ports"}

# Flags that imply a broad scan without naming the ports — we can't list
# the exact ports the tool will hit, so we mark the action as broad and
# probe a representative port at policy-eval time.
TOP_PORT_FLAGS = {"--top-ports", "-top-ports"}
ALL_PORT_FLAGS = {"-p-", "--all-ports"}

# Flag shapes for HTTP methods.
METHOD_FLAGS = {"-X", "--method", "-method", "-m", "--http-method"}

# Rate-limit flags across the common scanners.
RATE_FLAGS = {"-rate-limit", "--rate-limit", "-rl", "-rate", "--rate", "--rate-limit-min"}

# Cap range expansion. A `-p 1-65535` shouldn't blow up into a 65k-entry
# eval set; that's the "broad" case.
MAX_RANGE_EXPANSION = 100

# Conservative probe port — when a tool says "top ports" or "all ports"
# we can't list them all, so we ask the engine "would 22 be allowed?".
# An operator who allowlists only 80/443 will see this deny.
BROAD_PROBE_PORT = 22


@dataclass
class ArgvSignals:
    """Everything the parser found in one tool's argv.

    Each field is independent of every other: a tool that takes
    `-p 80 -X DELETE` produces both ports and methods. The caller
    iterates each and feeds them to the engine separately."""
    ports: set[int] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    rps: float | None = None
    # True when an argv flag implies a broad scan without naming ports
    # (e.g. nmap's `--top-ports 100`, naabu's `-top-ports`, `-p-`).
    broad_port_scan: bool = False

    def is_empty(self) -> bool:
        return (
            not self.ports
            and not self.methods
            and self.rps is None
            and not self.broad_port_scan
        )


def _flag_and_inline(token: str) -> tuple[str, str | None]:
    """Split `--port=80` into ("--port", "80"). Non-flag-style tokens
    return (token, None) and are filtered upstream by callers."""
    if not token.startswith("-"):
        return token, None
    if "=" in token:
        flag, _, value = token.partition("=")
        return flag, value
    return token, None


def _expand_port_value(value: str) -> tuple[set[int], bool]:
    """Parse a port-value token. Returns (ports, broad_signal).

    `broad_signal` is set when a comma-separated component looks like
    a too-wide range to enumerate (e.g. `1-65535`). The caller can
    still combine the explicit ports with the broad flag for evaluation."""
    ports: set[int] = set()
    broad = False
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo_s, hi_s = part.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
                if lo > hi:
                    lo, hi = hi, lo
                if hi - lo > MAX_RANGE_EXPANSION:
                    broad = True
                    continue
                ports.update(range(lo, hi + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 0 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return ports, broad


def extract(argv: list[str]) -> ArgvSignals:
    """Walk argv with one token of lookahead so `-p 80` (two tokens) and
    `-p=80` (one token) both produce port=80."""
    out = ArgvSignals()
    i = 0
    while i < len(argv):
        token = argv[i]
        if not token.startswith("-"):
            i += 1
            continue

        flag, inline = _flag_and_inline(token)

        # Ports — explicit
        if flag in PORT_FLAGS:
            value, consumed_extra = _take_value(argv, i, inline)
            if value is not None:
                ports, broad = _expand_port_value(value)
                out.ports.update(ports)
                if broad:
                    out.broad_port_scan = True
            i += 1 + (1 if consumed_extra else 0)
            continue

        # Ports — broad signals
        if flag in TOP_PORT_FLAGS:
            # `--top-ports 1000` carries a count, not a list of ports. We
            # consume the count token but mark the action as broad.
            _, consumed_extra = _take_value(argv, i, inline)
            out.broad_port_scan = True
            i += 1 + (1 if consumed_extra else 0)
            continue
        if flag in ALL_PORT_FLAGS:
            out.broad_port_scan = True
            i += 1
            continue

        # HTTP methods
        if flag in METHOD_FLAGS:
            value, consumed_extra = _take_value(argv, i, inline)
            if value:
                # Upper-case to match the engine's policy form (which
                # also upper-cases denied method tokens).
                for m in value.split(","):
                    m = m.strip().upper()
                    if m:
                        out.methods.add(m)
            i += 1 + (1 if consumed_extra else 0)
            continue

        # Rate limit
        if flag in RATE_FLAGS:
            value, consumed_extra = _take_value(argv, i, inline)
            if value:
                try:
                    out.rps = float(value)
                except ValueError:
                    pass
            i += 1 + (1 if consumed_extra else 0)
            continue

        i += 1

    return out


def _take_value(argv: list[str], i: int, inline: str | None) -> tuple[str | None, bool]:
    """Read the value for the flag at index `i`. Returns (value, was_next_token).
    If the flag had an inline value (`--port=80`), the next token is not
    consumed. If it didn't, the next token is the value (`-p 80`)."""
    if inline is not None:
        return inline, False
    if i + 1 < len(argv):
        candidate = argv[i + 1]
        # The next token is the value if it's not itself a flag (the
        # common -p VAL case). A flag-looking next token means the
        # current flag had no value at all (the operator wrote `-p -X`).
        if not candidate.startswith("-"):
            return candidate, True
    return None, False


def effective_argv(default_argv: list[str], step: dict[str, Any] | None) -> list[str]:
    """Resolve the argv a step will actually run with.

    Mirrors the runner's argv resolution:
      - `argv_replace` overrides the tool's default entirely.
      - `argv_extra` appends to whatever's left.
    """
    if not step:
        return list(default_argv)
    replace = step.get("argv_replace")
    extra = step.get("argv_extra")
    base = list(replace) if replace else list(default_argv)
    if extra:
        base.extend(extra)
    return base
