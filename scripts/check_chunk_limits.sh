#!/usr/bin/env bash
set -euo pipefail

# WHAT: Binds c-lim-0042 to an exact header rejection and to an instrumented peak-RSS bound.
# WHY: A bounded ingest window is not evidence that the assembled request path stays resident-memory bounded.
# HOW TO EXEMPT: There is no exemption; both executable directions and the RSS instrument control are required.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HTTP_EVIDENCE="${ROOT}/crates/http/tests/ingest_chunk_rules.rs"
RSS_EVIDENCE="${ROOT}/crates/http/tests/ingest_chunk_rules.rs"

fail() {
    printf 'check_chunk_limits: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
[[ -f "$HTTP_EVIDENCE" ]] || fail 'c-lim-0042 header-rejection evidence is missing'
[[ -f "$RSS_EVIDENCE" ]] || fail 'c-lim-0042 peak-RSS evidence is missing'

python3 - "$HTTP_EVIDENCE" "$RSS_EVIDENCE" <<'PYEOF'
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"check_chunk_limits: {message}")


def rust_code(text: str) -> str:
    out = list(text)
    index = 0
    block_depth = 0
    while index < len(text):
        if block_depth:
            if text.startswith("/*", index):
                out[index:index + 2] = "  "
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                out[index:index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if text[index] != "\n":
                    out[index] = " "
                index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            for cursor in range(index, end):
                out[cursor] = " "
            index = end
            continue
        if text.startswith("/*", index):
            out[index:index + 2] = "  "
            block_depth = 1
            index += 2
            continue
        prefix = None
        for candidate in ("br", "rb", "r", "b"):
            if text.startswith(candidate, index):
                quote = index + len(candidate)
                if quote < len(text) and text[quote] in ('"', "'"):
                    prefix = candidate
                    break
        quote_at = index + len(prefix) if prefix is not None else index
        if quote_at < len(text) and text[quote_at] in ('"', "'"):
            quote = text[quote_at]
            if quote == "'" and prefix is None:
                lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", text[index:])
                lifetime_end = index + len(lifetime.group(0)) if lifetime else index
                if lifetime and (lifetime_end >= len(text) or text[lifetime_end] != "'"):
                    index = lifetime_end
                    continue
            cursor = quote_at + 1
            while cursor < len(text):
                if text[cursor] == "\\":
                    cursor += 2
                    continue
                if text[cursor] == quote:
                    cursor += 1
                    break
                cursor += 1
            else:
                fail("Rust evidence contains an unterminated literal")
            for masked in range(index, cursor):
                if text[masked] != "\n":
                    out[masked] = " "
            index = cursor
            continue
        index += 1
    if block_depth:
        fail("Rust evidence contains an unterminated block comment")
    return "".join(out)


def function_body(code: str, name: str) -> str:
    marker = f"fn {name}("
    if code.count(marker) != 1:
        fail(f"{name} is missing or duplicated")
    start = code.index(marker)
    brace = code.find("{", start)
    if brace < 0:
        fail(f"{name} has no body")
    depth = 0
    for cursor in range(brace, len(code)):
        if code[cursor] == "{":
            depth += 1
        elif code[cursor] == "}":
            depth -= 1
            if depth == 0:
                return code[brace:cursor + 1]
    fail(f"{name} has an unterminated body")


http_text = Path(sys.argv[1]).read_text()
http_code = rust_code(http_text)
rss_text = Path(sys.argv[2]).read_text()
rss_code = rust_code(rss_text)

header_name = "c_ing_0021_a_four_gigabyte_chunk_is_refused_at_the_header_without_reading_a_data_byte"
if http_code.count(f"fn {header_name}()") != 1 or "c-lim-0042 / c-ing-0021" not in http_text:
    fail("c-lim-0042 header-rejection identity is missing or duplicated")
header_body = function_body(http_code, header_name)
for token in (
    "0xffff_ffff",
    "err.bytes_before_error(), 0",
    "ChunkReject::ChunkSizeTooLarge",
    "pipeline.decoded_bytes(), 0",
    "pipeline.window_bytes() <= 64 * 1024",
):
    if token not in header_body:
        fail(f"c-lim-0042 header-rejection evidence lost {token!r}")

rss_name = "c_lim_0042_four_gibibyte_chunk_peak_rss_stays_below_eight_mibibytes"
rss_body = function_body(rss_code, rss_name)
for token in (
    "measure_peak_rss(PeakMode::Control)",
    "measure_peak_rss(PeakMode::Attack)",
    "measure_peak_rss(PeakMode::Ballast)",
    "ballast.saturating_sub(control) >= RSS_HEADROOM_BYTES",
    "attack.saturating_sub(control) < RSS_HEADROOM_BYTES",
):
    if token not in rss_body:
        fail(f"c-lim-0042 peak-RSS evidence lost {token!r}")

probe_body = function_body(rss_code, "run_peak_probe")
for token in (
    "FOUR_GIB_CHUNK_HEADER.to_vec()",
    "ChunkReject::ChunkSizeTooLarge",
    "err.bytes_before_error(), 0",
    "std::hint::black_box",
):
    if token not in probe_body:
        fail(f"c-lim-0042 peak-RSS probe lost {token!r}")

measure_body = function_body(rss_code, "measure_peak_rss")
for token in (
    "std::process::Command::new",
    "output.status.success()",
    "parse_peak_rss(&String::from_utf8_lossy(&output.stderr))",
):
    if token not in measure_body:
        fail(f"c-lim-0042 RSS instrument lost {token!r}")
if rss_text.count('"/usr/bin/time"') != 1:
    fail("c-lim-0042 RSS instrument no longer uses exactly one OS peak-RSS observer")
if "const RSS_HEADROOM_BYTES: u64 = 8 * 1024 * 1024" not in rss_code:
    fail("c-lim-0042 peak-RSS ceiling is not exactly eight MiB")
for token in ("strip_prefix", "strip_suffix", "checked_mul"):
    if token not in rss_code:
        fail(f"c-lim-0042 RSS parser lost {token!r}")

print("OK: c-lim-0042 rejects a four-GiB chunk at its header and measures less than eight MiB peak-RSS growth")
PYEOF
