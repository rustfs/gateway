#!/usr/bin/env bash
# a-asm-0018: a second hot configuration load or a missing real pipeline stage is a violation.
# One ArcSwap load at request entry keeps hot configuration coherent for the whole request.
set -euo pipefail

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SOURCE_ROOT="${ROOT_DIR}/crates/gateway/src"
ALLOWLIST="${ROOT_DIR}/scripts/config_load_allowlist.txt"
RUNTIME_EVIDENCE="${ROOT_DIR}/crates/gateway/tests/service_config.rs"

fail() {
    printf 'check_config_load_once: %s\n' "$1" >&2
    exit 1
}

[[ -d "$SOURCE_ROOT" ]] || fail 'gateway source tree is missing'
[[ -f "${SOURCE_ROOT}/config.rs" ]] || fail 'the hot-configuration store is missing'
[[ -f "$ALLOWLIST" ]] || fail 'scripts/config_load_allowlist.txt is missing'
[[ -f "$RUNTIME_EVIDENCE" ]] || fail 'c-lim-0005 runtime evidence is missing'

# rcu also exposes a current snapshot; only assembly, update, and final-drop sites may use it.
# Every source line naming load, load_full or rcu is a ledger entry `path | enclosing fn | line`,
# compared as a multiset. A line number is not part of it: an edit elsewhere in the file moves a
# load without changing what it reads or where it runs (gateway#707, gateway#727). A new load, an
# edited load line, a load moved into another function, or a repeat of a listed one still fails.
python3 - "$ROOT_DIR" "$ALLOWLIST" <<'PY'
from collections import Counter
from pathlib import Path
import re
import sys

root, allowlist = Path(sys.argv[1]), Path(sys.argv[2])
load = re.compile(r"(\.|::)(load|load_full|rcu)([^A-Za-z0-9_]|$)")
ident = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
whitespace = re.compile(r"\s*")
raw_string = re.compile(r'[bc]?r(#*)"')


def enclosing_functions(text, offsets):
    """Name of the innermost `fn` whose body holds each offset; braces in comments, strings and
    char literals do not count, so a test-local `impl` above an assertion does not claim it."""
    pending_offsets = sorted(offsets)
    owners, stack, pending, depth, i = {}, [], None, 0, 0
    while True:
        while pending_offsets and pending_offsets[0] <= i:
            owners[pending_offsets.pop(0)] = stack[-1][0] if stack else "<no fn>"
        if not pending_offsets or i >= len(text):
            return owners
        c = text[i]
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            nesting, i = 1, i + 2
            while i < len(text) and nesting:
                if text.startswith("/*", i):
                    nesting, i = nesting + 1, i + 2
                elif text.startswith("*/", i):
                    nesting, i = nesting - 1, i + 2
                else:
                    i += 1
        elif match := raw_string.match(text, i):
            close = '"' + match.group(1)
            end = text.find(close, match.end())
            i = len(text) if end < 0 else end + len(close)
        elif c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
        elif c == "'":
            if text.startswith("\\", i + 1):
                end = text.find("'", i + 3)
                i = len(text) if end < 0 else end + 1
            elif text.startswith("'", i + 2):
                i += 3
            else:
                i += 1  # a lifetime
        elif word := ident.match(text, i):
            i = word.end()
            if word.group() == "fn":
                name = ident.match(text, whitespace.match(text, i).end())
                if name and name.start() > i:
                    pending = (name.group(), depth)
        else:
            if c == "{":
                if pending and pending[1] == depth:
                    stack.append(pending)
                    pending = None
                depth += 1
            elif c == "}":
                depth -= 1
                if stack and stack[-1][1] == depth:
                    stack.pop()
            elif c == ";" and pending and pending[1] == depth:
                pending = None  # a bodiless trait method
            i += 1


actual = Counter()
for path in sorted((root / "crates/gateway/src").rglob("*.rs")):
    text = path.read_text(encoding="utf-8")
    hits, offset = [], 0
    for line in text.splitlines(keepends=True):
        if match := load.search(line):
            hits.append((offset + match.start(), line.strip()))
        offset += len(line)
    if not hits:
        continue
    owners = enclosing_functions(text, [start for start, _ in hits])
    relative = path.relative_to(root).as_posix()
    actual.update(f"{relative} | {owners[start]} | {line}" for start, line in hits)

expected = Counter()
for number, line in enumerate(allowlist.read_text(encoding="utf-8").splitlines(), 1):
    entry = line.strip()
    if not entry or entry.startswith("#"):
        continue
    if len(entry.split(" | ", 2)) != 3:
        raise SystemExit(
            f"check_config_load_once: scripts/config_load_allowlist.txt:{number} is not `path | enclosing fn | line`: {entry}"
        )
    expected[entry] += 1

if not actual:
    raise SystemExit("check_config_load_once: no hot-configuration load exists")
if actual != expected:
    lines = ["check_config_load_once: the hot-configuration load ledger drifted"]
    for sign, heading, drift in (
        ("+", "unlisted (a new load, an edited load line, or a load moved into this fn):", actual - expected),
        ("-", "listed but absent (a removed load, an edited load line, or a load moved out of this fn):", expected - actual),
    ):
        if drift:
            lines.append(f"  {heading}")
            lines.extend(f"  {sign} {entry}" for entry in sorted(drift.elements()))
    lines.append("  A listed load moved within its function never drifts; update the allowlist only for a reviewed load.")
    raise SystemExit("\n".join(lines))
for entry_fn in ("call", "call_monomorphic"):
    if expected[f"crates/gateway/src/service.rs | {entry_fn} | let snapshot = self.inner.config.load_full();"] != 1:
        raise SystemExit("check_config_load_once: each request entry must allowlist exactly one assembly snapshot load")
PY

# Every write to the one ConfigStore is an rcu except the single complete replacement. A settings
# update and a registry update that each load, then store, can overwrite each other; no test can
# force that interleaving deterministically, so the write primitive itself is what is checked.
python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
# Receivers holding the store: Inner.config, ServiceBuilder.config, ConfigHandle.store; plus UFCS.
writes = re.compile(r"(?:\b(?:config|store)\s*\.\s*|\bArcSwap(?:Any)?\s*::\s*)(store|swap|compare_and_swap|rcu)\s*\(")
found = {}
for path in sorted((root / "crates/gateway/src").rglob("*.rs")):
    relative = path.relative_to(root).as_posix()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("//"):
            continue
        for match in writes.finditer(line):
            key = (relative, match.group(1))
            found[key] = found.get(key, 0) + 1
expected = {
    ("crates/gateway/src/builder.rs", "rcu"): 1,
    ("crates/gateway/src/config.rs", "rcu"): 1,
    ("crates/gateway/src/service/update.rs", "rcu"): 2,
    ("crates/gateway/src/service/update.rs", "store"): 1,
}
if found != expected:
    raise SystemExit(
        "check_config_load_once: every ConfigStore write except the one complete replacement must be an rcu, "
        f"so concurrent partial updates cannot overwrite each other; expected {sorted(expected.items())}, "
        f"found {sorted(found.items())}"
    )
PY

stages="$(grep -oE '\.(wire|targeted|routed|governed|meta_auth|route_authorized|guarded|decoded|authorized)\(' \
    "${SOURCE_ROOT}/service.rs" | tr -d '.(')"
expected_stages="$(printf '%s\n' wire targeted routed governed meta_auth route_authorized guarded decoded authorized)"
[[ "$stages" == "$expected_stages" ]] \
    || fail 'the real S3Service path no longer consumes the snapshot through all ten stages in order'

python3 - "${SOURCE_ROOT}/service.rs" "${SOURCE_ROOT}/request_config.rs" <<'PY'
from pathlib import Path
import sys

service = Path(sys.argv[1]).read_text(encoding="utf-8")
request_config = Path(sys.argv[2]).read_text(encoding="utf-8")
capture = """        let snapshot = self.inner.config.load_full();
        let runtime = snapshot.runtime();
"""
if service.count(capture) != 2:
    raise SystemExit("check_config_load_once: dynamic and monomorphic request entries must each capture one owned assembly snapshot")
handoff = """        self.call_with_mode(request, mode, Arc::clone(&snapshot.config), runtime)
            .await
"""
if service.count(handoff) != 2:
    raise SystemExit("check_config_load_once: request settings and middleware must come from the same entry snapshot")
capture = """        let request_cancellation = request.extensions().get::<tokio::sync::watch::Receiver<bool>>().cloned();
        let config = RequestConfig::enter(config).with_request_cancellation(request_cancellation);
"""
if service.count(capture) != 1:
    raise SystemExit("check_config_load_once: shared request entry does not carry cancellation beside its captured configuration")
for fragment in (
    "request_cancellation: Option<tokio::sync::watch::Receiver<bool>>,",
    "self.request_cancellation = request_cancellation;",
    "request_cancellation: self.request_cancellation,",
):
    if request_config.count(fragment) != 1:
        raise SystemExit("check_config_load_once: request cancellation does not cross every typed snapshot stage")
PY

python3 - "$RUNTIME_EVIDENCE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
signature = "async fn c_lim_0005_hot_update_does_not_tear_an_inflight_request() {"
if text.count(signature) != 1:
    raise SystemExit("check_config_load_once: c-lim-0005 active runtime evidence is missing or duplicated")

lines = text.splitlines()
index = lines.index(signature)
attributes = []
cursor = index - 1
while cursor >= 0 and lines[cursor].startswith("#["):
    attributes.append(lines[cursor])
    cursor -= 1
if attributes != ["#[tokio::test]"]:
    raise SystemExit("check_config_load_once: c-lim-0005 must be one unconditional tokio test")
if cursor < 0 or "c-lim-0005" not in lines[cursor]:
    raise SystemExit("check_config_load_once: c-lim-0005 runtime evidence lost its case identity")

end_marker = "\n}\n\n/// Regression: reconfiguring a builder"
start = text.index(signature)
end = text.find(end_marker, start)
if end < 0:
    raise SystemExit("check_config_load_once: c-lim-0005 runtime evidence has no bounded function body")
body = text[start:end]
required = (
    "wired().config(ServiceConfig::new(8))",
    "UpdatingFilter::new(handle.clone(), ServiceConfig::new(32))",
    "assert_eq!(first.status(), http::StatusCode::PAYLOAD_TOO_LARGE);",
    "assert_eq!(second.status(), http::StatusCode::OK);",
)
for fragment in required:
    if body.count(fragment) != 1:
        raise SystemExit(f"check_config_load_once: c-lim-0005 runtime evidence drifted at {fragment!r}")
if "#[cfg" in body:
    raise SystemExit("check_config_load_once: c-lim-0005 runtime evidence is conditionally disabled")
PY

printf 'OK: c-lim-0005 observes one settings and middleware snapshot per request; c-lim-0041 rejects later reloads\n'
