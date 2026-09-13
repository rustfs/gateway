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

# rcu also exposes a current snapshot; only assembly, update, and final-drop sites may use it.
# Every source line matching the load pattern — test code and comments included — is a site, keyed
# by file, enclosing item path, and whitespace-normalized line text. A line number is not a key: an
# unrelated insertion above an allowed load would move it. Entries and sites are compared as
# multisets, so an entry listed once must match exactly one site; a stale entry (no site) or an
# ambiguous one (a second identical load in the same item) fails instead of admitting a new load.
python3 - "$ROOT_DIR" "$ALLOWLIST" <<'PY'
from collections import Counter
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
allowlist = Path(sys.argv[2])
LOAD = re.compile(r"(?:\.|::)(?:load|load_full|rcu)(?:[^A-Za-z0-9_]|$)")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
NAMED = re.compile(r"\s+([A-Za-z_][A-Za-z0-9_]*)")
RAW_STRING = re.compile(r'b?r(#*)"')
CHAR = re.compile(r"'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]+\}|.)|[^\\'\n])'")
REQUEST_ENTRIES = ("impl S3Service / fn call", "impl S3Service / fn call_monomorphic")
SNAPSHOT = "let snapshot = self.inner.config.load_full();"


def fail(message):
    raise SystemExit(f"check_config_load_once: {message}")


def normalize(text):
    return " ".join(text.split())


def impl_label(header):
    """`impl<T: X> Trait for Type<T> where ...` -> `impl Trait for Type<T>`."""
    header = header.strip()
    if header.startswith("<"):
        depth = 0
        for index, char in enumerate(header):
            depth += {"<": 1, ">": -1}.get(char, 0)
            if depth == 0:
                header = header[index + 1 :]
                break
    header = re.split(r"\bwhere\b", header, maxsplit=1)[0]
    return "impl " + normalize(header)


def item_paths(text):
    """Map each 1-based line to the path of `mod`/`trait`/`impl`/`fn` items enclosing its start.

    Comments, strings and char literals are skipped so their braces do not count. The label only
    names a site; which lines are sites is decided by the plain-text pattern above.
    """
    paths = [None, ""]
    stack = []  # (brace depth inside the item, label)
    pending = None  # (label or None for an impl, bracket nesting, impl header start) awaiting `{`
    depth = nesting = 0
    index, size = 0, len(text)

    def advance_to(end):
        nonlocal index
        for _ in range(text.count("\n", index, end)):
            paths.append(" / ".join(label for _, label in stack))
        index = end

    while index < size:
        char = text[index]
        if char == "\n":
            advance_to(index + 1)
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = size if end < 0 else end
        elif text.startswith("/*", index):
            level, end = 0, index
            while end < size:
                if text.startswith("/*", end):
                    level, end = level + 1, end + 2
                elif text.startswith("*/", end):
                    level, end = level - 1, end + 2
                    if level == 0:
                        break
                else:
                    end += 1
            advance_to(end)
        elif (raw := RAW_STRING.match(text, index)) and (index == 0 or not IDENT.match(text[index - 1])):
            end = text.find('"' + raw.group(1), raw.end())
            advance_to(size if end < 0 else end + 1 + len(raw.group(1)))
        elif char == '"':
            end = index + 1
            while end < size and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            advance_to(min(end + 1, size))
        elif char == "'":
            literal = CHAR.match(text, index)
            index = literal.end() if literal else index + 1
        elif IDENT.match(char):
            word = IDENT.match(text, index)
            index = word.end()
            if pending is None and word.group(0) in ("fn", "mod", "trait"):
                name = NAMED.match(text, index)
                if name:
                    pending = (f"{word.group(0)} {name.group(1)}", nesting, None)
                    index = name.end()
            elif pending is None and word.group(0) == "impl":
                pending = (None, nesting, index)
        elif char in "([":
            nesting += 1
            index += 1
        elif char in ")]":
            nesting -= 1
            index += 1
        elif char == "{":
            depth += 1
            if pending is not None and pending[1] == nesting:
                label, _, header = pending
                stack.append((depth, label or impl_label(text[header:index])))
                pending = None
            index += 1
        elif char == "}":
            if stack and stack[-1][0] == depth:
                stack.pop()
            depth -= 1
            index += 1
        else:
            if char == ";" and pending is not None and pending[1] == nesting:
                pending = None
            index += 1
    paths.append(" / ".join(label for _, label in stack))
    return paths


sites = {}
for path in sorted((root / "crates/gateway/src").rglob("*.rs")):
    relative = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8")
    labels = None
    for number, line in enumerate(text.splitlines(), 1):
        if LOAD.search(line):
            labels = labels or item_paths(text)
            key = (relative, labels[number] or "-", normalize(line))
            sites.setdefault(key, []).append(number)
if not sites:
    fail("no hot-configuration load exists")

entries = Counter()
for number, raw in enumerate(allowlist.read_text(encoding="utf-8").splitlines(), 1):
    if not raw.strip() or raw.lstrip().startswith("#"):
        continue
    fields = raw.split(" | ", 2)
    if len(fields) != 3 or not all(field.strip() for field in fields):
        fail(f"scripts/config_load_allowlist.txt:{number} is not `FILE | ITEM PATH | LINE TEXT`: {raw!r}")
    entries[(fields[0].strip(), normalize(fields[1]), normalize(fields[2]))] += 1

problems = []
for key in sorted(set(entries) | set(sites)):
    listed, lines = entries[key], sites.get(key, [])
    file, item, snippet = key
    where = ", ".join(f"{file}:{line}" for line in lines)
    if listed == len(lines):
        continue
    if not listed:
        problems.append(f"unlisted load at {where} in `{item}`: {snippet}")
    elif not lines:
        problems.append(f"allowlist entry matches no load site: {file} | {item} | {snippet}")
    else:
        problems.append(
            f"allowlist entry is listed {listed} time(s) but matches {len(lines)} site(s) at {where}: "
            f"{file} | {item} | {snippet}"
        )
if problems:
    fail(
        "the load inventory differs from scripts/config_load_allowlist.txt; every entry must match "
        "exactly one site (`FILE | ITEM PATH | LINE TEXT`, repeated once per identical site):\n  "
        + "\n  ".join(problems)
    )

for item in REQUEST_ENTRIES:
    listed = [key for key in entries.elements() if key[0] == "crates/gateway/src/service.rs" and key[1] == item]
    if [key[2] for key in listed] != [SNAPSHOT]:
        fail("each request entry must allowlist exactly one assembly snapshot load")
PY

printf 'OK: c-lim-0005 observes one settings and middleware snapshot per request; c-lim-0041 rejects later reloads\n'
