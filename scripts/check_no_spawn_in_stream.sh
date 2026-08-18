#!/usr/bin/env bash
set -euo pipefail

# Back-pressure in the push model is the absence of a read-ahead task. A producer
# that spawns one keeps producing while its consumer has stopped, so the only
# thing that limited the read rate is gone and nothing reports its loss.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_no_spawn_in_stream: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
stream = root / "crates/stream/src"
crates = root / "crates"
if not stream.is_dir():
    print("check_no_spawn_in_stream: required input is missing: crates/stream/src", file=sys.stderr)
    raise SystemExit(1)
if not crates.is_dir():
    print("check_no_spawn_in_stream: required input is missing: crates", file=sys.stderr)
    raise SystemExit(1)

manifest = root / "crates/stream/Cargo.toml"
if not manifest.is_file():
    print("check_no_spawn_in_stream: required input is missing: crates/stream/Cargo.toml", file=sys.stderr)
    raise SystemExit(1)


def strip(text: str) -> str:
    """Blank out comments and string literals, keeping every newline in place.

    The rule is explained in prose directly above the code it governs, and a guard that
    fires on its own documentation is a guard somebody deletes. Line counts are preserved
    so a reported line number still points at the offending token.
    """
    out = []
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end < 0 else end
            continue
        if text.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    if text[index] == "\n":
                        out.append("\n")
                    index += 1
            continue
        raw = re.match(r'(?:b|c)?r(#*)"', text[index:])
        if raw:
            marker = '"' + raw.group(1)
            end = text.find(marker, index + raw.end())
            if end < 0:
                raise ValueError("unterminated raw string")
            out.append("\n" * text.count("\n", index, end + len(marker)))
            index = end + len(marker)
            continue
        # A lifetime looks like the start of a char literal and is not one. Left as-is:
        # it holds no `spawn` token and consuming it as a literal would swallow real code.
        lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*(?!')", text[index:])
        if lifetime:
            out.append(lifetime.group())
            index += lifetime.end()
            continue
        quote = index + 1 if text[index] in "bc" and index + 1 < length else index
        if text[quote] in "\"'":
            delimiter = text[quote]
            cursor = quote + 1
            while cursor < length:
                if text[cursor] == "\\":
                    cursor += 2
                elif text[cursor] == delimiter:
                    cursor += 1
                    break
                else:
                    cursor += 1
            else:
                raise ValueError("unterminated literal")
            out.append("\n" * text.count("\n", index, cursor))
            index = cursor
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


# `spawn` in any of its spellings, plus the two join types that only exist to hold the
# handle a spawn returned. `JoinSet`/`JoinHandle` are listed because dropping the name
# `spawn` behind a helper is the obvious way around a token match.
SPAWN = re.compile(r"\bspawn(?:_blocking|_local|_pinned|_on)?\s*\(|\bJoinSet\b|\bJoinHandle\b")

# A file that implements either half of the data plane. `PayloadStream` is the push half
# this rule is about; `AsyncPayloadRead` is included because an adapter that turns a
# reader into a stream is written as an `AsyncPayloadRead` impl just as often.
IMPL = re.compile(
    r"\bimpl\s*(?:<[^{;]*?>)?[^{;]*?\b(?:PayloadStream|AsyncPayloadRead)\b[^{;]*?\bfor\b",
    re.S,
)

violations = []

# Rule 1 — the crate that owns the pull/push adapters has no runtime and must not grow
# one. This is the structural half: with no async runtime in the dependency tree, a
# read-ahead task is not merely forbidden here, it is unwritable.
runtime_deps = re.findall(
    r"^\s*(tokio|async-std|smol|futures-executor)\b",
    manifest.read_text(),
    re.M,
)
for dependency in sorted(set(runtime_deps)):
    violations.append(
        f"crates/stream/Cargo.toml: declares the async runtime '{dependency}'; "
        "the payload crate must have no runtime, so a read-ahead task cannot be written in it"
    )

stream_files = sorted(stream.rglob("*.rs"))
if not stream_files:
    print("check_no_spawn_in_stream: no Rust sources found under crates/stream/src", file=sys.stderr)
    raise SystemExit(1)

# Rule 2 — every file anywhere in the workspace that implements either half of the data
# plane. Scoping this to `crates/stream` alone would miss the wire layer, which is where
# a producer that reads from a socket actually lives.
# Stripping comments and literals is the expensive step, and the trait names appear in a
# handful of files out of hundreds. Raw text is a superset of stripped text, so a file that
# does not mention either trait at all cannot implement one: skipping those costs no coverage.
impl_files = []
for path in sorted(crates.rglob("*.rs")):
    if "/generated/" in path.as_posix() or "/target/" in path.as_posix():
        continue
    try:
        text = path.read_text()
    except (OSError, UnicodeError) as error:
        print(f"check_no_spawn_in_stream: cannot read {path}: {error}", file=sys.stderr)
        raise SystemExit(1)
    if "PayloadStream" not in text and "AsyncPayloadRead" not in text:
        continue
    try:
        code = strip(text)
    except ValueError as error:
        print(f"check_no_spawn_in_stream: cannot read {path}: {error}", file=sys.stderr)
        raise SystemExit(1)
    if IMPL.search(code):
        impl_files.append((path, code))

if not impl_files:
    print(
        "check_no_spawn_in_stream: no PayloadStream/AsyncPayloadRead implementation found; "
        "the guard has lost its subject and cannot report green",
        file=sys.stderr,
    )
    raise SystemExit(1)

scanned = {path: code for path, code in impl_files}
for path in stream_files:
    if path not in scanned:
        scanned[path] = strip(path.read_text())

for path in sorted(scanned):
    for match in SPAWN.finditer(scanned[path]):
        line = scanned[path].count("\n", 0, match.start()) + 1
        violations.append(
            f"{path.relative_to(root)}:{line}: read-ahead task in the payload data plane; "
            "a producer that runs ahead of its consumer has no back-pressure left to lose"
        )

if violations:
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)

print(
    f"OK: no read-ahead task in the payload data plane "
    f"({len(scanned)} file(s) scanned, {len(impl_files)} carrying a PayloadStream/AsyncPayloadRead impl)"
)
PY
