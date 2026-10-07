#!/usr/bin/env bash
set -euo pipefail

# Back-pressure in the push model is the absence of a read-ahead task. A producer
# that spawns one keeps producing while its consumer has stopped, so the only
# thing that limited the read rate is gone and nothing reports its loss.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_no_spawn_in_stream)" || exit 1

"$PYTHON" - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys
import tomllib

root = Path(sys.argv[1])
stream = root / "crates/stream/src"
crates = root / "crates"
if not stream.is_dir():
    print("check_no_spawn_in_stream: required input is missing: crates/stream/src", file=sys.stderr)
    raise SystemExit(1)
if not crates.is_dir():
    print("check_no_spawn_in_stream: required input is missing: crates", file=sys.stderr)
    raise SystemExit(1)

# Both halves of the payload data plane: the crate that owns `Payload`, and the wire layer
# that produces one from a socket. Scoping the rule to `crates/stream` alone would leave the
# half where a producer actually reads bytes unguarded.
PLANE = ("crates/stream", "crates/http")
manifests = []
for crate in PLANE:
    manifest = root / crate / "Cargo.toml"
    directory = root / crate / "src"
    if not manifest.is_file():
        print(f"check_no_spawn_in_stream: required input is missing: {crate}/Cargo.toml", file=sys.stderr)
        raise SystemExit(1)
    if not directory.is_dir() or not any(directory.rglob("*.rs")):
        print(f"check_no_spawn_in_stream: required input is missing: {crate}/src", file=sys.stderr)
        raise SystemExit(1)
    manifests.append((crate, manifest))

# The sanctioned edge below is checked against the workspace entry it could inherit from, so
# the workspace manifest is a required input, not an optional one.
workspace_manifest = root / "Cargo.toml"
if not workspace_manifest.is_file():
    print("check_no_spawn_in_stream: required input is missing: Cargo.toml", file=sys.stderr)
    raise SystemExit(1)
try:
    workspace_dependencies = tomllib.loads(workspace_manifest.read_text()).get("workspace", {}).get("dependencies", {})
except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
    print(f"check_no_spawn_in_stream: cannot parse Cargo.toml: {error}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(workspace_dependencies, dict):
    workspace_dependencies = {}


# Compiled once, then matched with an offset. Cutting a fresh `text[index:]` slice copies the
# whole remainder of the file on every character, which makes an otherwise linear scan
# quadratic in file length; `pattern.match(text, index)` matches at the same place without the
# copy. No pattern here carries `^`, `\A`, `\b` or a lookbehind, so anchoring at the offset is
# exactly what slicing to it already meant. Both `.end()` values are now absolute offsets into
# `text`.
RAW_STRING_RE = re.compile(r'(?:b|c)?r(#*)"')
LIFETIME_RE = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*(?!')")


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
        raw = RAW_STRING_RE.match(text, index)
        if raw:
            marker = '"' + raw.group(1)
            end = text.find(marker, raw.end())
            if end < 0:
                raise ValueError("unterminated raw string")
            out.append("\n" * text.count("\n", index, end + len(marker)))
            index = end + len(marker)
            continue
        # A lifetime looks like the start of a char literal and is not one. Left as-is:
        # it holds no `spawn` token and consuming it as a literal would swallow real code.
        lifetime = LIFETIME_RE.match(text, index)
        if lifetime:
            out.append(lifetime.group())
            index = lifetime.end()
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

# Rule 1 — the structural half. The payload data plane has no runtime, so a read-ahead task is
# not merely forbidden here, it is unwritable. One edge is sanctioned, and every word of it is
# checked rather than listed: `crates/stream` may name `tokio` behind its `tokio-io` feature —
# optional, default features off, `io-util` as its only feature, and that feature its only door.
# A task can only be spawned under `rt` (`tokio::spawn`, `JoinHandle` and `JoinSet` do not exist
# without it), so the edge adds no way to write one. Feature unification in a workspace build
# can still bring `rt` in through a neighbouring crate, which is why Rule 2 scans the sources
# regardless of what this rule concludes.
RUNTIMES = {"tokio", "async-std", "smol", "futures-executor"}
RUNTIME_LINE = re.compile(r"^\s*(?:tokio|async-std|smol|futures-executor)\s*(?:=|\.)", re.M)
SANCTIONED = {"crates/stream": ("tokio", "tokio-io", frozenset({"io-util"}))}
NO_RUNTIME = "the payload data plane must have no runtime, so a read-ahead task cannot be written in it"


def dependency_tables(document):
    for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = document.get(kind, {})
        if isinstance(table, dict):
            yield kind, table
    targets = document.get("target", {})
    if not isinstance(targets, dict):
        return
    for selector, target in targets.items():
        if not isinstance(target, dict):
            continue
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            table = target.get(kind, {})
            if isinstance(table, dict):
                yield f"target.{selector}.{kind}", table


def runtime_edge_problem(crate, kind, alias, package, declaration, document):
    """Why this runtime dependency is not the one sanctioned edge, or None when it is."""
    rule = SANCTIONED.get(crate)
    if rule is None or package != rule[0]:
        return f"declares the async runtime '{package}'; {NO_RUNTIME}"
    _, gate, allowed_features = rule
    if kind != "dependencies":
        return f"[{kind}].{alias} declares '{package}'; the runtime-free edge is sanctioned under [dependencies] alone"
    if not isinstance(declaration, dict):
        return (
            f"[dependencies].{alias} declares '{package}' as a bare version; the sanctioned edge is "
            f"optional, default-features = false, features = {sorted(allowed_features)}"
        )
    features = {feature for feature in declaration.get("features", []) if isinstance(feature, str)}
    merged = dict(declaration)
    if declaration.get("workspace") is True:
        inherited = workspace_dependencies.get(alias, {})
        inherited = inherited if isinstance(inherited, dict) else {}
        # Cargo unions the features of a workspace-inherited dependency with the member's own.
        features |= {feature for feature in inherited.get("features", []) if isinstance(feature, str)}
        merged = {**inherited, **declaration}
    if merged.get("optional") is not True:
        return f"[dependencies].{alias} declares '{package}' as a mandatory dependency; the sanctioned edge is optional, behind the '{gate}' feature"
    if merged.get("default-features", True) is not False:
        return f"[dependencies].{alias} leaves the default features of '{package}' on; the sanctioned edge disables them so a future default cannot carry a runtime in"
    extra = sorted(feature for feature in features if feature not in allowed_features)
    if extra:
        return f"[dependencies].{alias} enables the {package} features {extra}; only {sorted(allowed_features)} are sanctioned, because a task can only be spawned under 'rt'"
    features_table = document.get("features", {})
    if not isinstance(features_table, dict):
        features_table = {}
    door = features_table.get(gate)
    if not isinstance(door, list) or f"dep:{alias}" not in door:
        return f"[dependencies].{alias} is optional but feature '{gate}' does not name 'dep:{alias}'; that feature is the sanctioned edge's only door"
    for name, members in features_table.items():
        if not isinstance(members, list):
            continue
        for member in members:
            if not isinstance(member, str):
                continue
            if member.startswith((f"{alias}/", f"{alias}?/")):
                return f"feature '{name}' enables '{member}', widening the sanctioned {package} feature set"
            if name != gate and member == f"dep:{alias}":
                return f"feature '{name}' also enables '{alias}'; '{gate}' must be the sanctioned edge's only door"
            if name == "default" and member == gate:
                return f"the default feature set enables '{gate}'; the runtime-free edge must stay off by default"
    return None


for crate, manifest in manifests:
    text = manifest.read_text()
    named = len(RUNTIME_LINE.findall(text))
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        if named:
            violations.append(f"{crate}/Cargo.toml: names an async runtime in a manifest that does not parse ({error}); {NO_RUNTIME}")
        else:
            violations.append(f"{crate}/Cargo.toml: cannot be parsed: {error}")
        continue
    recognised = 0
    for kind, table in dependency_tables(document):
        for alias, declaration in table.items():
            package = declaration.get("package", alias) if isinstance(declaration, dict) else alias
            if not isinstance(package, str) or package not in RUNTIMES:
                continue
            recognised += 1
            problem = runtime_edge_problem(crate, kind, alias, package, declaration, document)
            if problem is not None:
                violations.append(f"{crate}/Cargo.toml: {problem}")
    if named > recognised:
        violations.append(f"{crate}/Cargo.toml: names an async runtime outside its dependency tables; {NO_RUNTIME}")

# Every file in both crates, not only the ones carrying an impl: a producer can call a spawning
# helper that lives in a neighbouring module, and a file-scoped rule would read that as clean.
plane_files = sorted({path for crate in PLANE for path in (root / crate / "src").rglob("*.rs")})

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
for path in plane_files:
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
