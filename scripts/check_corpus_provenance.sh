#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_corpus_provenance.sh
#
# WHAT THIS CHECKS
#   Every `src` in a `corpus/**/*.jsonl` entry and every `[[source]] id` in
#   `corpus/MANIFEST.toml` names a source on the allowlist, and the allowlist it checks
#   against is read out of `crates/corpus/src/store.rs` rather than written down twice.
#   A `client-matrix:` source must also carry a pinned revision after `@`. Every entry
#   also names a `sut` from the closed vocabulary in `crates/corpus/src/store.rs`, the
#   manifest's `[[source]]` census reproduces the `(id, sut)` pairs the entries carry, and
#   its `entries_from_production_server` count matches the entries themselves.
#
# WHY
#   rustfs/backlog#1763 makes "zero production traffic" a hard constraint, not a
#   preference: production bodies carry user data and production headers carry
#   credentials, and a SigV4 request cannot be replayed once a header is rewritten, so
#   there is no sanitised form of it worth having. The allowlist is what turns that
#   constraint into something a machine can decide. The pinned revision is the second
#   half: when a differential result changes, "which client version produced this entry"
#   has to be answerable from the corpus alone.
#
#   `sut` is the third half, and it is separate from `src` on purpose. rustfs/gateway#624
#   measured that this repository has no runnable production server binary, so every
#   recorded entry today came from a reference backend behind a real listener. "A real
#   client spoke S3" and "a real client spoke to the production server" are different
#   claims, and a corpus that cannot tell them apart will be read as the stronger one.
#   Prose in a README does not survive; a field a script checks does.
#
# HOW TO EXEMPT
#   There is no exemption for production traffic. A new synthetic suite is added by
#   editing SOURCE_ALLOWLIST in crates/corpus/src/store.rs, which this guard then reads.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_corpus_provenance)" || exit 1

for required in corpus corpus/MANIFEST.toml crates/corpus/src/store.rs; do
    if [[ ! -e "${ROOT_DIR}/${required}" ]]; then
        printf 'check_corpus_provenance: required input is missing: %s\n' "$required" >&2
        exit 1
    fi
done

"$PYTHON" - "$ROOT_DIR" <<'PYEOF'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
store = (root / "crates/corpus/src/store.rs").read_text()

block = re.search(r"pub const SOURCE_ALLOWLIST: &\[\(&str, bool\)\] = &\[(.*?)\n\];", store, re.S)
if block is None:
    print("check_corpus_provenance: cannot find SOURCE_ALLOWLIST in crates/corpus/src/store.rs", file=sys.stderr)
    raise SystemExit(1)
allowlist = [(name, flag == "true") for name, flag in re.findall(r'\("([^"]+)",\s*(true|false)\)', block.group(1))]
if not allowlist:
    print("check_corpus_provenance: SOURCE_ALLOWLIST parsed as empty; the guard would pass on anything", file=sys.stderr)
    raise SystemExit(1)

# The system-under-test vocabulary, read out of the same file rather than restated here.
suts = set(re.findall(r'Sut::[A-Za-z]+ => "([a-z-]+)",', store))
if not suts:
    print("check_corpus_provenance: the sut vocabulary parsed as empty; the guard would pass on anything", file=sys.stderr)
    raise SystemExit(1)
production_suts = set(re.findall(r'Sut::RustfsServer => "([a-z-]+)",', store))


def refusal(src: str) -> str | None:
    for prefix, needs_revision in allowlist:
        matched = src.startswith(prefix) if prefix[-1] in ":@" else src == prefix
        if not matched:
            continue
        if needs_revision and "@" not in src[len(prefix):]:
            return f"source `{src}` names no pinned revision after `@`"
        return None
    return f"source `{src}` is not on the allowlist; the corpus admits synthetic test suites only"


violations = []
sources: set[tuple[str, str]] = set()
from_production = 0

for path in sorted((root / "corpus").rglob("*.jsonl")):
    relative = path.relative_to(root).as_posix()
    for index, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            violations.append(f"{relative}:{index}: not valid JSON: {error}")
            continue
        src = entry.get("src")
        if not isinstance(src, str) or not src:
            violations.append(f"{relative}:{index}: entry has no `src`")
            continue
        sut = entry.get("sut")
        if not isinstance(sut, str) or sut not in suts:
            violations.append(
                f"{relative}:{index}: entry names no system under test from the closed vocabulary "
                f"{sorted(suts)}: {sut!r}"
            )
            continue
        if sut in production_suts:
            from_production += 1
        sources.add((src, sut))
        reason = refusal(src)
        if reason:
            violations.append(f"{relative}:{index}: {reason}")

manifest = (root / "corpus/MANIFEST.toml").read_text()
declared = set(re.findall(r'(?m)^id = "([^"]+)"\nsut = "([^"]+)"$', manifest))
for src, _ in sorted(declared):
    reason = refusal(src)
    if reason:
        violations.append(f"corpus/MANIFEST.toml: {reason}")
if declared != sources:
    violations.append(
        "corpus/MANIFEST.toml source census disagrees with the entries: "
        f"only in manifest={sorted(declared - sources)}, only in entries={sorted(sources - declared)}"
    )

recorded = re.search(r"(?m)^entries_from_production_server = ([0-9]+)$", manifest)
if recorded is None:
    violations.append("corpus/MANIFEST.toml does not record entries_from_production_server")
elif int(recorded.group(1)) != from_production:
    violations.append(
        f"corpus/MANIFEST.toml records entries_from_production_server = {recorded.group(1)}, "
        f"but {from_production} entry/entries name a production system under test"
    )

for violation in violations:
    print(f"check_corpus_provenance: {violation}", file=sys.stderr)
if violations:
    raise SystemExit(1)
print(
    f"OK: {len(sources)}/{len(sources)} sources in allowlist, "
    f"{from_production} entry/entries recorded against a production server"
)
PYEOF
