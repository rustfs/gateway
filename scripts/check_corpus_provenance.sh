#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_corpus_provenance.sh
#
# WHAT THIS CHECKS
#   Every `src` in a `corpus/**/*.jsonl` entry and every `[[source]] id` in
#   `corpus/MANIFEST.toml` names a source on the allowlist, and the allowlist it checks
#   against is read out of `crates/corpus/src/store.rs` rather than written down twice.
#   A `client-matrix:` source must also carry a pinned revision after `@`.
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
# HOW TO EXEMPT
#   There is no exemption for production traffic. A new synthetic suite is added by
#   editing SOURCE_ALLOWLIST in crates/corpus/src/store.rs, which this guard then reads.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_corpus_provenance: required command is missing: python3\n' >&2
    exit 1
}

for required in corpus corpus/MANIFEST.toml crates/corpus/src/store.rs; do
    if [[ ! -e "${ROOT_DIR}/${required}" ]]; then
        printf 'check_corpus_provenance: required input is missing: %s\n' "$required" >&2
        exit 1
    fi
done

python3 - "$ROOT_DIR" <<'PYEOF'
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
sources = set()

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
        sources.add(src)
        reason = refusal(src)
        if reason:
            violations.append(f"{relative}:{index}: {reason}")

manifest = (root / "corpus/MANIFEST.toml").read_text()
declared = set(re.findall(r'(?m)^id = "([^"]+)"$', manifest))
for src in sorted(declared):
    reason = refusal(src)
    if reason:
        violations.append(f"corpus/MANIFEST.toml: {reason}")
if declared != sources:
    violations.append(
        "corpus/MANIFEST.toml source census disagrees with the entries: "
        f"only in manifest={sorted(declared - sources)}, only in entries={sorted(sources - declared)}"
    )

for violation in violations:
    print(f"check_corpus_provenance: {violation}", file=sys.stderr)
if violations:
    raise SystemExit(1)
print(f"OK: {len(sources)}/{len(sources)} sources in allowlist")
PYEOF
