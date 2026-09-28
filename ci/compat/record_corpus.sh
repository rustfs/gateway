#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# record_corpus.sh
#
# WHAT THIS DOES
#   Turns one client-matrix run into corpus material (rustfs/backlog#1765 a-cm-0008, the P8-04
#   "second source"): the probe records every cell captured are converted to corpus JSONL by
#   `corpus/tools/from_compat_probe.py`, ingested into a fresh corpus directory under the run
#   directory by the `corpus` CLI (sanitizing, deduplicating, refusing anything that still carries
#   credential material), and verified strictly. Nothing is written into the repository's
#   `corpus/`: refreshing that is a reviewed pull request, never a side effect of a cron job.
#
#   Then it asserts what the recording is for. The converted JSONL must hold at least one entry,
#   and with `--require-chunked` at least one entry — in the JSONL and in the ingested corpus —
#   must carry aws-chunked framing. A full matrix run always contains one (restic and mc send
#   STREAMING-AWS4-HMAC-SHA256-PAYLOAD), so a full run that records none has lost the traffic the
#   corpus exists to keep, and that is a failure rather than an empty artefact.
#
# USAGE
#   ci/compat/record_corpus.sh --run-dir <dir> --corpus-bin <path> [--require-chunked]
#
# EXIT
#   0 recorded   1 the recording holds no entry, or no chunked entry when one is required
#   3 an input or the corpus tooling is missing or refused the recording
# =============================================================================

ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
RUN_DIR=""
CORPUS_BIN=""
REQUIRE_CHUNKED=0

problem() {
    printf 'record_corpus: %s\n' "$*" >&2
    exit 3
}

while [[ $# -gt 0 ]]; do
    case "$1" in
    --run-dir)
        RUN_DIR="${2:?--run-dir requires a path}"
        shift 2
        ;;
    --corpus-bin)
        CORPUS_BIN="${2:?--corpus-bin requires a path}"
        shift 2
        ;;
    --require-chunked)
        REQUIRE_CHUNKED=1
        shift
        ;;
    *)
        problem "unknown argument $1"
        ;;
    esac
done

[[ -n "$RUN_DIR" && -n "$CORPUS_BIN" ]] || problem 'usage: record_corpus.sh --run-dir <dir> --corpus-bin <path> [--require-chunked]'
[[ -d "$RUN_DIR/results" ]] || problem "required input is missing: $RUN_DIR/results"
[[ -x "$CORPUS_BIN" ]] || problem "the corpus CLI is not executable at $CORPUS_BIN"

jsonl="$RUN_DIR/corpus.jsonl"
corpus="$RUN_DIR/corpus"

python3 "$ROOT_DIR/corpus/tools/from_compat_probe.py" "$RUN_DIR/results" \
    --pins "$ROOT_DIR/compat/versions.toml" \
    --recorded "$(date -u +%Y-%m-%d)" >"$jsonl" ||
    problem 'the probe records could not be converted'

if ! grep -q . "$jsonl"; then
    # Checked before ingest, which would only report an empty directory: a run whose cells
    # recorded no request at all is a recording failure, not a tooling one.
    printf 'record_corpus: the run recorded no corpus entry\n' >&2
    exit 1
fi

rm -rf "$corpus"
mkdir -p "$corpus"
"$CORPUS_BIN" ingest "$jsonl" --into "$corpus" --sanitize || problem 'corpus ingest refused the recording'
"$CORPUS_BIN" verify "$corpus" --strict || problem 'the recorded corpus does not verify'

python3 - "$jsonl" "$corpus/MANIFEST.toml" "$REQUIRE_CHUNKED" <<'PY'
import json
import sys
import tomllib
from pathlib import Path

jsonl, manifest_path, require_chunked = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3] == "1"


def chunked(entry):
    # The same three signals the corpus schema uses: a streaming payload mode, a declared
    # trailer, or the aws-chunked content coding.
    headers = {name.lower(): value for name, value in entry.get("headers", [])}
    return (
        headers.get("x-amz-content-sha256", "").startswith("STREAMING-")
        or "x-amz-trailer" in headers
        or "aws-chunked" in headers.get("content-encoding", "").lower()
    )


entries = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
framed = sum(1 for entry in entries if chunked(entry))
manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
retained, retained_framed = manifest.get("entries", 0), manifest.get("chunk_framed_entries", 0)
print(
    f"record_corpus: {len(entries)} probe entr(ies), {framed} chunk-framed; "
    f"corpus retained {retained}, {retained_framed} chunk-framed"
)
failures = []
if not entries or not retained:
    failures.append("the run recorded no corpus entry")
if require_chunked and not (framed and retained_framed):
    failures.append("a full run recorded no aws-chunked request, which the signed-chunk clients always send")
for line in failures:
    print(f"record_corpus: {line}", file=sys.stderr)
raise SystemExit(1 if failures else 0)
PY
