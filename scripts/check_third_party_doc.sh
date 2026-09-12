#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_third_party_doc.sh
#
# WHAT THIS CHECKS
#   That THIRD-PARTY-NOTICES.md carries a complete licence review for every
#   external acceptance suite this repository reaches for, and that each review
#   records four things rather than one:
#
#     1. the upstream URL
#     2. the licence, by SPDX identifier
#     3. whether it is vendored — stated, in both directions
#     4. **how the licence was verified**, as a command whose output was read
#
#   It also asserts the s3-tests commit recorded here is the same one
#   ci/s3tests/pins.env actually runs.
#
# WHY RULE 4 IS THE POINT
#   A licence line copied from a README is a claim about a repository somebody
#   looked at once. `spdx_id` from the API, the LICENSE blob, and the absence of
#   tags are facts a later reader can re-derive in ten seconds — and the reason
#   this matters here is that two of the three suites are commonly mis-stated:
#   minio/mint is Apache-2.0 while the server beside it is AGPL-3.0, and
#   ceph/s3-tests publishes no version at all. A review that records only its
#   conclusion cannot be checked, and is therefore re-done from scratch by every
#   agent who needs to trust it.
#
# WHY THE PIN CROSS-CHECK
#   A notice naming one commit while the runner clones another is worse than no
#   notice: it is a reviewed statement about software that is not the software
#   being run.
#
# HOW TO EXEMPT
#   None. A suite without a review is a suite nobody checked the licence of.
#
# USAGE
#   scripts/check_third_party_doc.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_third_party_doc.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_third_party_doc)" || exit 1
"$PYTHON" - "$ROOT_DIR" <<'PYEOF'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
notices = root / "THIRD-PARTY-NOTICES.md"
if not notices.is_file():
    print("check_third_party_doc: required input is missing: THIRD-PARTY-NOTICES.md", file=sys.stderr)
    raise SystemExit(1)
text = notices.read_text(encoding="utf-8")

# Each suite: the heading that must exist, the upstream that must be named, the SPDX id that
# must be recorded, and a phrase proving the vendoring decision was stated rather than implied.
SUITES = (
    ("Ceph s3-tests", "github.com/ceph/s3-tests", "MIT"),
    ("MinIO mint", "github.com/minio/mint", "Apache-2.0"),
    ("MinIO server", "github.com/minio/minio", "AGPL-3.0"),
)
# A verification is a command a reader can re-run. Prose is not a verification.
VERIFICATION = re.compile(r"`(?:gh api|git ls-remote|curl|docker (?:buildx )?imagetools)[^`]*`")

sections: dict[str, str] = {}
current: str | None = None
for line in text.splitlines():
    heading = re.fullmatch(r"#{2,3}\s+(.*\S)\s*", line)
    if heading is not None:
        current = heading.group(1)
        sections[current] = ""
        continue
    if current is not None:
        sections[current] += line + "\n"

failures: list[str] = []
for name, upstream, spdx in SUITES:
    body = sections.get(name)
    if body is None:
        failures.append(
            f"THIRD-PARTY-NOTICES.md has no `{name}` section; every external suite this "
            "repository reaches for carries its own licence review"
        )
        continue
    if upstream not in body:
        failures.append(f"the `{name}` review does not name its upstream {upstream}")
    # On the Licence line specifically. The verification command below it prints the same
    # identifier, so a search over the whole section would go on passing after somebody
    # replaced the stated licence with an adjective.
    licence_line = re.search(r"(?m)^\s*[-*]\s*Licen[cs]e:.*$", body)
    if licence_line is None:
        failures.append(f"the `{name}` review has no `- Licence:` line")
    elif spdx not in licence_line.group(0):
        failures.append(
            f"the `{name}` review's licence line does not name the SPDX identifier {spdx}: "
            f"{licence_line.group(0).strip()!r}"
        )
    if not re.search(r"[Vv]endored:", body):
        failures.append(
            f"the `{name}` review does not state whether it is vendored; the decision is the "
            "whole reason the review exists"
        )
    if not VERIFICATION.search(body):
        failures.append(
            f"the `{name}` review records no command that verifies the licence. A conclusion "
            "nobody can re-derive is re-derived from scratch by everyone who needs it."
        )
    if not re.search(r"[Vv]erified\s+\d{4}-\d{2}-\d{2}", body):
        failures.append(f"the `{name}` review carries no `Verified <YYYY-MM-DD>` date")

# The pin the notice claims must be the pin the runner uses.
pins = root / "ci/s3tests/pins.env"
if not pins.is_file():
    failures.append("required input is missing: ci/s3tests/pins.env")
else:
    match = re.search(r"(?m)^S3TESTS_SHA=([0-9a-f]{40})\s*$", pins.read_text(encoding="utf-8"))
    if match is None:
        failures.append("ci/s3tests/pins.env declares no 40-hex S3TESTS_SHA")
    elif match.group(1) not in sections.get("Ceph s3-tests", ""):
        failures.append(
            f"THIRD-PARTY-NOTICES.md does not record the commit the runner actually clones "
            f"({match.group(1)}); a review of software that is not the software being run is worse "
            "than none"
        )

# The same for the mint image: the digest the notice reviewed must be the one the runner pulls.
mint_pins = root / "ci/mint/pins.env"
if not mint_pins.is_file():
    failures.append("required input is missing: ci/mint/pins.env")
else:
    match = re.search(r"(?m)^MINT_IMAGE=\S+@(sha256:[0-9a-f]{64})\s*$", mint_pins.read_text(encoding="utf-8"))
    if match is None:
        failures.append("ci/mint/pins.env declares no digest-pinned MINT_IMAGE")
    elif match.group(1) not in sections.get("MinIO mint", ""):
        failures.append(
            f"THIRD-PARTY-NOTICES.md does not record the image digest the mint runner pulls ({match.group(1)}); "
            "a review of software that is not the software being run is worse than none"
        )

if failures:
    for failure in failures:
        print(f"check_third_party_doc: {failure}", file=sys.stderr)
    raise SystemExit(1)

print(f"OK: {len(SUITES)}/{len(SUITES)} suites documented with licence, verification and pin")
PYEOF
