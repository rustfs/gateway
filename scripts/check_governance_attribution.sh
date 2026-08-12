#!/usr/bin/env bash
set -euo pipefail

# WHAT: Keep the s3s relationship statement and the adapted aws-sigv4 helpers attributed.
# WHY:  rustfs/backlog#1711 closes the repository-governance provenance contract.
# HOW TO EXEMPT: There are no exemptions; update the pinned source facts through review.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_governance_attribution: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$REPO_ROOT" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
readme_path = root / "README.md"
notice_path = root / "NOTICE"
source_path = root / "crates/sig/src/derive.rs"

for path in (readme_path, notice_path, source_path):
    if not path.is_file():
        raise SystemExit(f"check_governance_attribution: required input is missing: {path.relative_to(root)}")


def section(text: str, heading: str, next_marker=None) -> str:
    if text.count(heading) != 1:
        raise SystemExit(f"check_governance_attribution: expected one {heading!r} section")
    body = text.split(heading, 1)[1]
    if next_marker is None:
        return body
    if next_marker not in body:
        raise SystemExit(f"check_governance_attribution: {heading!r} has no closing marker")
    return body.split(next_marker, 1)[0]


def visible_markdown(text: str) -> str:
    """Return prose visible outside HTML comments and Markdown code blocks."""
    without_comments = []
    cursor = 0
    while cursor < len(text):
        start = text.find("<!--", cursor)
        if start == -1:
            without_comments.append(text[cursor:])
            break
        without_comments.append(text[cursor:start])
        end = text.find("-->", start + 4)
        if end == -1:
            break
        cursor = end + 3

    def without_container_prefixes(line: str) -> str:
        content = line
        while True:
            container = re.match(
                r" {0,3}(?:>[ \t]?|(?:[-+*]|[0-9]{1,9}[.)])[ \t]+)", content
            )
            if container is None:
                return content
            content = content[container.end() :]

    visible = []
    fence = None
    for line in "".join(without_comments).splitlines(keepends=True):
        candidate = line.rstrip("\r\n")
        content = without_container_prefixes(candidate)
        if fence is not None:
            marker, minimum = fence
            if re.fullmatch(rf" {{0,3}}{re.escape(marker)}{{{minimum},}}[ \t]*", content):
                fence = None
            continue

        if content.startswith("    ") or content.startswith("\t"):
            continue

        opened = re.fullmatch(r" {0,3}(`{3,}|~{3,})(.*)", content)
        if opened is not None:
            run, info = opened.groups()
            if run[0] == "~" or "`" not in info:
                fence = (run[0], len(run))
                continue
        visible.append(line)
    return "".join(visible)


readme = readme_path.read_text()
relationship = visible_markdown(section(readme, "## Relationship to s3s\n", "\n## "))
for fact in (
    "https://github.com/s3s-project/s3s",
    "issue and\npull-request history",
    "repository is not a fork",
    "independent implementation",
    "Apache-2.0 license",
    "never copied source code",
):
    if fact not in relationship:
        raise SystemExit(f"check_governance_attribution: README relationship is missing {fact!r}")

revision = "2880e0785db4cf2ceb086cfeba86a4cbdeb14176"
upstream_url = "https://github.com/smithy-lang/smithy-rs"
upstream_path = "aws/rust-runtime/aws-sigv4/src/sign/v4.rs"
local_path = "crates/sig/src/derive.rs"

notice = notice_path.read_text()
sigv4_notice = section(notice, "2. aws-sigv4 (AWS SDK for Rust)\n", "\n3. ")
notice_fields = {}
for line in sigv4_notice.splitlines():
    matched = re.fullmatch(r"   (Source|Crate|License|Commit|Path):[ \t]+(.*?)\s*", line)
    if matched is None:
        continue
    name, value = matched.groups()
    if name in notice_fields:
        raise SystemExit(f"check_governance_attribution: NOTICE aws-sigv4 repeats field {name!r}")
    notice_fields[name] = value
expected_notice_fields = {
    "Source": upstream_url,
    "Crate": "aws-sigv4 1.5.1",
    "License": "Apache License 2.0",
    "Commit": revision,
    "Path": upstream_path,
}
if notice_fields != expected_notice_fields:
    raise SystemExit("check_governance_attribution: NOTICE aws-sigv4 fields do not match reviewed facts")
for fact in (
    "`signing_key` adapted from `generate_signing_key`",
    "`calculate_signature` adapted from the upstream function of the same name",
    "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
):
    if fact not in sigv4_notice:
        raise SystemExit(f"check_governance_attribution: NOTICE aws-sigv4 entry is missing {fact!r}")
if "TODO" in sigv4_notice:
    raise SystemExit("check_governance_attribution: NOTICE aws-sigv4 attribution still contains a TODO")

registry = section(notice, "Copied code registry\n")
field_names = {
    "Local path",
    "Upstream project",
    "Upstream revision",
    "Upstream path",
    "License",
}
entries = []
entry = None
for line in registry.splitlines():
    matched = re.fullmatch(r"\s{2,}([^:]+):\s*(.*?)\s*", line)
    if matched is None or matched.group(1) not in field_names:
        continue
    name, value = matched.groups()
    if name == "Local path":
        if entry is not None:
            entries.append(entry)
        entry = {}
    if entry is None:
        raise SystemExit(f"check_governance_attribution: registry field {name!r} has no Local path")
    if name in entry:
        raise SystemExit(f"check_governance_attribution: copied-code registry repeats field {name!r}")
    entry[name] = value
if entry is not None:
    entries.append(entry)

matching_entries = [item for item in entries if item.get("Local path") == local_path]
if len(matching_entries) != 1:
    raise SystemExit(
        "check_governance_attribution: copied-code registry must contain exactly one derive.rs entry"
    )
expected_entry = {
    "Local path": local_path,
    "Upstream project": upstream_url,
    "Upstream revision": revision,
    "Upstream path": upstream_path,
    "License": "Apache-2.0",
}
if matching_entries[0] != expected_entry:
    raise SystemExit("check_governance_attribution: derive.rs registry entry does not match reviewed facts")

source = source_path.read_text().split("//!", 1)[0]
divider = "// ---------------------------------------------------------------------------\n"
attribution_marker = divider + "// ATTRIBUTION\n//\n"
if source.count(attribution_marker) != 1 or source.count("// ATTRIBUTION\n") != 1:
    raise SystemExit("check_governance_attribution: derive.rs must contain one ATTRIBUTION block")
attribution_tail = source.split(attribution_marker, 1)[1]
if divider not in attribution_tail:
    raise SystemExit("check_governance_attribution: derive.rs ATTRIBUTION block is not closed")
attribution = attribution_tail.split(divider, 1)[0]

attribution_fields = {}
function_mappings = []
for line in attribution.splitlines():
    matched = re.fullmatch(r"//     ([A-Za-z ]+):[ \t]+(.*?)\s*", line)
    if matched is None:
        continue
    name, value = matched.groups()
    if name == "Function mapping":
        function_mappings.append(value)
        continue
    if name in attribution_fields:
        raise SystemExit(f"check_governance_attribution: derive.rs repeats field {name!r}")
    attribution_fields[name] = value

expected_attribution_fields = {
    "Upstream URL": upstream_url,
    "Upstream path": upstream_path,
    "Revision": f"{revision} (aws-sigv4 1.5.1)",
    "License": "Apache-2.0",
    "Copyright": "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
}
expected_function_mappings = [
    "signing_key <- generate_signing_key",
    "calculate_signature <- calculate_signature",
]
if attribution_fields != expected_attribution_fields:
    raise SystemExit("check_governance_attribution: derive.rs fields do not match reviewed facts")
if function_mappings != expected_function_mappings:
    raise SystemExit("check_governance_attribution: derive.rs function mappings do not match reviewed facts")
PY
