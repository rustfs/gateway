#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_form_limits.sh
#
# WHAT THIS CHECKS
#   1. The six POST Object form cases of rustfs/backlog#1699 — c-lim-0002,
#      c-lim-0007, c-lim-0028, c-lim-0029, c-lim-0030 and c-lim-0031 — each name
#      exactly one active, unconditional test function.
#   2. `FileReader` cannot be built without a byte ceiling: it has no public
#      constructor, its crate-private one is called from exactly one place, and
#      that place is `FormReader::into_file`, whose ceiling argument is composed
#      with the deployment maximum by `min`.
#   3. `FormLimits` grows no unlimited constructor.
#
# WHY
#   The POST policy and its signature arrive inside the multipart body, and the
#   `content-length-range` that bounds the upload is inside the policy. So the
#   file's ceiling does not exist until the policy field has been read, and a
#   ceiling applied after the read bounds nothing (s3s#473). The type is what
#   holds that ordering — `into_file(ceiling)` is the only door to a file byte —
#   and this guard is what keeps a second door from being added.
#
#   The issue's acceptance list asks instead for `check_multer_constraints.sh`,
#   greping for `multer::Multipart::new(`. There is no `multer` in this
#   workspace, so that grep would be a check that cannot fail — the shape this
#   repository has caught eight times. The property
#   it stood in for is checked above instead, against the code that exists.
#
# HOW TO EXEMPT
#   Not applicable. A case that moves keeps its id in its new test name; a
#   second way to read a file part needs the ordering argument reopened first.
#
# USAGE
#   scripts/check_form_limits.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_form_limits.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

command -v python3 >/dev/null 2>&1 || {
    printf 'check_form_limits: required command is missing: python3\n' >&2
    exit 1
}

python3 - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1]).resolve()


def fail(message: str) -> None:
    raise SystemExit(f"check_form_limits: {message}")


def read(relative: str) -> str:
    path = root / relative
    if not path.is_file():
        fail(f"required input is missing: {relative}")
    return path.read_text()


# --- 1. Every case id names one active test -------------------------------------------------
#
# The evidence file is named per id rather than searched for, so a case that quietly moves to a
# file nobody registered is a failure here rather than an absence nobody notices.
CASES = {
    "c-lim-0002": "crates/sig/tests/post_object_form.rs",
    "c-lim-0007": "crates/http/tests/form_limits.rs",
    "c-lim-0028": "crates/http/tests/form_limits.rs",
    "c-lim-0029": "crates/http/tests/form_limits.rs",
    "c-lim-0030": "crates/http/tests/form_limits.rs",
    "c-lim-0031": "crates/http/tests/form_limits.rs",
}

sources = {relative: read(relative) for relative in sorted(set(CASES.values()))}

for case, relative in sorted(CASES.items()):
    source = sources[relative]
    symbol = case.replace("-", "_")
    pattern = re.compile(r"^\s*(?:async\s+)?fn\s+(" + re.escape(symbol) + r"_[A-Za-z0-9_]*)\s*\(", re.MULTILINE)
    matches = pattern.findall(source)
    if len(matches) != 1:
        fail(
            f"{case} must name exactly one test function in {relative}; found {len(matches)}. "
            f"A case with no test is an unstarted case wearing a finished one's name."
        )
    name = matches[0]
    # The attribute has to be `#[test]` and it has to be unconditional. `#[cfg(any())]` above a
    # test leaves the function in the file, the id in the grep, and nothing in the binary.
    declaration = re.search(r"((?:^\s*#\[[^\]]*\]\s*\n)+)\s*(?:async\s+)?fn\s+" + re.escape(name) + r"\s*\(", source, re.MULTILINE)
    if declaration is None:
        fail(f"{case}'s test `{name}` in {relative} carries no attributes, so it is not a test")
    attributes = declaration.group(1)
    if "#[test]" not in attributes and "#[tokio::test]" not in attributes:
        fail(f"{case}'s test `{name}` in {relative} is not a `#[test]`")
    if "cfg(" in attributes or "#[ignore]" in attributes:
        fail(f"{case}'s test `{name}` in {relative} is conditional or ignored, so it proves nothing")

# --- 2. The file part has exactly one door, and it takes a ceiling ---------------------------

FILE_MODULE = "crates/http/src/form/file.rs"
READER_MODULE = "crates/http/src/form/reader.rs"
file_source = read(FILE_MODULE)
reader_source = read(READER_MODULE)

if re.search(r"^\s*pub\s+fn\s+new\s*\(", file_source, re.MULTILINE):
    fail(
        f"{FILE_MODULE} declares a public `FileReader::new`. The whole ordering guarantee is that "
        f"a file reader cannot exist without a ceiling; a second constructor removes it."
    )

constructor = re.findall(r"pub\(super\)\s+fn\s+new\s*\(([^)]*)\)", file_source, re.DOTALL)
if len(constructor) != 1:
    fail(f"{FILE_MODULE} must declare exactly one crate-private `FileReader::new`; found {len(constructor)}")
if "ceiling" not in constructor[0]:
    fail(f"{FILE_MODULE}'s `FileReader::new` no longer takes a ceiling")

# The constructor is called from `into_file` and from nowhere else in the workspace.
call_sites = []
for path in sorted(root.glob("crates/*/src/**/*.rs")):
    for index, line in enumerate(path.read_text().splitlines(), start=1):
        if "FileReader::new(" in line:
            call_sites.append(f"{path.relative_to(root)}:{index}")
if call_sites != [f"{READER_MODULE}:{next(index for index, line in enumerate(reader_source.splitlines(), start=1) if 'FileReader::new(' in line)}"]:
    fail(
        "`FileReader::new` must be called from `FormReader::into_file` and nowhere else; found "
        + (", ".join(call_sites) if call_sites else "no call site at all")
    )

into_file = re.search(r"pub fn into_file\(self, ceiling: u64\)(.*?)\n    \}", reader_source, re.DOTALL)
if into_file is None:
    fail(f"{READER_MODULE} no longer declares `into_file(self, ceiling: u64)`")
body = into_file.group(1)
if "ceiling.min(self.limits.max_file_bytes())" not in body:
    fail(
        f"{READER_MODULE}'s `into_file` no longer composes the policy ceiling with the deployment "
        f"maximum by `min`. A policy that could widen the deployment limit is not a limit."
    )

# --- 3. No unlimited form limits -------------------------------------------------------------

MOD_MODULE = "crates/http/src/form/mod.rs"
mod_source = read(MOD_MODULE)
if re.search(r"fn\s+unlimited", mod_source):
    fail(f"{MOD_MODULE} declares an unlimited `FormLimits` constructor")

print("OK: six form cases bound; the file part has one door and it takes a ceiling")
PY
