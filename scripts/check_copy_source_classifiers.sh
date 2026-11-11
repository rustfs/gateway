#!/usr/bin/env bash
set -euo pipefail

# Both standard Copy operations must use the shared capability classifier (ADR-0045).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_copy_source_classifiers)" || exit 1
PYTHONPATH="${SCRIPT_DIR}${PYTHONPATH:+:${PYTHONPATH}}" "$PYTHON" - "$ROOT_DIR" <<'PYEOF'
import re
import sys
from pathlib import Path

from trait_policy_scan import mask_rust

root = Path(sys.argv[1])


def fail(message):
    print(f"check_copy_source_classifiers: {message}", file=sys.stderr)
    raise SystemExit(1)


def source(relative):
    path = root / relative
    if not path.is_file() or path.is_symlink():
        fail(f"{relative}: missing or not a regular file")
    try:
        return re.sub(r"\s+", "", mask_rust(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, ValueError) as error:
        fail(f"{relative}: cannot read Rust source: {error}")


def impl_body(text, name, relative):
    signature = f"implOperationfor{name}{{"
    if text.count(signature) != 1:
        fail(f"{relative}: classifier override has no unique standard operation implementation")
    if len(re.findall(r"impl[^{};]*for" + name + r"\{", text)) != 1:
        fail(f"{relative}: classifier override has another implementation for the operation")
    if re.search(r"#\[[^\]]*\](?:#\[[^\]]*\])*" + signature, text):
        fail(f"{relative}: classifier override implementation must be unconditional")
    start = text.index(signature) + len(signature)
    depth = 1
    end = start
    while end < len(text) and depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    if depth:
        fail(f"{relative}: classifier override implementation is unbalanced")
    return text[start : end - 1]


shared = source("crates/core/src/ops/shared/copy_source.rs")
if shared.count("modcapability;") != 1 or shared.count("pub(crate)usecapability::classify;") != 1:
    fail("shared copy source classifier wiring is missing or duplicated")
if len(re.findall(r"modcapability(?:;|\{)", shared)) != 1:
    fail("shared copy source classifier module has another definition")
for declaration in ("modcapability;", "pub(crate)usecapability::classify;"):
    if re.search(r"#\[[^\]]*\](?:#\[[^\]]*\])*" + re.escape(declaration), shared):
        fail("shared copy source classifier wiring must be unconditional")
capability = source("crates/core/src/ops/shared/copy_source/capability.rs")
classifier = "pub(crate)fnclassify(value:&CopySourceValue)->Result<CopySourceKind,CopySourceRejection>{"
if capability.count(classifier) != 1:
    fail("shared copy source classifier is missing or duplicated")
if re.search(r"#\[[^\]]*\](?:#\[[^\]]*\])*" + re.escape(classifier), capability):
    fail("shared copy source classifier must be unconditional")
if re.search(r"asclassify(?:[,;}])", capability):
    fail("shared copy source classifier has an alternate export")

for file, name in (("copy_object.rs", "CopyObject"), ("upload_part_copy.rs", "UploadPartCopy")):
    relative = f"crates/core/src/ops/{file}"
    text = source(relative)
    if text.count("usecrate::ops::shared::copy_source::{CopySourceResources,classify,seal_value};") != 1:
        fail(f"{file}: classifier override does not import the shared classifier")
    body = impl_body(text, name, file)
    expected = (
        "typeDerivedResources=CopySourceResources;"
        "fnclassify_copy_source(input:&Self::Input)->Result<Option<crate::CopySourceKind>,crate::authz::DerivedResourceError>{"
        "classify(&input.copy_source).map(Some).map_err(|error|crate::DerivedResourceError::new(error.code().clone(),error.reason()))}"
    )
    if body.count(expected) != 1 or body.count("fnclassify_copy_source(") != 1:
        fail(f"{file}: classifier override must call the shared classifier")

print("OK: both Copy operations use the shared source classifier")
PYEOF
