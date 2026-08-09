#!/usr/bin/env bash
# Copyright 2026 RustFS Team
# Licensed under the Apache License, Version 2.0.

set -euo pipefail

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
AUTHZ="$ROOT/crates/core/src/authz/mod.rs"
DISPATCH="$ROOT/crates/core/src/registry/handlers.rs"
OP="$ROOT/crates/core/src/op.rs"

for input in "$AUTHZ" "$DISPATCH" "$OP"; do
    if [[ ! -f "$input" ]]; then
        printf 'check_authz_consumption.sh: required input is missing: %s\n' "$input" >&2
        exit 1
    fi
done

python3 - "$AUTHZ" "$DISPATCH" "$OP" <<'PY'
import pathlib
import re
import sys

authz = pathlib.Path(sys.argv[1]).read_text()
dispatch = pathlib.Path(sys.argv[2]).read_text()
op = pathlib.Path(sys.argv[3]).read_text()

failures = []

if not re.search(
    r"fn\s+dispatch\s*<O,\s*B>\s*\([^)]*authorized\s*:\s*Authorized\s*<O>",
    dispatch,
    re.S,
):
    failures.append("dispatch must accept Authorized<O>, never Decoded<O> or Req<O>")

start = authz.find("impl<O: Operation> Authorized<O>")
if start < 0:
    failures.append("Authorized<O> impl is missing")
else:
    brace = authz.find("{", start)
    depth = 0
    end = None
    for index in range(brace, len(authz)):
        if authz[index] == "{":
            depth += 1
        elif authz[index] == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    block = authz[brace:end + 1] if end is not None else ""
    if re.search(r"pub\s+(?:const\s+)?fn\s+\w+\s*\([^)]*\)\s*->\s*Self", block, re.S):
        failures.append("Authorized<O> must have no public constructor returning Self")

read_match = re.search(r"pub\s+struct\s+AuthorizedRead\s*\{(?P<body>[^}]*)\}", authz, re.S)
if read_match is None or re.search(r"\bpub\b", read_match.group("body")):
    failures.append("AuthorizedRead must exist with private fields")

if re.search(r"pub\s+(?:const\s+)?fn\s+authorize_input", authz):
    failures.append("authorize_input must remain crate-private")

if re.search(r"pub\s+type\s+ErasedRequest\s*=", dispatch) or not re.search(
    r"pub\s+struct\s+ErasedRequest\s*\(\s*Box<dyn\s+Any\s*\+\s*Send>\s*\)\s*;",
    dispatch,
):
    failures.append("ErasedRequest must keep its authorization payload opaque")

trait_start = op.find("pub trait Operation")
trait_end = op.find("/// The reverse mapping", trait_start)
trait = op[trait_start:trait_end]
if not re.search(r"type\s+DerivedResources\s*:\s*DerivedResourceSet\s*;", trait):
    failures.append("Operation::DerivedResources must be mandatory and have no default")
if "fn derive_resources" not in trait:
    failures.append("Operation::derive_resources is missing")
if "fn seal_derived_input" not in trait:
    failures.append("Operation::seal_derived_input is missing")

if failures:
    for failure in failures:
        print(f"check_authz_consumption.sh: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("OK: authorization consumption boundary is structural")
PY
