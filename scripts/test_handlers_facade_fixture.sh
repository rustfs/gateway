#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
FIXTURE="${REPO_ROOT}/tests/fixtures/handlers-facade"

fail() {
    printf 'test_handlers_facade_fixture: %s\n' "$*" >&2
    exit 1
}

command -v cargo >/dev/null 2>&1 || fail 'required command missing: cargo'
command -v python3 >/dev/null 2>&1 || fail 'required command missing: python3'
[[ -f "${FIXTURE}/Cargo.toml" ]] || fail 'fixture manifest is missing'
[[ -f "${FIXTURE}/src/main.rs" ]] || fail 'fixture source is missing'

fixture_copy="$(mktemp -d "${TMPDIR:-/tmp}/gateway-handlers-facade.XXXXXX")"
trap 'rm -rf "$fixture_copy"' EXIT
mkdir -p "${fixture_copy}/src"
cp "${FIXTURE}/Cargo.toml" "${fixture_copy}/Cargo.toml"
cp "${FIXTURE}/src/main.rs" "${fixture_copy}/src/main.rs"

python3 - "${fixture_copy}/Cargo.toml" "${REPO_ROOT}/crates/gateway" <<'PYEOF'
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
gateway = Path(sys.argv[2]).resolve()
text = manifest.read_text()
old = 'rustfs-gateway = { path = "../../../crates/gateway" }'
if text.count(old) != 1:
    raise SystemExit("test_handlers_facade_fixture: facade dependency is not unique")
manifest.write_text(text.replace(old, f'rustfs-gateway = {{ path = "{gateway}" }}', 1))
PYEOF

output=""
if ! output="$(
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}" \
        cargo check --quiet --manifest-path "${fixture_copy}/Cargo.toml" 2>&1
)"; then
    printf 'test_handlers_facade_fixture: facade-only downstream fixture did not compile\n%s\n' "$output" >&2
    exit 1
fi

printf 'test_handlers_facade_fixture: facade-only downstream fixture compiles\n'
