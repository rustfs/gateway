#!/usr/bin/env bash
set -euo pipefail

# WHAT: Compile-checks `rdma/Cargo.toml` (`--features rdma --lib`) on the workspace toolchain
#       against a synthetic stand-in `vendor/rustfs-ucx` crate in a temporary staging directory,
#       without touching the repository checkout or contacting the private transport repository.
# WHY:  rustfs/gateway#1634 found `rdma/Cargo.toml` had bitrotted to `rust-version = "1.98.1"`
#       because CI never ran `cargo check` on `rdma/Cargo.toml` or `rustfs-gateway` with
#       `default-features = false, features = ["external-payload"]`.
# HOW TO EXEMPT: There is no exemption; keep `rdma/Cargo.toml` and the public `external-payload`
#       ports compiling on the workspace toolchain.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

[[ -f "${ROOT_DIR}/rdma/Cargo.toml" ]] || {
    printf 'verify_rdma_manifest: required input is missing: rdma/Cargo.toml\n' >&2
    exit 1
}

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/gateway-rdma-check.XXXXXX")"
cleanup() {
    rm -rf "$STAGING"
}
trap cleanup EXIT

mkdir -p "${STAGING}/rdma" "${STAGING}/vendor/rustfs-ucx/src" "${STAGING}/vendor/rustfs-ucx/integrations/gateway/src"
python3 - "${ROOT_DIR}" "${STAGING}" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
staging = Path(sys.argv[2]).resolve()
manifest = (root / "rdma/Cargo.toml").read_text(encoding="utf-8")
rewritten = manifest.replace('path = "../crates/', f'path = "{root}/crates/')
if rewritten == manifest:
    raise SystemExit("verify_rdma_manifest: rdma/Cargo.toml no longer depends on ../crates/*")
(staging / "rdma/Cargo.toml").write_text(rewritten, encoding="utf-8")
PY
if [[ -f "${ROOT_DIR}/Cargo.lock" ]]; then
    cp "${ROOT_DIR}/Cargo.lock" "${STAGING}/rdma/Cargo.lock"
fi

cat >"${STAGING}/vendor/rustfs-ucx/Cargo.toml" <<'TOML'
[package]
name = "rustfs-ucx"
version = "0.0.0"
edition = "2024"
publish = false

[features]
default = []
native = []
TOML

cat >"${STAGING}/vendor/rustfs-ucx/src/lib.rs" <<'RS'
//! Synthetic stand-in transport crate for CI compile verification of `rdma/Cargo.toml`.
pub const STAND_IN_NATIVE_ENABLED: bool = cfg!(feature = "native");
RS

cat >"${STAGING}/vendor/rustfs-ucx/integrations/gateway/src/lib.rs" <<'RS'
//! Synthetic stand-in integration entry verifying `rdma/Cargo.toml` and public `external-payload`
//! ports compile on the workspace toolchain without requiring the private `rustfs-ucx` checkout.

pub use rustfs_gateway::external_payload::{
    ExternalPayloadBinding, ExternalPayloadExchange, ExternalPayloadProvider, ExternalPayloadResponse,
    ExternalRequest, ExternalResponseConsumer,
};
pub use rustfs_gateway_core::external_payload::{
    ExternalPayloadContext, ExternalPayloadControl, ExternalPayloadError, ExternalPayloadExecution,
    ExternalPayloadHandler,
};
pub use rustfs_gateway_stream::ByteStream;

pub const fn native_feature_wired() -> bool {
    rustfs_ucx::STAND_IN_NATIVE_ENABLED
}
RS

TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT_DIR}/target}"
CARGO_TARGET_DIR="$TARGET_DIR" cargo check \
    --manifest-path "${STAGING}/rdma/Cargo.toml" \
    --features rdma \
    --lib

printf 'OK: rdma/Cargo.toml compiles with --features rdma against public external-payload ports\n'
