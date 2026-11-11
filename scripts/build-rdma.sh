#!/usr/bin/env bash
set -euo pipefail

# The private transport source is not a submodule: Cargo initialises every submodule of a git
# dependency, so one a consumer cannot fetch breaks the whole repository for them (#1591). The
# commit is pinned in rdma/rustfs-ucx.rev instead, and this script never fetches it: a build helper
# that reaches a private remote on its own would prompt for credentials or touch the network
# whenever someone only meant to compile. It prints the command and verifies the result.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
private="$ROOT_DIR/vendor/rustfs-ucx"
pin="$ROOT_DIR/rdma/rustfs-ucx.rev"

refuse() {
    printf '%s\n' "$@" >&2
    exit 2
}

[[ -f "$pin" ]] || refuse "The RDMA pin file rdma/rustfs-ucx.rev is missing; it records which private commit to build."

url=""
rev=""
branch=""
lineno=0
while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    case "$line" in
        '' | '#'*) continue ;;
        'url = '*) key=url value="${line#url = }" ;;
        'rev = '*) key=rev value="${line#rev = }" ;;
        'branch = '*) key=branch value="${line#branch = }" ;;
        *) refuse "rdma/rustfs-ucx.rev:${lineno}: expected 'url = ', 'branch = ' or 'rev = ', found: ${line}" ;;
    esac
    [[ -n "$value" ]] || refuse "rdma/rustfs-ucx.rev:${lineno}: '${key}' has no value."
    [[ -z "${!key}" ]] || refuse "rdma/rustfs-ucx.rev:${lineno}: '${key}' is recorded more than once."
    printf -v "$key" '%s' "$value"
done <"$pin"
[[ -n "$url" ]] || refuse "rdma/rustfs-ucx.rev records no 'url = ' line."
[[ "$rev" =~ ^[0-9a-f]{40}$ ]] ||
    refuse "rdma/rustfs-ucx.rev must record 'rev = ' as a full 40-character lowercase commit id; found '${rev}'."

if [[ ! -d "$private" ]] || [[ -z "$(ls -A "$private" 2>/dev/null)" ]]; then
    refuse 'RDMA requires the authorized private checkout vendor/rustfs-ucx, pinned in rdma/rustfs-ucx.rev.' \
        "Run: git clone ${url} ${private} && git -C ${private} checkout --detach ${rev}" \
        'Authenticate with an account that can read rustfs/rustfs-ucx.'
fi

command -v git >/dev/null 2>&1 || refuse 'Verifying vendor/rustfs-ucx requires git, which is not on PATH.'

# Without this check a plain directory would resolve to the enclosing gateway repository, and its
# HEAD would be compared against the pin instead of the private checkout's.
toplevel="$(git -C "$private" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$toplevel" || "$(cd "$toplevel" && pwd -P)" != "$(cd "$private" && pwd -P)" ]]; then
    refuse 'vendor/rustfs-ucx exists but is not a git checkout of its own, so its commit cannot be verified.' \
        "Remove it, then run: git clone ${url} ${private} && git -C ${private} checkout --detach ${rev}"
fi
actual="$(git -C "$private" rev-parse --verify --quiet 'HEAD^{commit}' 2>/dev/null || true)"
if [[ "$actual" != "$rev" ]]; then
    refuse "vendor/rustfs-ucx is checked out at ${actual:-no commit}, but rdma/rustfs-ucx.rev pins ${rev}." \
        "Run: git -C ${private} fetch origin && git -C ${private} checkout --detach ${rev}"
fi

if [[ ! -f "$private/Cargo.toml" || ! -f "$private/integrations/gateway/src/lib.rs" || ! -f "$private/scripts/build-env.sh" ]]; then
    refuse 'RDMA requires the authorized private checkout vendor/rustfs-ucx.' \
        "The checkout at ${rev} lacks Cargo.toml, integrations/gateway/src/lib.rs or scripts/build-env.sh." \
        'Authenticate with an account that can read rustfs/rustfs-ucx.'
fi

source "$private/scripts/build-env.sh"

exec cargo "+${RUSTFS_RDMA_TOOLCHAIN:-1.98.1}" build \
    --manifest-path "$ROOT_DIR/rdma/Cargo.toml" --features rdma \
    -j "${CARGO_BUILD_JOBS:-2}" "$@"
