#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# WHAT THIS CHECKS
#   rustfs-gateway-difftest (crates/difftest) stays migration-only
#   (rustfs/backlog#1762, a-df-0022):
#     1. its manifest says `publish = false`;
#     2. its README's first line still says `RING 2 — migration-only`;
#     3. no package reaches it through normal or build dependencies,
#        directly or through other packages, except the fuzz crate — its own
#        workspace, a tool nothing links — and nothing may reach the fuzz
#        crate in turn. `publish = false` is no exemption: RustFS consumes
#        gateway crates by path and git, not from crates.io, so every
#        workspace member ships. Every member (read from the root
#        `[workspace].members`, globs expanded) and the fuzz crate are read;
#        `name.workspace = true` resolves through the root
#        `[workspace.dependencies]`; `[dev-dependencies]` are free.
#
# WHY
#   The differential links the pinned s3s build. It exists to be deleted with
#   the compat feature once RustFS runs on the gateway; the day something ships
#   depending on it, it cannot be.
#
# HOW TO EXEMPT
#   There is no exemption.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_difftest_not_published: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
[[ -f "${ROOT_DIR}/crates/difftest/Cargo.toml" ]] || fail 'rule input is missing: crates/difftest/Cargo.toml'
[[ -f "${ROOT_DIR}/crates/difftest/README.md" ]] || fail 'rule input is missing: crates/difftest/README.md'

python3 - "$ROOT_DIR" <<'PY'
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
NAME = "rustfs-gateway-difftest"


def fail(message: str) -> None:
    print(f"check_difftest_not_published: {message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"{path.relative_to(root)}: {error}")


own = load(root / "crates/difftest/Cargo.toml")
if own.get("package", {}).get("name") != NAME:
    fail(f"crates/difftest/Cargo.toml no longer names {NAME}")
if own["package"].get("publish") is not False:
    fail("crates/difftest/Cargo.toml must say `publish = false` (a-df-0022)")

first = (root / "crates/difftest/README.md").read_text(encoding="utf-8").splitlines()[:1]
if not first or not first[0].startswith("# RING 2 — migration-only"):
    fail("crates/difftest/README.md must open with `# RING 2 — migration-only` (a-df-0022)")


def shipping_tables(document: dict):
    for key in ("dependencies", "build-dependencies"):
        yield key, document.get(key, {})
    for target, table in document.get("target", {}).items():
        for key in ("dependencies", "build-dependencies"):
            yield f"target.{target}.{key}", table.get(key, {})


workspace = load(root / "Cargo.toml").get("workspace", {})
inherited = {
    key: (spec.get("package", key) if isinstance(spec, dict) else key)
    for key, spec in workspace.get("dependencies", {}).items()
}
manifests = []
for member in workspace.get("members", []):
    manifests += sorted(path / "Cargo.toml" for path in root.glob(member) if (path / "Cargo.toml").is_file())
manifests.append(root / "fuzz/Cargo.toml")

packages: dict[str, tuple[set[str], Path]] = {}
for manifest in manifests:
    if not manifest.is_file():
        continue
    document = load(manifest)
    package = document.get("package", {})
    name = package.get("name")
    if not isinstance(name, str):
        continue
    shipping = set()
    for _, table in shipping_tables(document):
        for key, spec in table.items():
            if isinstance(spec, dict) and spec.get("workspace") is True:
                shipping.add(inherited.get(key, key))
            else:
                shipping.add(spec.get("package", key) if isinstance(spec, dict) else key)
    packages[name] = (shipping, manifest)

if NAME not in packages:
    fail(f"{NAME} is not a workspace member")
# Every package that reaches the differential through shipping dependencies.
reaching = {NAME}
grew = True
while grew:
    grew = False
    for name, (shipping, _) in packages.items():
        if name not in reaching and shipping & reaching:
            reaching.add(name)
            grew = True
TOOLING = {"rustfs-gateway-fuzz"}
offenders = sorted(reaching - {NAME} - TOOLING)
if offenders:
    for name in offenders:
        print(f"{packages[name][1].relative_to(root)}: {name} reaches {NAME} through a normal or build dependency (a-df-0022)", file=sys.stderr)
    fail("the migration-only differential must not ship inside another crate")
print(f"check_difftest_not_published: {NAME} is publish = false and nothing ships depending on it")
PY
