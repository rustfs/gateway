#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Check actual DTO mount/path diagnostics and scanner process scaling on small fixtures."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="gateway-dto-scan-") as directory:
    base = Path(directory)
    repo = base / "repo"
    source = repo / "crates/types/src/lib.rs"
    source.parent.mkdir(parents=True)
    source.write_text('#[path = "../generated/./ops/../lib.rs"]\nmod dto;\n')
    mount = repo / "crates/types/generated"
    mount.symlink_to("../../generated/dto")
    (repo / "generated/dto").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    tools = base / "tools"
    tools.mkdir()
    counter = base / "calls"
    for name in ("dirname", "sed", "grep", "awk", "python3"):
        executable = shutil.which(name)
        assert executable, f"required tool missing: {name}"
        shim = tools / name
        shim.write_text('#!/bin/sh\nprintf "call\\n" >>"$SCAN_CALLS"\n'
                        + f'exec {shlex.quote(executable)} "$@"\n')
        shim.chmod(0o755)
    env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
               GATEWAY_CHECK_ROOT=str(repo), SCAN_CALLS=str(counter))

    def check(diagnostic=None):
        counter.write_text("")
        result = subprocess.run(["bash", str(root / "scripts/check_generated_dto_packaged.sh")],
                                env=env, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        if diagnostic is None:
            assert result.returncode == 0, output
            assert output == "", "valid fixture emitted an unexpected diagnostic: " + output
        else:
            assert result.returncode != 0 and diagnostic in output, output
        return len(counter.read_text().splitlines())

    small = check()
    assert small > 0, "scanner observer saw no processes"
    valid = source.read_text()
    source.write_text('  #[path\t= "../../../outside.rs"]\nmod dto;\n')
    check('crates/types/src/lib.rs: #[path = "../../../outside.rs"] resolves to outside.rs')
    # Existing behavior also treats an attribute in a comment as a path: optimization may not
    # silently change that lexical contract while selecting the same candidate files.
    source.write_text('// #[path = "../../../outside.rs"]\n')
    check("outside the crate directory")
    source.write_text(valid)
    nested = repo / "crates/types/src/nested space/probe.rs"
    nested.parent.mkdir()
    nested.write_text('#[path = "../../../../outside.rs"]\nmod external;\n')
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    check('crates/types/src/nested space/probe.rs: #[path = "../../../../outside.rs"] resolves to outside.rs')
    nested.unlink()  # Preserve the existing unstaged-deletion handling.
    check()
    mount.unlink()
    check("missing; rustfs-gateway-types mounts")
    mount.mkdir()
    check("is a real directory")
    mount.rmdir()
    mount.write_text("../../generated/dto")
    check("exists but is not a symlink")
    mount.unlink()
    mount.symlink_to("../../wrong/dto")
    check("expected generated/dto")
    mount.unlink()
    mount.symlink_to("../../generated/dto")
    for index in range(100):
        (source.parent / f"ordinary_{index}.rs").write_text("fn ordinary() {}\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    large = check()
    print(f"DTO scanner processes: {small} -> {large}")
    assert large <= small + 4, f"scanner process growth: {small} -> {large} for 100 irrelevant sources"
    for candidate in source.parent.rglob("*.rs"):
        candidate.unlink()
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    check()  # An empty source census must still validate the mount, without waiting for stdin.
    mount.unlink()
    check("missing; rustfs-gateway-types mounts")
print("OK: DTO path and mount checks preserve diagnostics with bounded scanner growth")
