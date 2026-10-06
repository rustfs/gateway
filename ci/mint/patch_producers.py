#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Apply narrow producer corrections to externally acquired Mint source files.

Owns byte-verified edits, not source fetching, dependency resolution, image
building, or SDK assertions. The caller must supply a reviewed source SHA-256;
computing it from an unverified download would defeat that precondition.
Existing copyright/license text and all unrelated bytes remain intact.

Source shapes reviewed for rustfs/gateway#720:
- minio/minio-dotnet@ac5dc79dfdd35b425f98233f55f8227aa705afb9
- minio/mint@12559d50625b722d11fd798ae8ac2fb204e66dd1
- minio/mc@7394ce0dd2a80935aded936b09fa12cbb3cb8096
The launcher and mc source hashes were verified against the pinned Mint image on 2026-09-23.
The MC stdin-test diagnostic correction is tracked by rustfs/gateway#1270.
Fixed failure-stage labels for its existing assertions are tracked by #1275.
"""
import argparse
import hashlib
from pathlib import Path


def replace_line(source: str, old: str, new: str) -> str:
    """Reject missing, duplicated, or already edited statement lines."""
    lines = source.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.strip() == old]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one unchanged statement: {old}")
    i = matches[0]
    lines[i] = lines[i].replace(old, new, 1)
    return "".join(lines)


def transform(kind: str, source: str) -> str:
    if kind == "logger":
        source = replace_line(source, "WriteIndented = false,",
                              "WriteIndented = false,\n        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,")
        source = replace_line(source, 'Name = $"{Name} : {testName}";', "TestName = testName;")
        return replace_line(source, 'public string Name { get; } = "minio-dotnet";',
                            'public string Name { get; } = "minio-dotnet";\n\n    public string TestName { get; }')
    if kind == "dotnet-runner":
        if source.count("/mint/run/core/minio-dotnet/out/Minio.Functional.Tests") != 1:
            raise ValueError("expected one original functional executable path")
        old = '/mint/run/core/minio-dotnet/out/Minio.Functional.Tests 1>>"$output_log_file" 2>"$error_log_file"'
        return replace_line(source, old, old.replace("/mint/run/core/minio-dotnet/out/", "/opt/mint-dotnet/"))
    if kind == "mc":
        marker = "function validate_dependencies() {\n"
        if source.count(marker) != 1:
            raise ValueError("expected one validate_dependencies function")
        begin = source.index(marker) + len(marker)
        end = source.find("\n}", begin)
        if end < 0:
            raise ValueError("missing validate_dependencies closing brace")
        for statement in ('echo "Dependency validation complete"',
                          'echo "jq is missing, please install: \'sudo apt install jq\'"'):
            if not any(line.strip() == statement for line in source[begin:end].splitlines()):
                raise ValueError("dependency diagnostic moved outside validate_dependencies")
            source = replace_line(source, statement, statement + " >&2")
            # The first edit changes the function's length.
            end = source.find("\n}", begin)
        marker = "function test_cat_stdin() {\n"
        if source.count(marker) != 1:
            raise ValueError("expected one test_cat_stdin function")
        begin = source.index(marker) + len(marker)
        end = source.find("\n}", begin)
        if end < 0:
            raise ValueError("missing test_cat_stdin closing brace")
        body = source[begin:end]
        for statement in ('mc_cmd mb "${SERVER_ALIAS}/${bucket_name}"',
                          'echo "testcontent" | mc_cmd pipe "${SERVER_ALIAS}/${bucket_name}/${object_name}"'):
            body = replace_line(body, statement, statement + " >&2")
        prefix = 'assert_success "$start_time" "${FUNCNAME[0]}" '
        for command, stage in (("show_on_failure", "cat_status"),
                               ("check_md5sum", "checksum"), ("mc_cmd rm", "cleanup")):
            matches = [line.strip() for line in body.splitlines()
                       if line.strip().startswith(prefix + command + " ")]
            if len(matches) != 1:
                raise ValueError(f"expected one unchanged stdin assertion: {command}")
            statement = matches[0]
            labelled = statement.replace('"${FUNCNAME[0]}"', '"${FUNCNAME[0]}:' + stage + '"', 1)
            body = replace_line(body, statement, labelled)
        return source[:begin] + body + source[end:]
    raise ValueError(f"unknown producer kind: {kind}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("logger", "dotnet-runner", "mc"))
    parser.add_argument("source", type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        original = args.source.read_bytes()
        if hashlib.sha256(original).hexdigest() != args.sha256:
            raise ValueError("source SHA-256 mismatch; refusing to patch")
        patched = transform(args.kind, original.decode("utf-8"))
        date = "2026-10-07" if args.kind == "mc" else "2026-09-23"
        notice = f"Modified by RustFS Team on {date}: correct Mint record production.\n"
        if args.kind == "logger":
            patched = "// " + notice + patched
        else:
            first, separator, rest = patched.partition("\n")
            if not first.startswith("#!") or not separator:
                raise ValueError("expected script shebang before modification notice")
            patched = first + separator + "# " + notice + rest
        args.source.write_bytes(patched.encode("utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(1, f"patch_producers: {error}\n")


if __name__ == "__main__":
    main()
