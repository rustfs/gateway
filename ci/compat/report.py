#!/usr/bin/env python3
"""Client-matrix preflight and aggregation.

Responsible for: refusing to run against unpinned or drifted clients, turning the per-cell driver
results and the server's own wire records into `compat/matrix.json`, and applying the same
KNOWN / REGRESSION / FIXED verdicts the conformance baseline uses.
NOT responsible for: running any client, starting the system under test, or rendering the README
table. Those are `ci/compat/run_matrix.sh` and `scripts/gen_compat_table.sh`.

Exit codes: 0 = no regression, 1 = at least one regression, 3 = the environment or a driver is
broken, which is deliberately not the same as "every scenario failed": recording a broken
environment as a wall of failures is how a baseline gets poisoned.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

OK = 0
REGRESSION = 1
ENVIRONMENT = 3

STREAMING_SIGNED = re.compile(r"^STREAMING-AWS4-HMAC-SHA256-PAYLOAD(-TRAILER)?$")


def problem(message: str) -> int:
    print(f"compat: {message}", file=sys.stderr)
    return ENVIRONMENT


# ---------------------------------------------------------------------------------------------
# Scenario and manifest inputs
# ---------------------------------------------------------------------------------------------


def load_scenarios(directory: Path) -> dict:
    try:
        import yaml
    except ImportError as error:  # pragma: no cover - reported, never swallowed
        raise SystemExit(problem(f"PyYAML is required to read scenario definitions: {error}"))
    scenarios = {}
    for path in sorted(directory.glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or "id" not in document:
            raise SystemExit(problem(f"{path} is not a scenario definition"))
        if document["id"] != path.stem:
            raise SystemExit(problem(f"{path} declares id {document['id']!r}, which is not its file name"))
        scenarios[document["id"]] = document
    if not scenarios:
        raise SystemExit(problem(f"no scenarios found under {directory}"))
    return scenarios


def load_versions(path: Path) -> dict:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    clients = document.get("clients")
    if not isinstance(clients, dict) or not clients:
        raise SystemExit(problem(f"{path} declares no clients"))
    return clients


def load_known_fail(path: Path) -> dict[str, dict[str, str]]:
    """Read the excused-failure list as `<client>/<scenario>  <issue>  <reason>`.

    The issue reference is required: it is what the manifest carries beside the cell so a reader
    can tell an owned gap from an unowned one without leaving the file.
    """
    entries: dict[str, dict[str, str]] = {}
    if not path.is_file():
        raise SystemExit(problem(f"required input is missing: {path}"))
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        # A comment is a line that starts with `#`. It cannot be a trailing comment, because the
        # issue reference on every entry contains one.
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            raise SystemExit(
                problem(f"{path}:{number}: expected <client>/<scenario> <issue> <reason>, found {line!r}")
            )
        cell, issue, reason = parts[0], parts[1], parts[2].strip()
        if cell.count("/") != 1:
            raise SystemExit(problem(f"{path}:{number}: expected <client>/<scenario>, found {cell!r}"))
        if not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+#[0-9]+", issue):
            raise SystemExit(problem(f"{path}:{number}: {issue!r} is not an <owner>/<repo>#<number> reference"))
        entries[cell] = {"issue": issue, "reason": reason}
    return entries


# ---------------------------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------------------------


def observed_version(name: str, spec: dict) -> str:
    install = spec.get("install")
    if install == "pip":
        package = spec["package"]
        code = f"import {package}; print({package}.__version__)"
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return f"<not installed: {result.stderr.strip().splitlines()[-1] if result.stderr.strip() else 'unknown'}>"
        return result.stdout.strip()
    if install == "go":
        binary = shutil.which(spec["binary"])
        if binary is None:
            return f"<not on PATH: {spec['binary']}>"
        result = subprocess.run(["go", "version", "-m", binary], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            # `go version -m` needs the binary on PATH and a Go toolchain. Both are the runner's
            # job to provide, so their absence is an environment problem, not a client version.
            return f"<unreadable: {result.stderr.strip().splitlines()[-1] if result.stderr.strip() else 'unknown'}>"
        wanted = spec["module_version_path"]
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0] == "mod" and fields[1] == wanted:
                return fields[2]
        return "<no module version recorded in the binary>"
    raise SystemExit(problem(f"client {name} declares an unknown install method {install!r}"))


def declared_capabilities(path: Path) -> list[str]:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    operations = document.get("operations")
    if not isinstance(operations, list) or not operations:
        raise SystemExit(problem(f"{path} declares no operations"))
    return sorted(str(name) for name in operations)


def preflight(arguments: argparse.Namespace) -> int:
    clients = load_versions(Path(arguments.versions))
    declared = declared_capabilities(Path(arguments.capabilities))
    actual = sorted(
        line.strip()
        for line in Path(arguments.sut_capabilities).read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    failures = []
    if declared != actual:
        failures.append(
            "compat/capabilities.toml does not match the system under test's registry: "
            f"undeclared={sorted(set(actual) - set(declared))}, "
            f"declared-but-absent={sorted(set(declared) - set(actual))}"
        )
    for name, spec in sorted(clients.items()):
        pinned = str(spec.get("version", ""))
        found = observed_version(name, spec)
        if found != pinned:
            failures.append(f"client {name} is pinned at {pinned} but the installed one reports {found}")
        else:
            print(f"compat: {name} {found} matches its pin")
    if failures:
        for line in failures:
            print(f"compat: {line}", file=sys.stderr)
        return ENVIRONMENT
    print(f"OK: {len(clients)} client(s) pinned, {len(actual)} operation(s) declared")
    return OK


# ---------------------------------------------------------------------------------------------
# Wire assertions
# ---------------------------------------------------------------------------------------------


def evaluate_wire_assertions(assertions: list, records: list[dict]) -> tuple[bool, str, dict]:
    """Judge a scenario against what the server recorded, not against the driver's exit code."""
    evidence = {
        "requests": len(records),
        "payload_modes": sorted({record.get("payload_mode", "") for record in records if record.get("payload_mode")}),
        "max_signed_chunks": max((record.get("signed_chunks", 0) for record in records), default=0),
        "trailer_signatures": max((record.get("trailer_signature", 0) for record in records), default=0),
        "content_encodings": sorted({record.get("content_encoding", "") for record in records if record.get("content_encoding")}),
        "declared_trailers": sorted({record.get("declared_trailer", "") for record in records if record.get("declared_trailer")}),
    }
    if not records:
        return False, "the system under test recorded no request for this scenario", evidence
    for assertion in assertions:
        if not isinstance(assertion, dict) or len(assertion) != 1:
            return False, f"malformed wire assertion {assertion!r}", evidence
        (kind, value), = assertion.items()
        if kind == "payload_mode_matches":
            pattern = re.compile(value)
            if not any(pattern.match(record.get("payload_mode", "")) for record in records):
                return False, f"no request declared a payload mode matching {value}", evidence
        elif kind == "signed_chunks_gte":
            if evidence["max_signed_chunks"] < int(value):
                return (
                    False,
                    f"the largest request carried {evidence['max_signed_chunks']} signed chunk(s), expected at least {value}",
                    evidence,
                )
        elif kind == "content_encoding_contains":
            if not any(value in record.get("content_encoding", "") for record in records):
                return False, f"no request declared a content encoding containing {value!r}", evidence
        elif kind == "declared_trailer_present":
            present = any(record.get("declared_trailer") for record in records)
            if present != bool(value):
                return False, "no request declared a trailing header", evidence
        elif kind == "status_observed":
            if not any(record.get("status") == int(value) for record in records):
                return False, f"no request was answered {value}", evidence
        else:
            return False, f"unknown wire assertion {kind!r}", evidence
    return True, "", evidence


# ---------------------------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------------------------


def git_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() or "unknown"


def aggregate(arguments: argparse.Namespace) -> int:
    root = Path(arguments.root)
    scenarios = load_scenarios(Path(arguments.scenarios))
    clients = load_versions(Path(arguments.versions))
    known_fail = load_known_fail(Path(arguments.known_fail))
    results_dir = Path(arguments.results)

    driver_errors: list[str] = []
    clients_out = []
    summary = {"pass": 0, "fail": 0, "unsupported": 0}
    verdicts = {"KNOWN": 0, "REGRESSION": 0, "FIXED": 0, "STALE": 0}
    regressions: list[str] = []
    fixed: list[str] = []
    streaming_clients: set[str] = set()
    seen_cells: set[str] = set()

    for client in sorted(clients):
        rows = []
        for scenario_id in sorted(scenarios):
            cell = f"{client}/{scenario_id}"
            seen_cells.add(cell)
            path = results_dir / client / f"{scenario_id}.json"
            if not path.is_file():
                if arguments.allow_missing:
                    continue
                driver_errors.append(f"{cell}: the runner recorded no result file")
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
            status, detail, evidence = resolve_cell(raw, scenarios[scenario_id], driver_errors, cell)
            if any(STREAMING_SIGNED.match(record.get("payload_mode", "")) for record in raw.get("probe", [])):
                streaming_clients.add(client)
            verdict = None
            if status == "fail":
                if cell in known_fail:
                    verdict = "KNOWN"
                else:
                    verdict = "REGRESSION"
                    regressions.append(f"{cell}: {detail}")
            elif cell in known_fail:
                verdict = "FIXED" if status == "pass" else "STALE"
                fixed.append(f"{cell} is recorded in known-fail.txt but now reports {status}")
            if verdict:
                verdicts[verdict] += 1
            summary[status] += 1
            rows.append(
                {
                    "id": scenario_id,
                    "status": status,
                    "detail": detail or None,
                    "verdict": verdict,
                    # The owning issue travels with the cell. A manifest that says only "known"
                    # tells a reader it was excused but not by whom or for how long.
                    "issue": known_fail[cell]["issue"] if cell in known_fail else None,
                    "evidence": evidence,
                }
            )
        clients_out.append({"name": client, "version": str(clients[client].get("version", "")), "scenarios": rows})

    for cell in sorted(set(known_fail) - seen_cells) if not arguments.allow_missing else []:
        driver_errors.append(f"known-fail.txt names {cell}, which is not a client/scenario this matrix runs")

    if driver_errors:
        for line in driver_errors:
            print(f"compat: {line}", file=sys.stderr)
        return ENVIRONMENT

    capabilities = declared_capabilities(Path(arguments.capabilities))
    matrix = {
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "sut": {
            # Named in full, and machine-readable, so a later reader can tell exactly what answered
            # these rows. Generation 1 was measured against `compat-sut`: the binary this task added
            # to assemble the reference backend behind a real listener, because until then the
            # workspace shipped no runnable S3 server at all (rustfs/gateway#624). It is the
            # production `S3Service` with real SigV4 verification, not a mock — but it is also not
            # the general-purpose server binary that issue asks for, so the identity is recorded
            # rather than assumed, and these rows must be re-measured when that binary lands.
            # Generation 2 (rustfs/gateway#719): the same binary also serves a TLS listener with a
            # throwaway authority, and a scenario a client can only express over TLS (boto3's
            # x-amz-trailer upload) is measured there. The assembly changed, so the rows are a new
            # generation even though the binary name did not.
            "name": "rustfs-gateway-fs",
            "version": arguments.sut_version,
            "commit": git_commit(root),
            "generation": 2,
            "binary": "compat-sut",
            "package": "rustfs-gateway-compat-sut",
            "assembly": (
                "rustfs-gateway-fs behind rustfs-gateway-server, SigV4 verified, plaintext plus a TLS "
                "listener (throwaway self-signed authority) for TLS-only scenarios"
            ),
            "provisional": True,
            "provisional_reason": (
                "measured against the matrix's own launcher; the general-purpose server binary is "
                "tracked in rustfs/gateway#624 and these rows are re-measured when it lands"
            ),
            "capabilities": capabilities,
        },
        "clients": clients_out,
        "summary": summary | {key.lower(): value for key, value in verdicts.items()},
        "streaming_signed_clients": sorted(streaming_clients),
    }
    Path(arguments.out).write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")

    print(
        f"compat: pass={summary['pass']} fail={summary['fail']} unsupported={summary['unsupported']} "
        f"known={verdicts['KNOWN']} regression={verdicts['REGRESSION']} fixed={verdicts['FIXED']}"
    )
    print(f"compat: clients emitting STREAMING-AWS4-HMAC-SHA256: {sorted(streaming_clients) or 'none'}")
    for line in fixed:
        print(f"compat: FIXED — remove it from compat/known-fail.txt: {line}")
    if regressions:
        for line in regressions:
            print(f"compat: REGRESSION {line}", file=sys.stderr)
        return REGRESSION
    return OK


def resolve_cell(raw: dict, scenario: dict, driver_errors: list[str], cell: str) -> tuple[str, str, dict]:
    if raw.get("skipped_reason"):
        return "unsupported", raw["skipped_reason"], {}
    if raw.get("timed_out"):
        return "fail", f"the client did not finish within {raw.get('timeout_seconds')}s", {}
    driver = raw.get("driver")
    if driver is None:
        # a-cm-0017: a driver whose output cannot be read is named, and the run is an environment
        # failure. Dropping the cell silently would leave a hole that reads like a skip.
        driver_errors.append(
            f"{cell}: the driver did not print a result object (exit {raw.get('exit_code')}): "
            f"{(raw.get('stdout') or '').strip()[:200]!r}"
        )
        return "fail", "driver output format error", {}
    status = driver.get("status")
    if status not in {"pass", "fail", "unsupported"}:
        driver_errors.append(f"{cell}: the driver reported an unknown status {status!r}")
        return "fail", "driver output format error", {}
    detail = driver.get("detail") or ""
    evidence = dict(driver.get("evidence") or {})
    assertions = scenario.get("wire_assertions") or []
    if assertions and status == "pass":
        satisfied, reason, wire = evaluate_wire_assertions(assertions, raw.get("probe", []))
        evidence["wire"] = wire
        if not satisfied:
            return "fail", reason, evidence
    elif assertions:
        evidence["wire"] = evaluate_wire_assertions([], raw.get("probe", []))[2]
    return status, detail, evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    check = subcommands.add_parser("preflight", help="refuse to run against unpinned or drifted clients")
    check.add_argument("--versions", required=True)
    check.add_argument("--capabilities", required=True)
    check.add_argument("--sut-capabilities", required=True)
    check.set_defaults(handler=preflight)

    build = subcommands.add_parser("aggregate", help="turn per-cell results into compat/matrix.json")
    build.add_argument("--root", required=True)
    build.add_argument("--results", required=True)
    build.add_argument("--scenarios", required=True)
    build.add_argument("--versions", required=True)
    build.add_argument("--capabilities", required=True)
    build.add_argument("--known-fail", required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--sut-version", required=True)
    build.add_argument(
        "--allow-missing",
        action="store_true",
        help="tolerate cells the run did not cover, for a filtered local run only",
    )
    build.set_defaults(handler=aggregate)

    arguments = parser.parse_args()
    return arguments.handler(arguments)


if __name__ == "__main__":
    sys.exit(main())
