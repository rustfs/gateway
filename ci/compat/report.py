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

A cell that is neither a pass nor a fail is one of two skips, and they are never merged:
`client-unsupported` is a driver's statement that its client cannot express the scenario, and
`sut-unregistered` is the server's: the launcher's own registry lacks an operation the scenario
needs, or — against an external endpoint, whose registry nobody here can read — the endpoint
answered `501` or `405` to a request of a cell that then failed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
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

# Every status a manifest cell may carry, in the order the summary prints them.
STATUSES = ("pass", "fail", "client-unsupported", "sut-unregistered")

# The answers by which a server says it does not serve what it was asked: `501 NotImplemented`
# for an operation with no handler, `405 MethodNotAllowed` for a method its router does not route.
UNREGISTERED_ANSWERS = (501, 405)

# What answered the rows. `gateway-fs` is this repository's launcher, whose registry the run
# reads before any client starts; `external` is an endpoint started elsewhere and observed through
# `compat-sut --external`, whose registry is known only from its answers.
SUT_KINDS = ("gateway-fs", "external")


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
    if install in {"venv", "program"}:
        return commanded_version(name, spec)
    raise SystemExit(problem(f"client {name} declares an unknown install method {install!r}"))


def clients_dir() -> Path:
    return Path(os.environ.get("COMPAT_CLIENTS_DIR") or Path(__file__).resolve().parents[2] / "target/compat-clients")


def commanded_version(name: str, spec: dict) -> str:
    """Ask the installed client what it is, and read the version out of its own answer.

    For a `program` client the answer comes from the SDK the program linked, not from its lock
    file: a lock file says what was asked for, and only the artefact says what was built.
    """
    environment = dict(os.environ)
    environment["COMPAT_CLIENT_OUT"] = str(clients_dir() / name)
    environment["PATH"] = f"{clients_dir() / 'bin'}{os.pathsep}{environment.get('PATH', '')}"
    try:
        result = subprocess.run(
            ["bash", "-c", spec["version_command"]],
            capture_output=True,
            text=True,
            check=False,
            env=environment,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return "<version command did not finish within 120s>"
    if result.returncode != 0:
        tail = (result.stderr.strip() or result.stdout.strip()).splitlines()
        return f"<version command exited {result.returncode}: {tail[-1] if tail else 'no output'}>"
    pattern = re.compile(spec.get("version_pattern") or r"^(\S+)$")
    found = [match.group(1) for line in result.stdout.splitlines() if (match := pattern.search(line.strip()))]
    if len(found) != 1:
        return f"<version command printed {len(found)} line(s) matching {pattern.pattern!r}>"
    return found[0]


def declared_capabilities(path: Path) -> list[str]:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    operations = document.get("operations")
    if not isinstance(operations, list) or not operations:
        raise SystemExit(problem(f"{path} declares no operations"))
    return sorted(str(name) for name in operations)


def preflight(arguments: argparse.Namespace) -> int:
    clients = load_versions(Path(arguments.versions))
    failures = []
    actual: list[str] = []
    if arguments.sut_capabilities:
        declared = declared_capabilities(Path(arguments.capabilities))
        actual = sorted(
            line.strip()
            for line in Path(arguments.sut_capabilities).read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
        if declared != actual:
            failures.append(
                "compat/capabilities.toml does not match the system under test's registry: "
                f"undeclared={sorted(set(actual) - set(declared))}, "
                f"declared-but-absent={sorted(set(declared) - set(actual))}"
            )
    else:
        # An external endpoint publishes no registry. Nothing is skipped before it runs; what it
        # does not serve is read from its answers, cell by cell.
        print("compat: the system under test is external; its registry is read from its answers")
    selected = {name for name in (arguments.clients or "").split(",") if name}
    unknown = sorted(selected - set(clients))
    if unknown:
        failures.append(f"--clients names undeclared client(s) {unknown}")
    for name, spec in sorted(clients.items()):
        # A filtered run checks the clients it is about to run, and only those: a local run of one
        # cell must not need all thirteen toolchains installed.
        if selected and name not in selected:
            continue
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
    checked = len(selected) if selected else len(clients)
    print(f"OK: {checked} client(s) pinned, {len(actual)} operation(s) declared")
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


def measured_against(kind: str, endpoint_build: str | None, product: str | None) -> dict:
    """The manifest's record of what answered it.

    `endpoint_build` is the endpoint's own `Server` header, read once before any client runs, or
    `None` when it sent none. `product` is the operator's declaration of what the endpoint is; it
    is required for an external endpoint because the rule that a RustFS endpoint registers every
    operation the matrix needs (`scripts/check_compat_matrix.sh`) keys on it, and a missing input
    must stop the run rather than switch that rule off.
    """
    if kind not in SUT_KINDS:
        raise ValueError(f"the system under test must be one of {SUT_KINDS}, not {kind!r}")
    if kind == "gateway-fs":
        if endpoint_build is not None or product is not None:
            raise ValueError("the launcher is named by the sut block; an endpoint build or product belongs to an external endpoint")
        return {"sut": "gateway-fs"}
    if not (product or "").strip():
        raise ValueError("an external system under test needs --product, the name of what it is")
    return {"sut": "external", "endpoint_build": endpoint_build, "product": product.strip()}


def sut_block(arguments: argparse.Namespace, root: Path, capabilities: list[str]) -> dict:
    """The `sut` block: the launcher's full identity, or the external endpoint's known part."""
    if arguments.sut_kind == "external":
        # Nothing here can read an external server's commit or registry. What is known is
        # recorded, what is not is said, and the harness commit is named as the harness's.
        return {
            "name": arguments.product,
            "version": arguments.endpoint_build or "unreported",
            "commit": "unreported",
            "generation": SUT_GENERATION,
            "binary": "external",
            "package": "external",
            "assembly": (
                f"an external endpoint at {arguments.endpoint}, observed through compat-sut --external: no "
                "filesystem backend; the observer forwards every request unchanged, and TLS, when a scenario "
                "uses it, terminates at the observer"
            ),
            "provisional": False,
            "harness_commit": git_commit(root),
        }
    return {
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
        "generation": SUT_GENERATION,
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
    }


SUT_GENERATION = 2


def aggregate(arguments: argparse.Namespace) -> int:
    root = Path(arguments.root)
    try:
        against = measured_against(
            arguments.sut_kind,
            (arguments.endpoint_build or None) if arguments.sut_kind == "external" else None,
            arguments.product if arguments.sut_kind == "external" else None,
        )
    except ValueError as error:
        return problem(str(error))
    if arguments.sut_kind == "gateway-fs" and (arguments.product or arguments.endpoint):
        return problem("--product and --endpoint describe an external endpoint; the launcher is named by its build")
    if arguments.sut_kind == "external" and not arguments.endpoint:
        return problem("an external system under test needs --endpoint")
    external = arguments.sut_kind == "external"
    scenarios = load_scenarios(Path(arguments.scenarios))
    clients = load_versions(Path(arguments.versions))
    known_fail = load_known_fail(Path(arguments.known_fail))
    results_dir = Path(arguments.results)

    driver_errors: list[str] = []
    clients_out = []
    summary = {status: 0 for status in STATUSES}
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
            status, detail, evidence = resolve_cell(raw, scenarios[scenario_id], driver_errors, cell, external=external)
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

    capabilities = [] if external else declared_capabilities(Path(arguments.capabilities))
    matrix = {
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "measured_against": against,
        "sut": sut_block(arguments, root, capabilities),
        "clients": clients_out,
        "summary": summary | {key.lower(): value for key, value in verdicts.items()},
        "streaming_signed_clients": sorted(streaming_clients),
    }
    Path(arguments.out).write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")

    print(
        f"compat: pass={summary['pass']} fail={summary['fail']} "
        f"client-unsupported={summary['client-unsupported']} sut-unregistered={summary['sut-unregistered']} "
        f"known={verdicts['KNOWN']} regression={verdicts['REGRESSION']} fixed={verdicts['FIXED']}"
    )
    print(f"compat: measured against {json.dumps(against, sort_keys=True)}")
    print(f"compat: clients emitting STREAMING-AWS4-HMAC-SHA256: {sorted(streaming_clients) or 'none'}")
    for line in fixed:
        print(f"compat: FIXED — remove it from compat/known-fail.txt: {line}")
    if regressions:
        for line in regressions:
            print(f"compat: REGRESSION {line}", file=sys.stderr)
        return REGRESSION
    return OK


def unregistered_answers(records: list[dict]) -> list[dict]:
    """The requests an external endpoint answered as not served: `501` or `405`, from upstream."""
    return [
        {"method": record.get("method", ""), "path": record.get("path", ""), "status": record.get("status")}
        for record in records
        if record.get("answered_by") == "upstream" and record.get("status") in UNREGISTERED_ANSWERS
    ]


def resolve_cell(
    raw: dict, scenario: dict, driver_errors: list[str], cell: str, *, external: bool = False
) -> tuple[str, str, dict]:
    client, scenario_id = cell.split("/", 1)
    if raw.get("client") != client or raw.get("scenario") != scenario_id:
        driver_errors.append(f"{cell}: the raw result does not identify the requested cell")
        return "fail", "driver output format error", {}
    if raw.get("skipped_reason"):
        # Decided before the client ran, from the launcher's own registry.
        return "sut-unregistered", raw["skipped_reason"], {}
    unreached = [record for record in raw.get("probe", []) if record.get("answered_by") == "observer"]
    if unreached:
        # The observer answered these itself because the endpoint did not: nothing about the
        # endpoint was measured, so the run is an environment failure, never a cell verdict.
        driver_errors.append(
            f"{cell}: the observer could not reach the external endpoint for {len(unreached)} request(s); "
            "this run measured the network, not the endpoint"
        )
        return "fail", "the external endpoint was unreachable", {}
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
    if driver.get("scenario") != scenario_id:
        driver_errors.append(f"{cell}: the driver result does not identify the requested scenario")
        return "fail", "driver output format error", {}
    if status in {"pass", "unsupported"} and raw.get("exit_code") != 0:
        driver_errors.append(f"{cell}: a driver reporting {status} requires a zero process exit")
        return "fail", "driver output format error", {}
    detail = driver.get("detail") or ""
    evidence = dict(driver.get("evidence") or {})
    if status == "unsupported":
        # The driver protocol keeps one word for it: a driver only ever knows its own client.
        return "client-unsupported", detail, evidence
    if status == "fail" and external:
        unregistered = unregistered_answers(raw.get("probe", []))
        if unregistered:
            first = unregistered[0]
            more = f" (and {len(unregistered) - 1} more)" if len(unregistered) > 1 else ""
            evidence["unregistered"] = unregistered
            return (
                "sut-unregistered",
                f"the system under test answered {first['status']} to {first['method']} {first['path']}{more}; "
                f"the driver reported: {detail or 'no detail'}",
                evidence,
            )
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
    check.add_argument(
        "--sut-capabilities",
        default="",
        help="the launcher's --print-capabilities output; omitted only for an external endpoint",
    )
    check.add_argument("--clients", default="", help="the comma-separated clients a filtered run will run")
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
    build.add_argument("--sut-kind", choices=SUT_KINDS, default="gateway-fs", help="what answered the rows")
    build.add_argument("--endpoint", default="", help="the external endpoint's URL")
    build.add_argument(
        "--endpoint-build", default="", help="the external endpoint's Server header; empty when it sent none"
    )
    build.add_argument("--product", default="", help="what the external endpoint is, e.g. rustfs")
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
