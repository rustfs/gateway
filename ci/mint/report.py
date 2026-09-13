#!/usr/bin/env python3
# Copyright 2026 RustFS Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Baseline-aware report for a MinIO mint run.

Responsible for: redacting a copied `/mint/log` tree and the console transcript in place,
reading every SDK's JSON records, deciding whether the run is complete, comparing each SDK's
failure count with `ci/mint/baseline.txt`, and turning that comparison into an exit code a
scheduled job can act on.
NOT responsible for: pulling or running the image, launching the system under test, or
editing the reviewed baseline. Upstream: `ci/mint/run.sh`. Downstream: the `e2e-mint`
workflow's job summary and artifact, and the ratchet guard `scripts/check_mint_baseline.sh`.

Provenance: written for this repository from mint's documented log format (one JSON
document per test, carrying `name`, `function` and a `status` of PASS, FAIL or NA) and the
verdict rules recorded on rustfs/backlog#1764. No code was copied from mint or from any
other project's report script.

# Verdicts, per SDK

    failures above the baseline   -> REGRESSION  exit 1 (0 in record mode)
    failures equal and non-zero   -> KNOWN
    failures below the baseline   -> IMPROVED    the count should come down
    no failures, baseline zero    -> OK
    NA records                    -> reported as `na`; never a failure, never a pass

# Why an incomplete run exits 3 and is never compared

If a partial run were judged against the baseline, every SDK that never ran would read as
IMPROVED, and a record-mode proposal built from it would bank the gap as the new normal. So
the run is incomplete, exits 3 and writes no proposal when any of these is true:

    * an SDK the runner asked for left no record, or its log is empty;
    * a record is not a JSON object, or carries a status other than PASS, FAIL or NA;
    * a directory under the log names a suite the runner did not ask for;
    * the console never reported an SDK starting or finishing;
    * an SDK's runner exited non-zero without writing a FAIL record, which leaves the
      failure unattributable.

# Excluded SDKs

A baseline line `<sdk> excluded <owner issue URL> <reason>` takes an SDK out of the verdict,
but never out of the run or the report. An excluded SDK:

    * is still run and still has to start and finish on the console, in order: an excluded
      SDK that hangs or reorders the run hides every SDK after it;
    * may leave no record, an unreadable record or an unattributable failure, and none of that
      makes the run incomplete. Each is reported in the excluded section instead;
    * never counts toward a regression, and a record-mode proposal carries its line unchanged;
    * makes the run incomplete if its log holds a record naming a counted SDK. Those results
      would be dropped along with the exclusion, so a counted SDK would be judged on a subset
      without anybody noticing;
    * is flagged RECOVERED, without changing the exit code, when its log becomes a complete,
      attributable measurement. That is the signal to remove the line.

Exit codes: 0 ok, 1 regression, 2 usage, 3 environment.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

EXIT_OK = 0
EXIT_REGRESSION = 1
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3

STATUSES = ("PASS", "FAIL", "NA")
SDK_NAME = re.compile(r"[A-Za-z0-9._-]+")
REDACTED = "[REDACTED]"
EXCLUDED = "excluded"
# An exclusion is owned by an issue in this repository or in the planning tracker, and nowhere
# else: an owner outside the project is an owner nobody here is obliged to close.
OWNER = re.compile(r"https://github\.com/rustfs/(?:gateway|backlog)/issues/[1-9][0-9]*")
# A reason is a sentence, not a token: `tbd` or `flaky` names no cause anybody could check.
REASON_MIN_WORDS = 3
# A failing function name is the one piece of third-party text the aggregate report carries,
# because a count cannot be attributed without it. It is redacted, stripped of control
# characters and capped, and only this many are listed per SDK.
FUNCTION_LIMIT = 160
FUNCTIONS_PER_SDK = 50

# Each pattern's first group is kept and everything the rest matches is replaced. Together they
# cover the places an S3 client or server puts signing material into text: the Authorization
# header, SigV4 and SigV2 presigned query parameters, security-token headers, and the
# StringToSign / CanonicalRequest / SignatureProvided elements of a signature-mismatch body.
# The last of those is exactly the "expected signature" oracle AGENTS.md forbids in logs.
REDACTIONS = (
    re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?)[^\"'\r\n]+"),
    re.compile(
        r"(?im)((?:^|[?&;,\s\"'])(?:x-amz-signature|x-amz-credential|x-amz-security-token|"
        r"signature|credential)=)[^&\s\"'<>,]+"
    ),
    re.compile(r"(?i)(x-amz-(?:signature|credential|security-token)[\"']?\s*:\s*[\"']?)[^\"'\s,}]+"),
    re.compile(
        r"(?is)(<(StringToSign|StringToSignBytes|CanonicalRequest|CanonicalRequestBytes|"
        r"SignatureProvided)>).*?(?=</\2>)"
    ),
    re.compile(r"(?i)(expected[ _-]?signature[\"']?\s*[:=]?\s*[\"']?)[^\s\"'<>,]+"),
)

# Mint prints `(<j>/<n>) Running <sdk> tests ... ` before an SDK and `done in` or `FAILED in`
# after it. Only these markers are read from the console; nothing else in it is interpreted.
RUNNING = re.compile(r"^\((\d+)/(\d+)\) Running (\S+) tests \.\.\. ", re.MULTILINE)
FINISHED = re.compile(r"\b(done|FAILED) in \d")


class ReportError(Exception):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def redact_text(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    for pattern in REDACTIONS:
        text = pattern.sub(lambda match: match.group(1) + REDACTED, text)
    return text


def redact_paths(paths: list[Path], secrets: list[str]) -> int:
    """Rewrites every regular file under `paths` in place. Returns how many changed."""
    files: list[Path] = []
    for path in paths:
        if path.is_symlink():
            continue
        if path.is_dir():
            files.extend(sorted(child for child in path.rglob("*") if child.is_file() and not child.is_symlink()))
        elif path.is_file():
            files.append(path)
        else:
            raise ReportError(f"cannot redact {path}: it does not exist", EXIT_ENVIRONMENT)
    changed = 0
    for file in files:
        try:
            original = file.read_bytes().decode("utf-8", errors="surrogateescape")
            redacted = redact_text(original, secrets)
            if redacted != original:
                file.write_bytes(redacted.encode("utf-8", errors="surrogateescape"))
                changed += 1
        except OSError as error:
            raise ReportError(f"cannot redact {file}: {error.__class__.__name__}", EXIT_ENVIRONMENT) from error
    return changed


def printable(value: object, limit: int = FUNCTION_LIMIT) -> str:
    """Third-party text made safe for a one-line report cell."""
    if not isinstance(value, str) or not value.strip():
        return "(unnamed)"
    text = redact_text(value, [])
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


@dataclass
class Exclusion:
    owner: str
    reason: str


def read_baseline(path: Path) -> tuple[int, dict[str, int], dict[str, Exclusion]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ReportError(f"cannot read the baseline {path}: {error}", EXIT_ENVIRONMENT) from error
    generation: int | None = None
    counts: dict[str, int] = {}
    exclusions: dict[str, Exclusion] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("# generation:"):
            value = line[len("# generation:"):].strip()
            if not re.fullmatch(r"[0-9]+", value):
                raise ReportError(f"{path}:{number}: generation must be a non-negative integer", EXIT_ENVIRONMENT)
            if generation is not None:
                raise ReportError(f"{path}:{number}: the generation is declared more than once", EXIT_ENVIRONMENT)
            generation = int(value)
            continue
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        parts = entry.split()
        if not SDK_NAME.fullmatch(parts[0]):
            raise ReportError(
                f"{path}:{number}: expected `<sdk> <failures>` or `<sdk> {EXCLUDED} <owner> <reason>`", EXIT_ENVIRONMENT
            )
        if parts[0] in counts or parts[0] in exclusions:
            raise ReportError(f"{path}:{number}: {parts[0]} is listed more than once", EXIT_ENVIRONMENT)
        if len(parts) >= 2 and parts[1] == EXCLUDED:
            if len(parts) < 3 or not OWNER.fullmatch(parts[2]):
                raise ReportError(
                    f"{path}:{number}: the exclusion of {parts[0]} names no owning rustfs/gateway or rustfs/backlog issue",
                    EXIT_ENVIRONMENT,
                )
            if len(parts[3:]) < REASON_MIN_WORDS:
                raise ReportError(f"{path}:{number}: the exclusion of {parts[0]} gives no reason", EXIT_ENVIRONMENT)
            exclusions[parts[0]] = Exclusion(parts[2], " ".join(parts[3:]))
            continue
        if len(parts) != 2 or not re.fullmatch(r"[0-9]+", parts[1]):
            raise ReportError(
                f"{path}:{number}: expected `<sdk> <failures>` or `<sdk> {EXCLUDED} <owner> <reason>`", EXIT_ENVIRONMENT
            )
        counts[parts[0]] = int(parts[1])
    if generation is None:
        raise ReportError(f"{path}: no `# generation: <n>` header; the ratchet has nothing to compare", EXIT_ENVIRONMENT)
    if not counts:
        raise ReportError(f"{path} counts no SDK; a baseline with nothing in it judges nothing", EXIT_ENVIRONMENT)
    return generation, counts, exclusions


@dataclass
class Tally:
    sdk: str
    passed: int = 0
    failed: int = 0
    na: int = 0
    failing: list[str] = field(default_factory=list)


def read_records(log_dir: Path, sdk: str, problems: list[str]) -> Tally | None:
    path = log_dir / sdk / "log.json"
    if not path.is_file():
        problems.append(f"{sdk}: produced no record ({sdk}/log.json is missing)")
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        problems.append(f"{sdk}: {sdk}/log.json is unreadable ({error.__class__.__name__})")
        return None
    decoder = json.JSONDecoder()
    tally = Tally(sdk)
    position = 0
    ordinal = 0
    while True:
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            break
        ordinal += 1
        try:
            document, position = decoder.raw_decode(text, position)
        except json.JSONDecodeError:
            problems.append(f"{sdk}: record {ordinal} in {sdk}/log.json is not valid JSON")
            return None
        if not isinstance(document, dict):
            problems.append(f"{sdk}: record {ordinal} in {sdk}/log.json is not a JSON object")
            return None
        status = document.get("status")
        if status == "PASS":
            tally.passed += 1
        elif status == "FAIL":
            tally.failed += 1
            tally.failing.append(printable(document.get("function")))
        elif status == "NA":
            tally.na += 1
        else:
            problems.append(
                f"{sdk}: record {ordinal} has status {printable(status, 24)!r}, which is not one of "
                + ", ".join(STATUSES)
            )
            return None
    if ordinal == 0:
        problems.append(f"{sdk}: produced no record ({sdk}/log.json is empty)")
        return None
    return tally


def records_naming(log_dir: Path, sdk: str, counted: dict[str, str]) -> dict[str, int]:
    """Counts the records in `sdk`'s log whose `name` is a counted SDK's, keyed by that SDK.

    Unlike `read_records` this reads past text that is not JSON, because an excluded SDK's log
    is allowed to be broken, and a broken log is exactly where a stray record would otherwise go
    unseen. `counted` maps a name with any leading dot removed to the SDK directory it names:
    mint's `.minio-dotnet` writes records named `minio-dotnet`.
    """
    try:
        text = (log_dir / sdk / "log.json").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    decoder = json.JSONDecoder()
    found: dict[str, int] = {}
    position = text.find("{")
    while position >= 0:
        try:
            document, end = decoder.raw_decode(text, position)
        except json.JSONDecodeError:
            position = text.find("{", position + 1)
            continue
        name = document.get("name") if isinstance(document, dict) else None
        if isinstance(name, str) and name.lstrip(".") in counted:
            other = counted[name.lstrip(".")]
            found[other] = found.get(other, 0) + 1
        position = text.find("{", end)
    return found


def read_progress(path: Path, sdks: list[str], problems: list[str]) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        problems.append(f"the console transcript is unreadable ({error.__class__.__name__})")
        return {}
    starts = list(RUNNING.finditer(text))
    outcomes: dict[str, str] = {}
    reported: set[str] = set()
    for index, match in enumerate(starts):
        ordinal, total, name = int(match.group(1)), int(match.group(2)), match.group(3)
        expected = sdks[index] if index < len(sdks) else None
        if total != len(sdks) or ordinal != index + 1 or name != expected:
            shown = name if SDK_NAME.fullmatch(name) else "(unrecognised)"
            problems.append(
                f"the console reports ({ordinal}/{total}) {shown} where the runner asked for "
                f"({index + 1}/{len(sdks)}) {expected or '(nothing)'}"
            )
            continue
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        # The last marker in the segment is mint's own; an SDK's output precedes it.
        finished = list(FINISHED.finditer(text, match.end(), end))
        reported.add(name)
        if not finished:
            problems.append(f"{name}: the console never reported it finishing; the run was cut short")
            continue
        outcomes[name] = finished[-1].group(1)
    for sdk in sdks:
        if sdk not in reported:
            problems.append(f"{sdk}: the console never reported it starting")
    return outcomes


@dataclass
class Row:
    sdk: str
    tally: Tally
    baseline: int
    verdict: str


def verdict_for(failed: int, baseline: int) -> str:
    if failed > baseline:
        return "REGRESSION"
    if failed < baseline:
        return "IMPROVED"
    return "KNOWN" if failed else "OK"


@dataclass
class ExcludedRow:
    sdk: str
    exclusion: Exclusion
    # Repository-authored text only: what this run observed about the SDK's records.
    observed: str
    recovered: bool
    tally: Tally | None


def render_excluded(excluded: list[ExcludedRow]) -> list[str]:
    if not excluded:
        return []
    lines = [
        "",
        "### Excluded SDKs",
        "",
        "Run, reported, and never judged: they count toward neither completeness nor the ratchet.",
        "",
        "| SDK | owner | reason | observed |",
        "| --- | --- | --- | --- |",
    ]
    for row in excluded:
        observed = f"**RECOVERED**: {row.observed}; remove the exclusion" if row.recovered else row.observed
        cells = (row.exclusion.owner, printable(row.exclusion.reason, 400), printable(observed, 400))
        lines.append(f"| `{row.sdk}` | " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
    return lines


def render_markdown(
    image: str, generation: int, rows: list[Row], excluded: list[ExcludedRow], problems: list[str], code: int
) -> str:
    lines = ["## MinIO mint", ""]
    if image:
        lines += [f"Image: `{image}`", ""]
    if problems:
        lines += [
            "**Incomplete run.** It measured nothing that may be compared with the baseline, "
            "and it is not a regression.",
            "",
        ]
        lines += [f"- {printable(problem, 400)}" for problem in problems]
        lines.append("")
    lines += [f"Baseline generation {generation}; exit {code}.", ""]
    lines += ["| SDK | verdict | PASS | FAIL | NA | baseline |", "| --- | --- | ---: | ---: | ---: | ---: |"]
    for row in rows:
        lines.append(
            f"| `{row.sdk}` | {row.verdict} | {row.tally.passed} | {row.tally.failed} | {row.tally.na} | {row.baseline} |"
        )
    failing = [row for row in rows if row.tally.failing]
    if failing:
        lines += ["", "### Failing functions", ""]
        for row in failing:
            shown = row.tally.failing[:FUNCTIONS_PER_SDK]
            lines.append(f"- `{row.sdk}`: " + "; ".join(name.replace("|", "\\|") for name in shown))
            if len(row.tally.failing) > len(shown):
                lines.append(f"  - and {len(row.tally.failing) - len(shown)} more")
    lines += render_excluded(excluded)
    return "\n".join(lines) + "\n"


def render_proposal(generation: int, sdks: list[str], rows: list[Row], excluded: list[ExcludedRow]) -> str:
    passed = sum(row.tally.passed for row in rows)
    failed = sum(row.tally.failed for row in rows)
    na = sum(row.tally.na for row in rows)
    lines = [
        "# Proposed ci/mint/baseline.txt, written by ci/mint/report.py in record mode.",
        f"# Measured {len(rows)} SDK(s): {passed} PASS, {failed} FAIL, {na} NA; {len(excluded)} excluded.",
        "# Attribute every non-zero count below before it replaces the reviewed baseline.",
        "# Exclusions are carried over unchanged; removing one is a separate, reviewed decision.",
        f"# generation: {generation + 1}",
    ]
    counted = {row.sdk: row for row in rows}
    uncounted = {row.sdk: row for row in excluded}
    for sdk in sdks:
        if sdk in counted:
            row = counted[sdk]
            for name in row.tally.failing[:FUNCTIONS_PER_SDK]:
                lines.append(f"#   {sdk} failed: {name}")
            lines.append(f"{sdk} {row.tally.failed}")
        elif sdk in uncounted:
            entry = uncounted[sdk]
            state = "RECOVERED" if entry.recovered else "observed"
            lines.append(f"#   {sdk} {state}: {printable(entry.observed, 400)}")
            lines.append(f"{sdk} {EXCLUDED} {entry.exclusion.owner} {entry.exclusion.reason}")
    return "\n".join(lines) + "\n"


def judge(args: argparse.Namespace) -> int:
    sdks = args.sdks.split()
    if not sdks or len(set(sdks)) != len(sdks) or not all(SDK_NAME.fullmatch(sdk) for sdk in sdks):
        raise ReportError("--sdks must name each SDK the runner asked for exactly once", EXIT_USAGE)
    baseline_path = Path(args.baseline)
    record_path = Path(args.record) if args.record else None
    if record_path is not None and record_path.resolve() == baseline_path.resolve():
        raise ReportError("record mode writes a proposal; it never overwrites the reviewed baseline", EXIT_USAGE)
    generation, allowed, exclusions = read_baseline(baseline_path)

    problems: list[str] = []
    listed = set(allowed) | set(exclusions)
    missing = sorted(set(sdks) - listed)
    extra = sorted(listed - set(sdks))
    if missing:
        problems.append("the baseline has no line for: " + ", ".join(missing))
    if extra:
        problems.append("the baseline names SDKs the runner did not run: " + ", ".join(extra))

    log_dir = Path(args.log_dir)
    tallies: dict[str, Tally] = {}
    # What an excluded SDK's log would have made incomplete, kept apart instead of discarded.
    excluded_reads: dict[str, tuple[Tally | None, list[str]]] = {}
    if not log_dir.is_dir():
        problems.append("the copied /mint/log directory is missing")
    else:
        for entry in sorted(log_dir.iterdir()):
            if entry.is_dir() and entry.name not in sdks:
                shown = entry.name if SDK_NAME.fullmatch(entry.name) else "(unrecognised)"
                problems.append(f"{shown}: an unknown suite wrote records; the census no longer describes the image")
        for sdk in sdks:
            if sdk in exclusions:
                observed: list[str] = []
                excluded_reads[sdk] = (read_records(log_dir, sdk, observed), observed)
                continue
            tally = read_records(log_dir, sdk, problems)
            if tally is not None:
                tallies[sdk] = tally

    # Excluded SDKs stay in the console check: one that hangs or runs out of order hides every
    # SDK after it, which is the run breaking, not the SDK.
    outcomes = read_progress(Path(args.progress), sdks, problems)
    for sdk, tally in tallies.items():
        if outcomes.get(sdk) == "FAILED" and tally.failed == 0:
            problems.append(
                f"{sdk}: its runner exited non-zero without writing a FAIL record, so the failure cannot be attributed"
            )

    counted_names = {sdk.lstrip("."): sdk for sdk in sdks if sdk not in exclusions}
    excluded: list[ExcludedRow] = []
    for sdk in sdks:
        if sdk not in exclusions:
            continue
        if log_dir.is_dir():
            for other, count in sorted(records_naming(log_dir, sdk, counted_names).items()):
                problems.append(
                    f"{sdk}: excluded, but its log carries {count} record(s) naming {other}, a counted SDK; "
                    f"the exclusion would drop them from {other}'s verdict"
                )
        tally, observed = excluded_reads.get(sdk, (None, ["the copied /mint/log directory is missing"]))
        if tally is not None and outcomes.get(sdk) == "FAILED" and tally.failed == 0:
            observed.append(f"{sdk}: its runner exited non-zero without writing a FAIL record")
        recovered = tally is not None and not observed
        if recovered:
            text = f"{tally.passed} PASS, {tally.failed} FAIL, {tally.na} NA"
        else:
            text = "; ".join(note.removeprefix(f"{sdk}: ") for note in observed)
        excluded.append(ExcludedRow(sdk, exclusions[sdk], text, recovered, tally))

    rows = [
        Row(sdk, tallies[sdk], allowed[sdk], verdict_for(tallies[sdk].failed, allowed[sdk]))
        for sdk in sdks
        if sdk in tallies and sdk in allowed
    ]
    regressions = [row for row in rows if row.verdict == "REGRESSION"]
    if problems:
        code = EXIT_ENVIRONMENT
    elif regressions and record_path is None:
        code = EXIT_REGRESSION
    else:
        code = EXIT_OK

    for row in rows:
        print(
            f"mint: {row.verdict:<10} {row.sdk} fail={row.tally.failed} baseline={row.baseline} "
            f"pass={row.tally.passed} na={row.tally.na}"
        )
    for entry in excluded:
        print(f"mint: EXCLUDED   {entry.sdk} owner={entry.exclusion.owner} observed: {printable(entry.observed, 400)}")
    for entry in excluded:
        if entry.recovered:
            print(
                f"mint: RECOVERED  {entry.sdk} wrote a complete, attributable log ({entry.observed}); "
                f"remove its exclusion and close or update {entry.exclusion.owner}"
            )
    for problem in problems:
        print(f"mint: INCOMPLETE {problem}")
    print(
        f"mint: sdks={len(sdks)} measured={len(rows)} "
        f"pass={sum(row.tally.passed for row in rows)} fail={sum(row.tally.failed for row in rows)} "
        f"na={sum(row.tally.na for row in rows)} regression={len(regressions)} "
        f"improved={sum(row.verdict == 'IMPROVED' for row in rows)} "
        f"known={sum(row.verdict == 'KNOWN' for row in rows)} excluded={len(excluded)} "
        f"recovered={sum(entry.recovered for entry in excluded)} incomplete={len(problems)} generation={generation}"
    )
    if problems:
        print("mint: the run is incomplete, so it measured nothing that may be compared with the baseline; "
              "it is NOT a regression")

    if args.markdown:
        Path(args.markdown).write_text(
            render_markdown(args.image, generation, rows, excluded, problems, code), encoding="utf-8"
        )
    if args.json:
        payload = {
            "image": args.image,
            "generation": generation,
            "exit": code,
            "complete": not problems,
            "incomplete": problems,
            "sdks": {
                row.sdk: {
                    "verdict": row.verdict,
                    "pass": row.tally.passed,
                    "fail": row.tally.failed,
                    "na": row.tally.na,
                    "baseline": row.baseline,
                    "failing_functions": row.tally.failing[:FUNCTIONS_PER_SDK],
                }
                for row in rows
            },
            "excluded": {
                entry.sdk: {
                    "owner": entry.exclusion.owner,
                    "reason": entry.exclusion.reason,
                    "observed": entry.observed,
                    "recovered": entry.recovered,
                }
                for entry in excluded
            },
        }
        Path(args.json).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if record_path is not None:
        if problems:
            # A stale proposal from an earlier run beside an incomplete one would be mistaken
            # for this run's measurement.
            record_path.unlink(missing_ok=True)
            print("mint: no baseline proposal written; an incomplete run must never become a baseline")
        else:
            record_path.write_text(render_proposal(generation, sdks, rows, excluded), encoding="utf-8")
            print(f"mint: proposed generation {generation + 1} written to {record_path}")
    return code


def redact_command(args: argparse.Namespace) -> int:
    secrets = [os.environ.get(name, "") for name in args.secret_env]
    changed = redact_paths([Path(path) for path in args.paths], secrets)
    print(f"mint: redacted {changed} file(s)")
    return EXIT_OK


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Redact and judge one MinIO mint run.")
    commands = parser.add_subparsers(dest="command", required=True)
    redact = commands.add_parser("redact", help="rewrite evidence files in place without signing material")
    redact.add_argument("paths", nargs="+")
    redact.add_argument("--secret-env", action="append", default=[], help="environment variable holding a secret")
    judging = commands.add_parser("judge", help="compare a run with the per-SDK baseline")
    judging.add_argument("--log-dir", required=True, help="the /mint/log tree copied out of the container")
    judging.add_argument("--progress", required=True, help="the container's console transcript")
    judging.add_argument("--baseline", required=True)
    judging.add_argument("--sdks", required=True, help="the SDKs the runner asked for, in order")
    judging.add_argument("--image", default="")
    judging.add_argument("--markdown")
    judging.add_argument("--json")
    judging.add_argument("--record", help="write a proposed baseline here; the reviewed one is never edited")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_request:
        return EXIT_OK if exit_request.code in (0, None) else EXIT_USAGE
    try:
        if args.command == "redact":
            return redact_command(args)
        return judge(args)
    except ReportError as error:
        print(f"mint: {error}", file=sys.stderr)
        return error.code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
