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
"""Baseline-aware report for a Ceph s3-tests run.

Responsible for: reading one pytest JUnit document, classifying every case into an S3
capability domain, comparing the failures against the checked-in xfail list, and turning
that comparison into an exit code a cron job can block on.
NOT responsible for: running the suite, launching the system under test, editing the xfail
list, or judging any case the suite did not report. Upstream: `ci/lib/sut.sh` and the
`e2e-s3tests` workflow. Downstream: the workflow's job summary and the ratchet guard
`scripts/check_xfail_ratchet.sh`.

Provenance: written for this repository from the verdict semantics described in
rustfs/backlog#1764. No code was copied from any other project's report script.

# Why a baseline instead of a plain pass/fail

A new S3 implementation's first s3-tests run is massively red. A runner that fails on any
red is switched off within a week and then reports nothing at all, which is strictly worse
than reporting a tolerated set. So the run is judged against `ci/s3tests/xfail.txt`:

    failing and listed      -> KNOWN       tolerated, exit stays 0
    failing and not listed  -> REGRESSION  exit 1
    passing and listed      -> FIXED       reported so the list can shrink
    listed and not reported -> STALE       reported; an entry naming a case the run never
                                           produced is dead weight that hides drift

# Why an all-errored run is an environment failure

`connection refused` reaches pytest as a setup *error* on every case. Recorded as
failures, that would mark the entire suite regressed and, worse, invite somebody to paste
the whole suite into the xfail list. So a run in which every reported case errored, or in
which nothing was reported at all, exits 3 and asserts nothing about the implementation.

Exit codes: 0 ok, 1 regression, 2 usage, 3 environment.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from pathlib import Path

EXIT_OK = 0
EXIT_REGRESSION = 1
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3

# Ordered domain rules: the first substring that matches a case id names its domain. The
# order is the contract, not the set — `test_multipart_copy_small` is multipart evidence
# before it is copy evidence, and reordering these rows silently moves counts between
# columns of every report ever compared against another. Rows are appended, not reordered.
DOMAIN_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("s3select", ("s3select", "select_object_content")),
    ("sts", ("_sts", "assume_role", "webidentity")),
    ("iam", ("iam_", "_iam", "user_policy", "managed_polic")),
    ("object-lock", ("object_lock", "retention", "legal_hold", "governance", "compliance")),
    ("lifecycle", ("lifecycle", "_transition", "expiration")),
    ("versioning", ("versioning", "versioned", "_version", "delete_marker")),
    ("multipart", ("multipart", "upload_part", "_mpu", "abort_upload")),
    ("encryption", ("encryption", "_sse", "sse_", "kms", "customer_key")),
    ("checksum", ("checksum", "_crc", "sha256_", "content_md5")),
    ("presigned", ("presign", "post_object", "_url_", "signature")),
    ("acl", ("_acl", "acl_", "grant", "canned")),
    ("policy", ("policy", "public_access_block")),
    ("cors", ("cors",)),
    ("tagging", ("tagging", "_tags", "tag_")),
    ("replication", ("replication",)),
    ("logging", ("logging",)),
    ("notification", ("notification", "topic")),
    ("website", ("website",)),
    ("cloud", ("cloud_transition", "cloud_restore")),
    ("copy", ("copy_object", "_copy_", "copy_source")),
    ("conditional", ("if_match", "if_none_match", "modified_since", "_conditional")),
    ("headers", ("_header", "header_", "bad_", "_expect_", "content_length", "user_agent")),
    ("listing", ("bucket_list", "list_objects", "list_buckets", "delimiter", "marker", "prefix")),
    ("range", ("_range", "ranged_")),
    ("object", ("object_", "_object", "get_obj", "put_obj", "head_obj", "delete_obj")),
    ("bucket", ("bucket",)),
)
FALLBACK_DOMAIN = "other"


def classify(case_id: str) -> str:
    """Names the S3 capability domain a case belongs to."""
    lowered = case_id.lower()
    for domain, needles in DOMAIN_RULES:
        for needle in needles:
            if needle in lowered:
                return domain
    return FALLBACK_DOMAIN


@dataclass(frozen=True)
class Case:
    """One reported case and the outcome the suite gave it."""

    id: str
    outcome: str  # passed | failed | errored | skipped


class ReportError(Exception):
    """An input the report cannot judge. Carries the exit code to leave with."""

    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def read_junit(path: Path) -> list[Case]:
    """Reads every `<testcase>` in a pytest JUnit document, in document order."""
    try:
        text = path.read_bytes()
    except OSError as error:
        raise ReportError(f"cannot read the JUnit document {path}: {error}", EXIT_ENVIRONMENT) from error
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        raise ReportError(f"{path} is not parseable XML: {error}", EXIT_ENVIRONMENT) from error

    cases: list[Case] = []
    for element in root.iter("testcase"):
        classname = element.get("classname", "").strip()
        name = element.get("name", "").strip()
        if not name:
            raise ReportError(f"{path} contains a testcase with no name", EXIT_ENVIRONMENT)
        case_id = f"{classname}::{name}" if classname else name
        outcome = "passed"
        # `error` outranks `failure`: a case that failed to set up never reached its
        # assertions, and the two are told apart to detect a dead system under test.
        if element.find("error") is not None:
            outcome = "errored"
        elif element.find("failure") is not None:
            outcome = "failed"
        elif element.find("skipped") is not None:
            outcome = "skipped"
        cases.append(Case(id=case_id, outcome=outcome))
    return cases


# An exclusion's owner: an issue in one of the two repositories that track this project's work.
# The same rule as ci/mint/baseline.txt, so both suites hand an exclusion to somebody.
OWNER_ISSUE = re.compile(r"https://github\.com/rustfs/(?:gateway|backlog)/issues/[1-9][0-9]*")
MINIMUM_REASON_WORDS = 3


@dataclass(frozen=True)
class Exclusion:
    """A case taken out of the verdict: `<case-id> excluded <owner issue URL> <reason>`."""

    owner: str
    reason: str


def read_xfail(path: Path) -> tuple[list[str], dict[str, Exclusion], int]:
    """Reads the xfail list: its tolerated entries, its exclusions, and its generation number.

    The generation is the one deliberate way the list may grow: `scripts/check_xfail_ratchet.sh`
    refuses an addition unless the header's `# generation:` number also went up, so widening
    the tolerated set is a visible one-line decision rather than a line somebody appended.

    A plain entry is a case expected to fail: it is KNOWN while it fails and FIXED once it
    passes. An exclusion is a case whose outcome this run does not judge at all, for a case whose
    result does not reproduce from run to run. It must name an owner issue and a reason, exactly
    like an excluded SDK in ci/mint/baseline.txt; an exclusion nobody owns is permanent.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ReportError(f"cannot read the xfail list {path}: {error}", EXIT_ENVIRONMENT) from error

    generation: int | None = None
    entries: list[str] = []
    excluded: dict[str, Exclusion] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("# generation:"):
            value = line.removeprefix("# generation:").strip()
            if not value.isdigit():
                raise ReportError(f"{path}:{number}: generation must be a non-negative integer", EXIT_ENVIRONMENT)
            if generation is not None:
                raise ReportError(f"{path}:{number}: the generation is declared more than once", EXIT_ENVIRONMENT)
            generation = int(value)
            continue
        if not line or line.startswith("#"):
            continue
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        fields = entry.split()
        case_id = fields[0]
        if case_id in entries or case_id in excluded:
            raise ReportError(f"{path}:{number}: duplicate xfail entry {case_id}", EXIT_ENVIRONMENT)
        if len(fields) == 1:
            entries.append(case_id)
            continue
        if fields[1] != "excluded" or len(fields) < 3 or not OWNER_ISSUE.fullmatch(fields[2]):
            raise ReportError(
                f"{path}:{number}: expected `<case-id>` or `<case-id> excluded <owner issue URL> <reason>`; an "
                "exclusion's owner is an issue in rustfs/gateway or rustfs/backlog",
                EXIT_ENVIRONMENT,
            )
        reason = " ".join(fields[3:])
        if len(fields[3:]) < MINIMUM_REASON_WORDS:
            raise ReportError(
                f"{path}:{number}: the exclusion of {case_id} needs a reason of at least "
                f"{MINIMUM_REASON_WORDS} words",
                EXIT_ENVIRONMENT,
            )
        excluded[case_id] = Exclusion(owner=fields[2], reason=reason)
    if generation is None:
        raise ReportError(f"{path}: no `# generation: <n>` header; the ratchet has nothing to compare", EXIT_ENVIRONMENT)
    return entries, excluded, generation


@dataclass
class Verdict:
    """The whole comparison, in the shape the summary and the JSON both render."""

    passed: list[str]
    known: list[str]
    regression: list[str]
    fixed: list[str]
    stale: list[str]
    skipped: list[str]
    errored: int
    total: int
    generation: int
    # Excluded cases that were reported, with the outcome this run gave them. Never judged.
    excluded: list[tuple[str, str]] = field(default_factory=list)
    exclusions: dict[str, Exclusion] = field(default_factory=dict)

    def exit_code(self) -> int:
        return EXIT_REGRESSION if self.regression else EXIT_OK


def judge(
    cases: list[Case], xfail: list[str], generation: int, exclusions: dict[str, Exclusion] | None = None
) -> Verdict:
    """Compares one run against the tolerated set; excluded cases are set aside unjudged."""
    exclusions = exclusions or {}
    excluded = [(case.id, case.outcome) for case in cases if case.id in exclusions]
    cases_judged = [case for case in cases if case.id not in exclusions]
    verdict = _judge(cases, cases_judged, xfail, generation)
    verdict.excluded = excluded
    verdict.exclusions = exclusions
    reported = {case.id for case in cases}
    verdict.stale = sorted(set(verdict.stale) | {case_id for case_id in exclusions if case_id not in reported})
    return verdict


def _judge(cases: list[Case], judged: list[Case], xfail: list[str], generation: int) -> Verdict:
    """Compares the judged (non-excluded) cases against the tolerated set.

    The environment checks look at every reported case, excluded or not: an exclusion must not be
    what lets a dead service through.
    """
    if not cases:
        raise ReportError(
            "the run reported no cases at all; that is an environment failure, not a result", EXIT_ENVIRONMENT
        )
    errored = sum(1 for case in cases if case.outcome == "errored")
    if errored == len(cases):
        raise ReportError(
            f"every one of the {len(cases)} reported cases errored during setup; the system under test was "
            "not reachable, so this run measures nothing and must not be recorded",
            EXIT_ENVIRONMENT,
        )

    tolerated = set(xfail)
    reported = {case.id for case in cases}
    passed: list[str] = []
    known: list[str] = []
    regression: list[str] = []
    fixed: list[str] = []
    skipped: list[str] = []
    for case in judged:
        if case.outcome in {"failed", "errored"}:
            (known if case.id in tolerated else regression).append(case.id)
        elif case.outcome == "passed":
            passed.append(case.id)
            if case.id in tolerated:
                fixed.append(case.id)
        else:
            skipped.append(case.id)
    # A skip is not evidence that a tolerated case still fails, so a listed case that was
    # skipped is stale for the same reason as one that was never reported: nothing measured it.
    skipped_ids = set(skipped)
    stale = sorted(entry for entry in tolerated if entry not in reported or entry in skipped_ids)
    return Verdict(
        passed=passed,
        known=known,
        regression=regression,
        fixed=fixed,
        stale=stale,
        skipped=skipped,
        errored=errored,
        total=len(cases),
        generation=generation,
    )


def by_domain(ids: list[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for case_id in ids:
        domain = classify(case_id)
        counts[domain] = counts.get(domain, 0) + 1
    return counts


def summary_line(verdict: Verdict) -> str:
    return (
        f"SUMMARY passed={len(verdict.passed)} known={len(verdict.known)} "
        f"regression={len(verdict.regression)} fixed={len(verdict.fixed)} "
        f"stale={len(verdict.stale)} skipped={len(verdict.skipped)} excluded={len(verdict.excluded)} "
        f"collected={verdict.total} xfail-generation={verdict.generation}"
    )


def render_markdown(verdict: Verdict, limit: int) -> str:
    """Renders the job summary. Regressions come first because they are the only actionable half."""
    lines: list[str] = ["## Ceph s3-tests", "", f"`{summary_line(verdict)}`", ""]
    if verdict.regression:
        lines.append(f"### {len(verdict.regression)} regression(s) — this run fails")
        lines.append("")
        lines.append("A failing case that `ci/s3tests/xfail.txt` does not list. Fix the implementation,")
        lines.append("or argue the addition in a pull request that also raises the xfail generation.")
        lines.append("")
        for case_id in verdict.regression[:limit]:
            lines.append(f"- `{case_id}` ({classify(case_id)})")
        if len(verdict.regression) > limit:
            lines.append(f"- … and {len(verdict.regression) - limit} more; the full list is in the run artifact")
        lines.append("")
    else:
        lines.append("No regression against the tolerated set.")
        lines.append("")
    if verdict.fixed:
        lines.append(f"### {len(verdict.fixed)} newly passing — remove from `ci/s3tests/xfail.txt`")
        lines.append("")
        for case_id in verdict.fixed[:limit]:
            lines.append(f"- `{case_id}` ({classify(case_id)})")
        lines.append("")
    if verdict.stale:
        lines.append(f"### {len(verdict.stale)} stale xfail entr(y/ies) — nothing measured them")
        lines.append("")
        for case_id in verdict.stale[:limit]:
            lines.append(f"- `{case_id}`")
        lines.append("")

    if verdict.excluded:
        lines.append(f"### {len(verdict.excluded)} excluded case(s) — reported, never judged")
        lines.append("")
        for case_id, outcome in verdict.excluded[:limit]:
            exclusion = verdict.exclusions[case_id]
            lines.append(f"- `{case_id}` {outcome} — {exclusion.reason} ({exclusion.owner})")
        lines.append("")

    domains = sorted(
        set(by_domain(verdict.known)) | set(by_domain(verdict.regression)) | set(by_domain(verdict.passed))
    )
    known_counts = by_domain(verdict.known)
    regression_counts = by_domain(verdict.regression)
    passed_counts = by_domain(verdict.passed)
    lines.append("### By capability domain")
    lines.append("")
    lines.append("| Domain | passed | known | regression |")
    lines.append("|---|---:|---:|---:|")
    for domain in domains:
        lines.append(
            f"| {domain} | {passed_counts.get(domain, 0)} | "
            f"{known_counts.get(domain, 0)} | {regression_counts.get(domain, 0)} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def render_xfail(verdict: Verdict, generation: int) -> str:
    """Renders a proposed xfail list from this run, grouped by domain.

    This is what `--record` writes. It is an artifact for a human to review and land, never
    something the workflow commits: a job that can widen its own tolerated set is not a gate.
    """
    failing = sorted(verdict.known + verdict.regression)
    grouped: dict[str, list[str]] = {}
    for case_id in failing:
        grouped.setdefault(classify(case_id), []).append(case_id)
    lines = [
        "# Ceph s3-tests cases this implementation is known to fail.",
        "#",
        "# The list may shrink freely. It may only grow in a pull request that also raises the",
        "# generation below; scripts/check_xfail_ratchet.sh refuses every other addition.",
        "# Each group names the domain that owns the gap.",
        "#",
        f"# generation: {generation}",
        "",
    ]
    for domain in sorted(grouped):
        lines.append(f"# --- {domain} ({len(grouped[domain])}) ---")
        lines.extend(grouped[domain])
        lines.append("")
    if verdict.exclusions:
        # Carried over verbatim: a record run measures the judged cases, and has no evidence either
        # way about a case whose outcome is excluded. Removing one is a reviewed decision.
        lines.append(f"# --- excluded ({len(verdict.exclusions)}) ---")
        for case_id in sorted(verdict.exclusions):
            exclusion = verdict.exclusions[case_id]
            lines.append(f"{case_id} excluded {exclusion.owner} {exclusion.reason}")
        lines.append("")
    return "\n".join(lines)


OUTCOMES = ("passed", "failed", "errored", "skipped")


def render_outcomes(cases: list[Case], generation: int) -> str:
    """Renders every reported case with the outcome this run gave it, one `<outcome> <id>` per line.

    This is the per-case record behind a generation of the xfail list: which cases passed, which
    failed, which errored in setup and which the suite skipped. The xfail list names only the
    tolerated failures; without this record nobody can tell a case that passes from one that was
    skipped, and `scripts/check_xfail_ratchet.sh` uses it to refuse an xfail entry that no run
    ever measured failing.
    """
    counts = {outcome: sum(1 for case in cases if case.outcome == outcome) for outcome in OUTCOMES}
    lines = [
        "# Per-case outcomes of the Ceph s3-tests run that measured this xfail generation.",
        "# Written by `ci/s3tests/report.py --outcomes`; refreshed together with ci/s3tests/xfail.txt.",
        "# " + " ".join(f"{outcome}={counts[outcome]}" for outcome in OUTCOMES) + f" collected={len(cases)}",
        "#",
        f"# generation: {generation}",
        "",
    ]
    for case in sorted(cases, key=lambda case: (OUTCOMES.index(case.outcome), case.id)):
        lines.append(f"{case.outcome} {case.id}")
    return "\n".join(lines) + "\n"


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ci/s3tests/report.py",
        description="Judge one Ceph s3-tests JUnit document against the checked-in xfail list.",
    )
    parser.add_argument("--junit", required=True, type=Path, help="pytest JUnit XML written by the run")
    parser.add_argument("--xfail", required=True, type=Path, help="the tolerated-failure list")
    parser.add_argument(
        "--outcomes",
        type=Path,
        help="write every case's outcome here, for the generation a --record run proposes",
    )
    parser.add_argument("--markdown", type=Path, help="write the job summary here")
    parser.add_argument("--json", dest="json_path", type=Path, help="write the machine-readable report here")
    parser.add_argument(
        "--record",
        type=Path,
        help="write a proposed xfail list from this run here, and do not fail on a regression",
    )
    parser.add_argument("--limit", type=int, default=50, help="how many ids to name per section (default 50)")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    options = parse_arguments(argv)
    if options.limit < 1:
        print("report: --limit must be at least 1", file=sys.stderr)
        return EXIT_USAGE
    try:
        cases = read_junit(options.junit)
        xfail, exclusions, generation = read_xfail(options.xfail)
        verdict = judge(cases, xfail, generation, exclusions)
    except ReportError as error:
        print(f"report: {error}", file=sys.stderr)
        return error.code

    markdown = render_markdown(verdict, options.limit)
    print(summary_line(verdict))
    for case_id in verdict.regression[: options.limit]:
        print(f"REGRESSION {classify(case_id)} {case_id}")
    for case_id in verdict.fixed[: options.limit]:
        print(f"FIXED {classify(case_id)} {case_id}")
    for case_id in verdict.stale[: options.limit]:
        print(f"STALE {case_id}")
    for case_id, outcome in verdict.excluded[: options.limit]:
        print(f"EXCLUDED {classify(case_id)} {case_id} {outcome}")

    if options.markdown:
        options.markdown.write_text(markdown, encoding="utf-8")
    if options.json_path:
        options.json_path.write_text(
            json.dumps(
                {
                    "collected": verdict.total,
                    "generation": verdict.generation,
                    "errored": verdict.errored,
                    "passed": verdict.passed,
                    "known": verdict.known,
                    "regression": verdict.regression,
                    "fixed": verdict.fixed,
                    "stale": verdict.stale,
                    "skipped": verdict.skipped,
                    "excluded": [
                        {
                            "id": case_id,
                            "outcome": outcome,
                            "owner": verdict.exclusions[case_id].owner,
                            "reason": verdict.exclusions[case_id].reason,
                        }
                        for case_id, outcome in verdict.excluded
                    ],
                    "by_domain": {
                        "passed": by_domain(verdict.passed),
                        "known": by_domain(verdict.known),
                        "regression": by_domain(verdict.regression),
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    if options.outcomes:
        proposed_generation = generation + 1 if options.record else generation
        options.outcomes.write_text(render_outcomes(cases, proposed_generation), encoding="utf-8")
    if options.record:
        options.record.write_text(render_xfail(verdict, generation + 1), encoding="utf-8")
        print(f"recorded a proposed xfail list at {options.record}; land it in a reviewed pull request")
        return EXIT_OK
    return verdict.exit_code()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
