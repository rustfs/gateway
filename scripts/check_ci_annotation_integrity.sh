#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   That no attacker-controlled free text from a webhook payload reaches the CI log as a
#   line the Actions runner would read as a workflow command, and that every guard which
#   consumes the pull-request body refuses an input that is not a single-line JSON string.
#
# WHY
#   GitHub Actions prints each step's `env:` block into the log, and the runner parses
#   `::`-prefixed lines in the log stream as workflow commands. Exporting a multi-line
#   pull-request body raw therefore lets its author:
#     * forge `::notice`/`::warning`/`::error` annotations that read as findings from this
#       repository's own guards, and
#     * emit `::stop-commands::<token>`, which disables command processing for the rest of
#       the job and swallows genuine annotations emitted afterwards.
#   The second half is what makes this worth fixing rather than noting: `ci_budget.sh`
#   raises a real `::warning::` past 80% of a job's budget so the next timeout cliff
#   announces itself, and a pull-request body must not be able to silence it.
#   Reported as rustfs/gateway#224; hit by accident, not on purpose, by rustfs/gateway#223.
#
#   The bound, stated so this is neither ignored nor over-escalated: the workflow triggers
#   on `pull_request`, not `pull_request_target`, so a fork gets a read-only token and no
#   secrets, and `::set-env`/`::add-path` were disabled by GitHub in 2020. This is CI
#   output integrity, not code execution.
#
# HOW IT CHECKS
#   Every free-text webhook field must be exported through `toJSON(...)`, which renders it
#   as one JSON string with `\n` escaped, so no log line can begin with `::`. The proof is
#   not a grep for `toJSON`: this guard renders the step's `env:` block the way the runner
#   prints it, using the expression actually written in the workflow, and runs a model of
#   the runner's command scanner over the result. It asserts both directions, and it
#   asserts them against a control that renders the same fixtures the vulnerable way — so
#   a scanner model that degrades into a no-op fails this guard instead of passing it.
#
# THE ONE THING THIS CANNOT OBSERVE
#   Whether GitHub's `toJSON` really emits a string on one line. It is documented to
#   pretty-print, and pretty-printing is only defined for objects, but no local test can
#   see the runner. That assumption is therefore enforced at run time instead of assumed:
#   every consumer rejects a `GATEWAY_PR_BODY_JSON` containing a raw newline, so if the
#   rendering ever changes, CI goes red rather than quietly reopening the hole. This guard
#   proves each consumer still does that, in both directions.
#
#   A raw U+2028 or U+2029 inside the encoded value is deliberately not checked. The runner
#   reads process output as .NET lines, which break on CR and LF alone, so neither of those
#   starts a new log line. If that ever stops being true, the check belongs next to the
#   newline one -- with a negative case, like every other assertion here.
#
# HOW TO EXEMPT
#   No exemption. Wrap the field in `toJSON(...)` and decode it in the consumer.
#
# USAGE
#   scripts/check_ci_annotation_integrity.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

fail() {
    printf 'check_ci_annotation_integrity: %s\n' "$*" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'required command is missing: python3'
[[ -d "${ROOT_DIR}/.github/workflows" ]] || fail 'rule input is missing: .github/workflows'
[[ -d "${ROOT_DIR}/scripts" ]] || fail 'rule input is missing: scripts'

python3 - "$ROOT_DIR" <<'PY' || exit 1
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])


def fail(message: str) -> None:
    print(f"check_ci_annotation_integrity: {message}", file=sys.stderr)
    raise SystemExit(1)


# Free text an outside contributor writes, which the webhook payload carries verbatim.
# `title` and `head_ref` cannot hold a newline today, but the rule covers them anyway:
# a single-line value interpolated alone into a `run:` block also starts a log line, and
# a rule with no case analysis in it is a rule nobody has to re-derive.
UNTRUSTED_FIELDS = (
    "github.event.pull_request.body",
    "github.event.pull_request.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.head_commit.message",
    "github.head_ref",
)
BODY_FIELD = "github.event.pull_request.body"

EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
BINDING = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*):\s*(\$\{\{.*?\}\})\s*$")

workflows = sorted(path for path in (root / ".github/workflows").iterdir() if path.suffix in {".yml", ".yaml"})
if not workflows:
    fail("no workflow files found; the rule has no input to judge")

body_bindings: list[tuple[str, str, str]] = []
for workflow in workflows:
    try:
        text = workflow.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read {workflow.name}: {error}")
    name = workflow.name

    # pull_request_target runs with a write token and repository secrets against the
    # fork's description. The severity bound above rests on this trigger being absent.
    if re.search(r"^\s*pull_request_target:", text, re.MULTILINE):
        fail(
            f"{name} triggers on pull_request_target, which hands a fork's text a write token "
            "and repository secrets (rule: rustfs/gateway#224)"
        )

    for match in EXPRESSION.finditer(text):
        expression = match.group(1).strip()
        for field in UNTRUSTED_FIELDS:
            if not re.search(rf"(?<![A-Za-z0-9_.]){re.escape(field)}(?![A-Za-z0-9_])", expression):
                continue
            if expression != f"toJSON({field})":
                fail(
                    f"{name} exposes {field} to the CI log as ${{{{ {expression} }}}}; a line of it "
                    "beginning :: would be parsed as a workflow command. Export "
                    f"${{{{ toJSON({field}) }}}} and decode it in the consumer "
                    "(rule: rustfs/gateway#224)"
                )

    for line in text.splitlines():
        binding = BINDING.match(line)
        if binding is None:
            continue
        key, expression = binding.groups()
        if BODY_FIELD in expression:
            body_bindings.append((name, key, expression.strip()))

if not body_bindings:
    fail(
        "no workflow step exports the pull-request body, so this guard has nothing to prove; "
        "if the export moved, move this rule with it (rule: rustfs/gateway#224)"
    )

# ---------------------------------------------------------------------------
# A model of the runner: how it prints a step's env block, and how it reads the
# resulting log stream back as workflow commands.
# ---------------------------------------------------------------------------
COMMAND = re.compile(r"^::([A-Za-z0-9_-]+)(\s[^:]*)?::(.*)$")
ANNOTATIONS = {"error", "warning", "notice", "debug"}


def render_env_block(key: str, value: str) -> list[str]:
    """The log the runner prints for a step whose env block binds `key` to `value`.

    A multi-line value is printed across as many log lines; only the first carries the
    key. That is the whole mechanism.
    """
    lines = ["Run bash scripts/check_protected_files.sh", "  shell: /usr/bin/bash -e {0}", "  env:"]
    first, separator, rest = value.partition("\n")
    lines.append(f"    {key}: {first}")
    if separator:
        lines.extend(rest.split("\n"))
    return lines


def scan(lines: list[str]) -> list[tuple[str, str]]:
    """Annotations the runner would raise from a log stream, honouring stop-commands."""
    raised: list[tuple[str, str]] = []
    stop_token: str | None = None
    for raw in lines:
        # Match on the left-trimmed line: the conservative reading, and the one that does
        # not depend on how deeply the runner happens to indent a continuation line.
        match = COMMAND.match(raw.lstrip())
        if stop_token is not None:
            if match is not None and match.group(1) == stop_token:
                stop_token = None
            continue
        if match is None:
            continue
        command, _, message = match.groups()
        if command == "stop-commands":
            stop_token = message
        elif command in ANNOTATIONS:
            raised.append((command, message))
    return raised


def evaluate(expression: str, value: str) -> str:
    """The text a workflow expression puts in the environment for a given payload value."""
    if expression == f"${{{{ toJSON({BODY_FIELD}) }}}}":
        return json.dumps(value)
    if expression == f"${{{{ {BODY_FIELD} }}}}":
        return value
    fail(f"unrecognised pull-request body expression, so its log rendering is unknown: {expression}")
    raise AssertionError("unreachable")


FORGED = "::warning file=scripts/ci_budget.sh,line=1::guard-self-test used 99% of its budget"
GENUINE = "::warning file=scripts/ci_budget.sh,line=1::guard-self-test used 84% of its budget"
FORGERY_BODY = f"Notes on the budget warning.\n{FORGED}\nEnd of the description."
SUPPRESSION_BODY = "Notes on the budget warning.\n::stop-commands::9f2c1d7a4b\nEnd of the description."

for name, key, expression in body_bindings:
    # Control: the same fixtures rendered the way the defect rendered them. If these two
    # do not reproduce forgery and suppression, the model above has stopped modelling
    # anything and the assertions under it are decoration.
    forged_control = scan(render_env_block(key, FORGERY_BODY))
    if ("warning", FORGED.split("::")[-1]) not in forged_control:
        fail(
            "the runner model no longer reproduces annotation forgery from a raw body, so the "
            f"assertions it backs cannot fail ({name}: {key})"
        )
    suppressed_control = scan(render_env_block(key, SUPPRESSION_BODY) + [GENUINE])
    if suppressed_control:
        fail(
            "the runner model no longer reproduces ::stop-commands:: suppression from a raw body, "
            f"so the assertions it backs cannot fail ({name}: {key})"
        )

    # Direction one: a body that contains an annotation command must raise nothing.
    forged = scan(render_env_block(key, evaluate(expression, FORGERY_BODY)))
    if forged:
        fail(
            f"{name} step env {key} lets a pull-request body forge CI annotations: {forged} "
            "(rule: rustfs/gateway#224)"
        )

    # Direction two: a body that contains ::stop-commands:: must not silence a genuine one.
    survived = scan(render_env_block(key, evaluate(expression, SUPPRESSION_BODY)) + [GENUINE])
    if survived != [("warning", GENUINE.split("::")[-1])]:
        fail(
            f"{name} step env {key} lets a pull-request body suppress genuine CI annotations; "
            f"the budget warning emitted afterwards came back as {survived} "
            "(rule: rustfs/gateway#224)"
        )

print(
    f"check_ci_annotation_integrity: {len(body_bindings)} pull-request body export(s) cannot forge "
    "or suppress an annotation"
)
PY

# ---------------------------------------------------------------------------
# The run-time half: every consumer must refuse a body that is not one JSON line.
#
# This is the enforcement of the single assumption the check above cannot observe.
# Both directions are probed: a multi-line value must be refused with the diagnostic that
# names the reason, and a well-formed single-line value must not be refused for it -- a
# consumer that rejects everything would satisfy a one-directional probe.
# ---------------------------------------------------------------------------
CONSUMER_DIAGNOSTIC='must be a single-line JSON string'

consumers=()
while IFS= read -r consumer; do
    consumers+=("$consumer")
done < <(
    python3 - "$ROOT_DIR" "$(basename "${BASH_SOURCE[0]}")" <<'PY'
import sys
from pathlib import Path

scripts = Path(sys.argv[1]) / "scripts"
myself = sys.argv[2]
for path in sorted(scripts.glob("check_*.sh")):
    if path.name == myself:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        continue
    if "GATEWAY_PR_BODY_JSON" in text:
        print(path.name)
PY
)

[[ "${#consumers[@]}" -ge 2 ]] || fail 'expected the protected-files and role-verdict guards to consume GATEWAY_PR_BODY_JSON, found '"${#consumers[@]}"

for consumer in "${consumers[@]}"; do
    script="${ROOT_DIR}/scripts/${consumer}"
    [[ -x "$script" ]] || fail "consumer is missing or not executable: scripts/${consumer}"

    multiline_output="$(GATEWAY_PR_BODY_JSON=$'"first"\n::warning::forged' bash "$script" 2>&1 || true)"
    case "$multiline_output" in
    *"$CONSUMER_DIAGNOSTIC"*) ;;
    *)
        fail "scripts/${consumer} accepts a multi-line GATEWAY_PR_BODY_JSON, so a body that was never JSON-encoded would reach it unnoticed (rule: rustfs/gateway#224)"
        ;;
    esac

    single_line_output="$(GATEWAY_PR_BODY_JSON='"a single line"' bash "$script" 2>&1 || true)"
    case "$single_line_output" in
    *"$CONSUMER_DIAGNOSTIC"*)
        fail "scripts/${consumer} rejects a well-formed single-line GATEWAY_PR_BODY_JSON, so its multi-line rejection proves nothing"
        ;;
    esac
done

printf 'check_ci_annotation_integrity: %s consumer(s) fail closed on a body that is not one JSON line\n' "${#consumers[@]}"
