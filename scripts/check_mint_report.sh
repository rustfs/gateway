#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_mint_report.sh
#
# WHAT THIS CHECKS
#   That ci/mint/report.py can actually fail, in every direction it claims to
#   have. Probes over synthetic /mint/log trees and console transcripts:
#
#     verdicts      a count above the baseline is a REGRESSION (exit 1); an
#                   equal non-zero count is KNOWN; a lower one is IMPROVED;
#                   NA is its own column and is neither a failure nor a pass
#     incomplete    malformed JSON, a non-object record, an unknown status, an
#                   unknown suite directory, a baseline SDK with no record or an
#                   empty log, an SDK the console never started or finished, an
#                   SDK that exited non-zero without a FAIL record, a baseline
#                   whose census differs, a baseline without a generation:
#                   every one exits 3, never 1
#     excluded      an excluded SDK with no record, a non-JSON log or an
#                   unattributed runner failure leaves the run complete and is
#                   listed in its own section, while the same SDK counted is
#                   exit 3; its FAIL records never become a regression; it is
#                   flagged RECOVERED only when its log is complete and
#                   attributable; a counted SDK's record inside its log, or its
#                   absence from the console, is exit 3; an exclusion without
#                   an in-project owner or a reason is refused
#     record        a complete run proposes generation + 1 with the observed
#                   counts and leaves the reviewed baseline byte-identical; an
#                   incomplete run proposes nothing and removes a stale proposal;
#                   a proposal aimed at the baseline itself is refused; an
#                   exclusion is carried into the proposal unchanged
#     redaction     Authorization, presigned-query signatures, StringToSign and
#                   the secret leave the evidence files, and the aggregate
#                   report carries no record's `error` text
#
# WHY THIS IS A GUARD AND NOT A UNIT TEST
#   The zombie failure mode for an external suite is that the judgement
#   silently stops judging: a reporter that stops reading FAIL records turns a
#   red run into a clean one, and a clean run reads exactly like a passing run.
#   AGENTS.md "Measurement" lists seven checks here that could not fail. The
#   tool that decides whether the scheduled job is green owes a check that runs
#   on every pull request, not only once a week beside the run it judges.
#
# HOW TO EXEMPT
#   None.
#
# USAGE
#   scripts/check_mint_report.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_mint_report.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
REPORT="${ROOT_DIR}/ci/mint/report.py"

if [[ ! -f "$REPORT" ]]; then
    printf 'check_mint_report: required input is missing: ci/mint/report.py\n' >&2
    exit 1
fi

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_mint_report)" || exit 1
"$PYTHON" - "$REPORT" <<'PYEOF'
import json
import subprocess
import sys
import tempfile
from pathlib import Path

report = sys.argv[1]
failures: list[str] = []
probes = 0

SDKS = ["awscli", "minio-go", ".minio-dotnet"]
SECRET = "probe-secret-that-must-never-survive"
UNIQUE_ERROR = "UNIQUE-UPSTREAM-ERROR-TEXT-7f3a"


def rec(sdk: str, function: str, status: str, **extra: object) -> str:
    return json.dumps({"name": sdk, "function": function, "duration": 5, "status": status, **extra})


def healthy_logs() -> dict[str, str | None]:
    return {
        "awscli": "\n".join([rec("awscli", "list-buckets", "PASS"), rec("awscli", "put-object", "PASS")]),
        "minio-go": "\n".join(
            [
                rec("minio-go", "PutObject(bucketName, objectName)", "PASS"),
                rec("minio-go", "GetObject(bucketName, objectName)", "PASS"),
                rec("minio-go", "SelectObjectContent(ctx)", "FAIL", error=UNIQUE_ERROR),
                rec("minio-go", "ListenBucketNotification(bucketName)", "NA"),
            ]
        ),
        ".minio-dotnet": rec("minio-dotnet", "MakeBucket", "PASS"),
    }


def console(outcomes: dict[str, str | None], order: list[str] | None = None) -> str:
    order = order if order is not None else SDKS
    lines = ["Running with", "SERVER_ENDPOINT:      127.0.0.1:9200", ""]
    for index, sdk in enumerate(order, start=1):
        outcome = outcomes.get(sdk, "done")
        if outcome is None:
            lines.append(f"({index}/{len(SDKS)}) Running {sdk} tests ... ")
            break
        lines.append(f"({index}/{len(SDKS)}) Running {sdk} tests ... {outcome} in 3 seconds")
    return "\n".join(lines) + "\n"


HEALTHY_PROGRESS = {"awscli": "done", "minio-go": "FAILED", ".minio-dotnet": "done"}


OWNER_URL = "https://github.com/rustfs/gateway/issues/9999"
EXCLUSION_REASON = "its runner cannot write a record in this probe"


def baseline(counts: dict[str, int] | None = None, generation: str | None = "4",
             excluded: dict[str, str] | None = None) -> str:
    """`excluded` maps an SDK to the rest of its line after `<sdk> excluded`."""
    counts = counts if counts is not None else {"awscli": 0, "minio-go": 1, ".minio-dotnet": 0}
    header = "" if generation is None else f"# generation: {generation}\n"
    lines = "".join(f"{sdk} {count}\n" for sdk, count in counts.items())
    lines += "".join(f"{sdk} excluded {rest}\n" for sdk, rest in (excluded or {}).items())
    return "# probe baseline\n" + header + lines


# The fixture's third SDK, excluded: the shape every excluded-SDK probe below starts from.
EXCLUDING_DOTNET = baseline({"awscli": 0, "minio-go": 1}, excluded={".minio-dotnet": f"{OWNER_URL} {EXCLUSION_REASON}"})


def probe(
    label: str,
    expected_code: int,
    expect: list[str] = [],
    forbid: list[str] = [],
    logs: dict[str, str | None] | None = None,
    progress: str | None = None,
    base: str | None = None,
    extra_dirs: dict[str, str] | None = None,
    record: bool = False,
    stale_proposal: bool = False,
    record_at_baseline: bool = False,
    after=None,
) -> None:
    global probes
    probes += 1
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        log_dir = work / "log"
        log_dir.mkdir()
        for sdk, text in (healthy_logs() if logs is None else logs).items():
            if text is None:
                continue
            (log_dir / sdk).mkdir()
            (log_dir / sdk / "log.json").write_text(text + ("\n" if text else ""), encoding="utf-8")
        for name, text in (extra_dirs or {}).items():
            (log_dir / name).mkdir()
            (log_dir / name / "log.json").write_text(text + "\n", encoding="utf-8")
        progress_path = work / "console.txt"
        progress_path.write_text(console(HEALTHY_PROGRESS) if progress is None else progress, encoding="utf-8")
        baseline_path = work / "baseline.txt"
        baseline_text = baseline() if base is None else base
        baseline_path.write_text(baseline_text, encoding="utf-8")
        markdown = work / "summary.md"
        report_json = work / "report.json"
        proposal = baseline_path if record_at_baseline else work / "baseline.proposed.txt"
        if stale_proposal:
            proposal.write_text("# generation: 99\nstale 0\n", encoding="utf-8")
        command = [
            sys.executable, report, "judge",
            "--log-dir", str(log_dir), "--progress", str(progress_path), "--baseline", str(baseline_path),
            "--sdks", " ".join(SDKS), "--markdown", str(markdown), "--json", str(report_json),
        ]
        if record or record_at_baseline:
            command += ["--record", str(proposal)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        combined = result.stdout + result.stderr
        for written in (markdown, report_json):
            if written.is_file():
                combined += written.read_text(encoding="utf-8")
        if result.returncode != expected_code:
            failures.append(
                f"{label}: expected exit {expected_code}, got {result.returncode}\n"
                + "\n".join(f"    {line}" for line in combined.splitlines())
            )
            return
        for needle in expect:
            if needle not in combined:
                failures.append(f"{label}: expected {needle!r} in the output, got:\n{combined}")
        for needle in forbid:
            if needle in combined:
                failures.append(f"{label}: {needle!r} must not appear in the output, got:\n{combined}")
        if baseline_path.read_text(encoding="utf-8") != baseline_text:
            failures.append(f"{label}: the reviewed baseline was modified")
        if after is not None:
            problem = after(work, proposal)
            if problem:
                failures.append(f"{label}: {problem}")


# --- verdicts ------------------------------------------------------------------------------
probe("a count equal to the baseline is KNOWN", 0,
      ["KNOWN      minio-go fail=1 baseline=1", "regression=0", "known=1", "incomplete=0"], ["REGRESSION "])

above = healthy_logs()
above["awscli"] += "\n" + rec("awscli", "delete-bucket-policy", "FAIL")
probe("a count above the baseline is a REGRESSION and fails", 1,
      ["REGRESSION awscli fail=1 baseline=0", "regression=1"],
      logs=above, progress=console({**HEALTHY_PROGRESS, "awscli": "FAILED"}))

below = healthy_logs()
below["minio-go"] = rec("minio-go", "PutObject(bucketName, objectName)", "PASS")
probe("a count below the baseline is IMPROVED, not silently KNOWN", 0,
      ["IMPROVED   minio-go fail=0 baseline=1", "improved=1"], ["REGRESSION "],
      logs=below, progress=console({**HEALTHY_PROGRESS, "minio-go": "done"}))

only_na = healthy_logs()
only_na[".minio-dotnet"] = "\n".join([rec("minio-dotnet", "MakeBucket", "NA"), rec("minio-dotnet", "ListBuckets", "NA")])
probe("NA is reported apart and is neither a failure nor a pass", 0,
      ["OK         .minio-dotnet fail=0 baseline=0 pass=0 na=2", "na=3"], ["REGRESSION "], logs=only_na)

# --- an incomplete run is exit 3 and never a regression -------------------------------------
broken = healthy_logs()
broken["awscli"] += "\n{\"name\": \"awscli\", \"status\": "
probe("a truncated JSON record is an incomplete run", 3, ["is not valid JSON"], ["REGRESSION "], logs=broken)

listed = healthy_logs()
listed["awscli"] += "\n[\"PASS\"]"
probe("a record that is not a JSON object is an incomplete run", 3, ["is not a JSON object"], logs=listed)

odd = healthy_logs()
odd["awscli"] += "\n" + rec("awscli", "head-object", "SKIPPED")
probe("an unknown status is an incomplete run, not a pass", 3, ["which is not one of"], ["REGRESSION "], logs=odd)

probe("a suite the runner never asked for is an incomplete run", 3, ["an unknown suite wrote records"],
      extra_dirs={"aws-sdk-rust": rec("aws-sdk-rust", "x", "FAIL")})

no_record = healthy_logs()
no_record["minio-go"] = None
probe("a baseline SDK that left no record is an incomplete run", 3,
      ["minio-go: produced no record"], ["IMPROVED "], logs=no_record)

empty = healthy_logs()
empty["awscli"] = ""
probe("an SDK with an empty log is an incomplete run", 3, ["awscli: produced no record"], logs=empty)

silent = healthy_logs()
probe("an SDK whose runner failed without a FAIL record is an incomplete run", 3,
      ["awscli: its runner exited non-zero without writing a FAIL record"], ["REGRESSION "],
      logs=silent, progress=console({**HEALTHY_PROGRESS, "awscli": "FAILED"}))

probe("an SDK the console never saw finish is an incomplete run", 3,
      [".minio-dotnet: the console never reported it finishing"],
      progress=console({**HEALTHY_PROGRESS, ".minio-dotnet": None}))

probe("an SDK the console never saw start is an incomplete run", 3,
      [".minio-dotnet: the console never reported it starting"],
      progress=console(HEALTHY_PROGRESS, order=["awscli", "minio-go"]))

probe("a console that ran the SDKs in another order is an incomplete run", 3,
      ["where the runner asked for"],
      progress=console(HEALTHY_PROGRESS, order=["minio-go", "awscli", ".minio-dotnet"]))

probe("a baseline without an SDK's line is an incomplete run", 3, ["the baseline has no line for: .minio-dotnet"],
      base=baseline({"awscli": 0, "minio-go": 1}))

probe("a baseline without a generation header is refused", 3, ["generation"], base=baseline(generation=None))

# --- excluded SDKs: reported apart, never judged, never a place to hide a counted one -------
DOTNET_FAILED = console({**HEALTHY_PROGRESS, ".minio-dotnet": "FAILED"})
dotnet_silent = healthy_logs()
dotnet_silent[".minio-dotnet"] = None
probe("an excluded SDK that left no record is reported apart and the run is complete", 0,
      ["EXCLUDED   .minio-dotnet owner=" + OWNER_URL, "produced no record", "### Excluded SDKs",
       EXCLUSION_REASON, "excluded=1", "recovered=0", "incomplete=0"],
      ["INCOMPLETE", "RECOVERED"], logs=dotnet_silent, base=EXCLUDING_DOTNET, progress=DOTNET_FAILED)

# The control: the same silent, failed runner is an incomplete run the moment it is counted.
probe("the same silent SDK, counted instead of excluded, is an incomplete run", 3,
      [".minio-dotnet: produced no record"], ["EXCLUDED "], logs=dotnet_silent, progress=DOTNET_FAILED)

# mc's shape: a runner that prints its own diagnostics into the record stream.
preamble = healthy_logs()
preamble[".minio-dotnet"] = "Dependency check complete\n" + rec("minio-dotnet", "MakeBucket", "FAIL")
probe("an excluded SDK whose log opens with text that is not JSON is reported apart", 0,
      ["EXCLUDED   .minio-dotnet", "record 1 in .minio-dotnet/log.json is not valid JSON"],
      ["INCOMPLETE", "REGRESSION ", "RECOVERED"], logs=preamble, base=EXCLUDING_DOTNET, progress=DOTNET_FAILED)

hiding = healthy_logs()
hiding[".minio-dotnet"] = "Dependency check complete\n" + rec("awscli", "put-object", "FAIL")
probe("an excluded SDK whose log carries a counted SDK's records is an incomplete run", 3,
      [".minio-dotnet: excluded, but its log carries 1 record(s) naming awscli"], ["REGRESSION "],
      logs=hiding, base=EXCLUDING_DOTNET, progress=DOTNET_FAILED)

recovered = healthy_logs()
recovered[".minio-dotnet"] = "\n".join([
    rec("minio-dotnet", "MakeBucket", "PASS"), rec("minio-dotnet", "PutObject", "FAIL"),
    rec("minio-dotnet", "ListenBucketNotification", "NA"),
])
probe("an excluded SDK that writes valid records again is flagged RECOVERED and still not judged", 0,
      ["RECOVERED  .minio-dotnet", "1 PASS, 1 FAIL, 1 NA", "recovered=1", "incomplete=0"],
      ["REGRESSION ", "INCOMPLETE"], logs=recovered, base=EXCLUDING_DOTNET, progress=DOTNET_FAILED)

# The other direction: valid records alone are not a recovery while the failure stays unattributed.
passing_but_failed = healthy_logs()
probe("an excluded SDK whose runner failed without a FAIL record is not RECOVERED", 0,
      ["EXCLUDED   .minio-dotnet", "exited non-zero without writing a FAIL record", "recovered=0"],
      ["RECOVERED ", "INCOMPLETE"], logs=passing_but_failed, base=EXCLUDING_DOTNET, progress=DOTNET_FAILED)

probe("an excluded SDK the console never saw start is still an incomplete run", 3,
      [".minio-dotnet: the console never reported it starting"], base=EXCLUDING_DOTNET,
      progress=console(HEALTHY_PROGRESS, order=["awscli", "minio-go"]))

probe("an exclusion without an owning issue is refused", 3, ["names no owning"],
      base=baseline({"awscli": 0, "minio-go": 1}, excluded={".minio-dotnet": EXCLUSION_REASON}))

probe("an exclusion owned outside this project is refused", 3, ["names no owning"],
      base=baseline({"awscli": 0, "minio-go": 1},
                    excluded={".minio-dotnet": "https://github.com/minio/mint/issues/1 " + EXCLUSION_REASON}))

probe("an exclusion without a reason is refused", 3, ["gives no reason"],
      base=baseline({"awscli": 0, "minio-go": 1}, excluded={".minio-dotnet": OWNER_URL}))

probe("an SDK both counted and excluded is refused", 3, [".minio-dotnet is listed more than once"],
      base=EXCLUDING_DOTNET + ".minio-dotnet 0\n")

# --- record mode ---------------------------------------------------------------------------


def proposed(counts: dict[str, int], generation: int):
    def check(work: Path, proposal: Path) -> str | None:
        if not proposal.is_file():
            return "no proposal was written"
        text = proposal.read_text(encoding="utf-8")
        if f"# generation: {generation}\n" not in text:
            return f"the proposal does not carry generation {generation}:\n{text}"
        for sdk, count in counts.items():
            if f"\n{sdk} {count}\n" not in text:
                return f"the proposal does not carry `{sdk} {count}`:\n{text}"
        if "stale" in text:
            return "the proposal still carries a stale run's content"
        return None

    return check


def no_proposal(work: Path, proposal: Path) -> str | None:
    return "an incomplete run left a proposal behind" if proposal.exists() else None


probe("record mode proposes generation + 1 from a complete run and does not fail on a regression", 0,
      ["proposed generation 5"], logs=above, progress=console({**HEALTHY_PROGRESS, "awscli": "FAILED"}),
      record=True, stale_proposal=True, after=proposed({"awscli": 1, "minio-go": 1, ".minio-dotnet": 0}, 5))

probe("record mode writes no proposal for an incomplete run and removes a stale one", 3,
      ["no baseline proposal written"], logs=no_record, record=True, stale_proposal=True, after=no_proposal)

probe("record mode refuses to overwrite the reviewed baseline", 2, ["never overwrites the reviewed baseline"],
      record_at_baseline=True)


def carries_exclusion(work: Path, proposal: Path) -> str | None:
    problem = proposed({"awscli": 0, "minio-go": 1}, 5)(work, proposal)
    if problem:
        return problem
    text = proposal.read_text(encoding="utf-8")
    if f"\n.minio-dotnet excluded {OWNER_URL} {EXCLUSION_REASON}\n" not in text:
        return f"the proposal dropped or rewrote the exclusion:\n{text}"
    if "\n.minio-dotnet 0\n" in text:
        return f"the proposal gave an excluded SDK a count:\n{text}"
    return None


probe("record mode carries an exclusion into the proposal unchanged and gives it no count", 0,
      ["proposed generation 5"], logs=dotnet_silent, base=EXCLUDING_DOTNET, progress=DOTNET_FAILED,
      record=True, after=carries_exclusion)

# --- what leaves the run -------------------------------------------------------------------
probe("the aggregate report never carries a record's error text", 0, ["SelectObjectContent(ctx)"], [UNIQUE_ERROR])

leaky = healthy_logs()
leaky["minio-go"] = leaky["minio-go"].replace(
    "SelectObjectContent(ctx)", "PresignedGetObject(url=http://x/b/o?X-Amz-Signature=feedfacefeedface0001)"
)
probe("a failing function name is redacted before it reaches the aggregate report", 0,
      ["X-Amz-Signature=[REDACTED]"], ["feedfacefeedface0001"], logs=leaky)

probes += 1
with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    (work / "log" / "awscli").mkdir(parents=True)
    evidence = work / "log" / "awscli" / "log.json"
    console_path = work / "console.txt"
    signed = (
        "Authorization: AWS4-HMAC-SHA256 Credential=AKIAPROBE/20260912/us-east-1/s3/aws4_request, "
        "SignedHeaders=host, Signature=0123456789abcdef0123456789abcdef\n"
        "GET /b/o?X-Amz-Credential=AKIAPROBE%2F20260912&X-Amz-Signature=cafebabecafebabe0002 HTTP/1.1\n"
        "<Error><StringToSign>AWS4-HMAC-SHA256 20260912T000000Z canonical-bytes-0003</StringToSign>"
        f"<SignatureProvided>badbadbad0004</SignatureProvided></Error> secret={SECRET}\n"
    )
    evidence.write_text(rec("awscli", "get-object", "FAIL", error=signed) + "\n", encoding="utf-8")
    console_path.write_text(signed, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, report, "redact", "--secret-env", "PROBE_SECRET", str(work / "log"), str(console_path)],
        capture_output=True, text=True, check=False, env={"PROBE_SECRET": SECRET, "PATH": "/usr/bin:/bin"},
    )
    if result.returncode != 0:
        failures.append(f"redaction exited {result.returncode}: {result.stdout}{result.stderr}")
    for path in (evidence, console_path):
        text = path.read_text(encoding="utf-8")
        for leaked in (
            "0123456789abcdef0123456789abcdef", "cafebabecafebabe0002", "canonical-bytes-0003",
            "badbadbad0004", SECRET, "AKIAPROBE/20260912",
        ):
            if leaked in text:
                failures.append(f"redaction left {leaked!r} in {path.name}:\n{text}")
        if "[REDACTED]" not in text:
            failures.append(f"redaction marked nothing in {path.name}")
    if json.loads(evidence.read_text(encoding="utf-8").splitlines()[0]).get("status") != "FAIL":
        failures.append("redaction broke the record it rewrote; the judge could no longer read it")

if failures:
    for failure in failures:
        print(f"check_mint_report: {failure}", file=sys.stderr)
    raise SystemExit(1)

print(f"OK: {probes} mint report probes; regressions fail, incomplete runs exit 3, NA stays apart, "
      "record proposes generation + 1 only from a complete run, and signing material is redacted")
PYEOF
