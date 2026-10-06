#!/usr/bin/env python3
"""Test narrow producer edits on authored fixtures, not a vendored SDK suite.

Checks byte preservation and shell behavior; real .NET compilation and SDK
execution belong to the native image trial and are not claimed by this guard.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import types

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "ci/mint/patch_producers.py"
module = types.ModuleType("producer_patch")
exec(compile(PATCH.read_text(), str(PATCH), "exec"), module.__dict__)

# Independently authored small shapes with the exact upstream patch anchors.
LOGGER = '''// license sentinel: preserve this byte for byte
class Probe {
    object options = new {
        WriteIndented = false,
    };
    void Construct(string testName, string function, string error) {
        Function = function;
        Name = $"{Name} : {testName}";
        Error = error;
    }
    public string Name { get; } = "minio-dotnet";
    public string Function { get; }
    public string Error { get; }
}
'''
RUNNER = '''#!/bin/bash
# license sentinel
output_log_file="$1"
error_log_file="$2"
/mint/run/core/minio-dotnet/out/Minio.Functional.Tests 1>>"$output_log_file" 2>"$error_log_file"
'''
BARE_CALLS = ('mc_cmd mb "${SERVER_ALIAS}/${bucket_name}"',
              'echo "testcontent" | mc_cmd pipe "${SERVER_ALIAS}/${bucket_name}/${object_name}"')
CAT = '''function test_cat_stdin() {
    bucket_name="authored-bucket"
    object_name="authored-object"
    mc_cmd mb "${SERVER_ALIAS}/${bucket_name}"
    echo "testcontent" | mc_cmd pipe "${SERVER_ALIAS}/${bucket_name}/${object_name}"
    assert_success "$start_time" "${FUNCNAME[0]}" show_on_failure "$cat_status" "authored cat detail"
    assert_success "$start_time" "${FUNCNAME[0]}" check_md5sum "authored digest" "authored output"
    assert_success "$start_time" "${FUNCNAME[0]}" mc_cmd rm "authored output"
    :
}
'''
MC = '''#!/bin/bash
# license sentinel
assert_success() { :; }
function validate_dependencies() {
    if [[ "$1" == ready ]]; then
        echo "Dependency validation complete"
    else
        echo "jq is missing, please install: 'sudo apt install jq'"
        exit 1
    fi
}
''' + CAT + '''helper_failure() { echo "independent failure detail"; return 9; }
helper_success() { echo "independent success detail"; }
validate_dependencies "$1"
if [[ "$2" == fail ]]; then
    detail=$(helper_failure)
    code=$?
    printf '{"name":"mc","function":"fixture","status":"FAIL","error":"%s"}\\n' "$detail"
    exit "$code"
fi
detail=$(helper_success)
printf '{"name":"mc","function":"fixture","status":"PASS","detail":"%s"}\\n' "$detail"
'''
PROBE = MC.partition('validate_dependencies "$1"\n')[0] + '''
mc_cmd() {
    if [[ "$1" == pipe ]]; then cat >/dev/null; fi
    if [[ "$1" == "$FAIL_VERB" ]]; then
        printf 'authored %s diagnostic "quoted"\\n' "$1"
        return 9
    fi
    return 0
}
SERVER_ALIAS=authored-alias
validate_dependencies ready
FAIL_VERB="$1"
if [[ "$1" == inspect ]]; then
    detail=$(mc_cmd inspect)
    code=$?
    python3 -c 'import json,sys; print(json.dumps(dict(name="mc",function="authored-capture",status="FAIL",error=sys.argv[1])))' "$detail"
    exit "$code"
fi
test_cat_stdin
code=$?
printf '{"name":"mc","function":"authored-bare","status":"PASS"}\\n'
exit "$code"
'''

STAGE_PROBE = MC.partition('validate_dependencies "$1"\n')[0] + '''
assert_success() {
    label="$2"
    shift 2
    detail=$("$@")
    status=$?
    if [[ "$status" != 0 ]]; then
        python3 -c 'import json,sys; print(json.dumps(dict(name="mc",function=sys.argv[1],status="FAIL",error=sys.argv[2])))' "$label" "$detail"
        exit "$status"
    fi
}
show_on_failure() {
    if [[ "$1" != 0 ]]; then printf '%s' "$2"; fi
    return "$1"
}
check_md5sum() {
    if [[ "$FAIL_STAGE" == checksum ]]; then
        printf 'authored checksum detail'
        return 8
    fi
}
mc_cmd() {
    if [[ "$1" == pipe ]]; then cat >/dev/null; fi
    if [[ "$1" == "$FAIL_STAGE" ]]; then return 11; fi
    if [[ "$1" == rm && "$FAIL_STAGE" == cleanup ]]; then
        printf 'authored cleanup detail'
        return 9
    fi
}
SERVER_ALIAS=authored-alias
FAIL_STAGE="$1"
start_time=0
cat_status=0
if [[ "$FAIL_STAGE" == cat_status ]]; then cat_status=7; fi
test_cat_stdin
printf '{"name":"mc","function":"test_cat_stdin","status":"PASS"}\\n'
'''

STAGE_ANCHORS = (
    ('show_on_failure "$cat_status" "authored cat detail"', "cat_status"),
    ('check_md5sum "authored digest" "authored output"', "checksum"),
    ('mc_cmd rm "authored output"', "cleanup"),
)


class ProducerPatch(unittest.TestCase):
    def test_logger_changes_only_serialization_and_identity(self):
        patched = module.transform("logger", LOGGER)
        expected = LOGGER.replace("WriteIndented = false,", "WriteIndented = false,\n        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,")
        expected = expected.replace('Name = $"{Name} : {testName}";', 'TestName = testName;')
        expected = expected.replace('public string Name { get; } = "minio-dotnet";', 'public string Name { get; } = "minio-dotnet";\n\n    public string TestName { get; }')
        self.assertEqual(patched, expected)
        self.assertIn("Function = function;", patched)
        self.assertIn("Error = error;", patched)

    def test_runner_only_relocates_executable(self):
        self.assertEqual(module.transform("dotnet-runner", RUNNER), RUNNER.replace(
            "/mint/run/core/minio-dotnet/out/Minio.Functional.Tests", "/opt/mint-dotnet/Minio.Functional.Tests"))

    def run_mc(self, dependency, outcome):
        patched = module.transform("mc", MC)
        return subprocess.run(["bash", "-c", patched, "fixture", dependency, outcome], capture_output=True, text=True)

    def test_mc_success_remains_json_and_keeps_helper_stdout(self):
        result = self.run_mc("ready", "pass")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertEqual(json.loads(result.stdout), dict(name="mc", function="fixture", status="PASS", detail="independent success detail"))
        self.assertEqual(result.stderr, "Dependency validation complete\n")

    def test_mc_failure_keeps_error_and_exit(self):
        result = self.run_mc("ready", "fail")
        self.assertEqual(result.returncode, 9)
        self.assertEqual(json.loads(result.stdout), dict(name="mc", function="fixture", status="FAIL", error="independent failure detail"))
        self.assertEqual(result.stderr, "Dependency validation complete\n")

    def test_dependency_failure_is_not_a_pass(self):
        result = self.run_mc("missing", "pass")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("jq is missing", result.stderr)

    def test_mc_only_changes_uncaptured_diagnostics_and_failure_labels(self):
        expected = MC.replace('echo "Dependency validation complete"', 'echo "Dependency validation complete" >&2')
        expected = expected.replace('echo "jq is missing, please install: \'sudo apt install jq\'"', 'echo "jq is missing, please install: \'sudo apt install jq\'" >&2')
        for statement in BARE_CALLS:
            expected = expected.replace(statement, statement + " >&2")
        for command, stage in STAGE_ANCHORS:
            expected = expected.replace('"${FUNCNAME[0]}" ' + command,
                                        '"${FUNCNAME[0]}:' + stage + '" ' + command)
        self.assertEqual(module.transform("mc", MC), expected)

    def run_stage(self, stage, *, patched):
        source = module.transform("mc", STAGE_PROBE) if patched else STAGE_PROBE
        return subprocess.run(["bash", "-c", source, "fixture", stage], capture_output=True, text=True)

    def test_stdin_failures_name_the_stage_without_changing_outcome(self):
        for stage, code, detail in (("cat_status", 7, "authored cat detail"),
                                    ("checksum", 8, "authored checksum detail"),
                                    ("cleanup", 9, "authored cleanup detail")):
            with self.subTest(stage=stage):
                before = self.run_stage(stage, patched=False)
                after = self.run_stage(stage, patched=True)
                expected = dict(name="mc", function="test_cat_stdin", status="FAIL", error=detail)
                self.assertEqual((before.returncode, json.loads(before.stdout)), (code, expected))
                expected["function"] += ":" + stage
                self.assertEqual((after.returncode, json.loads(after.stdout)), (code, expected))
                self.assertEqual((before.stderr, after.stderr), ("", ""))

    def test_stdin_success_keeps_its_single_original_record(self):
        before = self.run_stage("none", patched=False)
        after = self.run_stage("none", patched=True)
        expected = dict(name="mc", function="test_cat_stdin", status="PASS")
        self.assertEqual((before.returncode, json.loads(before.stdout)), (0, expected))
        self.assertEqual((after.returncode, json.loads(after.stdout)), (0, expected))
        self.assertEqual((before.stderr, after.stderr), ("", ""))

    def test_stdin_unasserted_setup_failures_do_not_gain_new_outcomes(self):
        for verb in ("mb", "pipe"):
            with self.subTest(verb=verb):
                before = self.run_stage(verb, patched=False)
                after = self.run_stage(verb, patched=True)
                expected = dict(name="mc", function="test_cat_stdin", status="PASS")
                self.assertEqual((before.returncode, json.loads(before.stdout)), (0, expected))
                self.assertEqual((after.returncode, json.loads(after.stdout)), (0, expected))
                self.assertEqual((before.stderr, after.stderr), ("", ""))

    def test_missing_stdin_assertion_is_refused(self):
        for command, _ in STAGE_ANCHORS:
            line = '    assert_success "$start_time" "${FUNCNAME[0]}" ' + command
            with self.subTest(command=command), self.assertRaises(ValueError):
                module.transform("mc", MC.replace(line, "    :"))

    def test_duplicated_stdin_assertion_is_refused(self):
        for command, _ in STAGE_ANCHORS:
            line = '    assert_success "$start_time" "${FUNCNAME[0]}" ' + command
            with self.subTest(command=command), self.assertRaises(ValueError):
                module.transform("mc", MC.replace(line, line + "\n" + line))

    def test_moved_stdin_assertion_is_refused(self):
        for command, _ in STAGE_ANCHORS:
            line = '    assert_success "$start_time" "${FUNCNAME[0]}" ' + command
            with self.subTest(command=command), self.assertRaises(ValueError):
                module.transform("mc", MC.replace(line, "    :") + "\n" + line)

    def test_reapplied_stdin_labels_are_refused(self):
        for command, stage in STAGE_ANCHORS:
            with self.subTest(command=command), self.assertRaises(ValueError):
                module.transform("mc", MC.replace('"${FUNCNAME[0]}" ' + command,
                                                   '"${FUNCNAME[0]}:' + stage + '" ' + command))

    def run_probe(self, outcome):
        return subprocess.run(["bash", "-c", module.transform("mc", PROBE), "fixture", outcome],
                              capture_output=True, text=True)

    def test_bare_failures_keep_json_fields_count_and_return(self):
        for verb in ("mb", "pipe"):
            with self.subTest(verb=verb):
                result = self.run_probe(verb)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertEqual(json.loads(result.stdout), dict(name="mc", function="authored-bare", status="PASS"))
                self.assertEqual(result.stderr, f'Dependency validation complete\nauthored {verb} diagnostic "quoted"\n')

    def test_bare_success_keeps_streams_and_return(self):
        result = self.run_probe("none")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), dict(name="mc", function="authored-bare", status="PASS"))
        self.assertEqual(result.stderr, "Dependency validation complete\n")

    def test_asserted_failure_keeps_captured_error_and_return(self):
        result = self.run_probe("inspect")
        self.assertEqual(result.returncode, 9)
        self.assertEqual(json.loads(result.stdout), dict(name="mc", function="authored-capture", status="FAIL",
                                                       error='authored inspect diagnostic "quoted"'))
        self.assertEqual(result.stderr, "Dependency validation complete\n")

    def test_other_function_calls_are_preserved(self):
        other = "function independent_calls() {\n" + "".join("    " + line + "\n" for line in BARE_CALLS) + "}\n"
        source = MC + other
        expected = module.transform("mc", MC) + other
        self.assertEqual(module.transform("mc", source), expected)

    def test_missing_cat_function_is_refused(self):
        with self.assertRaises(ValueError):
            module.transform("mc", MC.replace("function test_cat_stdin()", "function independent()"))

    def test_duplicate_cat_function_is_refused(self):
        with self.assertRaises(ValueError):
            module.transform("mc", MC + CAT)

    def test_unclosed_cat_function_is_refused(self):
        with self.assertRaises(ValueError):
            module.transform("mc", MC.replace(CAT, CAT.removesuffix("}\n")))

    def test_missing_bare_statements_are_refused(self):
        for statement in BARE_CALLS:
            with self.subTest(statement=statement), self.assertRaises(ValueError):
                module.transform("mc", MC.replace(statement, ":"))

    def test_duplicate_bare_statements_are_refused(self):
        for statement in BARE_CALLS:
            with self.subTest(statement=statement), self.assertRaises(ValueError):
                module.transform("mc", MC.replace(statement, statement + "\n    " + statement))

    def test_moved_bare_statements_are_refused(self):
        for statement in BARE_CALLS:
            source = MC.replace(statement, ":") + statement + "\n"
            with self.subTest(statement=statement), self.assertRaises(ValueError):
                module.transform("mc", source)

    def test_reapplied_bare_statements_are_refused(self):
        for statement in BARE_CALLS:
            with self.subTest(statement=statement), self.assertRaises(ValueError):
                module.transform("mc", MC.replace(statement, statement + " >&2"))

    def test_cli_mc_hash_drift_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mc"
            drifted = MC + "# authored drift\n"
            path.write_text(drifted)
            digest = hashlib.sha256(MC.encode()).hexdigest()
            result = subprocess.run([sys.executable, str(PATCH), "mc", str(path), "--sha256", digest],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source SHA-256 mismatch", result.stderr)
            self.assertEqual(path.read_text(), drifted)

    def test_missing_duplicate_and_reapplied_anchors_fail(self):
        cases = [("logger", LOGGER, "WriteIndented = false,"),
                 ("logger", LOGGER, 'Name = $"{Name} : {testName}";'),
                 ("logger", LOGGER, 'public string Name { get; } = "minio-dotnet";'),
                 ("dotnet-runner", RUNNER, "/mint/run/core/minio-dotnet/out/Minio.Functional.Tests"),
                 ("mc", MC, 'echo "Dependency validation complete"'),
                 ("mc", MC, 'echo "jq is missing, please install: \'sudo apt install jq\'"')]
        for kind, source, anchor in cases:
            for invalid in (source.replace(anchor, "drift"), source + "\n" + anchor):
                with self.subTest(kind=kind, anchor=anchor, invalid=invalid[-30:]):
                    with self.assertRaises(ValueError):
                        module.transform(kind, invalid)
        for kind, source in (("logger", LOGGER), ("dotnet-runner", RUNNER), ("mc", MC)):
            with self.subTest(reapplied=kind), self.assertRaises(ValueError):
                module.transform(kind, module.transform(kind, source))

    def test_mc_diagnostic_outside_dependency_function_is_refused(self):
        for invalid in (MC.replace("function validate_dependencies()", "function other()"),
                        MC.replace('        echo "Dependency validation complete"', '        :') + '\necho "Dependency validation complete"\n'):
            with self.subTest(source=invalid), self.assertRaises(ValueError):
                module.transform("mc", invalid)

    def test_cli_hash_mismatch_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner"
            path.write_text(RUNNER)
            result = subprocess.run([sys.executable, str(PATCH), "dotnet-runner", str(path), "--sha256", "0" * 64], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source SHA-256 mismatch", result.stderr)
            self.assertEqual(path.read_text(), RUNNER)

    def test_cli_patches_verified_bytes_and_preserves_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner"
            path.write_text(RUNNER)
            path.chmod(0o751)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result = subprocess.run([sys.executable, str(PATCH), "dotnet-runner", str(path), "--sha256", digest], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = module.transform("dotnet-runner", RUNNER).replace(
                "#!/bin/bash\n", "#!/bin/bash\n# Modified by RustFS Team on 2026-09-23: correct Mint record production.\n", 1)
            self.assertEqual(path.read_text(), expected)
            self.assertEqual(path.stat().st_mode & 0o777, 0o751)

    def test_cli_adds_modification_notice_without_damaging_license_or_shebang(self):
        for kind, source in (("logger", LOGGER), ("dotnet-runner", RUNNER), ("mc", MC)):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                date = "2026-10-07" if kind == "mc" else "2026-09-23"
                notice = f"Modified by RustFS Team on {date}: correct Mint record production."
                path = Path(directory) / "producer"
                path.write_text(source)
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                result = subprocess.run([sys.executable, str(PATCH), kind, str(path),
                                         "--sha256", digest], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                changed = path.read_text()
                prefix = "// " if kind == "logger" else "# "
                self.assertEqual(changed.count(prefix + notice), 1)
                self.assertEqual(changed.replace(prefix + notice + "\n", ""),
                                 module.transform(kind, source))
                if kind != "logger":
                    self.assertTrue(changed.startswith("#!/bin/bash\n"))

    def test_script_without_shebang_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner"
            source = RUNNER.replace("#!/bin/bash\n", "")
            path.write_text(source)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result = subprocess.run([sys.executable, str(PATCH), "dotnet-runner", str(path),
                                     "--sha256", digest], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_text(), source)

    def test_cli_missing_source_and_missing_hash_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "absent"
            for args in ([], ["--sha256", "0" * 64]):
                with self.subTest(args=args):
                    result = subprocess.run([sys.executable, str(PATCH), "mc", str(path), *args], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
