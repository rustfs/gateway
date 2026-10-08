#!/usr/bin/env python3
"""Exercise the real Mint runner and reporter through a fake Docker subprocess.

Owns image-selection, census, and evidence provenance controls, not SDK behavior, and
the `--external` path: what it launches in front of an endpoint started elsewhere, what it
refuses, and what the report says answered the run (rustfs/backlog#2758).
The guard suite invokes this file; only Docker and SUT lifecycle are fixtures.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOCAL = "sha256:" + "a" * 64
SDKS = ".minio-dotnet aws-sdk-go-v2 aws-sdk-java-v2 aws-sdk-php aws-sdk-ruby awscli healthcheck mc minio-go minio-java minio-js minio-py s3cmd s3select versioning".split()
DOCKER = r'''
import json, os, sys
from pathlib import Path
a = sys.argv[1:]
state = Path(os.environ["FAKE_STATE"])
with (state / "calls").open("a") as f:
    f.write(json.dumps(a) + "\n")
scenario = os.environ.get("FAKE_SCENARIO", "")
sdks = os.environ["FAKE_SDKS"].split()
if a[0] == "pull":
    sys.exit(1 if scenario == "pull-fails" else 0)
if a[:2] == ["image", "inspect"]:
    if scenario == "missing": sys.exit(1)
    print("linux/arm64" if scenario == "arm" else "windows/amd64" if scenario == "windows" else "linux/amd64")
elif a[0] == "run":
    if scenario == "census-fails": sys.exit(1)
    if scenario == "extra": sdks += ["minio-dotnet"]
    if scenario == "missing-sdk": sdks.remove(".minio-dotnet")
    print("\n".join(sdks))
elif a[0] == "create":
    name = a[a.index("--name") + 1]
    # Docker options precede the image, followed by the SDK argv.
    selected = a[a.index("--env-file") + 3:]
    (state / name).write_text(json.dumps(selected))
elif a[0] == "start":
    selected = json.loads((state / a[-1]).read_text())
    for i, sdk in enumerate(selected, 1):
        print(f"({i}/{len(selected)}) Running {sdk} tests ... done in 1 seconds")
elif a[0] == "cp":
    if scenario == "copy-fails": sys.exit(1)
    name = a[1].split(":")[0]
    selected = json.loads((state / name).read_text())
    for sdk in selected:
        dest = Path(a[2]) / sdk
        dest.mkdir(parents=True)
        record = {"name": sdk.lstrip("."), "function": "probe", "duration": 1, "status": "PASS"}
        (dest / "log.json").write_text(json.dumps(record) + "\n")
elif a[0] != "rm":
    raise SystemExit("unexpected Docker call: " + repr(a))
'''


class MintLocalImage(unittest.TestCase):
    def probe(self, args, scenario="", extra_env=None):
        with tempfile.TemporaryDirectory(prefix="mint-local-test-") as directory:
            root = Path(directory)
            for name in ("ci/mint/run.sh", "ci/mint/pins.env", "ci/mint/report.py", "ci/mint/_redaction.py"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            (root / "ci/lib").mkdir()
            (root / "ci/lib/sut.sh").write_text('''
SUT_PID=""
sut_die() { printf '%s\\n' "$*" >&2; exit 3; }
sut_start() {
    SUT_HOST=127.0.0.1; SUT_PORT=9200
    printf '%s' "$GATEWAY_SUT_COMMAND" >"$FAKE_STATE/sut-command"
    # What the observer would have recorded while mint ran: the endpoint's answers, one the
    # observer wrote itself, or no log at all.
    if [[ -n "${MINT_EXTERNAL:-}" ]]; then
        case "${FAKE_OBSERVER:-upstream}" in
        upstream) printf '{"status":200,"answered_by":"upstream"}\n' >"$MINT_OBSERVER_PROBE" ;;
        observer) printf '{"status":200,"answered_by":"upstream"}\n{"status":502,"answered_by":"observer"}\n' >"$MINT_OBSERVER_PROBE" ;;
        esac
    fi
}
sut_stop() { :; }
sut_wait_ready() { return 0; }
sut_external_endpoint() { SUT_EXTERNAL_HOST=127.0.0.1; SUT_EXTERNAL_PORT=9000; }
sut_server_header() { printf '%s\n' "${FAKE_SERVER_HEADER-RustFS}"; }
''')
            (root / "ci/mint/baseline.txt").write_text("# generation: 3\n" + "".join(f"{sdk} 0\n" for sdk in SDKS))
            binary = root / "bin"
            binary.mkdir()
            docker = binary / "docker"
            docker.write_text(f"#!{sys.executable}\n" + DOCKER)
            docker.chmod(0o755)
            state = root / "state"
            state.mkdir()
            env = {k: v for k, v in os.environ.items() if not k.startswith(("MINT_", "GATEWAY_SUT_", "FAKE_"))}
            env.update(PATH=str(binary) + os.pathsep + os.environ["PATH"], FAKE_STATE=str(state),
                       FAKE_SDKS=" ".join(SDKS), FAKE_SCENARIO=scenario)
            env.update(extra_env or {})
            baseline = (root / "ci/mint/baseline.txt").read_bytes()
            result = subprocess.run(["bash", str(root / "ci/mint/run.sh"), "--work", str(root / "work"),
                                     "--out", str(root / "out"), *args], env=env, capture_output=True, text=True, timeout=15)
            calls = [json.loads(line) for line in (state / "calls").read_text().splitlines()] if (state / "calls").exists() else []
            report = json.loads((root / "out/report.json").read_text()) if (root / "out/report.json").exists() else None
            self.assertEqual((root / "ci/mint/baseline.txt").read_bytes(), baseline, "the reviewed baseline changed")
            self.launched = (state / "sut-command").read_text() if (state / "sut-command").exists() else None
            return result, calls, report

    def assert_success(self, args, local):
        result, calls, report = self.probe(args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(report["complete"])
        image = LOCAL if local else next(c[-1] for c in calls if c[0] == "pull")
        self.assertEqual(report["image"], image)
        pulls = [c for c in calls if c[0] == "pull"]
        self.assertEqual(pulls, [] if local else [["pull", "--quiet", "--platform", "linux/amd64", image]])
        if not local:
            self.assertRegex(image, r"^docker\.io/minio/mint@sha256:[0-9a-f]{64}$")
        inspections = [c for c in calls if c[:2] == ["image", "inspect"]]
        self.assertEqual(len(inspections), 1)
        self.assertEqual(inspections[0][-1], image)
        census = [c for c in calls if c[0] == "run"]
        self.assertEqual(len(census), 1)
        self.assertEqual(census[0][-3:], [image, "-A", "/mint/run/core"])
        creates = [c for c in calls if c[0] == "create"]
        self.assertEqual(len(creates), 2)
        selected = []
        for call in creates:
            i = call.index("--env-file") + 2
            self.assertEqual(call[i], image)
            self.assertEqual(call[call.index("--platform") + 1], "linux/amd64")
            selected.extend(call[i + 1:])
        self.assertCountEqual(selected, SDKS)
        self.assertEqual(len(selected), 15)
        self.assertEqual(creates[1][-1], "aws-sdk-java-v2")
        self.assertEqual(report["measured_against"], {"sut": "gateway-fs"})
        self.assertNotIn("--external", self.launched)

    def test_help_lists_local_usage(self):
        result, calls, report = self.probe(["--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("[--local-image <id>]", result.stdout)
        self.assertEqual(calls, [])
        self.assertIsNone(report)

    def test_default_pinned_ratchet(self):
        self.assert_success([], False)

    def test_local_record(self):
        self.assert_success(["--mode", "record", "--local-image", LOCAL], True)

    def test_local_usage_rejections(self):
        for value in ("", "latest", "a" * 64, "sha256:abc", "sha256:" + "A" * 64,
                      LOCAL + "0", "docker.io/minio/mint@" + LOCAL):
            with self.subTest(value=value):
                result, calls, report = self.probe(["--mode", "record", "--local-image", value])
                self.assertEqual(result.returncode, 2)
                self.assertIn("--local-image requires a full sha256 image ID", result.stderr)
                self.assertEqual(calls, [])
                self.assertIsNone(report)

    def test_local_ratchet(self):
        self.assert_success(["--mode", "ratchet", "--local-image", LOCAL], True)

    def test_missing_local_argument(self):
        result, calls, _ = self.probe(["--mode", "record", "--local-image"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("--local-image requires a full sha256 image ID", result.stderr)
        self.assertEqual(calls, [])

    def test_local_environment_rejections(self):
        for scenario, diagnostic in (("missing", "cannot inspect"), ("arm", "not the pinned linux/amd64"),
                                     ("windows", "not the pinned linux/amd64"), ("extra", "SDK census"),
                                     ("missing-sdk", "SDK census"), ("census-fails", "cannot list"),
                                     ("copy-fails", "cannot copy /mint/log")):
            with self.subTest(scenario=scenario):
                result, calls, report = self.probe(["--mode", "record", "--local-image", LOCAL], scenario)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertIn(diagnostic, result.stderr)
                self.assertFalse(any(c[0] == "pull" for c in calls))
                self.assertIsNone(report)
                if scenario != "copy-fails":
                    self.assertFalse(any(c[0] == "create" for c in calls))

    EXTERNAL = ["--external", "http://127.0.0.1:9000", "--local-image", LOCAL]
    CREDENTIALS = {"MINT_ACCESS_KEY": "AKIAEXTERNALPROBE000", "MINT_SECRET_KEY": "external-probe-secret"}

    def test_external_runs_through_the_observer_and_says_so(self):
        result, calls, report = self.probe(self.EXTERNAL, extra_env=self.CREDENTIALS)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report["measured_against"], {"sut": "external", "endpoint_build": "RustFS"})
        self.assertTrue(report["complete"])
        # The observer is launched in front of the endpoint, with no data root and no credential.
        self.assertIn('--external "$MINT_EXTERNAL"', self.launched)
        for flag in ("--data", "--access-key", "--secret-key", "--region"):
            self.assertNotIn(flag, self.launched)
        # Both passes still run, the TLS one against the observer's encrypted listener.
        self.assertEqual(len([c for c in calls if c[0] == "create"]), 2)

    def test_external_without_a_server_header_records_null(self):
        _, _, report = self.probe(self.EXTERNAL, extra_env={**self.CREDENTIALS, "FAKE_SERVER_HEADER": ""})
        self.assertEqual(report["measured_against"], {"sut": "external", "endpoint_build": None})

    def test_n_external_without_the_endpoints_credentials_is_refused(self):
        for missing in ("MINT_ACCESS_KEY", "MINT_SECRET_KEY"):
            with self.subTest(missing=missing):
                env = {name: value for name, value in self.CREDENTIALS.items() if name != missing}
                result, calls, report = self.probe(self.EXTERNAL, extra_env=env)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("the endpoint's own credentials", result.stderr)
                self.assertEqual((calls, report, self.launched), ([], None, None))

    def test_n_external_beside_an_adopted_endpoint_is_refused(self):
        env = {**self.CREDENTIALS, "GATEWAY_SUT_ENDPOINT": "http://127.0.0.1:9000"}
        result, calls, report = self.probe(self.EXTERNAL, extra_env=env)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("unset GATEWAY_SUT_ENDPOINT", result.stderr)
        self.assertEqual((calls, report), ([], None))

    def test_n_external_without_a_url_is_refused(self):
        result, calls, _ = self.probe(["--external"], extra_env=self.CREDENTIALS)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(calls, [])

    def test_n_an_answer_the_observer_wrote_makes_the_run_incomplete(self):
        result, _, report = self.probe(self.EXTERNAL, extra_env={**self.CREDENTIALS, "FAKE_OBSERVER": "observer"})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("could not reach http://127.0.0.1:9000 for 1 request(s)", result.stderr)
        self.assertIsNone(report)

    def test_n_an_observer_that_recorded_nothing_makes_the_run_incomplete(self):
        result, _, report = self.probe(self.EXTERNAL, extra_env={**self.CREDENTIALS, "FAKE_OBSERVER": "none"})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("wrote no probe log", result.stderr)
        self.assertIsNone(report)

    def test_pinned_pull_failure(self):
        result, calls, report = self.probe([], "pull-fails")
        self.assertEqual(result.returncode, 3)
        self.assertIn("cannot pull the pinned image", result.stderr)
        self.assertFalse(any(c[0] == "create" for c in calls))
        self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main()
