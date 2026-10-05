#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Check client-matrix cell identity and execution evidence.

Exercises the reporter's verdict boundary, not SDK behavior, YAML parsing or a
server. The guard harness is upstream; report.py's aggregate consumes this verdict.
"""

from pathlib import Path
import runpy
import unittest

REPORT = Path(__file__).resolve().parents[1] / "ci/compat/report.py"
RESOLVE = runpy.run_path(str(REPORT))["resolve_cell"]
CELL = "probe-client/roundtrip"


def record(status="pass", exit_code=0):
    return {
        "client": "probe-client",
        "scenario": "roundtrip",
        "driver": {
            "scenario": "roundtrip",
            "status": status,
            "detail": "driver control",
            "evidence": {"bytes_checked": 37},
        },
        "exit_code": exit_code,
        "timed_out": False,
        "timeout_seconds": 5,
        "skipped_reason": "",
        "probe": [],
    }


class CompatCellTests(unittest.TestCase):
    def judge(self, raw):
        errors = []
        verdict = RESOLVE(raw, {"id": "roundtrip"}, errors, CELL)
        return verdict, errors

    def refused(self, raw):
        verdict, errors = self.judge(raw)
        self.assertEqual(verdict[0], "fail")
        self.assertTrue(errors, "a broken driver must prevent aggregate publication")
        self.assertTrue(all(error.startswith(CELL + ":") for error in errors))

    def test_wrong_raw_client(self):
        raw = record()
        raw["client"] = "other-client"
        self.refused(raw)

    def test_wrong_raw_scenario(self):
        raw = record()
        raw["scenario"] = "other-scenario"
        self.refused(raw)

    def test_missing_raw_identity(self):
        for key in ("client", "scenario"):
            with self.subTest(key=key):
                raw = record()
                del raw[key]
                self.refused(raw)

    def test_wrong_driver_scenario(self):
        raw = record()
        raw["driver"]["scenario"] = "other-scenario"
        self.refused(raw)

    def test_missing_driver_scenario(self):
        raw = record()
        del raw["driver"]["scenario"]
        self.refused(raw)

    def test_success_with_failed_process(self):
        for code in (1, 17, -9):
            with self.subTest(code=code):
                self.refused(record(exit_code=code))

    def test_success_without_exit_receipt(self):
        raw = record()
        del raw["exit_code"]
        self.refused(raw)

    def test_unsupported_with_failed_process(self):
        for code in (1, 17):
            with self.subTest(code=code):
                self.refused(record(status="unsupported", exit_code=code))

    def test_identity_checked_before_capability_skip_or_timeout(self):
        for key in ("skipped_reason", "timed_out"):
            with self.subTest(key=key):
                raw = record()
                raw["client"] = "other-client"
                raw["driver"] = None
                raw[key] = "absent operation" if key == "skipped_reason" else True
                self.refused(raw)

    def test_matching_success(self):
        verdict, errors = self.judge(record())
        self.assertEqual((verdict, errors), (("pass", "driver control", {"bytes_checked": 37}), []))

    def test_matching_driver_unsupported(self):
        verdict, errors = self.judge(record(status="unsupported"))
        self.assertEqual((verdict, errors), (("unsupported", "driver control", {"bytes_checked": 37}), []))

    def test_legitimate_failures_remain_operation_failures(self):
        for code in (0, 1, -9):
            with self.subTest(code=code):
                verdict, errors = self.judge(record(status="fail", exit_code=code))
                self.assertEqual((verdict, errors), (("fail", "driver control", {"bytes_checked": 37}), []))

    def test_capability_skip_needs_no_driver(self):
        raw = record()
        raw["driver"] = None
        raw["skipped_reason"] = "the system under test registers no GetObject"
        verdict, errors = self.judge(raw)
        self.assertEqual((verdict, errors), (("unsupported", raw["skipped_reason"], {}), []))

    def test_timeout_remains_a_cell_failure(self):
        raw = record(exit_code=124)
        raw["driver"] = None
        raw["timed_out"] = True
        verdict, errors = self.judge(raw)
        self.assertEqual((verdict, errors), (("fail", "the client did not finish within 5s", {}), []))


if __name__ == "__main__":
    unittest.main()
