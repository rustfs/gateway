#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Check client-matrix cell identity, execution evidence and the two skip statuses.

Exercises the reporter's verdict boundary, not SDK behavior, YAML parsing or a
server. The guard harness is upstream; report.py's aggregate consumes this verdict.
A skip is either `client-unsupported` (the driver said its client cannot express the
scenario) or `sut-unregistered` (the server does not serve an operation the scenario
needs: the launcher's own registry says so, or an external server answered 501 or 405).
"""

from pathlib import Path
import runpy
import unittest

REPORT = Path(__file__).resolve().parents[1] / "ci/compat/report.py"
MODULE = runpy.run_path(str(REPORT))
RESOLVE = MODULE["resolve_cell"]
MEASURED_AGAINST = MODULE["measured_against"]
CELL = "probe-client/roundtrip"


def answer(status, method="PUT", path="/cm-probe-client-roundtrip", answered_by="upstream"):
    """One observer record, as `compat-sut --external` writes it."""
    return {"method": method, "path": path, "query": "", "status": status, "answered_by": answered_by}


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
    def judge(self, raw, external=False):
        errors = []
        verdict = RESOLVE(raw, {"id": "roundtrip"}, errors, CELL, external=external)
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
        # A driver only ever knows what its own client cannot express.
        verdict, errors = self.judge(record(status="unsupported"))
        self.assertEqual((verdict, errors), (("client-unsupported", "driver control", {"bytes_checked": 37}), []))

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
        self.assertEqual((verdict, errors), (("sut-unregistered", raw["skipped_reason"], {}), []))

    def test_timeout_remains_a_cell_failure(self):
        raw = record(exit_code=124)
        raw["driver"] = None
        raw["timed_out"] = True
        verdict, errors = self.judge(raw)
        self.assertEqual((verdict, errors), (("fail", "the client did not finish within 5s", {}), []))


class ExternalClassificationTests(unittest.TestCase):
    """An external server's registry is unknown, so its own answer is the only evidence."""

    def judge(self, raw, external=True):
        errors = []
        verdict = RESOLVE(raw, {"id": "roundtrip"}, errors, CELL, external=external)
        return verdict, errors

    def failed_with(self, *answers):
        raw = record(status="fail", exit_code=0)
        raw["probe"] = list(answers)
        return raw

    def test_an_external_501_behind_a_failure_is_sut_unregistered(self):
        verdict, errors = self.judge(self.failed_with(answer(200, "GET", "/"), answer(501)))
        self.assertEqual(errors, [])
        self.assertEqual(verdict[0], "sut-unregistered")
        self.assertIn("501 to PUT /cm-probe-client-roundtrip", verdict[1])
        # The driver's own account of the failure is kept beside the answer that explains it.
        self.assertIn("driver control", verdict[1])
        self.assertEqual(verdict[2]["unregistered"], [{"method": "PUT", "path": "/cm-probe-client-roundtrip", "status": 501}])

    def test_an_external_405_behind_a_failure_is_sut_unregistered(self):
        verdict, errors = self.judge(self.failed_with(answer(405, "POST", "/cm-probe-client-roundtrip")))
        self.assertEqual((verdict[0], errors), ("sut-unregistered", []))
        self.assertIn("405 to POST /cm-probe-client-roundtrip", verdict[1])

    def test_n_an_external_failure_without_an_unregistered_answer_stays_a_failure(self):
        for status in (400, 403, 404, 500, 502, 503):
            with self.subTest(status=status):
                verdict, errors = self.judge(self.failed_with(answer(status)))
                self.assertEqual((verdict[0], errors), ("fail", []))

    def test_n_an_external_failure_with_no_record_stays_a_failure(self):
        verdict, errors = self.judge(self.failed_with())
        self.assertEqual((verdict[0], errors), ("fail", []))

    def test_n_a_501_from_the_launchers_own_registry_stays_a_failure(self):
        # In-repository runs decide registration from `--print-capabilities` before any client
        # runs. A 501 there is a server defect behind a declared operation, and reclassifying it
        # would turn a REGRESSION into a skip.
        verdict, errors = self.judge(self.failed_with(answer(501, answered_by="service")), external=False)
        self.assertEqual((verdict[0], errors), ("fail", []))

    def test_n_the_launchers_run_never_reclassifies_whoever_answered(self):
        # The run kind alone decides: even a forwarded 501 is a failure when the run is the
        # launcher's, whose registry was read before any client ran.
        verdict, errors = self.judge(self.failed_with(answer(501)), external=False)
        self.assertEqual((verdict[0], errors), ("fail", []))

    def test_n_a_501_nobody_forwarded_is_not_the_endpoints_answer(self):
        # Only an answer the observer passed through from the endpoint speaks for the endpoint.
        verdict, errors = self.judge(self.failed_with(answer(501, answered_by="service")))
        self.assertEqual((verdict[0], errors), ("fail", []))

    def test_n_an_external_pass_is_never_reclassified(self):
        raw = record(status="pass")
        raw["probe"] = [answer(501, "GET", "/cm-probe-client-roundtrip", answered_by="upstream")]
        verdict, errors = self.judge(raw)
        self.assertEqual((verdict[0], errors), ("pass", []))

    def test_n_a_client_the_driver_calls_unsupported_stays_client_unsupported(self):
        # The converse control: a server that registers nothing must not turn a client's own
        # limitation into a server gap.
        raw = record(status="unsupported")
        raw["probe"] = [answer(501)]
        verdict, errors = self.judge(raw)
        self.assertEqual((verdict[0], errors), ("client-unsupported", []))

    def test_n_an_answer_the_observer_made_itself_is_an_environment_error(self):
        # A 502 the observer wrote because the endpoint was unreachable measured nothing about
        # the endpoint; it must stop the run, not become a cell.
        for status in ("pass", "fail"):
            with self.subTest(status=status):
                raw = record(status=status)
                raw["probe"] = [answer(502, answered_by="observer")]
                verdict, errors = self.judge(raw)
                self.assertTrue(errors and all(error.startswith(CELL + ":") for error in errors), errors)
                self.assertIn("could not reach", errors[0])


class MeasuredAgainstTests(unittest.TestCase):
    """What answered the rows, as the manifest records it."""

    def test_the_launcher_names_only_itself(self):
        self.assertEqual(MEASURED_AGAINST("gateway-fs", None, None), {"sut": "gateway-fs"})

    def test_an_external_endpoint_records_its_server_header_and_product(self):
        self.assertEqual(
            MEASURED_AGAINST("external", "RustFS", "rustfs"),
            {"sut": "external", "endpoint_build": "RustFS", "product": "rustfs"},
        )

    def test_an_external_endpoint_without_a_server_header_records_null(self):
        self.assertEqual(
            MEASURED_AGAINST("external", None, "rustfs"),
            {"sut": "external", "endpoint_build": None, "product": "rustfs"},
        )

    def test_n_an_external_endpoint_without_a_product_is_refused(self):
        for product in (None, "", "  "):
            with self.subTest(product=product):
                with self.assertRaises(ValueError):
                    MEASURED_AGAINST("external", "RustFS", product)

    def test_n_an_unknown_kind_is_refused(self):
        for kind in ("", "fs", "External", "rustfs"):
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):
                    MEASURED_AGAINST(kind, None, "rustfs")

    def test_n_the_launcher_refuses_an_external_only_field(self):
        with self.assertRaises(ValueError):
            MEASURED_AGAINST("gateway-fs", "RustFS", None)
        with self.assertRaises(ValueError):
            MEASURED_AGAINST("gateway-fs", None, "rustfs")


if __name__ == "__main__":
    unittest.main()
