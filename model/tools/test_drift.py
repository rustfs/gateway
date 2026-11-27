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

"""Unit tests for model/tools/drift.py trait classification and diff semantics."""

from __future__ import annotations

import copy
import json
import os
import sys
import unittest

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(TOOLS_DIR))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

import drift  # noqa: E402


def _base_model():
    return {
        "smithy": "2.0",
        "shapes": {
            "com.example#Svc": {
                "type": "service",
                "operations": [{"target": "com.example#Ping"}],
                "traits": {
                    "aws.protocols#awsQuery": {},
                    "aws.auth#sigv4a": {"name": "example"},
                },
            },
            "com.example#Ping": {
                "type": "operation",
                "input": {"target": "com.example#PingInput"},
                "output": {"target": "com.example#PingOutput"},
                "errors": [{"target": "com.example#PingError"}],
            },
            "com.example#PingInput": {
                "type": "structure",
                "members": {
                    "Secret": {"target": "com.example#SecretString"},
                },
                "traits": {"smithy.api#input": {}},
            },
            "com.example#PingOutput": {
                "type": "structure",
                "members": {
                    "Payload": {
                        "target": "com.example#EventBlob",
                        "traits": {"smithy.api#eventPayload": {}},
                    },
                },
                "traits": {"smithy.api#output": {}},
            },
            "com.example#SecretString": {
                "type": "string",
                "traits": {"smithy.api#sensitive": {}},
            },
            "com.example#EventBlob": {"type": "blob"},
            "com.example#PingError": {
                "type": "structure",
                "traits": {
                    "smithy.api#error": "client",
                    "aws.protocols#awsQueryError": {
                        "code": "PingFailed",
                        "httpResponseCode": 400,
                    },
                },
            },
        },
    }


class TraitClassificationTests(unittest.TestCase):
    # ── negative ─────────────────────────────────────────────────────────────

    def test_wire_and_ignored_trait_sets_are_disjoint_and_consistent(self):
        overlap = drift.WIRE_TRAITS & drift.IGNORED_TRAITS
        self.assertEqual(overlap, frozenset(), f"traits in both WIRE and IGNORED: {overlap}")
        self.assertTrue(
            drift.HTTP_TRAITS <= drift.WIRE_TRAITS,
            f"HTTP_TRAITS outside WIRE_TRAITS: {drift.HTTP_TRAITS - drift.WIRE_TRAITS}",
        )
        self.assertTrue(
            drift.XML_TRAITS <= drift.WIRE_TRAITS,
            f"XML_TRAITS outside WIRE_TRAITS: {drift.XML_TRAITS - drift.WIRE_TRAITS}",
        )

    def test_unclassified_trait_is_still_reported(self):
        cur = _base_model()
        cand = copy.deepcopy(cur)
        cand["shapes"]["com.example#PingInput"]["traits"]["example.future#inventedTrait"] = {}
        diff = drift.diff_models("test", cur, cand)
        unclassified = [c for c in diff.changes if c.category == "unclassified"]
        self.assertEqual(len(unclassified), 1)
        self.assertIn("example.future#inventedTrait", unclassified[0].detail)
        self.assertFalse(unclassified[0].breaking)

    def test_aws_query_error_change_is_breaking_http_binding(self):
        cur = _base_model()
        cand = copy.deepcopy(cur)
        cand["shapes"]["com.example#PingError"]["traits"]["aws.protocols#awsQueryError"] = {
            "code": "PingRenamed",
            "httpResponseCode": 403,
        }
        diff = drift.diff_models("test", cur, cand)
        http_changes = [c for c in diff.changes if c.category == "http-binding"]
        self.assertEqual(len(http_changes), 1)
        self.assertTrue(http_changes[0].breaking)
        self.assertIn("awsQueryError", http_changes[0].detail)

    def test_gaining_aws_query_error_on_existing_shape_is_breaking(self):
        cur = _base_model()
        del cur["shapes"]["com.example#PingError"]["traits"]["aws.protocols#awsQueryError"]
        cand = _base_model()
        diff = drift.diff_models("test", cur, cand)
        http_changes = [c for c in diff.changes if c.category == "http-binding"]
        self.assertEqual(len(http_changes), 1)
        self.assertTrue(http_changes[0].breaking)
        self.assertIn("gained `awsQueryError`", http_changes[0].detail)

    def test_losing_aws_query_error_on_existing_shape_is_breaking(self):
        cur = _base_model()
        cand = copy.deepcopy(cur)
        del cand["shapes"]["com.example#PingError"]["traits"]["aws.protocols#awsQueryError"]
        diff = drift.diff_models("test", cur, cand)
        http_changes = [c for c in diff.changes if c.category == "http-binding"]
        self.assertEqual(len(http_changes), 1)
        self.assertTrue(http_changes[0].breaking)
        self.assertIn("lost `awsQueryError`", http_changes[0].detail)

    def test_gaining_sensitive_on_existing_shape_is_reported(self):
        cur = _base_model()
        del cur["shapes"]["com.example#SecretString"]["traits"]["smithy.api#sensitive"]
        cand = _base_model()
        diff = drift.diff_models("test", cur, cand)
        self.assertEqual(len(diff.changes), 1)
        self.assertEqual(diff.changes[0].category, "members")
        self.assertFalse(diff.changes[0].breaking)
        self.assertIn("gained `sensitive`", diff.changes[0].detail)

    def test_losing_sensitive_on_existing_shape_is_breaking(self):
        cur = _base_model()
        cand = copy.deepcopy(cur)
        del cand["shapes"]["com.example#SecretString"]["traits"]["smithy.api#sensitive"]
        diff = drift.diff_models("test", cur, cand)
        self.assertEqual(len(diff.changes), 1)
        self.assertEqual(diff.changes[0].category, "members")
        self.assertTrue(diff.changes[0].breaking)
        self.assertIn("lost `sensitive`", diff.changes[0].detail)

    def test_service_protocol_and_event_payload_changes_are_breaking(self):
        for shape_id, member, trait in (
            ("com.example#Svc", None, "aws.protocols#awsQuery"),
            ("com.example#Svc", None, "aws.auth#sigv4a"),
            ("com.example#PingOutput", "Payload", "smithy.api#eventPayload"),
        ):
            with self.subTest(trait=trait):
                cur = _base_model()
                cand = copy.deepcopy(cur)
                if member is None:
                    del cand["shapes"][shape_id]["traits"][trait]
                else:
                    del cand["shapes"][shape_id]["members"][member]["traits"][trait]
                diff = drift.diff_models("test", cur, cand)
                self.assertEqual(len(diff.breaking()), 1, f"expected breaking diff when removing {trait}")

    def test_pinned_models_have_no_unclassified_traits(self):
        for name in drift.MODELS:
            path = os.path.join(REPO_ROOT, "model", f"{name}.json")
            with open(path, "r", encoding="utf-8") as handle:
                projected = drift.project(json.load(handle))
            self.assertEqual(
                projected["unknown_traits"],
                {},
                f"unclassified traits found in pinned model/{name}.json: {projected['unknown_traits']}",
            )

    # ── positive ─────────────────────────────────────────────────────────────

    def test_input_and_output_marker_traits_are_ignored(self):
        cur = _base_model()
        cand_removed = copy.deepcopy(cur)
        del cand_removed["shapes"]["com.example#PingInput"]["traits"]["smithy.api#input"]
        del cand_removed["shapes"]["com.example#PingOutput"]["traits"]["smithy.api#output"]
        diff_removed = drift.diff_models("test", cur, cand_removed)
        self.assertTrue(
            diff_removed.is_empty(),
            f"expected empty diff when removing markers, got: {[c.detail for c in diff_removed.changes]}",
        )
        diff_added = drift.diff_models("test", cand_removed, cur)
        self.assertTrue(
            diff_added.is_empty(),
            f"expected empty diff when adding markers, got: {[c.detail for c in diff_added.changes]}",
        )

    def test_new_shapes_with_classified_traits_produce_no_unclassified_entries(self):
        cur = _base_model()
        cand = copy.deepcopy(cur)
        cand["shapes"]["com.example#ExtraOp"] = {
            "type": "operation",
            "input": {"target": "com.example#ExtraInput"},
            "output": {"target": "com.example#ExtraOutput"},
            "errors": [{"target": "com.example#ExtraError"}],
        }
        cand["shapes"]["com.example#ExtraInput"] = {
            "type": "structure",
            "traits": {"smithy.api#input": {}},
        }
        cand["shapes"]["com.example#ExtraOutput"] = {
            "type": "structure",
            "traits": {"smithy.api#output": {}, "smithy.api#sensitive": {}},
        }
        cand["shapes"]["com.example#ExtraError"] = {
            "type": "structure",
            "traits": {
                "smithy.api#error": "client",
                "aws.protocols#awsQueryError": {"code": "Extra", "httpResponseCode": 400},
            },
        }
        diff = drift.diff_models("test", cur, cand)
        unclassified = [c for c in diff.changes if c.category == "unclassified"]
        self.assertEqual(unclassified, [])
        self.assertEqual([c.category for c in diff.changes], ["operations"])


if __name__ == "__main__":
    unittest.main()
