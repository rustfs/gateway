#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Refuse ambiguous registrations and measure only the selected handler variant."""

import unittest

import gen_rustfs_admin_route_inventory as inventory


FILE = "rustfs/src/admin/handlers/example.rs"
FIXTURE = '''
const ADMIN_PREFIX: &str = "/admin";
enum Kind { Probe, Read, Write, Inspect, Update }
struct Handler(Kind);
fn register_example_routes(router: &mut Router) {
    for (method, path, handler) in [
        (Method::GET, "/probe", &Handler(Kind::Probe)),
        (Method::POST, "/write", &Handler(Kind::Write)),
    ] {
        router.insert(method, &format!("{ADMIN_PREFIX}{path}"), AdminOperation(handler))?;
    }
}
impl Operation for Handler {
    async fn call(&self, req: Request) -> Result<Response> {
        authorize(permission(self.0))?;
        if matches!(self.0, Kind::Probe) {
            return json_response("ready");
        }
        match self.0 {
            Kind::Read => json_response("read"),
            Kind::Write => {
                let body = read_compatible_admin_body(req.input);
                json_response(body)
            }
            Kind::Inspect | Kind::Update => {
                let result = if matches!(self.0, Kind::Inspect) {
                    json_response("inspect")
                } else {
                    read_compatible_admin_body(req.input)
                };
                json_response(result)
            }
            Kind::Probe => json_response("ready"),
        }
    }
}
'''


class Source:
    def __init__(self, text=FIXTURE):
        self.files = {FILE: inventory.strip_comments(text)}

    def const(self, name, relative):
        if name != "ADMIN_PREFIX" or relative != FILE:
            raise inventory.InventoryError("unknown fixture constant")
        return "/admin"


def facts(variant, text=FIXTURE):
    _, body, streams = inventory.handler_body(Source(text), "Handler", ("Kind", variant))
    return inventory.body_facts(body, streams)


class VariantTests(unittest.TestCase):
    def test_loop_records_each_constructor_binding(self):
        sites = inventory.insert_sites(Source())
        self.assertEqual(
            [(row["method"], row["path"], row["handler"], row["variant"]) for row in sites],
            [("GET", "/admin/probe", "Handler", ("Kind", "Probe")),
             ("POST", "/admin/write", "Handler", ("Kind", "Write"))],
        )

    def test_selected_writes_read_the_sealed_body(self):
        for variant in ("Write", "Update"):
            with self.subTest(variant=variant):
                self.assertEqual(facts(variant), ("request-on-minio-alias", "buffered", "buffered"))

    def test_read_variants_never_inherit_a_writes_secret_or_body(self):
        for variant in ("Probe", "Read", "Inspect"):
            with self.subTest(variant=variant):
                self.assertEqual(facts(variant), ("none", "not-read", "buffered"))

    def test_a_common_body_read_is_not_discarded(self):
        text = FIXTURE.replace("authorize(permission(self.0))?;", "read_compatible_admin_body(req.input);")
        self.assertEqual(facts("Probe", text), ("request-on-minio-alias", "buffered", "buffered"))

    def test_unknown_variant_is_refused(self):
        with self.assertRaisesRegex(inventory.InventoryError, "variant"):
            facts("Missing")

    def test_a_constructor_with_another_tuple_type_is_refused(self):
        with self.assertRaisesRegex(inventory.InventoryError, "tuple"):
            facts("Probe", FIXTURE.replace("struct Handler(Kind)", "struct Handler(Other)"))

    def test_unreadable_variant_condition_is_refused(self):
        text = FIXTURE.replace("matches!(self.0, Kind::Probe)", "self.0 == Kind::Probe")
        with self.assertRaisesRegex(inventory.InventoryError, "condition"):
            facts("Probe", text)

    def test_guarded_match_arm_is_refused(self):
        text = FIXTURE.replace("Kind::Read =>", "Kind::Read if enabled() =>")
        with self.assertRaisesRegex(inventory.InventoryError, "arm"):
            facts("Read", text)

    def test_borrowed_variant_dispatch_is_refused(self):
        text = FIXTURE.replace("match self.0", "match &self.0")
        with self.assertRaisesRegex(inventory.InventoryError, "dispatch"):
            facts("Read", text)

    def test_returning_match_arm_does_not_inherit_unreachable_body_reads(self):
        text = FIXTURE.replace('Kind::Read => json_response("read"),', 'Kind::Read => { return json_response("read"); },')
        text = text.replace('Kind::Probe => json_response("ready"),\n        }',
                            'Kind::Probe => json_response("ready"),\n        }\n        read_compatible_admin_body(req.input);')
        self.assertEqual(facts("Read", text), ("none", "not-read", "buffered"))

    def test_return_match_expression_is_refused(self):
        text = FIXTURE.replace("match self.0 {", "return match self.0 {")
        text = text.replace('Kind::Probe => json_response("ready"),\n        }',
                            'Kind::Probe => json_response("ready"),\n        };\n        read_compatible_admin_body(req.input);')
        with self.assertRaisesRegex(inventory.InventoryError, "return"):
            facts("Read", text)

    def test_registration_using_an_unbound_handler_is_refused(self):
        text = FIXTURE.replace("AdminOperation(handler)", "AdminOperation(other)")
        with self.assertRaisesRegex(inventory.InventoryError, "bind"):
            inventory.insert_sites(Source(text))

    def test_multiple_insert_sites_in_one_loop_are_refused(self):
        text = FIXTURE.replace(
            "router.insert(method,",
            'router.insert(method, &format!("{ADMIN_PREFIX}{path}"), AdminOperation(handler))?; router.insert(method,',
        )
        with self.assertRaisesRegex(inventory.InventoryError, "insert"):
            inventory.insert_sites(Source(text))


if __name__ == "__main__":
    unittest.main()
