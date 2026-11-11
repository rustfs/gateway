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


SHARED = "rustfs/src/admin/handlers/mod.rs"
SEALING_HELPER = '''
pub(crate) fn owned_admin_json_response<T: Serialize>(path: &str, secret_key: &str, payload: &T) -> S3Result<AdminResponse> {
    let (body, content_type) = crate::admin::utils::encode_compatible_admin_payload(path, secret_key, to_vec(payload)?)?;
    Ok(AdminResponse::new(body, content_type))
}
'''


class Source:
    def __init__(self, text=FIXTURE, shared=None):
        self.files = {FILE: inventory.strip_comments(text)}
        if shared is not None:
            self.files[SHARED] = inventory.strip_comments(shared)

    def const(self, name, relative):
        if name != "ADMIN_PREFIX" or relative != FILE:
            raise inventory.InventoryError("unknown fixture constant")
        return "/admin"


def facts(variant, text=FIXTURE, shared=None):
    _, body, streams = inventory.handler_body(Source(text, shared), "Handler", ("Kind", variant))
    return inventory.body_facts(body, streams)


def read_with(call):
    return FIXTURE.replace('Kind::Read => json_response("read"),', f"Kind::Read => {call},")


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

    def test_path_qualified_operation_impl_is_read(self):
        for path in ("crate::admin::router::", "super::", "router::"):
            with self.subTest(path=path):
                text = FIXTURE.replace("impl Operation for Handler", f"impl {path}Operation for Handler")
                self.assertEqual(facts("Write", text), ("request-on-minio-alias", "buffered", "buffered"))

    def test_another_trait_named_like_operation_is_not_read(self):
        for spelling in ("OwnedOperation", "crate::admin::OperationExt", "Operation2"):
            with self.subTest(spelling=spelling):
                text = FIXTURE.replace("impl Operation for Handler", f"impl {spelling} for Handler")
                with self.assertRaisesRegex(inventory.InventoryError, "no `impl Operation for Handler`"):
                    facts("Write", text)

    def test_path_qualified_stream_impl_marks_the_response_streamed(self):
        read = FIXTURE.replace('Kind::Read => json_response("read"),', 'Kind::Read => json_response(Feed),')
        for path in ("futures::", "futures_core::", "futures::stream::", "rustfs_s3_types::"):
            with self.subTest(path=path):
                text = read + f"struct Feed;\nimpl {path}Stream for Feed {{}}\n"
                self.assertEqual(facts("Read", text), ("none", "not-read", "streamed"))

    def test_a_stream_impl_the_handler_never_names_leaves_it_buffered(self):
        text = FIXTURE + "struct Feed;\nimpl futures_core::Stream for Feed {}\n"
        self.assertEqual(facts("Read", text), ("none", "not-read", "buffered"))

    def test_owned_stream_body_marks_the_response_streamed(self):
        for spelling in ("Body::from_stream(ReceiverStream::new(rx))", "rustfs_s3_types::Body::from_stream(feed)"):
            with self.subTest(spelling=spelling):
                text = FIXTURE.replace('Kind::Read => json_response("read"),', f"Kind::Read => json_response({spelling}),")
                self.assertEqual(facts("Read", text), ("none", "not-read", "streamed"))

    def test_owned_body_from_bytes_stays_buffered(self):
        for spelling in ("Body::from(bytes)", "Body::empty()", "Body::from_streamed_len(n)"):
            with self.subTest(spelling=spelling):
                text = FIXTURE.replace('Kind::Read => json_response("read"),', f"Kind::Read => json_response({spelling}),")
                self.assertEqual(facts("Read", text), ("none", "not-read", "buffered"))

    def test_owned_request_body_taken_and_passed_on_is_handed_on(self):
        for spelling in ("req.take_body()", "req.into_body()", "s3s_req.take_body()"):
            with self.subTest(spelling=spelling):
                text = FIXTURE.replace('Kind::Read => json_response("read"),', f"Kind::Read => decode_elsewhere({spelling}),")
                self.assertEqual(facts("Read", text), ("none", "handed-on", "buffered"))

    def test_owned_request_body_taken_and_buffered_is_buffered(self):
        text = FIXTURE.replace('Kind::Read => json_response("read"),',
                               "Kind::Read => json_response(req.take_body().store_all_limited(64)),")
        self.assertEqual(facts("Read", text), ("none", "buffered", "buffered"))

    def test_a_body_method_on_something_else_is_not_a_request_read(self):
        for spelling in ("response.into_body()", "self.take_bodyguard()", "req.take_body_size"):
            with self.subTest(spelling=spelling):
                text = FIXTURE.replace('Kind::Read => json_response("read"),', f"Kind::Read => json_response({spelling}),")
                self.assertEqual(facts("Read", text), ("none", "not-read", "buffered"))

    def test_path_qualified_static_handler_type_is_read(self):
        source = Source(FIXTURE + "static EXAMPLE_HANDLER: crate::admin::handlers::example::Handler = Handler(Kind::Read);\n")
        self.assertEqual(inventory.handler_type(source, "EXAMPLE_HANDLER", FILE), "Handler")

    def test_a_shared_sealing_helper_seals_the_response(self):
        for call in ("super::owned_admin_json_response(path, &secret, &payload)",
                     "crate::admin::handlers::owned_admin_json_response(path, &secret, &payload)",
                     "owned_admin_json_response(path, &secret, &payload)"):
            with self.subTest(call=call):
                self.assertEqual(facts("Read", read_with(call), SEALING_HELPER), ("response-on-minio-alias", "not-read", "buffered"))

    def test_a_shared_helper_reached_through_a_same_file_helper_seals_the_response(self):
        text = read_with("answer(&payload)") + "\nfn answer(payload: &P) -> R { super::owned_admin_json_response(p, s, payload) }\n"
        self.assertEqual(facts("Read", text, SEALING_HELPER), ("response-on-minio-alias", "not-read", "buffered"))

    def test_an_uncalled_sealing_helper_seals_nothing(self):
        self.assertEqual(facts("Read", FIXTURE, SEALING_HELPER), ("none", "not-read", "buffered"))

    def test_a_shared_helper_that_does_not_seal_seals_nothing(self):
        plain = SEALING_HELPER.replace("encode_compatible_admin_payload", "encode_plain_payload")
        self.assertEqual(facts("Read", read_with("super::owned_admin_json_response(p, s, x)"), plain),
                         ("none", "not-read", "buffered"))

    def test_a_sealing_helper_only_in_the_shared_test_module_seals_nothing(self):
        shared = "#[cfg(test)]\nmod tests {\n" + SEALING_HELPER + "}\n"
        self.assertEqual(facts("Read", read_with("owned_admin_json_response(p, s, x)"), shared),
                         ("none", "not-read", "buffered"))

    def test_a_similarly_named_call_does_not_follow_the_helper(self):
        for call in ("owned_admin_json_response_plain(p)", "x.owned_admin_json_response(p)"):
            with self.subTest(call=call):
                self.assertEqual(facts("Read", read_with(call), SEALING_HELPER), ("none", "not-read", "buffered"))

    def test_the_shared_helper_lends_no_body_facts_but_its_seal(self):
        reading = SEALING_HELPER.replace("Ok(AdminResponse::new(body, content_type))",
                                         "store_all_limited(req.input); Ok(StreamingBlob::wrap(body))")
        self.assertEqual(facts("Read", read_with("owned_admin_json_response(p, s, x)"), reading),
                         ("response-on-minio-alias", "not-read", "buffered"))

    def test_plain_text_markers_stay_literal(self):
        saved = inventory.STREAMED_RESPONSES, inventory.BUFFERED_READS
        try:
            inventory.STREAMED_RESPONSES = ("Stream.Body(",)
            inventory.BUFFERED_READS = ("read.body(",)
            for text, expected in (("StreamxBody(", "buffered"), ("Stream.Body(", "streamed")):
                with self.subTest(text=text):
                    self.assertEqual(inventory.body_facts(text, set())[2], expected)
            for text, expected in (("readxbody(", "not-read"), ("read.body(", "buffered")):
                with self.subTest(text=text):
                    self.assertEqual(inventory.body_facts(text, set())[1], expected)
        finally:
            inventory.STREAMED_RESPONSES, inventory.BUFFERED_READS = saved

    def test_owned_stream_pattern_is_a_pattern_not_a_marker(self):
        self.assertTrue(all("\\" not in marker for marker in inventory.STREAMED_RESPONSES))
        self.assertEqual(inventory.body_facts("Body::from_stream(s)", set())[2], "streamed")
        self.assertEqual(inventory.body_facts("OwnedBody::from_stream(s)", set())[2], "buffered")

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
