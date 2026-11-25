#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Read RustFS's metadata listing selector, and refuse every shape the reader cannot vouch for."""

import unittest
from pathlib import Path

import gen_rustfs_admin_route_inventory as inventory
import rustfs_metadata_listing_routes as metadata

# A self-written fixture with the shape the reader expects: a GET-only selector over a bucket, one
# `metadata=true` gate, then the versions and list-type arms, and the access check's action match.
FIXTURE = '''
fn metadata_operation(method: &Method, uri: &Uri, headers: &HeaderMap, host: Option<&MultiDomain>) -> Option<BucketTarget> {
    if method != Method::GET {
        return None;
    }
    let bucket = bucket_from_request(uri, headers, host).ok()?;
    let query = uri.query()?;
    if query_value(query, "metadata").as_deref() != Some("true") {
        return None;
    }
    let operation = if query_has(query, "versions") {
        MetadataOperation::ListObjectVersions
    } else if query_value(query, "list-type").as_deref() == Some("2") {
        MetadataOperation::ListObjectsV2
    } else {
        return None;
    };
    Some(BucketTarget { operation, bucket })
}
async fn check_metadata_access(req: &mut S3Request<Body>, target: BucketTarget) -> S3Result<()> {
    let action = match target.operation {
        MetadataOperation::ListObjectVersions => S3Action::ListBucketVersionsAction,
        MetadataOperation::ListObjectsV2 => S3Action::ListBucketAction,
    };
    authorize_bucket_listing(req, &target.bucket, action).await
}
'''


def read(text):
    return metadata.metadata_listing_routes(text, metadata.METADATA_ROUTE, inventory.fail, inventory.matching_close)


class MetadataListingRoutes(unittest.TestCase):
    def test_reads_both_shapes_in_the_order_rustfs_tries_them(self):
        rows = read(FIXTURE)
        self.assertEqual([row["name"] for row in rows], [
            "MetadataOperation::ListObjectVersions",
            "MetadataOperation::ListObjectsV2",
        ])
        versions, v2 = rows
        self.assertEqual(versions["query_discriminator"], {"key": "versions", "rule": "present"})
        self.assertEqual(v2["query_discriminator"], {"key": "list-type", "rule": "equals:2"})
        for row in rows:
            self.assertEqual(row["method"], "GET")
            self.assertEqual(row["target"], "bucket")
            self.assertEqual(row["query_requires"], [{"key": "metadata", "rule": "equals:true"}])
            self.assertEqual(row["claimed_by"], "rustfs/src/app/metadata_route.rs")
            self.assertEqual((row["auth_mode"], row["auth_detail"]), ("custom", "SignedOrAnonymousThenBucketListing"))
            self.assertEqual(row["iam_action_enum"], "S3Action")
        self.assertEqual(versions["iam_action"], "ListBucketVersionsAction")
        self.assertEqual(v2["iam_action"], "ListBucketAction")

    def refused(self, text, fragment):
        with self.assertRaises(inventory.InventoryError) as raised:
            read(text)
        self.assertIn(fragment, str(raised.exception))

    def test_n_a_missing_selector_is_refused(self):
        self.refused(FIXTURE.replace("fn metadata_operation(", "fn other_operation("), "metadata_operation not found")

    def test_n_a_selector_that_is_not_get_only_is_refused(self):
        self.refused(FIXTURE.replace("if method != Method::GET {", "if method == Method::PUT {"), "GET-only")

    def test_n_a_selector_that_names_no_bucket_is_refused(self):
        self.refused(FIXTURE.replace("bucket_from_request(uri, headers, host)", "object_from_request(uri)"), "bucket")

    def test_n_a_changed_gate_value_is_refused(self):
        self.refused(FIXTURE.replace('Some("true")', 'Some("1")'), "metadata=true gate")

    def test_n_a_case_insensitive_gate_is_refused(self):
        changed = FIXTURE.replace(
            'query_value(query, "metadata").as_deref() != Some("true")',
            '!query_value(query, "metadata").is_some_and(|v| v.eq_ignore_ascii_case("true"))',
        )
        self.refused(changed, "metadata=true gate")

    def test_n_an_unreadable_arm_is_refused(self):
        changed = FIXTURE.replace('query_has(query, "versions")', 'query_starts(query, "versions")')
        self.refused(changed, "unreadable")

    def test_n_a_third_operation_is_refused(self):
        changed = FIXTURE.replace(
            "    } else {\n        return None;",
            '    } else if query_has(query, "uploads") {\n        MetadataOperation::ListMultipartUploads\n'
            "    } else {\n        return None;",
        )
        self.refused(changed, "ListMultipartUploads")

    def test_n_an_operation_without_an_action_is_refused(self):
        changed = FIXTURE.replace("        MetadataOperation::ListObjectsV2 => S3Action::ListBucketAction,\n", "")
        self.refused(changed, "no authorisation action")

    def test_n_an_action_outside_s3_action_is_refused(self):
        changed = FIXTURE.replace("S3Action::ListBucketAction", "AdminAction::ListBucketAction")
        self.refused(changed, "no authorisation action")


class NativeMetadataTests(unittest.TestCase):
    def test_published_tables_trace_executed_steps_to_their_typed_overlay(self):
        path = Path(__file__).resolve().parents[1] / metadata.DIALECT_DIR / "src/native/extensions.rs"
        source = inventory.strip_comments(path.read_text(encoding="utf-8"))

        def read(text, table):
            return metadata.published_table(text, table, inventory.matching_close, inventory.split_args, inventory.fail)

        s3 = read(source, "s3")
        control = read(source, "control_plane")
        self.assertEqual([kind for _, kind, _ in s3], ["ListObjectVersionsWithMetadata", "ListObjectsV2WithMetadata"])
        self.assertEqual(len(control), 8)
        self.assertTrue({kind for _, kind, _ in s3}.isdisjoint(kind for _, kind, _ in control))
        a, b = (row[0] for row in s3)
        rows = f"&[{a}::ROW, {b}::ROW]"
        for before, after in [
            (rows, f"&[{b}::ROW, {a}::ROW]"),
            (rows, f"&[{a}::ROW]"),
            (rows, f"&[{a}::ROW, {b}::ROW, {a}::ROW]"),
            (f"{a}::ROUTE,", f"{b}::ROUTE,"),
            (f"..ops::{a}::OVERLAY_ROW", f"..ops::{b}::OVERLAY_ROW"),
            (f"..ops::{a}::ROUTE", f"..ops::{b}::ROUTE"),
            ("precedence: ROW.precedence", "precedence: 0"),
            ("fold(&mut super::Declare, builder)", "super::control_plane::declare(builder)"),
            ("builder.declare::<O>(route)", "builder"),
            ('shadows("rustfs:ListObjectsV2WithMetadata",', 'shadows("rustfs:CheckReplication",'),
            ("winner: ROW.name,", "winner: shadowed,"),
            ("pub mod s3 {", "#[cfg(test)] pub mod s3 {"),
            ("use crate::ops;", "use crate::native::ops;"),
            (f"mod {a} {{", f"#[path = \"other.rs\"] mod {a} {{"),
        ]:
            with self.subTest(change=(before, after)):
                self.assertIn(before, source)
                with self.assertRaises(inventory.InventoryError):
                    read(source.replace(before, after, 1), "s3")

    def test_published_modules_must_be_direct_unconditional_declarations(self):
        pattern = r"\bpub mod extensions;"
        for text in ('mod other { pub mod extensions; }', '#[path = "elsewhere.rs"] pub mod extensions;',
                     'pub mod extensions; pub mod extensions;'):
            with self.subTest(text=text), self.assertRaises(inventory.InventoryError):
                metadata.direct_item(text, pattern, "native extensions", inventory.matching_close, inventory.fail)

    def test_control_declarations_require_the_same_live_registrations_and_overlay(self):
        dialect = ("for name in BORROWED { rows.push(OVERLAY.row(name).copied().ok_or(GatewayAssemblyError::AdminOverlayMissing)?); } "
                   "let record = RECORD.get_or_init(|| DialectOverlay { name: \"rustfs-control-plane\", vendor: OVERLAY.vendor, "
                   "claims: CLAIMS, operations: ROWS.get_or_init(|| rows), }); "
                   "Dialect::assemble(record) .declare_claimed::<ControlPlane>(ROUTE) "
                   ".declare_claimed::<PostV3SpeedtestClientDevnull>(ClaimedRoute { rows: rows(), }) "
                   ".declare_form::<StsForm>(STS_ROUTE) .declare::<Example>(Example::ROUTE) .build() "
                   ".map_err(GatewayAssemblyError::AdminDialect)")
        assembly = ("let service = builder .hand_caller_secret_to_every_operation_after_listing_in_the_posture_report() "
                    ".dialect(&dialect()?) .register::<ControlPlane, _>(Arc::clone(&host)) "
                    ".register::<PostV3SpeedtestClientDevnull, _>(Arc::clone(&host)) "
                    ".register::<StsForm, _>(Arc::clone(&host)) .register::<Example, _>(host) "
                    ".build() .map_err(GatewayAssemblyError::Service)?; "
                    "Ok(GatewayStack { service, keystone_auth: assembly.keystone_auth, control_plane: true, })")
        source = ("use rustfs_gateway_dialect_rustfs_admin::ops::{"
                  "post_v3_speedtest_client_devnull::PostV3SpeedtestClientDevnull, example::Example}; "
                  "const BORROWED: [&str; 2] = [PostV3SpeedtestClientDevnull::NAME, Example::NAME];")
        def bindings(src, dec, reg):
            return metadata.control_bindings(src, dec, reg, inventory.split_args, inventory.fail)
        self.assertEqual(bindings(source, dialect, assembly), [("example", "Example")])
        for src, dec, reg in [
            (source, dialect, assembly.replace(".register::<Example, _>(host)", "")),
            (source, dialect.replace("Example::ROUTE", "Other::ROUTE"), assembly),
            (source.replace("Example::NAME", "Other::NAME"), dialect, assembly),
            (source, dialect, assembly.replace("control_plane: true", "control_plane: false")),
            (source, dialect.replace(".declare::<Example>", ".declare::<Other>"), assembly),
            (source, dialect, assembly.replace(".dialect(&dialect()?)", ".dialect(&other()?)")),
            (source, dialect.replace("operations: ROWS.get_or_init(|| rows)", "operations: OTHER"), assembly),
        ]:
            with self.subTest(src=src, dec=dec, reg=reg), self.assertRaises(inventory.InventoryError):
                bindings(src, dec, reg)

    def test_only_the_locked_dialect_commit_is_accepted(self):
        revision = "1" * 40
        lock = ('[[package]]\nname = "rustfs-gateway-dialect-rustfs-admin"\n'
                f'source = "git+https://github.com/rustfs/gateway.git?rev={revision}#{revision}"\n')
        self.assertEqual(metadata.locked_revision(lock, inventory.fail), revision)
        for other in ("", lock + lock, lock.replace("#" + revision, "#" + "2" * 40),
                      lock.replace("github.com/rustfs/", "github.com/other/")):
            with self.subTest(lock=other), self.assertRaises(inventory.InventoryError):
                metadata.locked_revision(other, inventory.fail)

    def test_runtime_predicates_and_host_authority_must_agree(self):
        source = r'''
            pub const NAME: &str = "rustfs:Example";
            pub const AUTH: AuthRequirement = AuthRequirement::new("s3:Read", ResourceShape::Bucket);
            static SPEC: OperationSpec = admin::spec(NAME, AUTH, false);
            static FLOOR: OperationFloor = admin::listing_floor(NAME);
            impl Operation for Example {
                const NAME: &'static str = NAME;
                fn spec() -> &'static OperationSpec { &SPEC }
                fn floor() -> &'static OperationFloor { &FLOOR }
            }
            pub static SELECTOR: &[Predicate] = &[Predicate::Method(http::Method::GET),
                Predicate::Target(TargetKind::Bucket), Predicate::QueryPresent("flag"),
                Predicate::QueryEquals("metadata", "true")];
            pub const ROUTE: DialectRoute = DialectRoute {
                precedence: 70, selector: SELECTOR, path_shape: "/{Bucket}", shadows: SHADOWS,
            };
            impl ExtensionOperation for Example { const ROUTE: DialectRoute = ROUTE; }
            pub const OVERLAY_ROW: OverlayRow = OverlayRow {
                name: NAME, precedence: 70, selector: "Method(GET) ∧ Target(Bucket) ∧ QueryPresent(\"flag\") ∧ QueryEquals(\"metadata\", \"true\")", action: "s3:Read",
                resource: ResourceShape::Bucket, success_status: 200, anonymous: false, evidence: &[],
            };
        '''
        def read(text):
            row = metadata.typed_route(text, "Example", inventory.fail, inventory.split_args)
            metadata.verify_listing(row, "s3:Read", inventory.fail)
            return row
        row = read(source)
        self.assertEqual((row["precedence"], row["query_discriminator"], row["query_requires"]),
                         (70, {"key": "flag", "rule": "present"}, [{"key": "metadata", "rule": "equals:true"}]))
        for old, new in (('Method::GET', 'Method::POST'), ('TargetKind::Bucket', 'TargetKind::Object'),
                         ('"s3:Read"', '"s3:Write"'), ('"metadata", "true"', '"metadata", "false"'),
                         ('selector: SELECTOR', 'selector: OTHER'), ('Method(GET) ∧', 'Method(HEAD) ∧'), (' = ROUTE;', ' = OTHER;'),
                         ('admin::listing_floor', 'admin::floor'), ('{ &SPEC }', '{ &OTHER }')):
            with self.subTest(change=new), self.assertRaises(inventory.InventoryError):
                read(source.replace(old, new))


if __name__ == "__main__":
    unittest.main()
