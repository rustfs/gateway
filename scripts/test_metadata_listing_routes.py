#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Read RustFS's metadata listing selector, and refuse every shape the reader cannot vouch for."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
