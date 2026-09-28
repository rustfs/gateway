// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! RustFS's own lifecycle write rules on the reference backend (rustfs/gateway#999).
//!
//! Responsible for: a rule `Status` other than exactly `Enabled`/`Disabled` refused as
//! `MalformedXML` with nothing stored, and a rule written without `ID` stored under the id RustFS
//! generates (`rule-<index>`, suffixed past a collision).
//! NOT responsible for: the shared lifecycle contract, which stays lenient about `Status` for
//! persisted documents (`q-lc-0014`); this is the RustFS write path the backend mirrors.
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;

const LOWERCASE: &str = "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix>a/</Prefix></Filter><Status>enabled</Status><Expiration><Days>2</Days></Expiration></Rule></LifecycleConfiguration>";
const LOWERCASE_MD5: &str = "GTmTRwUObYfbfJOgRBfVjw==";
const INVALID: &str = "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix>a/</Prefix></Filter><Status>invalid</Status><Expiration><Days>2</Days></Expiration></Rule></LifecycleConfiguration>";
const INVALID_MD5: &str = "6dyeOLv1UWjh+uwjC8V68A==";
const NO_ID: &str = "<LifecycleConfiguration><Rule><Filter><Prefix>a/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>31</Days></Expiration></Rule><Rule><ID>rule-0</ID><Filter><Prefix>b/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>2</Days></Expiration></Rule><Rule><Filter><Prefix>c/</Prefix></Filter><Status>Disabled</Status><Expiration><Days>3</Days></Expiration></Rule></LifecycleConfiguration>";
const NO_ID_MD5: &str = "0dE7hp3ypbP35mMhNcPbCQ==";

async fn put(service: &S3Service, body: &'static str, md5: &str) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-md5", http::HeaderValue::from_str(md5).expect("a header value"));
    exchange(
        service,
        signed_with_headers(http::Method::PUT, "/lcrules?lifecycle", Bytes::from_static(body.as_bytes()), headers),
    )
    .await
}

fn text(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

/// Negative — `enabled` and `invalid` are `MalformedXML`, as RustFS's
/// `validate_lifecycle_rule_status` answers them, and neither replaces nothing with something.
#[tokio::test]
async fn n_a_status_outside_enabled_and_disabled_is_malformed_xml() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "lcrules").await;
    for (body, md5) in [(LOWERCASE, LOWERCASE_MD5), (INVALID, INVALID_MD5)] {
        let refused = put(&service, body, md5).await;
        assert_eq!(refused.status(), 400, "{}", text(&refused));
        assert!(text(&refused).contains("<Code>MalformedXML</Code>"), "{}", text(&refused));
        let read = exchange(&service, signed(http::Method::GET, "/lcrules?lifecycle", Bytes::new())).await;
        assert_eq!(read.status(), 404, "{}", text(&read));
    }
}

/// Positive — rules without `ID` are stored under RustFS's generated ids, which skip an id another
/// rule already carries.
#[tokio::test]
async fn rules_without_an_id_get_rustfs_generated_ids() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "lcrules").await;
    let written = put(&service, NO_ID, NO_ID_MD5).await;
    assert_eq!(written.status(), 200, "{}", text(&written));
    let read = exchange(&service, signed(http::Method::GET, "/lcrules?lifecycle", Bytes::new())).await;
    let body = text(&read);
    for id in ["<ID>rule-0-1</ID>", "<ID>rule-0</ID>", "<ID>rule-2</ID>"] {
        assert!(body.contains(id), "missing {id} in {body}");
    }
    assert_eq!(body.matches("<ID>").count(), 3, "{body}");
}
