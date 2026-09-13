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

//! GetBucketLocation: the request-context proof rustfs/backlog#1752 asked for before M1.
//!
//! Responsible for: proving, for the single real app call #1752 names, that a gateway request can
//! become an `s3s::S3Request<GetBucketLocationInput>` whose `uri`, `headers`, `extensions`,
//! `credentials` and `region` — the five context members the M1 audit found missing from
//! `Req<O>` — plus `method`, `service` and the trailer handle equal what the s3s service hands its
//! handler, and that both stacks decode the same two input members from the same bytes.
//! NOT responsible for: the RustFS extensions the app body then reads (`ReqInfo`,
//! `RequestContext`, the server context slot), which the conversion never produces and the ring-2
//! adapter must install; or a GetBucketLocation input conversion, which is two strings here.
//! Upstream: the harness in `super`. Downstream: nothing.

use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_types::dto;

use super::{
    ACCESS_KEY, BASE_DOMAIN, CapturedInput, Compared, ContextRequest, PATH_HOST, access_key, compare, differing_context,
    region_of,
};

const NONE: &[&str] = &[];

fn compared(request: &ContextRequest) -> Compared {
    let compared = compare(request).expect("both stacks reach their GetBucketLocation handler");
    assert_eq!(compared.operation, "GetBucketLocation");
    compared
}

/// Both decoded inputs, as `(bucket, expected_bucket_owner)`.
fn inputs(compared: &Compared) -> ((String, Option<String>), (String, Option<String>)) {
    let meta = MetaView::addressed(&compared.wire, compared.resolved.target, compared.resolved.bucket().cloned())
        .expect("the meta view the pipeline built");
    let gateway = dto::GetBucketLocation::decode(&meta, RequestBody::None).expect("the gateway codec decodes");
    let CapturedInput::Location(oracle) = &compared.oracle.input else {
        panic!("s3s handed the request to PutObject");
    };
    (
        (gateway.bucket.as_str().to_owned(), gateway.expected_bucket_owner.clone()),
        (oracle.bucket.clone(), oracle.expected_bucket_owner.clone()),
    )
}

#[test]
fn an_anonymous_path_style_request_has_the_same_context_and_input() {
    let compared = compared(&ContextRequest::get(PATH_HOST, "/photos", "location"));

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(compared.converted.uri, "/photos?location");
    assert_eq!(compared.converted.method, http::Method::GET);
    assert!(compared.converted.credentials.is_none());
    let (gateway, oracle) = inputs(&compared);
    assert_eq!(gateway, oracle);
    assert_eq!(gateway.0, "photos");
}

#[test]
fn a_signed_path_style_request_has_the_same_principal_region_and_input() {
    let request = ContextRequest::get(PATH_HOST, "/photos", "location")
        .header("x-amz-expected-bucket-owner", b"111122223333")
        .signed("eu-west-1");
    let compared = compared(&request);

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(
        (access_key(&compared.converted), access_key(&compared.oracle)),
        (Some(ACCESS_KEY), Some(ACCESS_KEY))
    );
    assert_eq!(
        (region_of(&compared.converted), region_of(&compared.oracle)),
        (Some("eu-west-1"), Some("eu-west-1"))
    );
    assert_eq!(compared.converted.service.as_deref(), Some("s3"));
    let (gateway, oracle) = inputs(&compared);
    assert_eq!(gateway, oracle);
    assert_eq!(gateway.1.as_deref(), Some("111122223333"));
}

#[test]
fn a_signed_virtual_hosted_request_has_the_same_context_and_input() {
    let request = ContextRequest::get(&format!("photos.{BASE_DOMAIN}"), "/", "location")
        .virtual_hosted()
        .signed("us-east-1");
    let compared = compared(&request);

    assert_eq!(differing_context(&compared.converted, &compared.oracle), NONE);
    assert_eq!(compared.converted.uri, "/?location");
    let (gateway, oracle) = inputs(&compared);
    assert_eq!(gateway, oracle);
    assert_eq!(gateway.0, "photos");
}
