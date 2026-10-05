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

//! Private POST body completion and rejection regressions.
//!
//! Responsible for: queued output, completion hints, and discarded output after rejection.
//! NOT responsible for: authentication or multipart syntax coverage. Upstream: PostFileBody.
//! Downstream: no runtime consumers.

use super::*;
use http_body_util::{BodyExt, Full};

const BOUNDARY: &str = "ownership-boundary";
const CARRY: &[u8] = b"carry";
const REST: &str = "the rest of the owned file payload";

fn body(ceiling: u64, policy: AcceptedPolicy) -> Result<PostFileBody<Full<Bytes>>, String> {
    let header = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n");
    let mut reader = FormReader::new(&format!("multipart/form-data; boundary={BOUNDARY}"), FormLimits::default())
        .map_err(|_| "the fixture boundary must be valid")?;
    assert!(matches!(reader.push(header.as_bytes()), Ok(FormStep::FileReached { .. })));
    let mut file = reader.into_file(ceiling).map_err(|_| "the file header must be reached")?;
    let mut premature = Vec::new();
    assert_eq!(
        file.push(CARRY, &mut |bytes: &[u8]| premature.extend_from_slice(bytes)),
        Ok(FileStep::NeedMore)
    );
    assert!(premature.is_empty(), "the fixture must retain carry for the final push");
    let wire = Full::new(Bytes::new());
    let progress = WireProgress::for_body(BodyDigestObligation::None, Some(&wire));
    Ok(PostFileBody {
        frames: WireFrames::new(wire, progress, BodyCeilings::streaming(None), BodyTimeouts::S3),
        first: Some(Bytes::from(format!("{REST}\r\n--{BOUNDARY}--\r\n"))),
        initial: false,
        legacy_policy_errors: false,
        file,
        policy,
        bucket: "example-bucket".to_owned(),
        key: "upload".to_owned(),
        ended: false,
        pending: VecDeque::new(),
    })
}

async fn next_data(body: &mut PostFileBody<Full<Bytes>>) -> Result<Bytes, String> {
    body.frame()
        .await
        .ok_or("the next file frame must exist")?
        .map_err(|error| error.to_string())?
        .into_data()
        .map_err(|_| "the frame must contain file data".to_owned())
}

#[tokio::test]
async fn completion_never_hides_a_pending_final_file_frame() -> Result<(), String> {
    let mut body = body(1024, AcceptedPolicy::Anonymous)?;
    assert_eq!(next_data(&mut body).await?.as_ref(), CARRY);
    assert!(!body.is_end_stream(), "the final input has another output frame");
    assert_eq!(next_data(&mut body).await?.as_ref(), REST.as_bytes());
    assert!(body.is_end_stream(), "completion follows the final queued output");
    assert!(body.frame().await.is_none(), "completed output cannot repeat");
    Ok(())
}

fn minimum_length_policy() -> Result<AcceptedPolicy, String> {
    // Encodes expiration 2030-01-01, exact bucket/key, and a 100..1024 byte content range.
    // Authentication is outside this private adapter fixture; only final enforcement is tested.
    let encoded = "eyJleHBpcmF0aW9uIjoiMjAzMC0wMS0wMVQwMDowMDowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LHsia2V5IjoidXBsb2FkIn0sWyJjb250ZW50LWxlbmd0aC1yYW5nZSIsMTAwLDEwMjRdXX0=";
    let fields = [
        ("awsaccesskeyid", "fixture"),
        ("signature", "fixture"),
        ("key", "upload"),
        ("policy", encoded),
    ];
    Ok(AcceptedPolicy::SigV2(
        SigV2PostPolicy::parse(&fields, "", PostPolicyLimits::default(), RequestNow::from_unix_seconds(0))
            .map_err(|_| "the minimum-length policy must be valid")?,
    ))
}

async fn assert_rejected_without_output(mut body: PostFileBody<Full<Bytes>>, expected: &str) -> Result<(), String> {
    let Some(Err(error)) = body.frame().await else {
        return Err("the push must return a terminal refusal".to_owned());
    };
    assert_eq!(error.to_string(), expected);
    assert!(body.is_end_stream(), "a rejected push cannot leave output pending");
    assert!(body.frame().await.is_none(), "no bytes may escape after the refusal");
    Ok(())
}

#[tokio::test]
async fn a_final_policy_refusal_discards_every_frame_from_that_push() -> Result<(), String> {
    assert_rejected_without_output(body(1024, minimum_length_policy()?)?, "the POST file did not satisfy its policy").await
}

#[tokio::test]
async fn a_ceiling_refusal_discards_the_accepted_prefix_of_that_push() -> Result<(), String> {
    assert_rejected_without_output(body(10, AcceptedPolicy::Anonymous)?, "the POST file exceeded its policy ceiling").await
}

#[tokio::test]
async fn a_policy_refusal_keeps_the_transport_completion_observation() -> Result<(), String> {
    for (remaining, unfinished) in [(Bytes::new(), false), (Bytes::from_static(b"unread transport bytes"), true)] {
        let wire = Full::new(remaining);
        let progress = WireProgress::for_body(BodyDigestObligation::None, Some(&wire));
        let mut body = body(10, AcceptedPolicy::Anonymous)?;
        body.frames = WireFrames::new(wire, progress, BodyCeilings::streaming(None), BodyTimeouts::S3);
        body.legacy_policy_errors = true;
        let Some(Err(error)) = body.frame().await else {
            return Err("the file ceiling must refuse the pending push".to_owned());
        };
        let refusal = error.into_refusal();
        assert_eq!(refusal.code(), Some(&ErrorCode::ENTITY_TOO_LARGE));
        assert_eq!(refusal.body_unfinished.is_some(), unfinished);
    }
    Ok(())
}
