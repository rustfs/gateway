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

//! Accelerate and Request Payment persistence compatibility evidence.
//!
//! Responsible for: exercising independent pinned-old and production persistence codecs through
//! D1-D5. NOT responsible for: HTTP request policy or any other bucket configuration family.
//! Upstream: pinned-s3s observations and production persistence codecs. Downstream: the P9
//! migration golden gate.

use rustfs_gateway_types::compat::{
    S3sAccelerateObservation, S3sRequestPaymentObservation, parse_s3s_accelerate, parse_s3s_request_payment,
    serialize_s3s_accelerate, serialize_s3s_request_payment,
};
use rustfs_gateway_types::persistence::{
    PersistedAccelerateConfiguration, PersistedRequestPaymentConfiguration, parse_accelerate, parse_request_payment,
    serialize_accelerate, serialize_request_payment,
};

use crate::{ConfigKind, FourWayCodec, GoldenFailure, GoldenSample, assert_four_way};

/// Runs pinned-old versus production Accelerate persistence evidence.
///
/// # Errors
///
/// Returns invalid provenance or the first D1-D5 failure.
pub fn assert_accelerate_four_way(sample: &GoldenSample<PersistedAccelerateConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&AccelerateCodec, sample)
}

/// Runs pinned-old versus production Request Payment persistence evidence.
///
/// # Errors
///
/// Returns invalid provenance or the first D1-D5 failure.
pub fn assert_request_payment_four_way(sample: &GoldenSample<PersistedRequestPaymentConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&RequestPaymentCodec, sample)
}

#[derive(Clone, Copy, Debug)]
struct AccelerateCodec;

impl FourWayCodec for AccelerateCodec {
    const KIND: ConfigKind = ConfigKind::Accelerate;

    type Value = PersistedAccelerateConfiguration;
    type OldParsed = S3sAccelerateObservation;
    type NewParsed = PersistedAccelerateConfiguration;
    type Structure = PersistedAccelerateConfiguration;
    type Behavior = bool;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_accelerate(bytes).map_err(|error| error.to_string())
    }

    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_accelerate(bytes).map_err(|error| error.to_string())
    }

    fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
        value.structure.clone()
    }

    fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
        value.clone()
    }

    fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
        value.clone()
    }

    fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        serialize_s3s_accelerate(value).map_err(|error| error.to_string())
    }

    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_accelerate(value))
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        value.enabled
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        value.enabled()
    }
}

#[derive(Clone, Copy, Debug)]
struct RequestPaymentCodec;

impl FourWayCodec for RequestPaymentCodec {
    const KIND: ConfigKind = ConfigKind::RequestPayment;

    type Value = PersistedRequestPaymentConfiguration;
    type OldParsed = S3sRequestPaymentObservation;
    type NewParsed = PersistedRequestPaymentConfiguration;
    type Structure = PersistedRequestPaymentConfiguration;
    type Behavior = bool;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_request_payment(bytes).map_err(|error| error.to_string())
    }

    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_request_payment(bytes).map_err(|error| error.to_string())
    }

    fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
        value.structure.clone()
    }

    fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
        value.clone()
    }

    fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
        value.clone()
    }

    fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        serialize_s3s_request_payment(value).map_err(|error| error.to_string())
    }

    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_request_payment(value))
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        value.requester_pays
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        value.requester_pays()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCELERATE_EMPTY: &[u8] = b"<AccelerateConfiguration></AccelerateConfiguration>";
    const ACCELERATE_ENABLED: &[u8] = b"<AccelerateConfiguration><Status>Enabled</Status></AccelerateConfiguration>";
    const ACCELERATE_SUSPENDED: &[u8] = b"<AccelerateConfiguration><Status>Suspended</Status></AccelerateConfiguration>";
    const ACCELERATE_FUTURE: &[u8] = b"<AccelerateConfiguration><Status>Future</Status></AccelerateConfiguration>";
    const ACCELERATE_UNKNOWN_TOP: &[u8] =
        b"<AccelerateConfiguration><Future>value</Future><Status>Enabled</Status></AccelerateConfiguration>";
    const ACCELERATE_NAMESPACE: &[u8] = br#"<AccelerateConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></AccelerateConfiguration>"#;
    const ACCELERATE_BOM_CRLF: &[u8] =
        b"\xef\xbb\xbf<AccelerateConfiguration>\r\n<Status>Enabled</Status>\r\n</AccelerateConfiguration>";
    const ACCELERATE_TRAILING_TEXT: &[u8] = b"<AccelerateConfiguration></AccelerateConfiguration>trailing";
    const ACCELERATE_DOCTYPE: &[u8] = b"<!DOCTYPE AccelerateConfiguration><AccelerateConfiguration></AccelerateConfiguration>";
    const ACCELERATE_DOCTYPE_LEADING_WS: &[u8] =
        b" \n<!DOCTYPE AccelerateConfiguration><AccelerateConfiguration></AccelerateConfiguration>";
    const ACCELERATE_DOCTYPE_SPACE: &[u8] =
        b"<!DOCTYPE AccelerateConfiguration   ><AccelerateConfiguration></AccelerateConfiguration>";
    const ACCELERATE_DOCTYPE_XML_DECL: &[u8] =
        br#"<?xml version="1.0"?><!DOCTYPE AccelerateConfiguration><AccelerateConfiguration></AccelerateConfiguration>"#;
    const ACCELERATE_DUPLICATE: &[u8] =
        b"<AccelerateConfiguration><Status>Enabled</Status><Status>Suspended</Status></AccelerateConfiguration>";
    const ACCELERATE_NESTED_STATUS: &[u8] =
        b"<AccelerateConfiguration><Status><Future>Enabled</Future></Status></AccelerateConfiguration>";

    const PAYMENT_REQUESTER: &[u8] = b"<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>";
    const PAYMENT_OWNER: &[u8] = b"<RequestPaymentConfiguration><Payer>BucketOwner</Payer></RequestPaymentConfiguration>";
    const PAYMENT_FUTURE: &[u8] = b"<RequestPaymentConfiguration><Payer>Future</Payer></RequestPaymentConfiguration>";
    const PAYMENT_EMPTY: &[u8] = b"<RequestPaymentConfiguration><Payer></Payer></RequestPaymentConfiguration>";
    const PAYMENT_MISSING: &[u8] = b"<RequestPaymentConfiguration></RequestPaymentConfiguration>";
    const PAYMENT_UNKNOWN_TOP: &[u8] =
        b"<RequestPaymentConfiguration><Future>value</Future><Payer>Requester</Payer></RequestPaymentConfiguration>";
    const PAYMENT_NAMESPACE: &[u8] = br#"<RequestPaymentConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Payer>Requester</Payer></RequestPaymentConfiguration>"#;
    const PAYMENT_BOM_CRLF: &[u8] =
        b"\xef\xbb\xbf<RequestPaymentConfiguration>\r\n<Payer>Requester</Payer>\r\n</RequestPaymentConfiguration>";
    const PAYMENT_TRAILING_TEXT: &[u8] =
        b"<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>trailing";
    const PAYMENT_DOCTYPE: &[u8] = b"<!DOCTYPE RequestPaymentConfiguration><RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>";
    const PAYMENT_DOCTYPE_LEADING_WS: &[u8] = b" \n<!DOCTYPE RequestPaymentConfiguration><RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>";
    const PAYMENT_DOCTYPE_SPACE: &[u8] = b"<!DOCTYPE RequestPaymentConfiguration   ><RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>";
    const PAYMENT_DOCTYPE_XML_DECL: &[u8] = br#"<?xml version="1.0"?><!DOCTYPE RequestPaymentConfiguration><RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>"#;
    const PAYMENT_DUPLICATE: &[u8] =
        b"<RequestPaymentConfiguration><Payer>Requester</Payer><Payer>BucketOwner</Payer></RequestPaymentConfiguration>";
    const PAYMENT_NESTED_PAYER: &[u8] =
        b"<RequestPaymentConfiguration><Payer><Future>Requester</Future></Payer></RequestPaymentConfiguration>";

    #[test]
    fn pinned_old_serializers_define_the_exact_persistence_bytes() {
        assert_eq!(
            serialize_s3s_accelerate(&PersistedAccelerateConfiguration::default())
                .expect("old Accelerate serializer accepts absent status"),
            ACCELERATE_EMPTY
        );
        assert_eq!(
            serialize_s3s_accelerate(&PersistedAccelerateConfiguration {
                status: Some("Enabled".to_owned()),
            })
            .expect("old Accelerate serializer accepts Enabled"),
            ACCELERATE_ENABLED
        );
        assert_eq!(
            serialize_s3s_request_payment(&PersistedRequestPaymentConfiguration {
                payer: "Requester".to_owned(),
            })
            .expect("old Request Payment serializer accepts Requester"),
            PAYMENT_REQUESTER
        );
        assert_eq!(serialize_accelerate(&PersistedAccelerateConfiguration::default()), ACCELERATE_EMPTY);
        assert_eq!(
            serialize_request_payment(&PersistedRequestPaymentConfiguration { payer: String::new() }),
            PAYMENT_EMPTY
        );
    }

    #[test]
    fn pinned_old_parser_boundaries_are_observed_before_candidate_parity() {
        for accepted in [
            ACCELERATE_EMPTY,
            ACCELERATE_ENABLED,
            ACCELERATE_SUSPENDED,
            ACCELERATE_FUTURE,
            ACCELERATE_UNKNOWN_TOP,
            ACCELERATE_NAMESPACE,
            ACCELERATE_BOM_CRLF,
            ACCELERATE_TRAILING_TEXT,
            ACCELERATE_DOCTYPE,
            ACCELERATE_DOCTYPE_LEADING_WS,
            ACCELERATE_DOCTYPE_SPACE,
            ACCELERATE_DOCTYPE_XML_DECL,
        ] {
            let old = parse_s3s_accelerate(accepted).expect("old Accelerate parser accepts the observed boundary");
            let new = parse_accelerate(accepted).expect("new Accelerate parser accepts every old-readable boundary");
            assert_eq!(old.structure, new);
            assert_eq!(old.enabled, new.enabled());
        }
        for rejected in [ACCELERATE_DUPLICATE, ACCELERATE_NESTED_STATUS] {
            assert!(
                parse_s3s_accelerate(rejected).is_err(),
                "old Accelerate parser rejects the observed boundary"
            );
        }

        for accepted in [
            PAYMENT_REQUESTER,
            PAYMENT_OWNER,
            PAYMENT_FUTURE,
            PAYMENT_EMPTY,
            PAYMENT_UNKNOWN_TOP,
            PAYMENT_NAMESPACE,
            PAYMENT_BOM_CRLF,
            PAYMENT_TRAILING_TEXT,
            PAYMENT_DOCTYPE,
            PAYMENT_DOCTYPE_LEADING_WS,
            PAYMENT_DOCTYPE_SPACE,
            PAYMENT_DOCTYPE_XML_DECL,
        ] {
            let old = parse_s3s_request_payment(accepted).expect("old Request Payment parser accepts the observed boundary");
            let new = parse_request_payment(accepted).expect("new Request Payment parser accepts every old-readable boundary");
            assert_eq!(old.structure, new);
            assert_eq!(old.requester_pays, new.requester_pays());
        }
        for rejected in [PAYMENT_MISSING, PAYMENT_DUPLICATE, PAYMENT_NESTED_PAYER] {
            assert!(
                parse_s3s_request_payment(rejected).is_err(),
                "old Request Payment parser rejects the observed boundary"
            );
        }

        let large_status = accelerate_bytes(&"x".repeat(8 * 1024));
        let large_payer = payment_bytes(&"x".repeat(8 * 1024));
        parse_s3s_accelerate(&large_status).expect("old Accelerate parser accepts an 8 KiB status");
        parse_s3s_request_payment(&large_payer).expect("old Request Payment parser accepts an 8 KiB payer");
    }

    fn accelerate_bytes(status: &str) -> Vec<u8> {
        format!("<AccelerateConfiguration><Status>{status}</Status></AccelerateConfiguration>").into_bytes()
    }

    fn payment_bytes(payer: &str) -> Vec<u8> {
        format!("<RequestPaymentConfiguration><Payer>{payer}</Payer></RequestPaymentConfiguration>").into_bytes()
    }

    fn origin(sha256: &str) -> crate::SampleOrigin {
        crate::SampleOrigin {
            source: "P9 Accelerate and Request Payment persistence matrix".to_owned(),
            producer: "pinned s3s XML behavior".to_owned(),
            version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
            sha256: sha256.to_owned(),
        }
    }

    fn accelerate_sample(
        bytes: &[u8],
        sha256: &str,
        status: Option<&str>,
        notes: &str,
    ) -> GoldenSample<PersistedAccelerateConfiguration> {
        GoldenSample {
            kind: ConfigKind::Accelerate,
            bytes: bytes.to_vec(),
            value: PersistedAccelerateConfiguration {
                status: status.map(str::to_owned),
            },
            origin: origin(sha256),
            notes: notes.to_owned(),
        }
    }

    fn payment_sample(
        bytes: &[u8],
        sha256: &str,
        payer: &str,
        notes: &str,
    ) -> GoldenSample<PersistedRequestPaymentConfiguration> {
        GoldenSample {
            kind: ConfigKind::RequestPayment,
            bytes: bytes.to_vec(),
            value: PersistedRequestPaymentConfiguration { payer: payer.to_owned() },
            origin: origin(sha256),
            notes: notes.to_owned(),
        }
    }

    fn base_accelerate_sample() -> GoldenSample<PersistedAccelerateConfiguration> {
        accelerate_sample(
            ACCELERATE_NAMESPACE,
            "3fac4665dc20652bcf2fa9a28597ee39e80b836704b8e2557ff055292152e638",
            Some("Enabled"),
            "a historical namespace is ignored without changing the enabled decision",
        )
    }

    fn base_payment_sample() -> GoldenSample<PersistedRequestPaymentConfiguration> {
        payment_sample(
            PAYMENT_NAMESPACE,
            "aad02439b908cbad0ded5b0d4a418f4b2b9e8a4515d6134e2b124bdeab82f33e",
            "Requester",
            "a historical namespace is ignored without changing the requester-pays decision",
        )
    }

    #[test]
    fn ten_traceable_accelerate_samples_pass_d1_through_d5() {
        let large = accelerate_bytes(&"x".repeat(8 * 1024));
        let cases = [
            accelerate_sample(
                ACCELERATE_EMPTY,
                "7465c3ed92bf634fe1ee8ec2638f9c18a83c8c990c6104799882126496cdeffb",
                None,
                "absent optional status",
            ),
            accelerate_sample(
                ACCELERATE_ENABLED,
                "7ce1a176ccd38c459f3886283f343f4dc94e58b6601430a5ccba121c1bbefd5a",
                Some("Enabled"),
                "enabled decision control",
            ),
            accelerate_sample(
                ACCELERATE_SUSPENDED,
                "c4b4d348ce048b627ab1dc9df2654647d8182e11ee74fbeded579e2f77c7c4bc",
                Some("Suspended"),
                "suspended decision control",
            ),
            accelerate_sample(
                ACCELERATE_FUTURE,
                "8fc84999c6fe06f592ec8b3eab01dcf3c50ba9d7374c65e1e798487f216fbba8",
                Some("Future"),
                "unknown old-readable status must remain disabled",
            ),
            base_accelerate_sample(),
            accelerate_sample(
                ACCELERATE_UNKNOWN_TOP,
                "58772bae7579ef9dc188f25d3ad68f08bad2a044050862553b9096816a989166",
                Some("Enabled"),
                "unknown top-level element is ignored by the old parser",
            ),
            accelerate_sample(
                ACCELERATE_BOM_CRLF,
                "5aa8497ad5ef70f29cb473db7bbeec94323c918d29eb71f1da84dec1849fb702",
                Some("Enabled"),
                "BOM and CRLF historical bytes",
            ),
            accelerate_sample(
                ACCELERATE_TRAILING_TEXT,
                "ca7962b8b9de6f5a74e1d882f09fa95a922b4cba4580f6e2a01f59ee52dcddb3",
                None,
                "root-trailing text accepted by the old persistence parser",
            ),
            accelerate_sample(
                ACCELERATE_DOCTYPE,
                "03c3fc975d73b35f6698b919bb7a4e10ca9253a9c3f58d2c7959bd254f44cb0e",
                None,
                "document type declaration accepted by the old persistence parser",
            ),
            accelerate_sample(
                &large,
                "e4b382d6dcb3b41151b711c760bd67712f77e6ca034645180b93d7a14ab67f0f",
                Some(&"x".repeat(8 * 1024)),
                "old-readable status at the required 8 KiB boundary",
            ),
        ];
        for case in cases {
            assert_accelerate_four_way(&case).expect("Accelerate sample passes D1-D5");
        }
    }

    #[test]
    fn ten_traceable_request_payment_samples_pass_d1_through_d5() {
        let large = payment_bytes(&"x".repeat(8 * 1024));
        let cases = [
            payment_sample(
                PAYMENT_REQUESTER,
                "22b785fb6cc215e7d3e82981301fa6b8207d577f9b4210b4dc9ed27c3cc05365",
                "Requester",
                "requester-pays decision control",
            ),
            payment_sample(
                PAYMENT_OWNER,
                "fb15ebb09965945c36b53b2b296014788f9a628cd9229a9223a73b2389ecc071",
                "BucketOwner",
                "bucket-owner decision control",
            ),
            payment_sample(
                PAYMENT_FUTURE,
                "575333425114368e39108d08071e6010efa04e29beba8b3848b52251e7eab049",
                "Future",
                "unknown old-readable payer must not enable requester pays",
            ),
            payment_sample(
                PAYMENT_EMPTY,
                "cf8045b17a6c9eb08a8d69a99d20c17ba78a288e7369afab911663472597738a",
                "",
                "explicit empty required scalar remains present",
            ),
            base_payment_sample(),
            payment_sample(
                PAYMENT_UNKNOWN_TOP,
                "0e5aca456a23e43c239e25b3f20fd3d20b355ee02c8288b15067620848c44930",
                "Requester",
                "unknown top-level element is ignored by the old parser",
            ),
            payment_sample(
                PAYMENT_BOM_CRLF,
                "3a95c417e5cb50c80ba802dbbe7cd8ea584a6a436089d28e0c7dedf87df30dbe",
                "Requester",
                "BOM and CRLF historical bytes",
            ),
            payment_sample(
                PAYMENT_TRAILING_TEXT,
                "10bef466b525e6e55336ebeda42cfca67a25b05f3043de3889f9a4528388440f",
                "Requester",
                "root-trailing text accepted by the old persistence parser",
            ),
            payment_sample(
                PAYMENT_DOCTYPE,
                "4ee60ac9972f46bde8b98bc4987af8958d7e258977166574656d03de1577d272",
                "Requester",
                "document type declaration accepted by the old persistence parser",
            ),
            payment_sample(
                &large,
                "d406d21fee0449aa5c79bc361e5f5ab9e6701640f9c242400e6cbe68fdd59c9f",
                &"x".repeat(8 * 1024),
                "old-readable payer at the required 8 KiB boundary",
            ),
        ];
        for case in cases {
            assert_request_payment_four_way(&case).expect("Request Payment sample passes D1-D5");
        }
    }

    #[test]
    fn rejected_documents_match_the_old_parser_in_more_cases_than_the_positive_matrix() {
        let accelerate_rejected: [&[u8]; 14] = [
            ACCELERATE_DUPLICATE,
            ACCELERATE_NESTED_STATUS,
            b"<WrongRoot></WrongRoot>",
            b"<AccelerateConfiguration>",
            b"<AccelerateConfiguration><Status>Enabled</AccelerateConfiguration>",
            b"<AccelerateConfiguration broken=\"></AccelerateConfiguration>",
            b"<AccelerateConfiguration></AccelerateConfiguration><AccelerateConfiguration></AccelerateConfiguration>",
            b"<",
            b"</AccelerateConfiguration>",
            b"<AccelerateConfiguration><Status>",
            b"<AccelerateConfiguration><Status></Status>",
            b"<AccelerateConfiguration><Status></AccelerateConfiguration>",
            b"\xff",
            b"",
        ];
        let payment_rejected: [&[u8]; 14] = [
            PAYMENT_MISSING,
            PAYMENT_DUPLICATE,
            PAYMENT_NESTED_PAYER,
            b"<WrongRoot></WrongRoot>",
            b"<RequestPaymentConfiguration>",
            b"<RequestPaymentConfiguration><Payer>Requester</RequestPaymentConfiguration>",
            b"<RequestPaymentConfiguration broken=\"><Payer>Requester</Payer></RequestPaymentConfiguration>",
            b"<RequestPaymentConfiguration></RequestPaymentConfiguration><RequestPaymentConfiguration></RequestPaymentConfiguration>",
            b"<",
            b"</RequestPaymentConfiguration>",
            b"<RequestPaymentConfiguration><Payer>",
            b"<RequestPaymentConfiguration><Payer></Payer>",
            b"\xff",
            b"",
        ];
        for (index, bytes) in accelerate_rejected.into_iter().enumerate() {
            assert!(
                parse_s3s_accelerate(bytes).is_err(),
                "old Accelerate decoder rejects negative case {index}"
            );
            assert!(parse_accelerate(bytes).is_err(), "new Accelerate decoder matches the old refusal");
        }
        for (index, bytes) in payment_rejected.into_iter().enumerate() {
            assert!(
                parse_s3s_request_payment(bytes).is_err(),
                "old Request Payment decoder rejects negative case {index}"
            );
            assert!(
                parse_request_payment(bytes).is_err(),
                "new Request Payment decoder matches the old refusal"
            );
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct AccelerateMutant {
        old_byte_drift: bool,
        rollback_refusal: bool,
        stricter_new: bool,
        structure_drift: bool,
        behavior_drift: bool,
        panic_old_parse: bool,
    }

    impl FourWayCodec for AccelerateMutant {
        const KIND: ConfigKind = ConfigKind::Accelerate;
        type Value = PersistedAccelerateConfiguration;
        type OldParsed = S3sAccelerateObservation;
        type NewParsed = PersistedAccelerateConfiguration;
        type Structure = PersistedAccelerateConfiguration;
        type Behavior = bool;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_old_parse, "wrong kind must fail before observation");
            if self.rollback_refusal && bytes == ACCELERATE_ENABLED {
                return Err("mutation: old rollback parser rejects new output".to_owned());
            }
            AccelerateCodec.old_parse(bytes)
        }

        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.stricter_new && bytes == ACCELERATE_NAMESPACE {
                return Err("mutation: new parser rejects old-readable namespace".to_owned());
            }
            let mut parsed = AccelerateCodec.new_parse(bytes)?;
            if self.structure_drift {
                parsed.status = None;
            }
            Ok(parsed)
        }

        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            AccelerateCodec.old_structure(value)
        }
        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            AccelerateCodec.new_structure(value)
        }
        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            AccelerateCodec.expected_structure(value)
        }
        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = AccelerateCodec.old_serialize(value)?;
            if self.old_byte_drift {
                bytes.push(b' ');
            }
            Ok(bytes)
        }
        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            AccelerateCodec.new_serialize(value)
        }
        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            AccelerateCodec.old_behavior(value)
        }
        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            AccelerateCodec.new_behavior(value) ^ self.behavior_drift
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct PaymentMutant {
        old_byte_drift: bool,
        rollback_refusal: bool,
        stricter_new: bool,
        structure_drift: bool,
        behavior_drift: bool,
        panic_old_parse: bool,
    }

    impl FourWayCodec for PaymentMutant {
        const KIND: ConfigKind = ConfigKind::RequestPayment;
        type Value = PersistedRequestPaymentConfiguration;
        type OldParsed = S3sRequestPaymentObservation;
        type NewParsed = PersistedRequestPaymentConfiguration;
        type Structure = PersistedRequestPaymentConfiguration;
        type Behavior = bool;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_old_parse, "wrong kind must fail before observation");
            if self.rollback_refusal && bytes == PAYMENT_REQUESTER {
                return Err("mutation: old rollback parser rejects new output".to_owned());
            }
            RequestPaymentCodec.old_parse(bytes)
        }
        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.stricter_new && bytes == PAYMENT_NAMESPACE {
                return Err("mutation: new parser rejects old-readable namespace".to_owned());
            }
            let mut parsed = RequestPaymentCodec.new_parse(bytes)?;
            if self.structure_drift {
                parsed.payer.clear();
            }
            Ok(parsed)
        }
        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            RequestPaymentCodec.old_structure(value)
        }
        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            RequestPaymentCodec.new_structure(value)
        }
        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            RequestPaymentCodec.expected_structure(value)
        }
        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = RequestPaymentCodec.old_serialize(value)?;
            if self.old_byte_drift {
                bytes.push(b' ');
            }
            Ok(bytes)
        }
        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            RequestPaymentCodec.new_serialize(value)
        }
        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            RequestPaymentCodec.old_behavior(value)
        }
        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            RequestPaymentCodec.new_behavior(value) ^ self.behavior_drift
        }
    }

    #[test]
    fn accelerate_mutations_make_every_direction_fail() {
        for (mutant, expected) in [
            (
                AccelerateMutant {
                    structure_drift: true,
                    ..AccelerateMutant::default()
                },
                crate::Direction::D1CompatibleRead,
            ),
            (
                AccelerateMutant {
                    old_byte_drift: true,
                    ..AccelerateMutant::default()
                },
                crate::Direction::D2ByteWrite,
            ),
            (
                AccelerateMutant {
                    rollback_refusal: true,
                    ..AccelerateMutant::default()
                },
                crate::Direction::D3RollbackRead,
            ),
            (
                AccelerateMutant {
                    stricter_new: true,
                    ..AccelerateMutant::default()
                },
                crate::Direction::D4NotStricter,
            ),
            (
                AccelerateMutant {
                    behavior_drift: true,
                    ..AccelerateMutant::default()
                },
                crate::Direction::D5Behavior,
            ),
        ] {
            let failure = assert_four_way(&mutant, &base_accelerate_sample()).expect_err("mutant must be killed");
            assert_eq!(failure.direction, expected);
        }
    }

    #[test]
    fn request_payment_mutations_make_every_direction_fail() {
        for (mutant, expected) in [
            (
                PaymentMutant {
                    structure_drift: true,
                    ..PaymentMutant::default()
                },
                crate::Direction::D1CompatibleRead,
            ),
            (
                PaymentMutant {
                    old_byte_drift: true,
                    ..PaymentMutant::default()
                },
                crate::Direction::D2ByteWrite,
            ),
            (
                PaymentMutant {
                    rollback_refusal: true,
                    ..PaymentMutant::default()
                },
                crate::Direction::D3RollbackRead,
            ),
            (
                PaymentMutant {
                    stricter_new: true,
                    ..PaymentMutant::default()
                },
                crate::Direction::D4NotStricter,
            ),
            (
                PaymentMutant {
                    behavior_drift: true,
                    ..PaymentMutant::default()
                },
                crate::Direction::D5Behavior,
            ),
        ] {
            let failure = assert_four_way(&mutant, &base_payment_sample()).expect_err("mutant must be killed");
            assert_eq!(failure.direction, expected);
        }
    }

    #[test]
    fn wrong_family_fails_before_either_old_observation() {
        let mut accelerate = base_accelerate_sample();
        accelerate.kind = ConfigKind::RequestPayment;
        let accelerate_failure = assert_four_way(
            &AccelerateMutant {
                panic_old_parse: true,
                ..AccelerateMutant::default()
            },
            &accelerate,
        )
        .expect_err("wrong Accelerate family must fail closed");
        assert_eq!(accelerate_failure.direction, crate::Direction::Input);

        let mut payment = base_payment_sample();
        payment.kind = ConfigKind::Accelerate;
        let payment_failure = assert_four_way(
            &PaymentMutant {
                panic_old_parse: true,
                ..PaymentMutant::default()
            },
            &payment,
        )
        .expect_err("wrong Request Payment family must fail closed");
        assert_eq!(payment_failure.direction, crate::Direction::Input);
    }
}
