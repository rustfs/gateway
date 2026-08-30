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

use crate::{
    ConfigKind, CorpusCaseEvidence, CorpusCoverageError, CorpusVariant, FamilyCorpusEvidence, FourWayCodec, GoldenFailure,
    GoldenSample, RejectedGoldenSample, SampleOrigin, assert_four_way,
};

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
const PAYMENT_DOCTYPE: &[u8] =
    b"<!DOCTYPE RequestPaymentConfiguration><RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>";
const PAYMENT_DOCTYPE_LEADING_WS: &[u8] = b" \n<!DOCTYPE RequestPaymentConfiguration><RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>";
const PAYMENT_DOCTYPE_SPACE: &[u8] = b"<!DOCTYPE RequestPaymentConfiguration   ><RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>";
const PAYMENT_DOCTYPE_XML_DECL: &[u8] = br#"<?xml version="1.0"?><!DOCTYPE RequestPaymentConfiguration><RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>"#;
const PAYMENT_DUPLICATE: &[u8] =
    b"<RequestPaymentConfiguration><Payer>Requester</Payer><Payer>BucketOwner</Payer></RequestPaymentConfiguration>";
const PAYMENT_NESTED_PAYER: &[u8] =
    b"<RequestPaymentConfiguration><Payer><Future>Requester</Future></Payer></RequestPaymentConfiguration>";

fn accelerate_bytes(status: &str) -> Vec<u8> {
    format!("<AccelerateConfiguration><Status>{status}</Status></AccelerateConfiguration>").into_bytes()
}

fn payment_bytes(payer: &str) -> Vec<u8> {
    format!("<RequestPaymentConfiguration><Payer>{payer}</Payer></RequestPaymentConfiguration>").into_bytes()
}

fn origin(source: &str, sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: source.to_owned(),
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
        origin: origin("P9 Accelerate persistence matrix", sha256),
        notes: notes.to_owned(),
    }
}

fn payment_sample(bytes: &[u8], sha256: &str, payer: &str, notes: &str) -> GoldenSample<PersistedRequestPaymentConfiguration> {
    GoldenSample {
        kind: ConfigKind::RequestPayment,
        bytes: bytes.to_vec(),
        value: PersistedRequestPaymentConfiguration { payer: payer.to_owned() },
        origin: origin("P9 Request Payment persistence matrix", sha256),
        notes: notes.to_owned(),
    }
}

fn rejected(
    kind: ConfigKind,
    bytes: &[u8],
    sha256: &str,
    notes: &str,
    variant: CorpusVariant,
) -> (RejectedGoldenSample, Vec<CorpusVariant>) {
    (
        RejectedGoldenSample {
            kind,
            bytes: bytes.to_vec(),
            origin: origin(
                if kind == ConfigKind::Accelerate {
                    "P9 Accelerate persistence matrix"
                } else {
                    "P9 Request Payment persistence matrix"
                },
                sha256,
            ),
            notes: notes.to_owned(),
        },
        vec![variant],
    )
}

macro_rules! accepted_rows {
    ($builder:ident; $(($bytes:expr, $sha:literal, $value:expr, $notes:literal, [$($variant:ident),+])),+ $(,)?) => {
        vec![$(($builder($bytes, $sha, $value, $notes), vec![$(CorpusVariant::$variant),+])),+]
    };
}

macro_rules! rejected_rows {
    ($kind:expr; $(($bytes:expr, $sha:literal, $notes:literal, $variant:ident)),+ $(,)?) => {
        vec![$((rejected($kind, $bytes, $sha, $notes, CorpusVariant::$variant))) ,+]
    };
}

fn accelerate_accepted_samples() -> Vec<(GoldenSample<PersistedAccelerateConfiguration>, Vec<CorpusVariant>)> {
    let value = "x".repeat(8 * 1024);
    let large = accelerate_bytes(&value);
    accepted_rows!(accelerate_sample;
        (ACCELERATE_EMPTY, "7465c3ed92bf634fe1ee8ec2638f9c18a83c8c990c6104799882126496cdeffb", None, "absent optional status", [EmptyElement]),
        (ACCELERATE_ENABLED, "7ce1a176ccd38c459f3886283f343f4dc94e58b6601430a5ccba121c1bbefd5a", Some("Enabled"), "enabled decision control", [Canonical]),
        (ACCELERATE_SUSPENDED, "c4b4d348ce048b627ab1dc9df2654647d8182e11ee74fbeded579e2f77c7c4bc", Some("Suspended"), "suspended decision control", [Canonical]),
        (ACCELERATE_FUTURE, "8fc84999c6fe06f592ec8b3eab01dcf3c50ba9d7374c65e1e798487f216fbba8", Some("Future"), "unknown old-readable status must remain disabled", [UnknownScalar]),
        (ACCELERATE_NAMESPACE, "3fac4665dc20652bcf2fa9a28597ee39e80b836704b8e2557ff055292152e638", Some("Enabled"), "historical namespace keeps the enabled decision", [Namespace]),
        (ACCELERATE_UNKNOWN_TOP, "58772bae7579ef9dc188f25d3ad68f08bad2a044050862553b9096816a989166", Some("Enabled"), "unknown root child is ignored", [UnknownTopLevel]),
        (ACCELERATE_BOM_CRLF, "5aa8497ad5ef70f29cb473db7bbeec94323c918d29eb71f1da84dec1849fb702", Some("Enabled"), "BOM and CRLF historical bytes", [Bom, Crlf]),
        (ACCELERATE_TRAILING_TEXT, "ca7962b8b9de6f5a74e1d882f09fa95a922b4cba4580f6e2a01f59ee52dcddb3", None, "root-trailing text is old-readable", [EmptyElement]),
        (ACCELERATE_DOCTYPE, "03c3fc975d73b35f6698b919bb7a4e10ca9253a9c3f58d2c7959bd254f44cb0e", None, "document type declaration is old-readable", [EmptyElement]),
        (ACCELERATE_DOCTYPE_LEADING_WS, "8b3eeabd5510de2738237e385bca32fe11411d82e29f90e885fee85fb65c665d", None, "leading whitespace before doctype", [EmptyElement]),
        (ACCELERATE_DOCTYPE_SPACE, "7d0ea7e98deaa15578427f8be2064bebe94c877c75836921358b7b34c2be898d", None, "doctype trailing whitespace", [EmptyElement]),
        (ACCELERATE_DOCTYPE_XML_DECL, "86b798110df7c8cec857509e1ffafc4c73affa830a6a477ea1a8e9d0c2d4815e", None, "XML declaration before doctype", [EmptyElement]),
        (&large, "e4b382d6dcb3b41151b711c760bd67712f77e6ca034645180b93d7a14ab67f0f", Some(&value), "8 KiB old-readable status", [LargeValue]),
    )
}

fn payment_accepted_samples() -> Vec<(GoldenSample<PersistedRequestPaymentConfiguration>, Vec<CorpusVariant>)> {
    let value = "x".repeat(8 * 1024);
    let large = payment_bytes(&value);
    accepted_rows!(payment_sample;
        (PAYMENT_REQUESTER, "22b785fb6cc215e7d3e82981301fa6b8207d577f9b4210b4dc9ed27c3cc05365", "Requester", "requester-pays decision control", [Canonical]),
        (PAYMENT_OWNER, "fb15ebb09965945c36b53b2b296014788f9a628cd9229a9223a73b2389ecc071", "BucketOwner", "bucket-owner decision control", [Canonical]),
        (PAYMENT_FUTURE, "575333425114368e39108d08071e6010efa04e29beba8b3848b52251e7eab049", "Future", "future payer stays disabled", [UnknownScalar]),
        (PAYMENT_EMPTY, "cf8045b17a6c9eb08a8d69a99d20c17ba78a288e7369afab911663472597738a", "", "explicit empty payer", [EmptyElement]),
        (PAYMENT_NAMESPACE, "aad02439b908cbad0ded5b0d4a418f4b2b9e8a4515d6134e2b124bdeab82f33e", "Requester", "historical namespace keeps requester pays", [Namespace]),
        (PAYMENT_UNKNOWN_TOP, "0e5aca456a23e43c239e25b3f20fd3d20b355ee02c8288b15067620848c44930", "Requester", "unknown root child is ignored", [UnknownTopLevel]),
        (PAYMENT_BOM_CRLF, "3a95c417e5cb50c80ba802dbbe7cd8ea584a6a436089d28e0c7dedf87df30dbe", "Requester", "BOM and CRLF historical bytes", [Bom, Crlf]),
        (PAYMENT_TRAILING_TEXT, "10bef466b525e6e55336ebeda42cfca67a25b05f3043de3889f9a4528388440f", "Requester", "root-trailing text is old-readable", [Canonical]),
        (PAYMENT_DOCTYPE, "4ee60ac9972f46bde8b98bc4987af8958d7e258977166574656d03de1577d272", "Requester", "document type declaration is old-readable", [Canonical]),
        (PAYMENT_DOCTYPE_LEADING_WS, "e9ec34856f7fdd9e041018a901c3afed222841ea6b625c60c9131770d3388d31", "Requester", "leading whitespace before doctype", [Canonical]),
        (PAYMENT_DOCTYPE_SPACE, "c957a8c9556a383acf406249867a669d01ca7df39ea0c0b9ffa3d24f6bd59d91", "Requester", "doctype trailing whitespace", [Canonical]),
        (PAYMENT_DOCTYPE_XML_DECL, "4548344909ffdf99bd21a191de8442b364bb6c997aad7386f49b7f0f8db3ab77", "Requester", "XML declaration before doctype", [Canonical]),
        (&large, "d406d21fee0449aa5c79bc361e5f5ab9e6701640f9c242400e6cbe68fdd59c9f", &value, "8 KiB old-readable payer", [LargeValue]),
    )
}

fn accelerate_rejected_samples() -> Vec<(RejectedGoldenSample, Vec<CorpusVariant>)> {
    rejected_rows!(ConfigKind::Accelerate;
        (ACCELERATE_DUPLICATE, "71526810c50cb0deb1072b97819a5cdc65676f9feeea263091e6937b8743111f", "duplicate status", DuplicateField),
        (ACCELERATE_NESTED_STATUS, "579d905d928c1a1c1f32bc1bc924b48faaf9f9c6bc944d5cb75d62e25888c4a5", "nested status", UnknownNested),
        (b"<WrongRoot></WrongRoot>", "ec4479e283c2fa7e1dcc960b277dfd81dc72c53822c55ac73dadb05682c9980f", "wrong root", MissingField),
        (b"<AccelerateConfiguration>", "106a6bd0517cbfabfa4dc37ca3932420f908ef4e52b241ff3572844c21761e92", "truncated root", MissingField),
        (b"<AccelerateConfiguration><Status>Enabled</AccelerateConfiguration>", "552e5f7edae7ce746108581946438b0f73f4bccc076f6a215925b7d3d0338da6", "mismatched close", MissingField),
        (b"<AccelerateConfiguration broken=\"></AccelerateConfiguration>", "9fc057a7cf65f157e47ddbc8eb27e311256ce4885ba173f36800f313a909e26a", "malformed attribute", UnknownAttribute),
        (b"<AccelerateConfiguration></AccelerateConfiguration><AccelerateConfiguration></AccelerateConfiguration>", "ccdfd44f5a5d0bc64d5d78b17ea91145ecb7a54e9713bd62ec11ecca2760836f", "duplicate document", DuplicateField),
        (b"<", "dabd3aff769f07eb2965401eb029974ebba3407afd02b26ddb564ea5f8efae72", "incomplete opener", MissingField),
        (b"</AccelerateConfiguration>", "18a8e54f2f0ed1e5fd18793bf731d7f9a48480b2d481657e6f8a918b39099189", "closing root only", MissingField),
        (b"<AccelerateConfiguration><Status>", "6e187681d9adab45ef4046f8d88dc1ee2f4500311699cd123e999fa15c753c27", "truncated status", MissingField),
        (b"<AccelerateConfiguration><Status></Status>", "717e90b4c5e7217db80763b8c4a002af4ffbcfbe1036d69ade63c7a54bd68827", "missing root close", MissingField),
        (b"<AccelerateConfiguration><Status></AccelerateConfiguration>", "eb46f14e2ab1020a590766a24383d45bfe2d8bee175426583d4eeb07ea95d9a1", "mismatched empty status", MissingField),
        (b"\xff", "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89", "non-UTF-8 document", Unicode),
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty document", MissingField),
    )
}

fn payment_rejected_samples() -> Vec<(RejectedGoldenSample, Vec<CorpusVariant>)> {
    [
        (PAYMENT_MISSING, "e12aa1055b8234c176d89ce52dce06ae13b030d82e4aa2d40fd4ee21400efccc", "missing payer", CorpusVariant::MissingField),
        (PAYMENT_DUPLICATE, "b10f8676fd39a9c51c9fad1a9ccf6f199cad31fefc7c06c41ab01d63f453c97e", "duplicate payer", CorpusVariant::DuplicateField),
        (PAYMENT_NESTED_PAYER, "216e5b5ac91ca14f13daafe601f62da513555099afe6e165740e508297d098fc", "nested payer content", CorpusVariant::UnknownNested),
        (b"<WrongRoot></WrongRoot>", "ec4479e283c2fa7e1dcc960b277dfd81dc72c53822c55ac73dadb05682c9980f", "wrong root", CorpusVariant::MissingField),
        (b"<RequestPaymentConfiguration>", "db29b26b7daf51c39a5687fb2ab5fb32b0a307b62047d031b5a37b513177ccb3", "truncated root", CorpusVariant::MissingField),
        (b"<RequestPaymentConfiguration><Payer>Requester</RequestPaymentConfiguration>", "0bfad9740e12b01d8bc4fa2a77c4114299b4e5a32ce08350abed3bf5ec941717", "mismatched payer close", CorpusVariant::MissingField),
        (b"<RequestPaymentConfiguration broken=\"><Payer>Requester</Payer></RequestPaymentConfiguration>", "a91e85c6e586dd67b9782af763f821ece4897c4ba8e7881f0a32249ba7aaa13f", "malformed attribute", CorpusVariant::UnknownAttribute),
        (b"<RequestPaymentConfiguration></RequestPaymentConfiguration><RequestPaymentConfiguration></RequestPaymentConfiguration>", "fba7f41de6f583c971ec9475f36cc79c5faf0a2b5b87b88a60f8b274d0d38359", "duplicate document", CorpusVariant::DuplicateField),
        (b"<", "dabd3aff769f07eb2965401eb029974ebba3407afd02b26ddb564ea5f8efae72", "incomplete opener", CorpusVariant::MissingField),
        (b"</RequestPaymentConfiguration>", "72af931150c7d449a29173260d5d2534fac626838ab99c15bc5b773aaef3673d", "closing root only", CorpusVariant::MissingField),
        (b"<RequestPaymentConfiguration><Payer>", "62df2f61e3985841e9c9e6fcc7b446f8ed05fb72e06e3fe683b04e9d0cfe3f76", "truncated payer", CorpusVariant::MissingField),
        (b"<RequestPaymentConfiguration><Payer></Payer>", "cc3b440561459deaeefda26b18964035770792259ec10b72f2aa5153644fe4d6", "missing root close", CorpusVariant::MissingField),
        (b"\xff", "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89", "non-UTF-8 document", CorpusVariant::Unicode),
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty document", CorpusVariant::MissingField),
    ]
    .into_iter()
    .map(|(bytes, sha256, notes, variant)| rejected(ConfigKind::RequestPayment, bytes, sha256, notes, variant))
    .collect()
}

fn family_corpus<T>(
    kind: ConfigKind,
    accepted: Vec<(GoldenSample<T>, Vec<CorpusVariant>)>,
    rejected: Vec<(RejectedGoldenSample, Vec<CorpusVariant>)>,
) -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    let mut cases = Vec::new();
    for (sample, variants) in accepted {
        cases.push(CorpusCaseEvidence::accepted(&sample, &variants)?);
    }
    for (sample, variants) in rejected {
        cases.push(CorpusCaseEvidence::rejected(&sample, &variants)?);
    }
    Ok(FamilyCorpusEvidence::new(
        kind,
        vec![
            CorpusVariant::Canonical,
            CorpusVariant::EmptyElement,
            CorpusVariant::MissingField,
            CorpusVariant::UnknownTopLevel,
            CorpusVariant::UnknownNested,
            CorpusVariant::UnknownAttribute,
            CorpusVariant::Namespace,
            CorpusVariant::DuplicateField,
            CorpusVariant::UnknownScalar,
            CorpusVariant::LargeValue,
            CorpusVariant::Bom,
            CorpusVariant::Crlf,
            CorpusVariant::Unicode,
        ],
        cases,
    ))
}

pub(crate) fn accelerate_corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    family_corpus(ConfigKind::Accelerate, accelerate_accepted_samples(), accelerate_rejected_samples())
}

pub(crate) fn request_payment_corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    family_corpus(ConfigKind::RequestPayment, payment_accepted_samples(), payment_rejected_samples())
}

const _: [fn() -> Result<FamilyCorpusEvidence, CorpusCoverageError>; 2] =
    [accelerate_corpus_evidence, request_payment_corpus_evidence];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_corpus_report;

    #[test]
    fn family_owned_corpus_evidence_is_built_from_the_shared_case_objects() {
        let accelerate = accelerate_corpus_evidence().expect("Accelerate corpus evidence is traceable");
        let payment = request_payment_corpus_evidence().expect("Request Payment corpus evidence is traceable");
        build_corpus_report(&[ConfigKind::Accelerate, ConfigKind::RequestPayment], &[accelerate, payment])
            .expect("both scalar corpus rows are derived from shared cases");
    }

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

    fn base_accelerate_sample() -> GoldenSample<PersistedAccelerateConfiguration> {
        accelerate_accepted_samples()
            .into_iter()
            .find_map(|(sample, variants)| variants.contains(&CorpusVariant::Namespace).then_some(sample))
            .expect("Accelerate matrix carries its namespace control")
    }

    fn base_payment_sample() -> GoldenSample<PersistedRequestPaymentConfiguration> {
        payment_accepted_samples()
            .into_iter()
            .find_map(|(sample, variants)| variants.contains(&CorpusVariant::Namespace).then_some(sample))
            .expect("Request Payment matrix carries its namespace control")
    }

    #[test]
    fn ten_traceable_accelerate_samples_pass_d1_through_d5() {
        for (case, _) in accelerate_accepted_samples() {
            assert_accelerate_four_way(&case).expect("Accelerate sample passes D1-D5");
        }
    }

    #[test]
    fn ten_traceable_request_payment_samples_pass_d1_through_d5() {
        for (case, _) in payment_accepted_samples() {
            assert_request_payment_four_way(&case).expect("Request Payment sample passes D1-D5");
        }
    }

    #[test]
    fn rejected_documents_match_the_old_parser_in_more_cases_than_the_positive_matrix() {
        for (case, _) in accelerate_rejected_samples() {
            assert!(
                parse_s3s_accelerate(&case.bytes).is_err(),
                "old Accelerate decoder rejects {}",
                case.notes
            );
            assert!(parse_accelerate(&case.bytes).is_err(), "new Accelerate decoder matches the old refusal");
        }
        for (case, _) in payment_rejected_samples() {
            assert!(
                parse_s3s_request_payment(&case.bytes).is_err(),
                "old Request Payment decoder rejects {}",
                case.notes
            );
            assert!(
                parse_request_payment(&case.bytes).is_err(),
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
