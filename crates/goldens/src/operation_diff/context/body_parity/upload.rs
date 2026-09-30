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

//! The uploads the signed-body diff sends: five payload modes, ten ways to tamper with a signed
//! upload, and the wire bytes each becomes.
//!
//! Responsible for: signing one PutObject once with the gateway's own client signer — header
//! signature, then the aws-chunked chunk chain and trailer signature where the mode has them —
//! applying one tamper after signing, and cutting the wire body into transport pieces; plus the
//! CRC-32 a checksum trailer carries.
//! NOT responsible for: sending anything (the parent) or judging an answer (the proofs).
//! Upstream: `rustfs-gateway-sig`'s signer and chunk chain, the parent's credential and clock.
//! Downstream: the parent's exchange and every proof beside it.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    AmzDate, ChunkSigner, DeclaredTrailers, PayloadMode, RequestNow, SigService, SigV4Signer, SigningCredentials, SigningRequest,
    SigningScope, TrailerName, TrailerSet,
};
use sha2::{Digest, Sha256};

use super::super::{ACCESS_KEY, PATH_HOST, REGIONS, SECRET_KEY, amz_date};

/// The object every upload writes.
pub(super) const TARGET: &str = "/photos/chunked.bin";
/// The one checksum trailer every trailer upload declares.
pub(crate) const TRAILER: &str = "x-amz-checksum-crc32";

/// How the payload is covered, by its `x-amz-content-sha256` token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: aws-chunked, every chunk signed.
    Signed,
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`: the same, plus a signed checksum trailer.
    SignedTrailer,
    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: aws-chunked without signatures, plus a checksum trailer.
    UnsignedTrailer,
    /// `UNSIGNED-PAYLOAD`: the plain body, not covered by the signature.
    Unsigned,
    /// The plain body, its SHA-256 in `x-amz-content-sha256`.
    FullSha256,
}

impl Mode {
    /// Every mode, in the order the matrix reports them.
    pub(crate) const ALL: [Self; 5] = [
        Self::Signed,
        Self::SignedTrailer,
        Self::UnsignedTrailer,
        Self::Unsigned,
        Self::FullSha256,
    ];

    /// The aws-chunked modes.
    pub(crate) const FRAMED: [Self; 3] = [Self::Signed, Self::SignedTrailer, Self::UnsignedTrailer];

    /// The modes whose chunks carry signatures.
    pub(crate) const CHUNK_SIGNED: [Self; 2] = [Self::Signed, Self::SignedTrailer];

    /// The modes that end with a checksum trailer.
    pub(crate) const TRAILERED: [Self; 2] = [Self::SignedTrailer, Self::UnsignedTrailer];

    pub(crate) const fn framed(self) -> bool {
        matches!(self, Self::Signed | Self::SignedTrailer | Self::UnsignedTrailer)
    }

    pub(crate) const fn trailer(self) -> bool {
        matches!(self, Self::SignedTrailer | Self::UnsignedTrailer)
    }

    pub(crate) const fn chunk_signed(self) -> bool {
        matches!(self, Self::Signed | Self::SignedTrailer)
    }

    fn payload(self, object: &[u8]) -> Result<PayloadMode, String> {
        let declared = || -> Result<TrailerSet, String> {
            let name = TrailerName::new(TRAILER).map_err(|error| format!("trailer name: {error:?}"))?;
            let declared = DeclaredTrailers::new([name], false).map_err(|error| format!("trailer set: {error:?}"))?;
            Ok(TrailerSet::Declared(declared))
        };
        Ok(match self {
            Self::Signed => PayloadMode::StreamingSigned {
                trailer: TrailerSet::None,
            },
            Self::SignedTrailer => PayloadMode::StreamingSigned { trailer: declared()? },
            Self::UnsignedTrailer => PayloadMode::StreamingUnsigned { trailer: declared()? },
            Self::Unsigned => PayloadMode::Unsigned,
            Self::FullSha256 => PayloadMode::ExactSha256(Sha256::digest(object).into()),
        })
    }
}

/// One way the upload differs from what was signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tamper {
    /// Exactly what was signed.
    None,
    /// One hex digit of this chunk's signature is changed.
    ChunkSignature(usize),
    /// One byte of this chunk's data is changed after it was signed or checksummed.
    ChunkData(usize),
    /// The wire body stops half way through this chunk's data; `Content-Length` says so.
    CutInsideChunk(usize),
    /// The wire body stops this many bytes early; `Content-Length` says so, so HTTP framing holds.
    Truncate(usize),
    /// `x-amz-decoded-content-length` is the object's length plus this.
    DecodedLength(i64),
    /// The checksum trailer carries the checksum of other bytes; its signature is still valid.
    TrailerChecksum,
    /// The checksum trailer carries a value that is not base64 at all; its signature is still valid.
    TrailerValueUnreadable,
    /// The body ends after the terminal chunk with no trailer section, though one was declared.
    MissingTrailer,
    /// One hex digit of the trailer signature is changed.
    TrailerSignature,
    /// One body byte is changed after its SHA-256 was signed.
    PayloadDigest,
}

/// One signed upload.
#[derive(Clone, Debug)]
pub(crate) struct Upload {
    pub(crate) mode: Mode,
    pub(crate) object: Vec<u8>,
    /// Decoded bytes per aws-chunked data chunk.
    pub(crate) chunk: usize,
    /// Transport piece sizes, cycled over the wire body.
    pub(crate) pieces: Vec<usize>,
    pub(crate) tamper: Tamper,
}

/// The signed head and the wire body, as both stacks receive them.
pub(crate) struct Wire {
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

impl Upload {
    /// `object` in `mode`, in 8-byte chunks, delivered as one piece, untampered.
    pub(crate) fn new(mode: Mode, object: &[u8]) -> Self {
        Self {
            mode,
            object: object.to_vec(),
            chunk: 8,
            pieces: Vec::new(),
            tamper: Tamper::None,
        }
    }

    pub(crate) fn chunked(mut self, chunk: usize) -> Self {
        self.chunk = chunk.max(1);
        self
    }

    pub(crate) fn pieces(mut self, pieces: &[usize]) -> Self {
        self.pieces = pieces.to_vec();
        self
    }

    pub(crate) fn tampered(mut self, tamper: Tamper) -> Self {
        self.tamper = tamper;
        self
    }

    /// The object bytes that precede data chunk `index`.
    pub(crate) fn before_chunk(&self, index: usize) -> &[u8] {
        &self.object[..(index * self.chunk).min(self.object.len())]
    }

    /// The decoded length the head declares.
    fn declared(&self) -> u64 {
        let delta = match self.tamper {
            Tamper::DecodedLength(delta) => delta,
            _ => 0,
        };
        u64::try_from(i64::try_from(self.object.len()).unwrap_or(i64::MAX).saturating_add(delta)).unwrap_or(0)
    }

    /// The signed head and body, signed at `now`.
    pub(crate) fn wire(&self, now: RequestNow) -> Result<Wire, String> {
        let (measured, cut) = if self.mode.framed() {
            let (body, cut) = self.framed_body(None);
            (body.len(), cut)
        } else {
            (self.object.len(), None)
        };
        let length = match self.tamper {
            Tamper::Truncate(drop) => measured.saturating_sub(drop),
            Tamper::CutInsideChunk(_) => cut.unwrap_or(measured),
            _ => measured,
        };
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_static(PATH_HOST));
        headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(length));
        if self.mode.framed() {
            headers.insert(http::header::CONTENT_ENCODING, HeaderValue::from_static("aws-chunked"));
        }
        let stamp = AmzDate::parse(&amz_date(now.unix_seconds())).map_err(|error| format!("stamp: {error:?}"))?;
        let scope = SigningScope::new(stamp.day(), REGIONS[0], SigService::S3).map_err(|error| format!("scope: {error:?}"))?;
        let credentials =
            SigningCredentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|error| format!("credentials: {error:?}"))?;
        let mut signer = SigV4Signer::new(credentials, scope);
        let raw_host = RawHost::from_host_header(PATH_HOST.as_bytes()).map_err(|error| format!("host: {error:?}"))?;
        let method = Method::PUT;
        let payload = self.mode.payload(&self.object)?;
        let mut signing =
            SigningRequest::new(&method, TARGET, "", &headers, &raw_host, payload, stamp).with_wire_content_length(length as u64);
        if self.mode.framed() {
            signing = signing.with_decoded_content_length(self.declared());
        }
        let signed = signer.sign_headers(&signing).map_err(|error| format!("signing: {error:?}"))?;
        let mut body = if self.mode.framed() {
            let mut chain = signer
                .chunk_signer(&signed)
                .map_err(|error| format!("chunk chain: {error:?}"))?;
            self.framed_body(Some(&mut chain)).0
        } else if self.tamper == Tamper::PayloadDigest {
            flipped(&self.object, 0)
        } else {
            self.object.clone()
        };
        body.truncate(length);
        Ok(Wire {
            headers: signed.headers().clone(),
            body,
        })
    }

    /// The aws-chunked body, and where [`Tamper::CutInsideChunk`] cuts it. Signatures come from
    /// `chain`, or are 64 zeros when only measuring: every offset is the same either way.
    fn framed_body(&self, mut chain: Option<&mut ChunkSigner>) -> (Vec<u8>, Option<usize>) {
        let signed = self.mode.chunk_signed();
        let mut out = Vec::new();
        let mut cut = None;
        for (index, data) in self.object.chunks(self.chunk).enumerate() {
            let signature = signed.then(|| link(chain.as_deref_mut(), |chain| chain.sign_chunk(data).to_owned()));
            let signature = signature.map(|signature| {
                if self.tamper == Tamper::ChunkSignature(index) {
                    flipped_hex(&signature)
                } else {
                    signature
                }
            });
            size_line(&mut out, data.len(), signature.as_deref());
            if self.tamper == Tamper::CutInsideChunk(index) {
                cut = Some(out.len() + data.len() / 2);
            }
            if self.tamper == Tamper::ChunkData(index) {
                out.extend_from_slice(&flipped(data, 0));
            } else {
                out.extend_from_slice(data);
            }
            out.extend_from_slice(b"\r\n");
        }
        let terminal = signed.then(|| link(chain.as_deref_mut(), |chain| chain.sign_chunk(b"").to_owned()));
        size_line(&mut out, 0, terminal.as_deref());
        if self.mode.trailer() && self.tamper != Tamper::MissingTrailer {
            let checksummed = if self.tamper == Tamper::TrailerChecksum {
                [self.object.as_slice(), b"!"].concat()
            } else {
                self.object.clone()
            };
            let value = if self.tamper == Tamper::TrailerValueUnreadable {
                "not base64!".to_owned()
            } else {
                crc32_base64(&checksummed)
            };
            out.extend_from_slice(format!("{TRAILER}:{value}\r\n").as_bytes());
            if signed {
                let block = format!("{TRAILER}:{value}\n");
                let mut signature = link(chain, |chain| chain.sign_trailer(&block).to_owned());
                if self.tamper == Tamper::TrailerSignature {
                    signature = flipped_hex(&signature);
                }
                out.extend_from_slice(format!("x-amz-trailer-signature:{signature}\r\n").as_bytes());
            }
        }
        out.extend_from_slice(b"\r\n");
        (out, cut)
    }

    /// The wire body cut into the transport pieces.
    pub(crate) fn split(&self, body: &[u8]) -> Vec<Bytes> {
        let mut sizes = self.pieces.iter().copied().cycle();
        let mut out = Vec::new();
        let mut rest = body;
        while !rest.is_empty() {
            let size = sizes.next().unwrap_or(usize::MAX).clamp(1, rest.len());
            out.push(Bytes::copy_from_slice(&rest[..size]));
            rest = &rest[size..];
        }
        out
    }
}

fn link(chain: Option<&mut ChunkSigner>, sign: impl FnOnce(&mut ChunkSigner) -> String) -> String {
    chain.map_or_else(|| "0".repeat(64), sign)
}

fn size_line(out: &mut Vec<u8>, size: usize, signature: Option<&str>) {
    out.extend_from_slice(format!("{size:x}").as_bytes());
    if let Some(signature) = signature {
        out.extend_from_slice(b";chunk-signature=");
        out.extend_from_slice(signature.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
}

fn flipped(data: &[u8], at: usize) -> Vec<u8> {
    let mut data = data.to_vec();
    if let Some(byte) = data.get_mut(at) {
        *byte ^= 0x01;
    }
    data
}

fn flipped_hex(signature: &str) -> String {
    let first = if signature.starts_with('0') { '1' } else { '0' };
    format!("{first}{}", signature.get(1..).unwrap_or_default())
}

/// CRC-32 (IEEE, reflected), base64 as `x-amz-checksum-crc32` spells it.
pub(crate) fn crc32_base64(data: &[u8]) -> String {
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    base64(&(!crc).to_be_bytes())
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for group in bytes.chunks(3) {
        let word = group
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (index, &byte)| acc | u32::from(byte) << (16 - 8 * index));
        for index in 0..4 {
            if index <= group.len() {
                out.push(char::from(ALPHABET[(word >> (18 - 6 * index) & 0x3F) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
