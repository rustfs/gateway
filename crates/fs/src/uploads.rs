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

//! Persistent multipart-upload record authority for the filesystem reference backend.
//!
//! Responsible for: durably allocating opaque upload IDs, decoding one upload record, validating
//! its filesystem components, persisting multipart checksum negotiation and the user metadata the
//! initiating request carried, and enumerating active uploads without following symbolic links.
//! NOT responsible for: pagination, delimiter rollup, object publication, or lifecycle.
//! Upstream: upload initiation and retirement handlers. Downstream: upload capability resolution,
//! completion-time object publication, and `ListMultipartUploads`.
//!
//! # Why the metadata lives here and not on the completion
//!
//! S3 carries user metadata, content type, storage class and the encryption settings on
//! `CreateMultipartUpload` alone; a part upload and the completion carry none of them
//! (`q-mpu-metadata-0039`, evidenced in this repository against the AWS `CreateMultipartUpload`
//! reference). Losing them at initiation therefore loses them permanently, which is why the
//! initiating map is persisted into the upload record and read back at completion rather than
//! being taken from the request that finishes the upload.
//!
//! # Why allocation has its own root authority
//!
//! Upload directories are capability storage, not an index from which the next capability may be
//! inferred. A bucket-scoped sequence is advanced and synchronized before its ID is returned, so
//! a reopen cannot replay an active capability and allocation never enumerates upload directories.
//! Upload IDs are resolved together with their bucket and key, so that bucket is the complete
//! uniqueness scope and the counter can live beside the upload records whose scanner already
//! ignores exact dot-prefixed authority files.

use std::io::{self, Write as _};
use std::path::Path;
use std::sync::atomic::Ordering;

use rustfs_gateway::dto::{self, CompletedPart};
use rustfs_gateway::{ChecksumAlgorithm, ChecksumSpec, ChecksumType, ErrorCode, HandlerError, RecordedUpload};
use tokio::io::AsyncWriteExt as _;

use super::records::{ObjectAttributes, decode_trailing_sections, encode_trailing_sections, validate_attributes};
use super::{FsBackend, PARTS_DIR, UPLOAD_RECORD, storage_error};

const UPLOAD_ID_SEQUENCE: &str = ".multipart-upload-id-sequence";
const UPLOAD_ID_SEQUENCE_TEMP: &str = ".tmp-multipart-upload-id-sequence";

fn initialize_upload_id_sequence(uploads: &Path) -> io::Result<()> {
    let sequence = uploads.join(UPLOAD_ID_SEQUENCE);
    match std::fs::symlink_metadata(&sequence) {
        Ok(_) => read_upload_id_sequence(uploads).map(|_| ()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(sequence)?;
            file.write_all(b"0\n")?;
            file.sync_all()
        }
        Err(error) => Err(error),
    }
}

fn read_upload_id_sequence(uploads: &Path) -> io::Result<u64> {
    let sequence = uploads.join(UPLOAD_ID_SEQUENCE);
    let metadata = std::fs::symlink_metadata(&sequence)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(sequence_error());
    }
    let encoded = std::fs::read_to_string(sequence)?;
    let digits = encoded.strip_suffix('\n').ok_or_else(sequence_error)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(sequence_error());
    }
    digits.parse().map_err(|_| sequence_error())
}

fn persist_upload_id_sequence(uploads: &Path, next: u64) -> io::Result<()> {
    let sequence = uploads.join(UPLOAD_ID_SEQUENCE);
    let temporary = uploads.join(UPLOAD_ID_SEQUENCE_TEMP);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
    let written = (|| {
        file.write_all(format!("{next}\n").as_bytes())?;
        file.sync_all()?;
        let metadata = std::fs::symlink_metadata(&sequence)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(sequence_error());
        }
        std::fs::rename(&temporary, sequence)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    written
}

fn sequence_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the multipart upload ID sequence is not a safe canonical counter",
    )
}

fn validate_upload_id_sequence_for_delete(uploads: &Path) -> io::Result<bool> {
    let sequence = uploads.join(UPLOAD_ID_SEQUENCE);
    match std::fs::symlink_metadata(&sequence) {
        Ok(_) => {
            read_upload_id_sequence(uploads)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate_upload_id_sequence_temp_for_delete(uploads: &Path) -> io::Result<bool> {
    let temporary = uploads.join(UPLOAD_ID_SEQUENCE_TEMP);
    match std::fs::symlink_metadata(temporary) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(sequence_error()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy)]
pub(super) struct UploadChecksum {
    algorithm: ChecksumAlgorithm,
    kind: ChecksumType,
}

impl UploadChecksum {
    pub(super) fn negotiate(
        algorithm: Option<&dto::ChecksumAlgorithm>,
        kind: Option<&dto::ChecksumType>,
    ) -> Result<Option<Self>, HandlerError> {
        let Some(algorithm) = algorithm else {
            if kind.is_some() {
                return Err(invalid_checksum("a checksum type requires a negotiated checksum algorithm"));
            }
            return Ok(None);
        };
        let algorithm = ChecksumAlgorithm::from_wire_name(algorithm.as_str())
            .ok_or_else(|| invalid_checksum("the negotiated checksum algorithm is not supported"))?;
        let default_kind = if algorithm == ChecksumAlgorithm::Crc64Nvme {
            ChecksumType::FullObject
        } else {
            ChecksumType::Composite
        };
        let kind = kind.map_or(Ok(default_kind), |kind| {
            ChecksumType::parse(kind.as_str()).map_err(|_| invalid_checksum("the negotiated checksum type is not supported"))
        })?;
        if !valid_combination(algorithm, kind) {
            return Err(invalid_checksum(
                "the checksum algorithm does not support the requested multipart checksum type",
            ));
        }
        Ok(Some(Self { algorithm, kind }))
    }

    fn decode(algorithm: &str, kind: &str) -> Result<Self, HandlerError> {
        let algorithm = ChecksumAlgorithm::from_wire_name(algorithm).ok_or_else(storage_error)?;
        let kind = ChecksumType::parse(kind).map_err(|_| storage_error())?;
        if !valid_combination(algorithm, kind) {
            return Err(storage_error());
        }
        Ok(Self { algorithm, kind })
    }

    pub(super) fn dto_type(self) -> dto::ChecksumType {
        match self.kind {
            ChecksumType::Composite => dto::ChecksumType::COMPOSITE,
            ChecksumType::FullObject => dto::ChecksumType::FULL_OBJECT,
        }
    }

    pub(super) fn validate_part(self, claimed: Option<ChecksumSpec>, bytes: &[u8]) -> Result<ChecksumSpec, HandlerError> {
        let actual = checksum_of(self.algorithm, bytes)?;
        let Some(claimed) = claimed else {
            if self.kind == ChecksumType::Composite {
                return Err(invalid_checksum("a composite-checksum upload requires a checksum on every part"));
            }
            return Ok(actual);
        };
        if claimed.algorithm() != self.algorithm {
            return Err(invalid_checksum("the part checksum algorithm differs from the initiated upload"));
        }
        if claimed != actual {
            return Err(HandlerError::new(
                ErrorCode::X_AMZ_CONTENT_CHECKSUM_MISMATCH,
                "the part checksum did not match the received bytes",
            ));
        }
        Ok(actual)
    }

    pub(super) fn completed_part(self, part: &CompletedPart) -> Result<Option<ChecksumSpec>, HandlerError> {
        let values = [
            (ChecksumAlgorithm::Crc32, part.checksum_crc32.as_deref()),
            (ChecksumAlgorithm::Crc32c, part.checksum_crc32c.as_deref()),
            (ChecksumAlgorithm::Crc64Nvme, part.checksum_crc64nvme.as_deref()),
            (ChecksumAlgorithm::Sha1, part.checksum_sha1.as_deref()),
            (ChecksumAlgorithm::Sha256, part.checksum_sha256.as_deref()),
            (ChecksumAlgorithm::Sha512, part.checksum_sha512.as_deref()),
            (ChecksumAlgorithm::Md5, part.checksum_md5.as_deref()),
            (ChecksumAlgorithm::XxHash64, part.checksum_xxhash64.as_deref()),
            (ChecksumAlgorithm::XxHash3, part.checksum_xxhash3.as_deref()),
            (ChecksumAlgorithm::XxHash128, part.checksum_xxhash128.as_deref()),
        ];
        let mut present = values.into_iter().filter(|(_, value)| value.is_some());
        let Some((algorithm, Some(value))) = present.next() else {
            if self.kind == ChecksumType::Composite {
                return Err(invalid_part_checksum("a composite-checksum completed part has no checksum"));
            }
            return Ok(None);
        };
        if present.next().is_some() || algorithm != self.algorithm {
            return Err(invalid_part_checksum(
                "a completed part checksum differs from the initiated upload algorithm",
            ));
        }
        ChecksumSpec::parse_header(algorithm.header_name(), value)
            .map(Some)
            .map_err(|_| invalid_part_checksum("a completed part checksum is malformed"))
    }

    pub(super) fn validate_completion_type(self, kind: Option<&dto::ChecksumType>) -> Result<(), HandlerError> {
        if kind.is_some_and(|kind| kind.as_str() != self.kind.wire_name()) {
            return Err(HandlerError::new(
                ErrorCode::BAD_DIGEST,
                "the completion checksum type differs from the initiated upload",
            ));
        }
        Ok(())
    }

    pub(super) fn complete(self, parts: &[ChecksumSpec], bytes: &[u8]) -> Result<ChecksumSpec, HandlerError> {
        match self.kind {
            ChecksumType::Composite => ChecksumSpec::composite_of(parts).map_err(|_| storage_error()),
            ChecksumType::FullObject => checksum_of(self.algorithm, bytes),
        }
    }

    pub(super) fn validate_completed_object(
        self,
        claimed: Option<ChecksumSpec>,
        actual: &ChecksumSpec,
    ) -> Result<(), HandlerError> {
        if claimed.is_some_and(|claimed| claimed.algorithm() != self.algorithm || claimed != *actual) {
            return Err(HandlerError::new(
                ErrorCode::BAD_DIGEST,
                "the completed object checksum did not match the assembled bytes",
            ));
        }
        Ok(())
    }
}

pub(super) fn validate_completion_part_number(
    checksum: Option<UploadChecksum>,
    previous: i32,
    number: i32,
) -> Result<(), HandlerError> {
    if number <= previous {
        return Err(HandlerError::new(
            ErrorCode::INVALID_PART_ORDER,
            "completed part numbers must be strictly increasing",
        ));
    }
    if checksum.is_some() && number != previous + 1 {
        return Err(HandlerError::new(
            ErrorCode::INVALID_PART_ORDER,
            "checksum upload parts must start at one and be strictly consecutive",
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct UploadRecord {
    pub(super) bucket: String,
    pub(super) key: String,
    pub(super) upload_id: Option<String>,
    pub(super) initiated: Option<i64>,
    pub(super) checksum: Option<UploadChecksum>,
    /// The user metadata and representation headers the initiating `CreateMultipartUpload` carried.
    ///
    /// Boxed because upload listing holds records beside bare common prefixes in one enum, and the
    /// attributes are read only once, at completion.
    pub(super) attributes: Box<ObjectAttributes>,
}

impl RecordedUpload for UploadRecord {
    fn bucket(&self) -> &str {
        &self.bucket
    }

    fn key(&self) -> &str {
        &self.key
    }
}

impl FsBackend {
    async fn allocate_upload_id(&self, bucket: &str) -> Result<String, HandlerError> {
        let _guard = self.upload_id_lock.lock().await;
        let uploads = self.uploads_path(bucket);
        initialize_upload_id_sequence(&uploads).map_err(|_| storage_error())?;
        let current = read_upload_id_sequence(&uploads).map_err(|_| storage_error())?;
        let next = current.checked_add(1).ok_or_else(storage_error)?;
        persist_upload_id_sequence(&uploads, next).map_err(|_| storage_error())?;
        Ok(format!("fs-v2-{current:016x}"))
    }

    pub(super) fn upload_directory_is_empty_for_delete(&self, bucket: &str) -> Result<bool, HandlerError> {
        let uploads = self.uploads_path(bucket);
        let entries = std::fs::read_dir(&uploads).map_err(|_| storage_error())?;
        for entry in entries {
            let entry = entry.map_err(|_| storage_error())?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Ok(false);
            };
            match name.as_str() {
                UPLOAD_ID_SEQUENCE => {
                    validate_upload_id_sequence_for_delete(&uploads).map_err(|_| storage_error())?;
                }
                UPLOAD_ID_SEQUENCE_TEMP => {
                    validate_upload_id_sequence_temp_for_delete(&uploads).map_err(|_| storage_error())?;
                }
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    pub(super) fn remove_upload_id_authority_for_delete(&self, bucket: &str) -> Result<(), HandlerError> {
        let uploads = self.uploads_path(bucket);
        let sequence_exists = validate_upload_id_sequence_for_delete(&uploads).map_err(|_| storage_error())?;
        let temporary_exists = validate_upload_id_sequence_temp_for_delete(&uploads).map_err(|_| storage_error())?;
        if temporary_exists {
            std::fs::remove_file(uploads.join(UPLOAD_ID_SEQUENCE_TEMP)).map_err(|_| storage_error())?;
        }
        if sequence_exists {
            std::fs::remove_file(uploads.join(UPLOAD_ID_SEQUENCE)).map_err(|_| storage_error())?;
        }
        Ok(())
    }

    fn decode_upload_record(&self, upload: &Path) -> Result<UploadRecord, HandlerError> {
        let upload_metadata = std::fs::symlink_metadata(upload).map_err(|_| storage_error())?;
        if !upload_metadata.is_dir() || upload_metadata.file_type().is_symlink() {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the multipart upload path is not a safe directory",
            ));
        }
        let parts = upload.join(PARTS_DIR);
        let parts_metadata = std::fs::symlink_metadata(parts).map_err(|_| storage_error())?;
        if !parts_metadata.is_dir() || parts_metadata.file_type().is_symlink() {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the multipart parts path is not a safe directory",
            ));
        }
        let record = upload.join(UPLOAD_RECORD);
        let record_metadata = std::fs::symlink_metadata(&record).map_err(|_| storage_error())?;
        if !record_metadata.is_file() || record_metadata.file_type().is_symlink() {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the multipart record path is not a safe regular file",
            ));
        }
        let encoded = std::fs::read_to_string(record).map_err(|_| storage_error())?;
        let mut lines = encoded.lines();
        let decode = |line: &str| {
            hex::decode(line)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or_else(storage_error)
        };
        let bucket = decode(lines.next().ok_or_else(storage_error)?)?;
        let key = decode(lines.next().ok_or_else(storage_error)?)?;
        let upload_id = lines.next().map(decode).transpose()?;
        let initiated = lines.next().map(str::parse::<i64>).transpose().map_err(|_| storage_error())?;
        let checksum = match (lines.next(), lines.next()) {
            (None, None) | (Some("-"), Some("-")) => None,
            (Some(algorithm), Some(kind)) => Some(UploadChecksum::decode(algorithm, kind)?),
            _ => return Err(storage_error()),
        };
        let (metadata, headers) = decode_trailing_sections(&mut lines)?;
        Ok(UploadRecord {
            bucket,
            key,
            upload_id,
            initiated,
            checksum,
            attributes: Box::new(ObjectAttributes {
                metadata,
                headers,
                ..ObjectAttributes::default()
            }),
        })
    }

    /// Records one upload's capability, its negotiated checksum, and its initiating metadata.
    ///
    /// # Errors
    ///
    /// The metadata refusals of [`validate_user_metadata`], applied before the directory exists so
    /// that an upload whose metadata could never be published is never initiated, and
    /// [`storage_error`] for a filesystem failure.
    pub(super) async fn create_upload(
        &self,
        bucket: &rustfs_gateway::BucketName,
        key: &rustfs_gateway::ObjectKey,
        checksum: Option<UploadChecksum>,
        attributes: &ObjectAttributes,
    ) -> Result<String, HandlerError> {
        validate_attributes(attributes)?;
        self.require_bucket(bucket.as_str()).await?;
        let uploads = self.uploads_path(bucket.as_str());
        let upload_id = self.allocate_upload_id(bucket.as_str()).await?;
        let destination = self.upload_path(bucket.as_str(), &upload_id);
        if tokio::fs::symlink_metadata(&destination).await.is_ok() {
            return Err(storage_error());
        }
        let temporary = uploads.join(format!(
            ".tmp-upload-{}-{}",
            std::process::id(),
            self.temporary_id.fetch_add(1, Ordering::Relaxed)
        ));
        tokio::fs::create_dir(&temporary).await.map_err(|_| storage_error())?;
        let initialized = async {
            tokio::fs::create_dir(temporary.join(PARTS_DIR)).await?;
            let (algorithm, kind) =
                checksum.map_or(("-", "-"), |checksum| (checksum.algorithm.wire_name(), checksum.kind.wire_name()));
            let record = format!(
                "{}\n{}\n{}\n{}\n{algorithm}\n{kind}\n{}",
                hex::encode(bucket.as_str()),
                hex::encode(key.as_str()),
                hex::encode(&upload_id),
                self.clock.now().unix_seconds(),
                encode_trailing_sections(attributes),
            );
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(temporary.join(UPLOAD_RECORD))
                .await?;
            file.write_all(record.as_bytes()).await?;
            file.sync_all().await?;
            tokio::fs::rename(&temporary, destination).await
        }
        .await;
        if initialized.is_err() {
            let _ = tokio::fs::remove_dir_all(&temporary).await;
            return Err(storage_error());
        }
        Ok(upload_id)
    }

    pub(super) fn read_upload_record(&self, bucket: &str, upload_id: &str) -> Option<UploadRecord> {
        self.decode_upload_record(&self.upload_path(bucket, upload_id)).ok()
    }

    pub(super) async fn active_upload_records(&self, bucket: &str) -> Result<Vec<UploadRecord>, HandlerError> {
        self.require_bucket(bucket).await?;
        let uploads_path = self.uploads_path(bucket);
        let mut entries = tokio::fs::read_dir(&uploads_path).await.map_err(|_| storage_error())?;
        let mut records = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| storage_error())? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { return Err(storage_error()) };
            if name.starts_with('.') {
                continue;
            }
            if !name.starts_with("u-") {
                return Err(storage_error());
            }
            let file_type = entry.file_type().await.map_err(|_| storage_error())?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the multipart upload path is not a safe directory",
                ));
            }
            let record = self.decode_upload_record(&entry.path())?;
            let upload_id = record.upload_id.as_deref().ok_or_else(storage_error)?;
            if record.initiated.is_none() || record.bucket != bucket || self.upload_path(bucket, upload_id) != entry.path() {
                return Err(storage_error());
            }
            records.push(record);
        }
        Ok(records)
    }
}

fn checksum_of(algorithm: ChecksumAlgorithm, bytes: &[u8]) -> Result<ChecksumSpec, HandlerError> {
    let mut checksummer = algorithm.checksummer();
    checksummer.update(bytes);
    ChecksumSpec::from_digest(algorithm, &checksummer.finalize()).map_err(|_| storage_error())
}

fn valid_combination(algorithm: ChecksumAlgorithm, kind: ChecksumType) -> bool {
    (kind != ChecksumType::FullObject || algorithm.is_crc())
        && (algorithm != ChecksumAlgorithm::Crc64Nvme || kind == ChecksumType::FullObject)
}

fn invalid_checksum(message: &'static str) -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_REQUEST, message)
}

fn invalid_part_checksum(message: &'static str) -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_PART, message)
}

/// Writes a completed upload's checksum into the one CompleteMultipartUpload member its algorithm
/// names.
///
/// An algorithm this table does not know is a storage error rather than a silently omitted
/// checksum: the record claimed one, and a response without it would tell the client none exists.
pub(super) fn render_completed_checksum(
    output: &mut dto::CompleteMultipartUploadOutput,
    checksum: ChecksumSpec,
) -> Result<(), HandlerError> {
    let slot = match checksum.algorithm() {
        ChecksumAlgorithm::Crc32 => &mut output.checksum_crc32,
        ChecksumAlgorithm::Crc32c => &mut output.checksum_crc32c,
        ChecksumAlgorithm::Crc64Nvme => &mut output.checksum_crc64nvme,
        ChecksumAlgorithm::Sha1 => &mut output.checksum_sha1,
        ChecksumAlgorithm::Sha256 => &mut output.checksum_sha256,
        ChecksumAlgorithm::Sha512 => &mut output.checksum_sha512,
        ChecksumAlgorithm::Md5 => &mut output.checksum_md5,
        ChecksumAlgorithm::XxHash64 => &mut output.checksum_xxhash64,
        ChecksumAlgorithm::XxHash3 => &mut output.checksum_xxhash3,
        ChecksumAlgorithm::XxHash128 => &mut output.checksum_xxhash128,
        _ => return Err(storage_error()),
    };
    *slot = Some(checksum.render_base64().to_owned());
    Ok(())
}
