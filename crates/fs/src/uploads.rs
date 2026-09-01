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
//! Responsible for: decoding one upload record, validating its filesystem components, and
//! enumerating the active upload set without following symbolic links.
//! NOT responsible for: pagination, delimiter rollup, part bodies, completion, or lifecycle.
//! Upstream: upload initiation and retirement handlers. Downstream: upload capability resolution
//! and `ListMultipartUploads`.

use std::path::Path;

use rustfs_gateway::{ErrorCode, HandlerError, RecordedUpload};

use super::{FsBackend, PARTS_DIR, UPLOAD_RECORD, storage_error};

#[derive(Clone)]
pub(super) struct UploadRecord {
    pub(super) bucket: String,
    pub(super) key: String,
    pub(super) upload_id: Option<String>,
    pub(super) initiated: Option<i64>,
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
        if lines.next().is_some() {
            return Err(storage_error());
        }
        Ok(UploadRecord {
            bucket,
            key,
            upload_id,
            initiated,
        })
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
