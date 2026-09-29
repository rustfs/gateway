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

//! Every member of a versioning configuration kept, and MinIO's excluded prefixes and folders
//! applied as legacy RustFS applies them (rustfs/gateway#1078).
//!
//! Responsible for: the configuration reaching storage whole — `MfaDelete`, `ExcludeFolders` and
//! `ExcludedPrefixes` included, in legacy RustFS's persisted form — and surviving a restart; an
//! excluded key of an enabled bucket written as its null version and deleted without a marker; the
//! answer to GetBucketVersioning carrying the status alone, as legacy RustFS's does; a later
//! configuration without exclusions clearing them; and a corrupt configuration failing closed.
//! NOT responsible for: the wildcard match itself (`src/versioning/configuration_tests.rs`) or
//! versioning without exclusions (`versioning.rs`).
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use super::versioning::set_versioning;
use super::*;

const EXCLUDING: &str = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete><ExcludeFolders>true</ExcludeFolders><ExcludedPrefixes><Prefix>logs/</Prefix></ExcludedPrefixes><ExcludedPrefixes><Prefix>tmp*</Prefix></ExcludedPrefixes></VersioningConfiguration>";
const EXCLUDING_MD5: &str = "DN/O4UyIadzDITSN6vsBow==";
const SUSPENDED_EXCLUDING: &str = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Suspended</Status><ExcludedPrefixes><Prefix>logs/</Prefix></ExcludedPrefixes></VersioningConfiguration>";
const SUSPENDED_EXCLUDING_MD5: &str = "2Tib+X6N4jjx4elX14GhFw==";

async fn create_bucket(service: &S3Service, bucket: &str) {
    let created = exchange(service, signed(http::Method::PUT, &format!("/{bucket}"), Bytes::new())).await;
    assert_eq!(created.status(), 200);
}

async fn configure(service: &S3Service, bucket: &str, document: &'static str, md5: &str) {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("content-md5"),
        http::HeaderValue::from_str(md5).expect("a fixture checksum header"),
    );
    let response = exchange(
        service,
        signed_with_headers(
            http::Method::PUT,
            &format!("/{bucket}?versioning"),
            Bytes::from_static(document.as_bytes()),
            headers,
        ),
    )
    .await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
}

async fn put(service: &S3Service, bucket: &str, key: &str, body: &'static [u8]) -> rustfs_gateway::WireResponse {
    let response = exchange(service, signed(http::Method::PUT, &format!("/{bucket}/{key}"), Bytes::from_static(body))).await;
    assert_eq!(response.status(), 200, "{key}: {}", String::from_utf8_lossy(response.body()));
    response
}

async fn delete(service: &S3Service, bucket: &str, key: &str) -> rustfs_gateway::WireResponse {
    let response = exchange(service, signed(http::Method::DELETE, &format!("/{bucket}/{key}"), Bytes::new())).await;
    assert_eq!(response.status(), 204, "{key}");
    response
}

/// Every entry of the bucket's version census, as `(kind, key, version id)`.
async fn census(service: &S3Service, bucket: &str) -> Vec<(&'static str, String, String)> {
    let response = exchange(service, signed(http::Method::GET, &format!("/{bucket}?versions"), Bytes::new())).await;
    assert_eq!(response.status(), 200);
    let text = String::from_utf8_lossy(response.body()).into_owned();
    let mut entries = Vec::new();
    for (kind, open, close) in [
        ("version", "<Version>", "</Version>"),
        ("marker", "<DeleteMarker>", "</DeleteMarker>"),
    ] {
        for chunk in text.split(open).skip(1) {
            let entry = chunk.split(close).next().unwrap_or_default().as_bytes();
            entries.push((
                kind,
                element(entry, "Key").expect("an entry key"),
                element(entry, "VersionId").expect("an entry version"),
            ));
        }
    }
    entries.sort();
    entries
}

fn of_key<'a>(entries: &'a [(&'static str, String, String)], key: &str) -> Vec<&'a (&'static str, String, String)> {
    entries.iter().filter(|(_, held, _)| held == key).collect()
}

fn configuration_file(root: &TestRoot, bucket: &str) -> PathBuf {
    root.0
        .join(format!("b-{}", hex::encode(bucket)))
        .join("versioning-configuration")
}

/// Positive — under an enabled configuration that excludes `logs/`, `tmp*` and folders, an
/// excluded key keeps one null version however often it is written, and every other key is
/// versioned; the excluded write reports no version id.
#[tokio::test]
async fn an_excluded_key_is_written_as_its_null_version_and_every_other_key_versioned() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "excluding").await;
    configure(&service, "excluding", EXCLUDING, EXCLUDING_MD5).await;

    for key in ["logs/a", "tmpfile", "dir/", "data/a"] {
        let first = put(&service, "excluding", key, b"one").await;
        let second = put(&service, "excluding", key, b"two").await;
        let excluded = key != "data/a";
        for response in [&first, &second] {
            assert_eq!(header(response, "x-amz-version-id").is_none(), excluded, "{key}");
        }
    }

    let entries = census(&service, "excluding").await;
    for key in ["logs/a", "tmpfile", "dir/"] {
        assert_eq!(of_key(&entries, key), [&("version", key.to_owned(), "null".to_owned())], "{entries:?}");
    }
    let data = of_key(&entries, "data/a");
    assert_eq!(data.len(), 2, "{entries:?}");
    assert!(
        data.iter().all(|(kind, _, version)| *kind == "version" && version != "null"),
        "{entries:?}"
    );
    let read = exchange(&service, signed(http::Method::GET, "/excluding/logs/a", Bytes::new())).await;
    assert_eq!(read.body().as_ref(), b"two");
}

/// Negative — deleting an excluded key of an enabled bucket leaves no delete marker, as legacy
/// RustFS deletes it unversioned; deleting any other key leaves one.
#[tokio::test]
async fn n_deleting_an_excluded_key_leaves_no_delete_marker() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "deleting").await;
    configure(&service, "deleting", EXCLUDING, EXCLUDING_MD5).await;
    put(&service, "deleting", "logs/a", b"excluded").await;
    put(&service, "deleting", "data/a", b"versioned").await;

    let excluded = delete(&service, "deleting", "logs/a").await;
    assert!(header(&excluded, "x-amz-delete-marker").is_none());
    let versioned = delete(&service, "deleting", "data/a").await;
    assert_eq!(
        header(&versioned, "x-amz-delete-marker").and_then(|value| value.to_str().ok()),
        Some("true")
    );

    let entries = census(&service, "deleting").await;
    assert!(of_key(&entries, "logs/a").is_empty(), "{entries:?}");
    let data = of_key(&entries, "data/a");
    assert_eq!(data.iter().filter(|(kind, _, _)| *kind == "marker").count(), 1, "{entries:?}");
    assert_eq!(data.iter().filter(|(kind, _, _)| *kind == "version").count(), 1, "{entries:?}");
}

/// Positive — every member reaches storage in legacy RustFS's persisted form and reads back as
/// sent; GetBucketVersioning answers the status alone, as legacy RustFS's does; and the exclusions
/// still apply after a restart.
#[tokio::test]
async fn every_member_is_persisted_whole_and_survives_a_restart() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "persisted").await;
    configure(&running, "persisted", EXCLUDING, EXCLUDING_MD5).await;

    let stored = std::fs::read(configuration_file(&root, "persisted")).expect("the configuration reached storage");
    let expected = dto::VersioningConfiguration {
        status: Some(dto::Status::ENABLED),
        mfa_delete: Some(dto::MfaDelete::custom("Enabled")),
        exclude_folders: Some(true),
        excluded_prefixes: vec![
            dto::ExcludedPrefix {
                prefix: Some("logs/".to_owned()),
            },
            dto::ExcludedPrefix {
                prefix: Some("tmp*".to_owned()),
            },
        ],
    };
    assert_eq!(stored, rustfs_gateway::persistence::serialize_versioning_dto(&expected));
    let read_back = rustfs_gateway::persistence::parse_versioning_dto(&stored).expect("the stored configuration reads back");
    assert_eq!(read_back.status.as_ref().map(dto::Status::as_str), Some("Enabled"));
    assert_eq!(read_back.mfa_delete.as_ref().map(dto::MfaDelete::as_str), Some("Enabled"));
    assert_eq!(read_back.exclude_folders, Some(true));
    let prefixes: Vec<Option<&str>> = read_back
        .excluded_prefixes
        .iter()
        .map(|entry| entry.prefix.as_deref())
        .collect();
    assert_eq!(prefixes, [Some("logs/"), Some("tmp*")]);

    let answered = exchange(&running, signed(http::Method::GET, "/persisted?versioning", Bytes::new())).await;
    let text = String::from_utf8_lossy(answered.body()).into_owned();
    assert!(text.contains("<Status>Enabled</Status>"), "{text}");
    for absent in ["MfaDelete", "ExcludeFolders", "ExcludedPrefixes"] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }

    drop(running);
    let (_, reopened) = service(&root);
    put(&reopened, "persisted", "logs/b", b"one").await;
    put(&reopened, "persisted", "logs/b", b"two").await;
    let entries = census(&reopened, "persisted").await;
    assert_eq!(
        of_key(&entries, "logs/b"),
        [&("version", "logs/b".to_owned(), "null".to_owned())],
        "{entries:?}"
    );
}

/// Negative — a later configuration without exclusions clears them: the key is versioned again.
#[tokio::test]
async fn n_a_configuration_without_exclusions_clears_them() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "cleared").await;
    configure(&service, "cleared", EXCLUDING, EXCLUDING_MD5).await;
    assert_eq!(set_versioning(&service, "cleared", "Enabled").await.status(), 200);

    put(&service, "cleared", "logs/a", b"one").await;
    put(&service, "cleared", "logs/a", b"two").await;
    let entries = census(&service, "cleared").await;
    let logs = of_key(&entries, "logs/a");
    assert_eq!(logs.len(), 2, "{entries:?}");
    assert!(logs.iter().all(|(_, _, version)| version != "null"), "{entries:?}");
}

/// Negative — a suspended bucket's exclusions change nothing: every key is its null version.
#[tokio::test]
async fn n_a_suspended_bucket_writes_every_key_as_its_null_version() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "suspended").await;
    configure(&service, "suspended", SUSPENDED_EXCLUDING, SUSPENDED_EXCLUDING_MD5).await;
    for key in ["logs/a", "data/a"] {
        put(&service, "suspended", key, b"one").await;
        put(&service, "suspended", key, b"two").await;
    }
    let entries = census(&service, "suspended").await;
    for key in ["logs/a", "data/a"] {
        assert_eq!(of_key(&entries, key), [&("version", key.to_owned(), "null".to_owned())], "{entries:?}");
    }
}

/// Negative — a configuration this backend cannot read fails every write and delete closed rather
/// than versioning a key the stored configuration may exclude.
#[tokio::test]
async fn n_a_corrupt_versioning_configuration_fails_closed() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "corrupt-members").await;
    configure(&service, "corrupt-members", EXCLUDING, EXCLUDING_MD5).await;
    std::fs::write(configuration_file(&root, "corrupt-members"), b"<Broken").expect("the fixture is corruptible");

    let written = exchange(
        &service,
        signed(http::Method::PUT, "/corrupt-members/logs/a", Bytes::from_static(b"must-not-publish")),
    )
    .await;
    assert_eq!(written.status(), 500);
    let deleted = exchange(&service, signed(http::Method::DELETE, "/corrupt-members/logs/a", Bytes::new())).await;
    assert_eq!(deleted.status(), 500);
    assert!(census(&service, "corrupt-members").await.is_empty());
}

/// Positive — a bucket whose versioning configuration was written deletes whole once its versions
/// are gone, the configuration with it.
#[tokio::test]
async fn a_bucket_with_a_versioning_configuration_is_deleted_whole() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "removed").await;
    configure(&service, "removed", EXCLUDING, EXCLUDING_MD5).await;
    put(&service, "removed", "logs/a", b"excluded").await;
    delete(&service, "removed", "logs/a").await;
    assert!(configuration_file(&root, "removed").exists());

    let deleted = exchange(&service, signed(http::Method::DELETE, "/removed", Bytes::new())).await;
    assert_eq!(deleted.status(), 204, "{}", String::from_utf8_lossy(deleted.body()));
    assert!(!configuration_file(&root, "removed").exists());
    assert!(!root.0.join(format!("b-{}", hex::encode("removed"))).exists());
}
