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

//! Persisted XML exported by the RustFS release/candidate byte parity test.
//!
//! Responsible for: verifying the exact thirteen on-disk samples through the rollback codecs.
//! NOT responsible for: running the two RustFS servers or comparing non-XML storage metadata.
//! Upstream: RustFS e2e_test::persistence_parity. Downstream: four-way and corpus-report.

use crate::{ConfigKind, FamilyCorpusEvidence, GoldenFailure, SampleOrigin};

const WRITER_REVISION: &str = "868af666e9c393b182bc7b68f01b8e3c1fa8aa13";

struct Export {
    path: &'static str,
    bytes: &'static [u8],
    sha256: &'static str,
}

fn export(kind: ConfigKind) -> Export {
    macro_rules! raw {
        ($file:literal, $sha:literal) => {
            Export {
                path: concat!("crates/goldens/corpus/rustfs-persistence-parity/", $file),
                bytes: include_bytes!(concat!("../corpus/rustfs-persistence-parity/", $file)),
                sha256: $sha,
            }
        };
    }
    match kind {
        ConfigKind::Accelerate => raw!("accelerate.xml", "c4b4d348ce048b627ab1dc9df2654647d8182e11ee74fbeded579e2f77c7c4bc"),
        ConfigKind::Cors => raw!("cors.xml", "72bb998b5ce16ff5618cff6cb790c0b8b8562e4c3ca832cd1ee6a4c15208b371"),
        ConfigKind::BucketEncryption => {
            raw!("encryption.xml", "cb55d1d74144c5f9f50b3e22a249af0ddd47788c96474b0c341770f1e2d28419")
        }
        ConfigKind::Lifecycle => raw!("lifecycle.xml", "75666f5bd1616e723578796cf4be4850c7d30100660934422f77ec2be9bf69d7"),
        ConfigKind::Logging => raw!("logging.xml", "413da4a070d75269814adf306057f6f1933fa1548b9cf930338fdec785d0ebed"),
        ConfigKind::Notification => raw!("notification.xml", "71c4e1fe89d8284e4114b6bfb78a8aed2be71f205967639ece3c10771a73d42f"),
        ConfigKind::ObjectLock => raw!("object_lock.xml", "5ff645b9052ea9333a1e6c7d2831728a9091995a75302dfb9b8cbbdc57ce5a24"),
        ConfigKind::PublicAccessBlock => raw!(
            "public_access_block.xml",
            "17a660afaf61e74d7070b00c6740aeb03ed7adf984ff4e9bce23241c423e6acc"
        ),
        ConfigKind::Replication => raw!("replication.xml", "ca769b53104417ca9ca9bc51f20351681025e3053eab9f458b27f7d7c1733a22"),
        ConfigKind::RequestPayment => {
            raw!("request_payment.xml", "fb15ebb09965945c36b53b2b296014788f9a628cd9229a9223a73b2389ecc071")
        }
        ConfigKind::Tagging => raw!("tagging.xml", "63c4fdd805a4dfcd9927af204f2d5fb8eb6d14c3984b893e534ec2caf8af4fe9"),
        ConfigKind::Versioning => raw!("versioning.xml", "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a"),
        ConfigKind::Website => raw!("website.xml", "8a306ddb346e1640f476865fe3ad1246f441e8a07dab4fdf2353274536c5079a"),
    }
}

pub(crate) fn observe(kind: ConfigKind, families: &mut [FamilyCorpusEvidence]) -> Result<bool, GoldenFailure> {
    let export = export(kind);
    let origin = SampleOrigin {
        source: export.path.to_owned(),
        producer: "rustfs".to_owned(),
        version: WRITER_REVISION.to_owned(),
        sha256: export.sha256.to_owned(),
    };
    crate::captured_xml::observe(
        kind,
        export.bytes,
        origin,
        "Raw XML from a candidate bucket metadata file, byte-equal to RustFS 1.0.5.".to_owned(),
        families,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_candidate_bytes_reach_the_aggregate_corpus() {
        let families = crate::all_family_corpus_evidence().expect("valid corpus");
        for kind in ConfigKind::ALL {
            let Export {
                path: file,
                sha256: digest,
                ..
            } = export(kind);
            assert!(
                families
                    .iter()
                    .filter(|family| family.kind() == kind)
                    .flat_map(|family| family.source_a_registrations())
                    .any(|(_, sha, accepted)| accepted && sha == digest),
                "missing {file}"
            );
        }
    }

    #[test]
    fn changed_persisted_bytes_fail_even_after_the_original_is_registered() {
        let kind = ConfigKind::Versioning;
        let Export { path, bytes, sha256 } = export(kind);
        let mut families = crate::all_family_corpus_evidence().expect("valid corpus");
        let mut changed = bytes.to_vec();
        changed.push(b' ');
        let origin = SampleOrigin {
            source: path.to_owned(),
            producer: "rustfs".to_owned(),
            version: WRITER_REVISION.to_owned(),
            sha256: sha256.to_owned(),
        };
        let failure = crate::captured_xml::observe(kind, &changed, origin, "Changed XML bytes".to_owned(), &mut families)
            .expect_err("an existing digest cannot mask changed XML bytes");
        assert_eq!(failure.direction, crate::Direction::Input);
        assert_eq!(failure.left, sha256);
    }
}
