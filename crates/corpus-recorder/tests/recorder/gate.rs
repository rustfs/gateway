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

//! Responsible for: the runtime line of defence — a recorder is never constructed unless
//! recording was asked for with `RUSTFS_CORPUS_RECORD=1` and every configured access key is a
//! test credential (a-cp-0010, a-cp-0011).
//! Not responsible for: what a constructed recorder writes (`capture`, `signed_chunks`).
//! Upstream: `CorpusRecorderLayer::new_checked_with_env`.
//! Downstream: nothing.

use rustfs_gateway_corpus_recorder::{CorpusRecorderLayer, RECORD_ENV, RecorderRefused};

use crate::support::{TEST_KEY, config, enabled};

fn env_with(value: &'static str) -> impl Fn(&str) -> Option<String> {
    move |name| (name == RECORD_ENV).then(|| value.to_owned())
}

/// Negative (a-cp-0010) — compiled in, but the variable is unset: the recorder refuses, and it
/// refuses before it creates the output file.
#[test]
fn n_an_unset_record_variable_refuses_startup() {
    let config = config("gate-unset");
    let output = config.output.clone();
    let refused = CorpusRecorderLayer::new_checked_with_env(config, |_| None).expect_err("must refuse");
    assert!(matches!(refused, RecorderRefused::NotEnabled), "{refused}");
    assert!(refused.to_string().contains(RECORD_ENV), "{refused}");
    assert!(!output.exists(), "a refused recorder must not touch the output path");
}

/// Negative — only the exact value `1` opts in; every near miss is a refusal.
#[test]
fn n_a_record_variable_other_than_one_refuses_startup() {
    for value in ["0", "true", "yes", " 1", "1 ", "01", ""] {
        let refused =
            CorpusRecorderLayer::new_checked_with_env(config("gate-value"), env_with(value)).expect_err("only `1` opts in");
        assert!(matches!(refused, RecorderRefused::NotEnabled), "{value:?}: {refused}");
    }
}

/// Negative (a-cp-0011) — the variable is set but the configured credential is RustFS's shipped
/// default, which is what a real deployment still on its default looks like.
#[test]
fn n_the_shipped_default_credential_refuses_startup() {
    let mut config = config("gate-default-key");
    config.access_keys = vec!["rustfsadmin".to_owned()];
    let refused = CorpusRecorderLayer::new_checked_with_env(config, enabled).expect_err("must refuse");
    assert!(matches!(refused, RecorderRefused::CredentialNotAllowlisted { position: 0 }), "{refused}");
    assert!(
        !refused.to_string().contains("rustfsadmin"),
        "the refusal must not repeat the key: {refused}"
    );
}

/// Negative (a-cp-0011) — one production key among test keys is enough to refuse.
#[test]
fn n_one_real_credential_among_test_ones_refuses_startup() {
    let mut config = config("gate-mixed-keys");
    config.access_keys = vec![TEST_KEY.to_owned(), "AKIAREALPRODUCTIONKEY".to_owned()];
    let refused = CorpusRecorderLayer::new_checked_with_env(config, enabled).expect_err("must refuse");
    assert!(matches!(refused, RecorderRefused::CredentialNotAllowlisted { position: 1 }), "{refused}");
}

/// Negative — no configured credential proves nothing, so it is a refusal rather than a pass.
#[test]
fn n_no_configured_credential_refuses_startup() {
    let mut config = config("gate-no-keys");
    config.access_keys.clear();
    let refused = CorpusRecorderLayer::new_checked_with_env(config, enabled).expect_err("must refuse");
    assert!(matches!(refused, RecorderRefused::NoAccessKeys), "{refused}");
}

/// Negative (a-cp-0016 at the recorder) — a production provenance source refuses startup, instead
/// of every entry being refused later at ingest.
#[test]
fn n_a_production_source_refuses_startup() {
    let mut config = config("gate-source");
    config.src = "production".to_owned();
    let refused = CorpusRecorderLayer::new_checked_with_env(config, enabled).expect_err("must refuse");
    assert!(matches!(refused, RecorderRefused::UnknownSource(_)), "{refused}");
}

/// Negative — a zero cap would record nothing while claiming to record.
#[test]
fn n_a_zero_cap_refuses_startup() {
    let mut config = config("gate-zero-cap");
    config.max_body_bytes = 0;
    let refused = CorpusRecorderLayer::new_checked_with_env(config, enabled).expect_err("must refuse");
    assert!(matches!(refused, RecorderRefused::ZeroCap("max_body_bytes")), "{refused}");
}

/// Positive — the variable set to `1` and a test credential construct a recorder, which creates
/// its output file.
#[test]
fn an_enabled_recorder_over_test_credentials_starts() {
    let config = config("gate-ok");
    let output = config.output.clone();
    let layer = CorpusRecorderLayer::new_checked_with_env(config, enabled).expect("must start");
    assert!(output.exists());
    assert_eq!(layer.stats().recorded, 0);
}
