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

//! Paging a bucket to exhaustion answers the same set, once each, whatever the page size.
//!
//! Responsible for: the set semantics of [`super::paginate`] under a generated bucket, prefix,
//! delimiter and page size — completeness, no duplicates, order, termination, and the one that
//! ties them together: *the answer does not depend on how it was cut into pages*.
//! NOT responsible for: what a continuation token is made of, which is [`crate::token`] and
//! `fuzz/fuzz_targets/opaque_token.rs`; or what one page costs, which is
//! [`super::list_allocations`].
//! Upstream: `proptest` and the parent module's private paging. Downstream: nothing — it asserts.
//!
//! # Why the page-size invariance is the property worth generating
//!
//! Every other property here can be satisfied by a listing that is wrong in the one way this
//! family is actually wrong in the field. A resumed page that skips an entry still returns entries
//! in order, still returns no duplicates, and still terminates; it simply returns fewer things than
//! the bucket holds, and no single response shows it. s3s#350 is that failure with the opposite
//! sign — a client that never stops asking — and it took two responses and a token to see.
//!
//! So the generator pages the same bucket at several page sizes and requires the concatenations to
//! be *identical*. One entry per page and the whole bucket in one page are two walks over the same
//! answer, and only an implementation whose resumption is exactly right makes them agree. The
//! parent module's own comment names the trap this catches: with a delimiter in play the marker has
//! to be compared against the emitted *entry* rather than against the key, or resuming after `b/`
//! drops one key instead of the whole folded group. Comparing against the key passes every
//! single-response assertion in the list corpus and is caught here on the first generated case.

use proptest::prelude::*;

use super::{Fixture, StoredObject, fold, paginate};

/// The alphabet keys are drawn from.
///
/// Deliberately tiny, and deliberately holding both delimiter candidates. Collisions are the point:
/// a large alphabet generates buckets in which almost nothing folds together and almost nothing
/// shares a prefix, so the interesting cases — a folded group straddling a page boundary, a key
/// that is itself a prefix of another, a key equal to the prefix — are the ones it never reaches.
const ALPHABET: &str = "ab/-";

/// The bucket every generated case is built in.
const BUCKET: &str = "conf-prop";

/// One page's worth of entries, as they are emitted: keys and folded prefixes in one sequence.
///
/// Merged rather than kept apart because that is the sequence a cursor resumes. Paging the two
/// lists independently is a defect this collapses onto immediately.
fn entries_of(page: &super::Page) -> Vec<(String, bool)> {
    let mut merged: Vec<(String, bool)> = page.keys.iter().map(|key| (key.clone(), false)).collect();
    merged.extend(page.common_prefixes.iter().map(|value| (value.clone(), true)));
    merged.sort();
    merged
}

/// Pages the bucket to exhaustion at `max` and returns every entry, in the order it was emitted.
///
/// The page count is bounded rather than trusted. A listing that answers the same page forever is
/// the s3s#350 failure, and the honest way to state "it terminates" in a test is a ceiling that is
/// unreachable for a correct implementation and reached immediately by that one.
fn walk(fixture: &Fixture, prefix: &str, delimiter: Option<&str>, max: i32) -> Vec<(String, bool)> {
    let ceiling = 4 * fixture.keys_in(BUCKET).len() + 8;
    let mut all: Vec<(String, bool)> = Vec::new();
    let mut after: Option<String> = None;
    for pages in 0..=ceiling {
        assert!(pages < ceiling, "the listing did not terminate at max-keys={max}");
        let page = paginate(fixture, BUCKET, prefix, delimiter, after.as_deref(), max);
        let emitted = entries_of(&page);

        // A page never exceeds what was asked for, and the truncation flag and the cursor are one
        // fact written twice: a truncated page with no cursor strands the client, and a cursor on
        // an untruncated page makes it ask for a page that does not exist.
        assert!(emitted.len() <= max.max(0) as usize, "a page overran max-keys={max}");
        assert_eq!(page.truncated, page.next.is_some(), "the truncation flag and the next cursor disagree");
        if let Some(next) = page.next.as_deref() {
            assert_eq!(
                emitted.last().map(|(value, _)| value.as_str()),
                Some(next),
                "the cursor is not the last entry the page emitted"
            );
        }

        all.extend(emitted);
        match page.next {
            Some(next) => after = Some(next),
            None => return all,
        }
    }
    unreachable!("the loop above returns or asserts")
}

/// What the bucket holds, computed independently of the pager.
///
/// Written from the rule — every live key under the prefix, folded on the delimiter, deduplicated —
/// rather than from `paginate`, so an implementation that is consistently wrong does not get to
/// define the expectation.
fn expected(fixture: &Fixture, prefix: &str, delimiter: Option<&str>) -> Vec<(String, bool)> {
    let mut all: Vec<(String, bool)> = fixture
        .keys_in(BUCKET)
        .into_iter()
        .filter(|key| key.starts_with(prefix))
        .map(|key| match fold(key, prefix, delimiter) {
            Some(folded) => (folded, true),
            None => (key.to_owned(), false),
        })
        .collect();
    all.sort();
    all.dedup();
    all
}

fn fixture_of(keys: &[String]) -> Fixture {
    let mut fixture = Fixture::at(0);
    fixture.declare_bucket(BUCKET, false);
    for key in keys {
        fixture.put_object(BUCKET, key, StoredObject::new(b"x".to_vec(), None, 0));
    }
    fixture
}

prop_compose! {
    /// A bucket of up to twelve keys over [`ALPHABET`], each one to five characters long.
    fn a_bucket()(keys in prop::collection::vec(
        prop::collection::vec(prop::sample::select(ALPHABET.chars().collect::<Vec<char>>()), 1..=5)
            .prop_map(|chars| chars.into_iter().collect::<String>()),
        0..=12,
    )) -> Vec<String> {
        keys
    }
}

/// A prefix drawn from the same alphabet, so it lands on real boundaries rather than beside them.
fn a_prefix() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(ALPHABET.chars().collect::<Vec<char>>()), 0..=2)
        .prop_map(|chars| chars.into_iter().collect())
}

/// The delimiters worth generating: absent, one byte, and a two-byte one, which is the case
/// `c-list-0038` exists for.
fn a_delimiter() -> impl Strategy<Value = Option<String>> {
    prop::option::of(prop::sample::select(vec!["/".to_owned(), "-".to_owned(), "//".to_owned()]))
}

proptest! {
    /// The answer is the whole answer, once each, in order — and it does not depend on the page
    /// size.
    ///
    /// Four assertions over one generated bucket, because they are four ways of being wrong about
    /// one walk and separating them into four tests would generate four unrelated buckets and
    /// still not pin the relationship between them.
    #[test]
    fn paging_to_exhaustion_answers_the_same_set_whatever_the_page_size(
        keys in a_bucket(),
        prefix in a_prefix(),
        delimiter in a_delimiter(),
    ) {
        let fixture = fixture_of(&keys);
        let delimiter = delimiter.as_deref().filter(|value| !value.is_empty());
        let expected = expected(&fixture, &prefix, delimiter);

        // One entry at a time is the walk with the most resumptions in it, so it is the one a
        // resumption defect shows up in first. It is also the reference every other page size is
        // compared against.
        let one_at_a_time = walk(&fixture, &prefix, delimiter, 1);

        prop_assert_eq!(&one_at_a_time, &expected, "paging one entry at a time did not answer the bucket");

        // Strictly ascending, which is both the order S3 lists in and the property that rules out
        // a duplicate without a second pass over the list.
        for window in one_at_a_time.windows(2) {
            prop_assert!(
                window[0].0 < window[1].0,
                "entries are not strictly ascending: {:?} then {:?}",
                window[0],
                window[1]
            );
        }

        // The property this file exists for. `20` is past the largest bucket the generator builds,
        // so it is the whole answer in one page and the far end of the range.
        for max in [2_i32, 3, 5, 20] {
            prop_assert_eq!(
                walk(&fixture, &prefix, delimiter, max),
                one_at_a_time.clone(),
                "max-keys={} answered a different set than max-keys=1",
                max
            );
        }
    }

    /// Negative — `max-keys=0` is a page of nothing that is *not* truncated.
    ///
    /// AWS answers `IsTruncated` false, and a server that reports truncation here sends a client
    /// after a page it will never be given. `c-list-0027` is the wire form; this is the same rule
    /// over every generated bucket, which is where it is easy to get wrong: the natural loop marks
    /// the page truncated the moment it sees an entry it cannot fit, and at zero it sees one
    /// immediately.
    #[test]
    fn a_page_of_zero_is_empty_and_is_not_truncated(
        keys in a_bucket(),
        prefix in a_prefix(),
        delimiter in a_delimiter(),
    ) {
        let fixture = fixture_of(&keys);
        let delimiter = delimiter.as_deref().filter(|value| !value.is_empty());
        let page = paginate(&fixture, BUCKET, &prefix, delimiter, None, 0);
        prop_assert!(page.keys.is_empty() && page.common_prefixes.is_empty());
        prop_assert!(!page.truncated, "a page of zero reported more to come");
        prop_assert_eq!(page.next, None);
    }

    /// Negative — a cursor is a position, not a filter: resuming from an entry never re-emits it,
    /// and never emits anything at or before it.
    ///
    /// The `<=` is the whole assertion. An implementation that resumes from `>= marker` repeats one
    /// entry per page, which a client sees as a listing that grows every time it is read.
    #[test]
    fn a_resumed_page_starts_strictly_after_the_cursor(
        keys in a_bucket(),
        prefix in a_prefix(),
        delimiter in a_delimiter(),
        max in 1_i32..=4,
    ) {
        let fixture = fixture_of(&keys);
        let delimiter = delimiter.as_deref().filter(|value| !value.is_empty());
        let first = paginate(&fixture, BUCKET, &prefix, delimiter, None, max);
        let Some(cursor) = first.next.clone() else {
            return Ok(());
        };
        let second = paginate(&fixture, BUCKET, &prefix, delimiter, Some(&cursor), max);
        for (value, _) in entries_of(&second) {
            prop_assert!(
                value > cursor,
                "resuming after {:?} emitted {:?}, which is not after it",
                cursor,
                value
            );
        }
    }
}
