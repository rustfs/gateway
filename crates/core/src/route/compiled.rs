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

//! The same route table, arranged so that the common request is an array index.
//!
//! Responsible for: [`CompiledRouter`] — a `method × target` array of buckets, each holding a
//! precedence-ordered list of mask rules, and a precomputed answer for the no-subresource case.
//! NOT responsible for: routing *semantics*. Every answer this file gives must equal the answer
//! [`RouteTable::resolve`](super::RouteTable::resolve) gives, and the readable implementation is
//! kept for exactly that reason.
//! Upstream: `mask`, `selector`, `table`. Downstream: `crate::dispatch`.
//!
//! # What this buys, and what it costs
//!
//! The readable table is a linear scan with a predicate evaluation per entry. It is correct, and
//! it drags `GET /bucket/key` — the overwhelming majority of data-plane traffic, and a request
//! with no query keys the table routes on at all — through every subresource selector on the way
//! to the object band.
//!
//! Here, a request is placed into one of `8 × 3` buckets by method and target, its query is
//! reduced to a `u64` in the same pass that reads it, and a zero mask answers from
//! [`RouteBucket::default`] with no comparisons at all. A non-zero mask falls into the bucket's
//! rules, which are the same entries in the same order, filtered by two bitwise tests before any
//! predicate runs.
//!
//! The cost is a second implementation of a security-relevant decision. Three things pay for it:
//! the readable implementation is not deleted, `tests/hot_path.rs` runs both over every route case,
//! and a property test generates requests looking for one they answer differently. A fourth would
//! be a fuzz target, which this task cannot add (`fuzz/` is outside its file scope).
//!
//! # The fast path is only taken when it is provably right
//!
//! The shortcut answers one context and one only: **zero mask, standard endpoint, no ARN** — what
//! `GET /bucket/key`, `PUT /bucket/key`, `HEAD` and `DELETE` look like. Compiling a bucket walks
//! its rules in precedence order and *skips* the ones that cannot match that context (they need a
//! query bit, a different endpoint family, or an ARN). The first rule that survives decides: with
//! no residual predicates it always matches, so it becomes the shortcut; with any residual
//! predicate — a header test, a path literal, a query value — the outcome depends on the request
//! and no shortcut is installed for that bucket at all.
//!
//! Two consequences worth stating, because they are what makes the shortcut sound rather than
//! merely fast. An access-point entry sitting ahead of `GetObject` does not cost every plain
//! object read its fast path, because "needs an ARN" is decidable at compile time. And `POST
//! /bucket` keeps no shortcut at all, because whether it is a form upload depends on a header —
//! which is exactly the answer the naive shortcut would have got wrong.

use http::Method;

use super::mask::{CompileError, SubresourceBits};
use super::selector::{ArnForm, HostClass, Predicate, RouteEntry, RouteRequestParts, TargetKind};
use super::table::RouteTable;

/// An entry's position in the route table it was compiled from.
pub type OpId = u16;

/// How many methods the compiled table indexes.
const METHODS: usize = 8;
/// How many target kinds the compiled table indexes.
const TARGETS: usize = 3;

/// One `method × target` cell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteBucket {
    /// The answer when the subresource mask is zero, when that answer is decidable in advance.
    default: Option<OpId>,
    /// Where this bucket's rules start in the shared rule list.
    start: u16,
    /// How many rules it has.
    len: u16,
}

// A bucket is copied out of the array on every request; keeping it pointer-sized-ish is the
// difference between an index and a memcpy. Growing it is a decision, so it fails the build.
const _: () = assert!(size_of::<RouteBucket>() <= 64);

impl RouteBucket {
    /// The precomputed answer for a request with no routing query keys, if there is one.
    #[must_use]
    pub const fn default_op(&self) -> Option<OpId> {
        self.default
    }

    /// How many rules this bucket holds.
    #[must_use]
    pub const fn rule_count(&self) -> u16 {
        self.len
    }
}

/// One entry, arranged for bitwise pre-filtering.
///
/// The host class and the ARN form are lifted out of the residual predicate list and into two
/// `Option` fields. They are `Copy` scalars the request already carries, so testing them is an
/// integer comparison — and, more to the point, it lets the empty-mask shortcut *skip* an entry
/// that needs an Object Lambda endpoint or an access-point ARN instead of giving up on the whole
/// bucket. Without that, one access-point entry ahead of `GetObject` costs every plain object read
/// the fast path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rule {
    /// Bits that must all be present in the request mask.
    required_mask: u64,
    /// Bits that must all be absent from it.
    forbidden_mask: u64,
    /// The endpoint family this entry requires, if it requires one.
    host_class: Option<HostClass>,
    /// The ARN form this entry requires, if it requires one.
    arn_form: Option<ArnForm>,
    /// Where this rule's residual predicates start in the shared predicate list.
    extra_start: u16,
    /// How many it has. Zero for every plain subresource operation.
    extra_len: u16,
    /// The entry this rule selects.
    op: OpId,
}

const _: () = assert!(size_of::<Rule>() <= 32);

/// The route table compiled for lookup.
#[derive(Clone, Debug)]
pub struct CompiledRouter {
    buckets: [[RouteBucket; TARGETS]; METHODS],
    rules: Box<[Rule]>,
    extra: Box<[Predicate]>,
    bits: SubresourceBits,
    op_names: Box<[&'static str]>,
}

/// The index a method occupies, or `None` for a method no entry routes on.
fn method_index(method: &Method) -> Option<usize> {
    match *method {
        Method::GET => Some(0),
        Method::PUT => Some(1),
        Method::POST => Some(2),
        Method::DELETE => Some(3),
        Method::HEAD => Some(4),
        Method::OPTIONS => Some(5),
        _ => None,
    }
}

/// The index a target kind occupies.
const fn target_index(target: TargetKind) -> usize {
    match target {
        TargetKind::Service => 0,
        TargetKind::Bucket => 1,
        TargetKind::Object => 2,
    }
}

/// What an entry says about the two dimensions the array is indexed by, plus its masks.
struct Compiled {
    methods: Vec<usize>,
    targets: Vec<usize>,
    required_mask: u64,
    forbidden_mask: u64,
    host_class: Option<HostClass>,
    arn_form: Option<ArnForm>,
    extra: Vec<Predicate>,
}

/// Splits one entry into the bitwise part and the residue.
fn compile_entry(entry: &RouteEntry, bits: &SubresourceBits) -> Result<Compiled, CompileError> {
    let mut methods: Option<usize> = None;
    let mut targets: Option<usize> = None;
    let mut required_mask = 0u64;
    let mut forbidden_mask = 0u64;
    let mut host_class = None;
    let mut arn_form = None;
    let mut extra = Vec::new();

    for predicate in entry.selector.predicates() {
        match *predicate {
            Predicate::Method(ref method) => {
                let index = method_index(method).ok_or_else(|| CompileError::UnroutableMethod {
                    op_name: entry.op_name,
                    method: method.to_string(),
                })?;
                methods = Some(index);
            }
            Predicate::Target(target) => targets = Some(target_index(target)),
            Predicate::QueryPresent(key) => {
                let mask = bits.mask_for(key);
                if mask == 0 {
                    extra.push(predicate.clone());
                } else {
                    required_mask |= mask;
                }
            }
            Predicate::QueryAbsent(key) => {
                let mask = bits.mask_for(key);
                if mask == 0 {
                    extra.push(predicate.clone());
                } else {
                    forbidden_mask |= mask;
                }
            }
            Predicate::QueryEquals(key, _) => {
                // The bit says the key is there; only a predicate can say what its value is.
                let mask = bits.mask_for(key);
                if mask != 0 {
                    required_mask |= mask;
                }
                extra.push(predicate.clone());
            }
            Predicate::HostClass(class) => host_class = Some(class),
            Predicate::ArnForm(form) => arn_form = Some(form),
            _ => extra.push(predicate.clone()),
        }
    }

    Ok(Compiled {
        // An entry with no method predicate matches every method, so it belongs in every bucket.
        methods: methods.map_or_else(|| (0..METHODS).collect(), |index| vec![index]),
        targets: targets.map_or_else(|| (0..TARGETS).collect(), |index| vec![index]),
        required_mask,
        forbidden_mask,
        host_class,
        arn_form,
        extra,
    })
}

impl CompiledRouter {
    /// Compiles a built table.
    ///
    /// Runs once, at startup. A failure here is a startup failure: there is deliberately no
    /// runtime fallback to the readable implementation, because a fallback is a second code path
    /// that only executes in the situation nobody tested.
    ///
    /// # Errors
    ///
    /// [`CompileError`] — too many routing query keys for the mask, a method the array does not
    /// index, or more entries than an [`OpId`] can address.
    pub fn compile(table: &RouteTable) -> Result<Self, CompileError> {
        let entries = table.entries();
        if u16::try_from(entries.len()).is_err() {
            return Err(CompileError::TooManyEntries { count: entries.len() });
        }
        let bits = SubresourceBits::derive(entries)?;

        // Per bucket, the rules in table order — which is precedence order, so first match is
        // preserved without sorting anything a second time.
        let mut per_bucket: Vec<Vec<Rule>> = vec![Vec::new(); METHODS.saturating_mul(TARGETS)];
        let mut extra_pool: Vec<Predicate> = Vec::new();

        for (index, entry) in entries.iter().enumerate() {
            let compiled = compile_entry(entry, &bits)?;
            let extra_start =
                u16::try_from(extra_pool.len()).map_err(|_| CompileError::TooManyEntries { count: entries.len() })?;
            let extra_len =
                u16::try_from(compiled.extra.len()).map_err(|_| CompileError::TooManyEntries { count: entries.len() })?;
            extra_pool.extend(compiled.extra.iter().cloned());
            let op = u16::try_from(index).map_err(|_| CompileError::TooManyEntries { count: entries.len() })?;
            let rule = Rule {
                required_mask: compiled.required_mask,
                forbidden_mask: compiled.forbidden_mask,
                host_class: compiled.host_class,
                arn_form: compiled.arn_form,
                extra_start,
                extra_len,
                op,
            };
            for method in &compiled.methods {
                for target in &compiled.targets {
                    let slot = method.saturating_mul(TARGETS).saturating_add(*target);
                    if let Some(rules) = per_bucket.get_mut(slot) {
                        rules.push(rule);
                    }
                }
            }
        }

        let mut rules: Vec<Rule> = Vec::new();
        let mut buckets = [[RouteBucket::default(); TARGETS]; METHODS];
        for method in 0..METHODS {
            for target in 0..TARGETS {
                let slot = method.saturating_mul(TARGETS).saturating_add(target);
                let Some(bucket_rules) = per_bucket.get(slot) else {
                    continue;
                };
                let start = u16::try_from(rules.len()).map_err(|_| CompileError::TooManyEntries { count: entries.len() })?;
                let len = u16::try_from(bucket_rules.len()).map_err(|_| CompileError::TooManyEntries { count: entries.len() })?;
                let default = empty_mask_answer(bucket_rules);
                rules.extend(bucket_rules.iter().copied());
                if let Some(row) = buckets.get_mut(method)
                    && let Some(cell) = row.get_mut(target)
                {
                    *cell = RouteBucket { default, start, len };
                }
            }
        }

        Ok(Self {
            buckets,
            rules: rules.into_boxed_slice(),
            extra: extra_pool.into_boxed_slice(),
            bits,
            op_names: entries.iter().map(|entry| entry.op_name).collect(),
        })
    }

    /// The bit assignment this router was compiled with.
    #[must_use]
    pub fn bits(&self) -> &SubresourceBits {
        &self.bits
    }

    /// The bucket a method and target land in, for tests and explanations.
    #[must_use]
    pub fn bucket(&self, method: &Method, target: TargetKind) -> Option<RouteBucket> {
        let row = self.buckets.get(method_index(method)?)?;
        row.get(target_index(target)).copied()
    }

    /// The operation an id names.
    #[must_use]
    pub fn op_name(&self, op: OpId) -> Option<&'static str> {
        self.op_names.get(usize::from(op)).copied()
    }

    /// The entry a request selects, by table index.
    ///
    /// Equal to [`RouteTable::resolve`](super::RouteTable::resolve) on every request. Not `async`,
    /// holds nothing, allocates nothing.
    #[must_use]
    pub fn resolve(&self, request: &RouteRequestParts<'_>) -> Option<OpId> {
        self.resolve_counted(request).0
    }

    /// [`CompiledRouter::resolve`], also reporting how many predicates it had to evaluate.
    ///
    /// The count is the hot-path assertion: `GET /bucket/key` must answer with zero. A number that
    /// grows with the size of the table means the fast path was not taken, and
    /// `tests/hot_path.rs` says so.
    #[must_use]
    pub fn resolve_counted(&self, request: &RouteRequestParts<'_>) -> (Option<OpId>, usize) {
        let Some(index) = method_index(request.method) else {
            return (None, 0);
        };
        let Some(bucket) = self.buckets.get(index).and_then(|row| row.get(target_index(request.target))) else {
            return (None, 0);
        };
        let mask = self.bits.restrict(request.query.subresource_mask());
        // The canonical hot context: no routing query key, the ordinary endpoint, no ARN. That is
        // what `GET /bucket/key` and its siblings look like, and `empty_mask_answer` precomputed
        // the answer for exactly it.
        if mask == 0
            && request.host_class == HostClass::Standard
            && request.arn_form.is_none()
            && let Some(op) = bucket.default
        {
            return (Some(op), 0);
        }

        let start = usize::from(bucket.start);
        let end = start.saturating_add(usize::from(bucket.len));
        let Some(rules) = self.rules.get(start..end) else {
            return (None, 0);
        };
        let mut evaluations = 0usize;
        for rule in rules {
            if rule.required_mask & !mask != 0 || rule.forbidden_mask & mask != 0 {
                continue;
            }
            if let Some(class) = rule.host_class {
                evaluations = evaluations.saturating_add(1);
                if request.host_class != class {
                    continue;
                }
            }
            if let Some(form) = rule.arn_form {
                evaluations = evaluations.saturating_add(1);
                if request.arn_form != Some(form) {
                    continue;
                }
            }
            let extra_start = usize::from(rule.extra_start);
            let extra_end = extra_start.saturating_add(usize::from(rule.extra_len));
            let Some(extra) = self.extra.get(extra_start..extra_end) else {
                continue;
            };
            let mut matched = true;
            for predicate in extra {
                evaluations = evaluations.saturating_add(1);
                if !predicate.matches(request) {
                    matched = false;
                    break;
                }
            }
            if matched {
                return (Some(rule.op), evaluations);
            }
        }
        (None, evaluations)
    }
}

/// The answer for the canonical hot context: zero mask, standard endpoint, no ARN.
///
/// Walks the bucket in precedence order and skips every rule that provably cannot match it — one
/// needing a query bit, a non-standard endpoint, or an ARN. The first rule that survives decides:
/// with no residual predicates it always matches this context, so it is the answer; with residual
/// predicates the outcome depends on the request and no shortcut is installed.
fn empty_mask_answer(rules: &[Rule]) -> Option<OpId> {
    for rule in rules {
        if rule.required_mask != 0 {
            continue;
        }
        if rule.host_class.is_some_and(|class| class != HostClass::Standard) {
            continue;
        }
        if rule.arn_form.is_some() {
            continue;
        }
        if rule.extra_len != 0 {
            return None;
        }
        return Some(rule.op);
    }
    None
}
