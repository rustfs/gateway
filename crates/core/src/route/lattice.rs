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

//! Whether two selectors can be satisfied by one request — decided, not guessed.
//!
//! Responsible for: normalising a [`RouteSelector`] into a constraint record over independent
//! dimensions, computing the meet of two records, producing a witness request from a non-empty
//! meet, and deciding refinement (one selector accepting a subset of another's requests).
//! NOT responsible for: what to do about an overlap — same-precedence overlaps are conflicts and
//! cross-precedence ones are shadowing, and both decisions live in `table`.
//! Upstream: `selector`, `shape`. Downstream: `table`, `explain`.
//!
//! # Why equality comparison is not a check
//!
//! The obvious "detect ambiguity" implementation compares selectors pairwise for equality, or for
//! sharing a query key. It reports nothing about the pair that actually breaks:
//!
//! ```text
//! GET + Bucket + QueryPresent("acl")     — not equal to —     GET + Bucket
//! ```
//!
//! The second selector matches every `GET` on a bucket, including every request the first one
//! matches. They are not equal, they share no query key, and one of them is dead. The same shape
//! is what makes `?analytics` with and without `id` a routing defect in practice.
//!
//! So the question asked here is **satisfiability**: does a request exist that both selectors
//! accept? A selector is a conjunction of constraints over dimensions that do not interact —
//! method, target, host class, ARN form, path literal, one three-state constraint per query key,
//! one three-state constraint per header name. Two selectors overlap exactly when every dimension's
//! constraints have a common solution, which is a meet in the obvious lattice and is decidable in
//! time linear in the number of predicates. The meet is then *materialised into a request* and run
//! through the ordinary matcher, so a bug in this file cannot quietly report "no overlap".

use std::collections::BTreeMap;
use std::fmt;

use http::Method;

use super::selector::{ArnForm, HostClass, Predicate, RouteSelector, TargetKind};
use super::shape::RequestShape;

/// What a selector says about one query key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueryConstraint {
    /// The key must be present, with any value.
    Present,
    /// The key must be absent.
    Absent,
    /// The key must be present with this exact value.
    Equals(&'static str),
}

impl QueryConstraint {
    /// The strongest constraint implying both, or `None` when they cannot hold at once.
    fn meet(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::Absent, Self::Absent) => Some(Self::Absent),
            (Self::Absent, _) | (_, Self::Absent) => None,
            (Self::Present, keep) | (keep, Self::Present) => Some(keep),
            (Self::Equals(a), Self::Equals(b)) => (a == b).then_some(Self::Equals(a)),
        }
    }

    /// Whether every request satisfying `self` also satisfies `other`.
    fn implies(self, other: Self) -> bool {
        match (self, other) {
            (Self::Absent, Self::Absent) | (Self::Present, Self::Present) => true,
            (Self::Equals(_), Self::Present) => true,
            (Self::Equals(a), Self::Equals(b)) => a == b,
            _ => false,
        }
    }
}

/// What a selector says about one header name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderConstraint {
    /// The header must be present, with any value.
    Present,
    /// The header must be absent.
    Absent,
    /// The header must be present with a value starting with this non-empty prefix.
    Prefix(&'static str),
}

impl HeaderConstraint {
    fn meet(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::Absent, Self::Absent) => Some(Self::Absent),
            (Self::Absent, _) | (_, Self::Absent) => None,
            (Self::Present, keep) | (keep, Self::Present) => Some(keep),
            // Two prefixes are compatible exactly when one extends the other; the longer one is
            // then the meet. `multipart/form-data` and `multipart/` overlap, `text/` does not.
            (Self::Prefix(a), Self::Prefix(b)) => {
                if a.starts_with(b) {
                    Some(Self::Prefix(a))
                } else if b.starts_with(a) {
                    Some(Self::Prefix(b))
                } else {
                    None
                }
            }
        }
    }

    fn implies(self, other: Self) -> bool {
        match (self, other) {
            (Self::Absent, Self::Absent) | (Self::Present, Self::Present) => true,
            (Self::Prefix(_), Self::Present) => true,
            (Self::Prefix(a), Self::Prefix(b)) => a.starts_with(b),
            _ => false,
        }
    }
}

/// A selector as a set of independent constraints.
///
/// `None` on a scalar dimension means "unconstrained", which is the top element: it accepts every
/// value, and therefore overlaps every other constraint on that dimension.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Constraints {
    method: Option<Method>,
    target: Option<TargetKind>,
    host_class: Option<HostClass>,
    arn_form: Option<ArnForm>,
    path: Option<&'static str>,
    query: BTreeMap<&'static str, QueryConstraint>,
    headers: BTreeMap<&'static str, HeaderConstraint>,
}

/// A selector that no request can satisfy: it constrains one dimension two incompatible ways.
///
/// Always a table bug rather than a request-time outcome, so it is a build error and carries the
/// dimension by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contradiction {
    /// The dimension, named as an operator would search for it (`query:acl`, `method`).
    pub dimension: String,
    /// What the two constraints were.
    pub detail: String,
}

impl fmt::Display for Contradiction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is constrained two incompatible ways ({})", self.dimension, self.detail)
    }
}

/// Sets a scalar dimension, refusing a second, different value.
fn set_scalar<T: PartialEq + fmt::Debug>(slot: &mut Option<T>, value: T, dimension: &str) -> Result<(), Contradiction> {
    match slot {
        Some(existing) if *existing != value => Err(Contradiction {
            dimension: dimension.to_owned(),
            detail: format!("{existing:?} and {value:?}"),
        }),
        _ => {
            *slot = Some(value);
            Ok(())
        }
    }
}

/// Meets two scalar dimensions. The outer `None` is "no common value".
fn meet_scalar<T: PartialEq>(a: Option<T>, b: Option<T>) -> Option<Option<T>> {
    match (a, b) {
        (None, other) | (other, None) => Some(other),
        (Some(x), Some(y)) => (x == y).then_some(Some(x)),
    }
}

impl Constraints {
    /// Normalises a selector, or reports the contradiction inside it.
    ///
    /// # Errors
    ///
    /// [`Contradiction`] when the selector constrains one dimension incompatibly — `QueryPresent`
    /// and `QueryAbsent` on the same key, two different methods, two disjoint header prefixes.
    pub(crate) fn of(selector: &RouteSelector) -> Result<Self, Contradiction> {
        let mut out = Self::default();
        for predicate in selector.predicates() {
            match *predicate {
                Predicate::Method(ref method) => set_scalar(&mut out.method, method.clone(), "method")?,
                Predicate::Target(target) => set_scalar(&mut out.target, target, "target")?,
                Predicate::HostClass(class) => set_scalar(&mut out.host_class, class, "host_class")?,
                Predicate::ArnForm(form) => set_scalar(&mut out.arn_form, form, "arn_form")?,
                Predicate::PathLiteral(path) => set_scalar(&mut out.path, path, "path")?,
                Predicate::QueryPresent(key) => out.add_query(key, QueryConstraint::Present)?,
                Predicate::QueryAbsent(key) => out.add_query(key, QueryConstraint::Absent)?,
                Predicate::QueryEquals(key, value) => out.add_query(key, QueryConstraint::Equals(value))?,
                Predicate::HeaderPrefix(name, prefix) => out.add_header(name, HeaderConstraint::Prefix(prefix))?,
                Predicate::HeaderPresent { header, negated } => {
                    let constraint = if negated {
                        HeaderConstraint::Absent
                    } else {
                        HeaderConstraint::Present
                    };
                    out.add_header(header, constraint)?;
                }
            }
        }
        Ok(out)
    }

    fn add_query(&mut self, key: &'static str, constraint: QueryConstraint) -> Result<(), Contradiction> {
        let merged = match self.query.get(key) {
            Some(existing) => existing.meet(constraint).ok_or_else(|| Contradiction {
                dimension: format!("query:{key}"),
                detail: format!("{existing:?} and {constraint:?}"),
            })?,
            None => constraint,
        };
        self.query.insert(key, merged);
        Ok(())
    }

    fn add_header(&mut self, name: &'static str, constraint: HeaderConstraint) -> Result<(), Contradiction> {
        let merged = match self.headers.get(name) {
            Some(existing) => existing.meet(constraint).ok_or_else(|| Contradiction {
                dimension: format!("header:{name}"),
                detail: format!("{existing:?} and {constraint:?}"),
            })?,
            None => constraint,
        };
        self.headers.insert(name, merged);
        Ok(())
    }

    /// Whether this record constrains nothing at all, and therefore matches every request.
    pub(crate) fn is_top(&self) -> bool {
        *self == Self::default()
    }

    /// The strongest record implying both, or `None` when no request satisfies both.
    ///
    /// This *is* the overlap decision: two selectors overlap exactly when their meet exists.
    pub(crate) fn meet(&self, other: &Self) -> Option<Self> {
        let mut out = Self {
            method: meet_scalar(self.method.clone(), other.method.clone())?,
            target: meet_scalar(self.target, other.target)?,
            host_class: meet_scalar(self.host_class, other.host_class)?,
            arn_form: meet_scalar(self.arn_form, other.arn_form)?,
            path: meet_scalar(self.path, other.path)?,
            query: self.query.clone(),
            headers: self.headers.clone(),
        };
        for (key, constraint) in &other.query {
            let merged = match out.query.get(key) {
                Some(existing) => existing.meet(*constraint)?,
                None => *constraint,
            };
            out.query.insert(key, merged);
        }
        for (name, constraint) in &other.headers {
            let merged = match out.headers.get(name) {
                Some(existing) => existing.meet(*constraint)?,
                None => *constraint,
            };
            out.headers.insert(name, merged);
        }
        Some(out)
    }

    /// Whether every request this record accepts is also accepted by `other`.
    ///
    /// Total shadowing — the shape that makes a route unreachable — is exactly
    /// `shadowed.refines(winner)` with the winner earlier in the table.
    pub(crate) fn refines(&self, other: &Self) -> bool {
        fn scalar<T: PartialEq>(mine: Option<&T>, theirs: Option<&T>) -> bool {
            match theirs {
                None => true,
                Some(value) => mine == Some(value),
            }
        }
        if !scalar(self.method.as_ref(), other.method.as_ref())
            || !scalar(self.target.as_ref(), other.target.as_ref())
            || !scalar(self.host_class.as_ref(), other.host_class.as_ref())
            || !scalar(self.arn_form.as_ref(), other.arn_form.as_ref())
            || !scalar(self.path.as_ref(), other.path.as_ref())
        {
            return false;
        }
        let query_ok = other
            .query
            .iter()
            .all(|(key, theirs)| self.query.get(key).is_some_and(|mine| mine.implies(*theirs)));
        let headers_ok = other
            .headers
            .iter()
            .all(|(name, theirs)| self.headers.get(name).is_some_and(|mine| mine.implies(*theirs)));
        query_ok && headers_ok
    }

    /// A concrete request satisfying every constraint in this record.
    ///
    /// Unconstrained dimensions take the least surprising value; a query key constrained `Absent`
    /// is simply not rendered.
    pub(crate) fn witness(&self) -> RequestShape {
        let target = self.target.unwrap_or(TargetKind::Bucket);
        let query = self
            .query
            .iter()
            .filter_map(|(key, constraint)| match constraint {
                QueryConstraint::Absent => None,
                QueryConstraint::Present => Some(((*key).to_owned(), String::new())),
                QueryConstraint::Equals(value) => Some(((*key).to_owned(), (*value).to_owned())),
            })
            .collect();
        let headers = self
            .headers
            .iter()
            .filter_map(|(name, constraint)| match constraint {
                HeaderConstraint::Absent => None,
                // Any value satisfies `Present`; `x` is short and obviously a placeholder.
                HeaderConstraint::Present => Some(((*name).to_owned(), "x".to_owned())),
                HeaderConstraint::Prefix(prefix) => Some(((*name).to_owned(), (*prefix).to_owned())),
            })
            .collect();
        RequestShape {
            method: self.method.clone().unwrap_or(Method::GET),
            path: self.path.unwrap_or(target.witness_path()).to_owned(),
            target,
            host_class: self.host_class.unwrap_or(HostClass::Standard),
            arn_form: self.arn_form,
            query,
            headers,
        }
    }
}

/// A request both selectors accept, or `None` when no such request exists.
///
/// The returned shape has been run through the ordinary matcher for both selectors; a shape that
/// the meet produced but the matcher rejects is reported as [`OverlapError::Inconsistent`] rather
/// than swallowed, because that combination means this file and `selector` disagree about what a
/// predicate means.
///
/// # Errors
///
/// [`OverlapError`] when either selector is internally contradictory, or when the witness does not
/// survive the round trip through the matcher.
pub(crate) fn overlap_witness(
    a: &RouteSelector,
    a_constraints: &Constraints,
    b: &RouteSelector,
    b_constraints: &Constraints,
) -> Result<Option<RequestShape>, OverlapError> {
    let Some(meet) = a_constraints.meet(b_constraints) else {
        return Ok(None);
    };
    let shape = meet.witness();
    let Some(materialised) = shape.materialise() else {
        return Err(OverlapError::Inconsistent {
            witness: Box::new(shape),
            reason: "the witness cannot be expressed as an acceptable request",
        });
    };
    let parts = materialised.parts();
    if !a.matches(&parts) || !b.matches(&parts) {
        return Err(OverlapError::Inconsistent {
            witness: Box::new(shape),
            reason: "the lattice reported an overlap the matcher does not agree with",
        });
    }
    Ok(Some(shape))
}

/// A failure of the overlap decision itself, as opposed to an overlap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverlapError {
    /// The lattice and the matcher disagree. Always a bug in this crate, never in the table.
    Inconsistent {
        /// The witness that did not survive the round trip.
        witness: Box<RequestShape>,
        /// Which half of the round trip failed.
        reason: &'static str,
    },
}

impl fmt::Display for OverlapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inconsistent { witness, reason } => {
                write!(f, "route lattice inconsistency: {reason}; witness: {witness}")
            }
        }
    }
}

impl std::error::Error for OverlapError {}
