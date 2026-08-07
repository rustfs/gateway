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

//! The honesty ledger: proof that every declaration the frozen schema allows is one this harness
//! actually looks at.
//!
//! Responsible for: enumerating every key `conformance/case.schema.json` declares, recording at
//! run time which of them the harness read and from where, and auditing one against the other.
//! NOT responsible for: what a key *means* — that is `crate::inprocess`, `crate::expect` and
//! `crate::fixture`.
//! Upstream: `crate::json`, `crate::schema`, `crate::value`. Downstream: `crate::corpus`,
//! `crate::cli` (the `audit-keys` command), and `scripts/check_case_keys_honoured.sh`.
//!
//! # The defect this exists to make unwritable
//!
//! A case declares a precondition; the harness never reads it; the case runs against a different
//! scenario than the one it describes and reports green. That has happened here four times —
//! `Outcome::Response` hard-coded, a constant `request_progress`, a `sign_request` that dropped the
//! query tamper, `contains_utf8` compared against unredacted bytes — and twice more found by this
//! module's first run: `setup.buckets[].object_lock` and `connection.pipeline` were parsed,
//! schema-checked, and then dropped on the floor.
//!
//! The schema is frozen and enumerates every key a case may write. So the invariant is simply:
//! **every key in that enumeration is read by something, or something says in writing why not.**
//!
//! # What counts as proof that a key is read
//!
//! Not that the crate compiles: a key nothing mentions compiles perfectly. Not that the key's name
//! appears in the source: `region` appears in `inprocess.rs`, but it is `sign.region` — the
//! identically named `setup.buckets[].region` was read by nothing. Grep cannot tell those apart,
//! which is why this guard is not a shell script.
//!
//! The proof is dynamic and fused to the access itself. [`Value::read`] takes the *schema location*
//! of a key, records it, and then fetches the TOML key **derived from that location**. There is no
//! way to record one name and read another, because the name that is recorded is the name that is
//! fetched.
//!
//! Three further rules stop the ledger from becoming the very thing it is checking — an assertion
//! that cannot fail:
//!
//! 1. **Grounded.** A recorded name that the frozen schema does not declare is a finding
//!    ([`Finding::Invented`]). Coverage cannot be manufactured by inventing key names.
//! 2. **Not blanket.** One source location may claim at most one key ([`Finding::Blanket`]). The
//!    cheapest way to make this audit vacuous — `for key in EVERY_KEY { node.read(key) }` — is one
//!    location claiming a hundred keys, and it is rejected. This is why the loops that used to read
//!    `("message_present", "Message")` and its sibling from an array literal are written out.
//! 3. **Not contradicted.** A key that is both read and declared unread is a finding
//!    ([`Finding::Contradicted`]), so [`DECLARED`] cannot drift into fiction.
//!
//! What this still cannot prove is that a value which *was* read went on to change anything —
//! `let _ = node.read(k)` would satisfy the ledger. [`Value::read`] is `#[must_use]` so that
//! discarding the result does not survive `-D warnings`, and the remaining hole needs a deliberate
//! `let _ =` that a reviewer sees in the diff. That is a smaller hole than silence, which is what
//! there was before, but it is a hole and it is stated here rather than papered over.
//!
//! # The three dispositions
//!
//! A key that is not read must appear in [`DECLARED`] with one of:
//!
//! * [`Disposition::Inert`] — prose or coverage metadata whose whole contract is the schema's own
//!   `required`/`minLength`. No runner behaviour turns on the value.
//! * [`Disposition::Unhonoured`] — a real instruction this harness cannot carry out. Every case
//!   that declares one is given a warning naming the key and the reason, so the gap appears in the
//!   report on the case that is affected by it, instead of nowhere.
//! * [`Disposition::BehindRefusal`] — unreachable, because a named ancestor declaration is refused
//!   on sight and the case is skipped before any child is looked at. The named ancestor must itself
//!   be in the ledger, which is checked.
//! * [`Disposition::Unexercised`] — read only from inside a container no case in this corpus writes,
//!   so the run cannot demonstrate the read. The declaration names the container, and the audit
//!   fails the moment a case writes it: the exemption deletes itself as soon as it stops being
//!   true, rather than waiting for someone to notice.
//!
//! Refusing a case outright is not a disposition here: a refusal *reads* the key in order to refuse
//! it, so it is an ordinary ledger entry.

use crate::corpus::Corpus;
use crate::diagnostic::Diagnostic;
use crate::json;
use crate::schema::Schema;
use crate::value::Value;
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::Location;
use std::sync::{Mutex, OnceLock};

/// A source location that read a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Site {
    /// Source file, as `file!()` spells it.
    pub file: &'static str,
    /// Line number.
    pub line: u32,
}

impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// Keys read so far in this process, and the sites that read them.
pub type Ledger = BTreeMap<&'static str, BTreeSet<Site>>;

fn ledger() -> &'static Mutex<Ledger> {
    static LEDGER: OnceLock<Mutex<Ledger>> = OnceLock::new();
    LEDGER.get_or_init(|| Mutex::new(Ledger::new()))
}

#[track_caller]
fn record(key: &'static str) {
    let location = Location::caller();
    let site = Site {
        file: location.file(),
        line: location.line(),
    };
    if let Ok(mut ledger) = ledger().lock() {
        ledger.entry(key).or_default().insert(site);
    }
}

/// Every key read so far in this process, with the sites that read each one.
///
/// Meaningful only in a process that has actually run cases, and only in a process that has run
/// *nothing else*: the audit is the `audit-keys` command for that reason, rather than a unit test
/// sharing a process where one test poking at a field would stand in for the runner reading it.
#[must_use]
pub fn recorded() -> Ledger {
    ledger().lock().map(|ledger| ledger.clone()).unwrap_or_default()
}

/// The TOML key a schema location names: everything after the last `.`.
///
/// `setup.buckets[].object_lock` names the TOML key `object_lock`. This is the function that fuses
/// recording to reading — [`Value::read`] records the location and fetches *this*, so the two can
/// never name different fields.
#[must_use]
pub fn leaf(key: &str) -> &str {
    match key.rsplit_once('.') {
        Some((_, last)) => last,
        None => key,
    }
}

impl Value {
    /// Reads the field a schema location names, recording that this harness looked at it.
    ///
    /// `key` is the location in `conformance/case.schema.json`, not the TOML key: `expect.status`,
    /// `setup.buckets[].object_lock`, `signSpec.tamper.component`. The TOML key actually fetched is
    /// [`leaf`] of it. Pass a location the schema does not declare and the audit reports
    /// [`Finding::Invented`].
    ///
    /// Recording happens whether or not the field is present, because the fact being recorded is
    /// that the harness *looks* — a case that omits an optional key must not make the harness look
    /// honest about a key it would have ignored anyway.
    #[must_use]
    #[track_caller]
    pub fn read(&self, key: &'static str) -> Option<&Value> {
        record(key);
        self.get(leaf(key))
    }

    /// [`Value::read`] for a key holding an array of strings.
    ///
    /// Absent is `Some(empty)` and present-but-wrong-shape is `None`, exactly as
    /// [`Value::string_array`] defines it.
    #[must_use]
    #[track_caller]
    pub fn read_strings(&self, key: &'static str) -> Option<Vec<&str>> {
        record(key);
        self.string_array(leaf(key))
    }
}

/// Why a declaration the frozen schema allows is not read by this harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Prose or coverage metadata. The schema's own constraints are the whole contract.
    Inert,
    /// A real instruction this harness cannot carry out. Cases declaring it are warned.
    Unhonoured,
    /// Unreachable: the named ancestor declaration is refused on sight, so the case is skipped
    /// before this key could be looked at. The named ancestor must itself be read.
    BehindRefusal(&'static str),
    /// Read only from inside the named container, which no case in this corpus writes — so this run
    /// cannot demonstrate the read. The entry fails as soon as a case writes the container.
    Unexercised(&'static str),
}

impl Disposition {
    /// The lowercase spelling used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Disposition::Inert => "inert",
            Disposition::Unhonoured => "unhonoured",
            Disposition::BehindRefusal(_) => "behind-refusal",
            Disposition::Unexercised(_) => "unexercised",
        }
    }
}

/// Every schema declaration this harness does **not** read, with the reason.
///
/// This list is the one place a gap can hide, and that is deliberate: adding a line here is a
/// visible act in a diff, whereas the two defects that prompted this module — `object_lock` and
/// `connection.pipeline` — were invisible because nothing had to be written down at all. An entry
/// naming a key the schema does not declare, or a key the ledger shows as read, is a hard failure,
/// so the list cannot rot in either direction.
pub const DECLARED: &[(&str, Disposition, &str)] = &[
    // -- Prose and coverage metadata -----------------------------------------------------------
    (
        "caseMeta.rationale",
        Disposition::Inert,
        "prose for a future maintainer deciding whether the case may be deleted; the schema's \
         `required` and `minLength` are its whole contract and no verdict turns on the text",
    ),
    (
        "caseMeta.operation",
        Disposition::Inert,
        "an AWS operation name for coverage matrices built outside this runner; the suite groups \
         its report by capability domain, which is the directory",
    ),
    (
        "evidence.summary",
        Disposition::Inert,
        "one original sentence for a human reader; the 200-character ceiling is a compliance \
         control the schema enforces, and no verdict turns on the text",
    ),
    (
        "evidence.kind",
        Disposition::Inert,
        "classifies the evidence link for a reader; the report prints the URL, which is what a \
         maintainer follows",
    ),
    // -- Instructions this harness cannot carry out ---------------------------------------------
    (
        "dataChunk.delay_ms",
        Disposition::Unhonoured,
        "wall-clock pacing before a chunk is written. The in-process target hands frames to a body \
         the service pulls from, and nothing here observes arrival timing; sleeping would make the \
         `timing` assertions depend on the load of the build machine. What survives is the frame \
         shape, so a server that stops pulling part way through is still distinguishable",
    ),
    (
        "dataChunk.flush",
        Disposition::Unhonoured,
        "asks for a flush boundary on a socket. The in-process target has no write buffer to flush; \
         one frame per chunk is already the boundary the service sees",
    ),
    (
        "expect.events[].headers",
        Disposition::Unhonoured,
        "per-frame headers of an event stream. The event matcher counts frames by `type`; no \
         transport here produces framed events at all, so a case using them fails on the counts \
         first",
    ),
    (
        "expect.events[].payload",
        Disposition::Unhonoured,
        "per-frame payload of an event stream, judged as a body expectation. Not compared, for the \
         same reason as the headers above",
    ),
    // -- Unreachable behind a refusal -------------------------------------------------------------
    (
        "controlChunk.delay_ms",
        Disposition::BehindRefusal("controlChunk.action"),
        "a control chunk is refused by its `action`, which the schema makes mandatory, so the case \
         is skipped before this is looked at",
    ),
    (
        "controlChunk.duration_ms",
        Disposition::BehindRefusal("controlChunk.action"),
        "how long a `stall` or `stop_reading` holds; reached only through a control chunk, which is refused by its `action`",
    ),
    (
        "connection.tls.enabled",
        Disposition::BehindRefusal("connection.tls"),
        "the whole `[connection.tls]` block is refused: there is no socket to negotiate on",
    ),
    (
        "connection.tls.alpn",
        Disposition::BehindRefusal("connection.tls"),
        "the protocol list offered in the handshake; the whole `[connection.tls]` block is refused for want of a socket",
    ),
    (
        "connection.tls.sni",
        Disposition::BehindRefusal("connection.tls"),
        "the server name offered in the handshake; the whole `[connection.tls]` block is refused for want of a socket",
    ),
    (
        "connection.tls.min_version",
        Disposition::BehindRefusal("connection.tls"),
        "the floor of the negotiated version; the whole `[connection.tls]` block is refused for want of a socket",
    ),
    (
        "connection.tls.close_notify",
        Disposition::BehindRefusal("connection.tls"),
        "the truncation shape, tearing TCP down without a TLS close_notify; the whole `[connection.tls]` block is refused for want of a socket",
    ),
    (
        "h2Frame.type",
        Disposition::BehindRefusal("requestSpec.h2_frames"),
        "frame scripting is refused as a whole; there is no HTTP/2 framing layer here",
    ),
    (
        "h2Frame.stream_id",
        Disposition::BehindRefusal("requestSpec.h2_frames"),
        "which stream a scripted frame belongs to; `request.h2_frames` is refused whole for want of an HTTP/2 framing layer",
    ),
    (
        "h2Frame.flags",
        Disposition::BehindRefusal("requestSpec.h2_frames"),
        "the flags on a scripted frame; `request.h2_frames` is refused whole for want of an HTTP/2 framing layer",
    ),
    (
        "h2Frame.payload_hex",
        Disposition::BehindRefusal("requestSpec.h2_frames"),
        "the bytes of a scripted frame; `request.h2_frames` is refused whole for want of an HTTP/2 framing layer",
    ),
    (
        "h2Frame.error_code",
        Disposition::BehindRefusal("requestSpec.h2_frames"),
        "the code of a scripted RST_STREAM or GOAWAY; `request.h2_frames` is refused whole for want of an HTTP/2 framing layer",
    ),
    (
        "h2Frame.increment",
        Disposition::BehindRefusal("requestSpec.h2_frames"),
        "the size of a scripted WINDOW_UPDATE; `request.h2_frames` is refused whole for want of an HTTP/2 framing layer",
    ),
    (
        "h2Frame.delay_ms",
        Disposition::BehindRefusal("requestSpec.h2_frames"),
        "the pause before a scripted frame is written; `request.h2_frames` is refused whole for want of an HTTP/2 framing layer",
    ),
    // -- Read, but out of reach of this corpus ---------------------------------------------------
    (
        "expect.events[].type",
        Disposition::Unexercised("expect.events"),
        "`crate::expect::check_events` reads it once per declared event, and no case in this corpus \
         declares an event stream, so this run cannot show the read happening",
    ),
    (
        "expect.events[].min_count",
        Disposition::Unexercised("expect.events"),
        "the floor on how many frames of a type arrived; read once per declared event, and no case in this corpus declares an event stream",
    ),
    (
        "expect.events[].max_count",
        Disposition::Unexercised("expect.events"),
        "the ceiling on how many frames of a type arrived; read once per declared event, and no case in this corpus declares an event stream",
    ),
    (
        "signSpec.payload_hash_literal",
        Disposition::BehindRefusal("signSpec.payload_hash"),
        "only reachable with `payload_hash = \"literal\"`, which is refused by name",
    ),
];

/// Looks a key up in [`DECLARED`].
#[must_use]
pub fn declared(key: &str) -> Option<(Disposition, &'static str)> {
    DECLARED
        .iter()
        .find(|(name, _, _)| *name == key)
        .map(|(_, disposition, reason)| (*disposition, *reason))
}

/// One way the harness and the frozen schema disagree about what is being read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The schema declares this key, nothing reads it, and nothing says why. A case writing it
    /// would be asserting into the void.
    Silent(String),
    /// Something recorded a name the frozen schema does not declare.
    Invented(String),
    /// [`DECLARED`] names a key the frozen schema does not declare.
    Stale(String),
    /// [`DECLARED`] says a key is not read, and the ledger shows that it is.
    Contradicted(String),
    /// One source location claimed several keys, which is how a blanket loop would fake coverage.
    Blanket(Site, Vec<String>),
    /// A [`Disposition::BehindRefusal`] whose named ancestor is not itself read, so the claim that
    /// the case is skipped first rests on nothing.
    Ungrounded {
        /// The key whose disposition makes the claim.
        key: String,
        /// The ancestor it names.
        ancestor: String,
    },
    /// A [`Disposition::Unexercised`] whose container the corpus now writes, so the run could have
    /// demonstrated the read and the exemption has outlived its reason.
    Exercised {
        /// The key whose disposition makes the claim.
        key: String,
        /// The container it named as unwritten.
        container: String,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::Silent(key) => write!(
                f,
                "`{key}` is declared by the frozen schema and nothing in this harness reads it. A \
                 case writing it would state a precondition or an assertion that never reaches the \
                 target. Read it, refuse it by name, or add it to keys::DECLARED with the reason"
            ),
            Finding::Invented(key) => write!(
                f,
                "`{key}` was recorded as read but the frozen schema declares no such location; \
                 coverage of a key that does not exist is coverage of nothing"
            ),
            Finding::Stale(key) => write!(
                f,
                "keys::DECLARED names `{key}`, which the frozen schema does not declare; the entry \
                 outlived the field"
            ),
            Finding::Contradicted(key) => write!(
                f,
                "keys::DECLARED says `{key}` is not read, and the ledger shows that it is; one of \
                 the two is fiction"
            ),
            Finding::Blanket(site, keys) => write!(
                f,
                "{site} claims {} keys ({}); one site may claim one key, because a loop over every \
                 key is exactly how this audit would be made vacuous",
                keys.len(),
                keys.join(", ")
            ),
            Finding::Ungrounded { key, ancestor } => write!(
                f,
                "`{key}` is declared unreachable behind `{ancestor}`, but `{ancestor}` is not read \
                 either, so nothing refuses the case and both are silent"
            ),
            Finding::Exercised { key, container } => write!(
                f,
                "`{key}` is excused as unexercised because no case writes `{container}`, and a case \
                 now does; drop the entry and let the run prove the read"
            ),
        }
    }
}

/// Audits a ledger against a schema key inventory and a disposition list.
///
/// Pure, so the guard's own failure modes are unit-testable without running a corpus.
#[must_use]
pub fn audit(
    inventory: &BTreeSet<String>,
    ledger: &Ledger,
    declarations: &[(&str, Disposition, &str)],
    exercised: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let declared: BTreeMap<&str, Disposition> = declarations.iter().map(|(key, how, _)| (*key, *how)).collect();

    for key in inventory {
        if ledger.contains_key(key.as_str()) || declared.contains_key(key.as_str()) {
            continue;
        }
        findings.push(Finding::Silent(key.clone()));
    }
    for key in ledger.keys() {
        if !inventory.contains(*key) {
            findings.push(Finding::Invented((*key).to_owned()));
        }
    }
    for (key, disposition) in &declared {
        if !inventory.contains(*key) {
            findings.push(Finding::Stale((*key).to_owned()));
        }
        if ledger.contains_key(key) {
            findings.push(Finding::Contradicted((*key).to_owned()));
        }
        if let Disposition::BehindRefusal(ancestor) = disposition
            && !ledger.contains_key(ancestor)
        {
            findings.push(Finding::Ungrounded {
                key: (*key).to_owned(),
                ancestor: (*ancestor).to_owned(),
            });
        }
        if let Disposition::Unexercised(container) = disposition
            && exercised.contains(*container)
        {
            findings.push(Finding::Exercised {
                key: (*key).to_owned(),
                container: (*container).to_owned(),
            });
        }
    }

    let mut by_site: BTreeMap<Site, Vec<String>> = BTreeMap::new();
    for (key, sites) in ledger {
        for site in sites {
            by_site.entry(*site).or_default().push((*key).to_owned());
        }
    }
    for (site, mut keys) in by_site {
        if keys.len() > 1 {
            keys.sort();
            findings.push(Finding::Blanket(site, keys));
        }
    }
    findings
}

/// Every key the frozen schema declares, and where each one may appear in a case document.
#[derive(Debug, Clone)]
pub struct Inventory {
    root: Value,
    validator: Schema,
    keys: BTreeSet<String>,
}

impl Inventory {
    /// Compiles the frozen schema into a key inventory.
    ///
    /// # Errors
    ///
    /// Returns a message when the schema is not JSON or this runner cannot evaluate it.
    pub fn compile(source: &str) -> Result<Inventory, String> {
        let root = json::parse(source).map_err(|error| error.to_string())?;
        let validator = Schema::compile(source).map_err(|error| error.to_string())?;
        let mut inventory = Inventory {
            root,
            validator,
            keys: BTreeSet::new(),
        };
        let mut keys = BTreeSet::new();
        inventory.walk(&inventory.root, "", "", Scope::All, &mut Vec::new(), &mut |key, _| {
            keys.insert(key.to_owned());
        });
        inventory.keys = keys;
        Ok(inventory)
    }

    /// Every key the schema declares, in name order.
    #[must_use]
    pub fn keys(&self) -> &BTreeSet<String> {
        &self.keys
    }

    /// The keys a case document actually writes, each with the JSON pointers it writes them at.
    #[must_use]
    pub fn declared_in(&self, document: &Value) -> BTreeMap<String, Vec<String>> {
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        self.walk(&self.root, "", "", Scope::At(document), &mut Vec::new(), &mut |key, pointer| {
            out.entry(key.to_owned()).or_default().push(pointer.to_owned());
        });
        out
    }

    fn resolve<'a>(&'a self, reference: &str) -> Option<(&'a str, &'a Value)> {
        let name = reference.strip_prefix("#/$defs/")?;
        // The name is taken from the schema's own table rather than from the reference string, so
        // that it outlives the caller's borrow of the reference.
        self.root
            .get("$defs")?
            .as_table()?
            .iter()
            .find(|(key, _)| key == name)
            .map(|(key, target)| (key.as_str(), target))
    }

    fn walk<'a>(
        &'a self,
        node: &'a Value,
        prefix: &str,
        pointer: &str,
        scope: Scope<'_>,
        seen: &mut Vec<&'a str>,
        emit: &mut impl FnMut(&str, &str),
    ) {
        if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
            if let Some((name, target)) = self.resolve(reference)
                && !seen.contains(&name)
            {
                seen.push(name);
                self.walk(target, name, pointer, scope, seen, emit);
                seen.pop();
            }
            return;
        }
        for combinator in ["allOf", "anyOf", "oneOf"] {
            let Some(Value::Array(branches)) = node.get(combinator) else { continue };
            for branch in branches {
                // In document mode only the branch the instance satisfies contributes: `chunk` is a
                // `oneOf` of a data chunk and a control chunk, and both declare `delay_ms`, so
                // walking the unsatisfied branch would report a key the case did not write.
                if let Scope::At(instance) = scope
                    && !self.validator.accepts(branch, instance)
                {
                    continue;
                }
                self.walk(branch, prefix, pointer, scope, seen, emit);
            }
        }
        if let Some(Value::Table(properties)) = node.get("properties") {
            for (name, child) in properties {
                if matches!(child, Value::Bool(_)) {
                    continue;
                }
                let key = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                let at = format!("{pointer}/{name}");
                match scope {
                    Scope::All => {
                        emit(&key, &at);
                        self.walk(child, &key, &at, Scope::All, seen, emit);
                    }
                    Scope::At(instance) => {
                        let Some(value) = instance.get(name) else { continue };
                        emit(&key, &at);
                        self.walk(child, &key, &at, Scope::At(value), seen, emit);
                    }
                }
            }
        }
        if let Some(items) = node.get("items")
            && items.as_table().is_some()
        {
            let key = format!("{prefix}[]");
            match scope {
                Scope::All => self.walk(items, &key, pointer, Scope::All, seen, emit),
                Scope::At(instance) => {
                    for (index, element) in instance.as_array().unwrap_or_default().iter().enumerate() {
                        let at = format!("{pointer}/{index}");
                        self.walk(items, &key, &at, Scope::At(element), seen, emit);
                    }
                }
            }
        }
        if let Some(additional) = node.get("additionalProperties")
            && additional.as_table().is_some()
        {
            let key = format!("{prefix}.*");
            match scope {
                Scope::All => self.walk(additional, &key, pointer, Scope::All, seen, emit),
                Scope::At(instance) => {
                    let named = node.get("properties");
                    for (name, value) in instance.as_table().unwrap_or_default() {
                        if named.and_then(|table| table.get(name)).is_some() {
                            continue;
                        }
                        let at = format!("{pointer}/{name}");
                        self.walk(additional, &key, &at, Scope::At(value), seen, emit);
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Scope<'a> {
    /// Every declaration, whether or not any case writes it.
    All,
    /// Only the declarations this document writes.
    At(&'a Value),
}

/// Warns each case that declares a key this harness does not carry out.
///
/// The reason travels with the case rather than living in a document nobody reads, because the
/// person who needs it is whoever is looking at that case's result.
pub fn note_unhonoured(corpus: &mut Corpus) {
    let mut notes: Vec<Vec<Diagnostic>> = Vec::with_capacity(corpus.cases().len());
    for case in corpus.cases() {
        let mut found = Vec::new();
        if let Some(document) = case.document.as_ref() {
            for (key, pointers) in corpus.inventory().declared_in(document) {
                let Some((Disposition::Unhonoured, reason)) = declared(&key) else { continue };
                for pointer in pointers {
                    found.push(Diagnostic::warn(
                        "harness/unhonoured",
                        &pointer,
                        format!("`{key}` is declared here and this harness does not carry it out: {reason}"),
                    ));
                }
            }
        }
        notes.push(found);
    }
    for (case, found) in corpus.cases_mut().iter_mut().zip(notes) {
        case.diagnostics.extend(found);
    }
}

/// Audits the ledger this process filled against the frozen schema, and renders the result.
///
/// Call it only after the corpus has been *run*: the ledger is filled by the harness reading cases,
/// so an audit taken before anything ran would report that the harness reads nothing.
#[must_use]
pub fn report(corpus: &Corpus) -> (Vec<Finding>, String) {
    let ledger = recorded();
    let exercised: BTreeSet<String> = corpus
        .cases()
        .iter()
        .filter_map(|case| case.document.as_ref())
        .flat_map(|document| corpus.inventory().declared_in(document).into_keys())
        .collect();
    let findings = audit(corpus.inventory().keys(), &ledger, DECLARED, &exercised);
    let mut out = String::new();
    out.push_str(&format!(
        "case keys: {} declared by the frozen schema, {} read by this harness, {} accounted for in \
         keys::DECLARED\n",
        corpus.inventory().keys().len(),
        ledger.len(),
        DECLARED.len(),
    ));

    let mut writers: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for case in corpus.cases() {
        let Some(document) = case.document.as_ref() else { continue };
        for key in corpus.inventory().declared_in(document).into_keys() {
            if let Some((name, _, _)) = DECLARED.iter().find(|(name, _, _)| *name == key) {
                writers.entry(name).or_default().push(case.id.as_str());
            }
        }
    }
    for (key, disposition, reason) in DECLARED {
        out.push_str(&format!("  {:<14} {key}\n      {reason}\n", disposition.as_str()));
        if let Some(cases) = writers.get(key) {
            out.push_str(&format!("      declared by: {}\n", cases.join(", ")));
        }
    }
    if findings.is_empty() {
        out.push_str("no finding: every declaration the frozen schema allows is read, or is accounted for above\n");
    } else {
        out.push_str(&format!("\n{} finding(s):\n", findings.len()));
        for finding in &findings {
            out.push_str(&format!("  {finding}\n"));
        }
    }
    (findings, out)
}

#[cfg(test)]
mod tests;
