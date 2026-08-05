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

//! Comparing a generated IR document against a hand-written golden.
//!
//! Responsible for: a structural diff that names each difference by JSON path, so a mismatch
//! against `spec/ir/samples/*.json` is a reviewable list rather than "the files differ".
//! NOT responsible for: deciding who is right. A difference is a question for a human: either the
//! sample was written from an older model, or lowering is wrong.
//! Upstream: [`crate::run`]. Downstream: the `xtask codegen` report.
//!
//! Objects are compared as unordered maps and arrays as ordered sequences, except that an array
//! whose elements carry a `name` member is matched by name — field order inside `input.fields` is
//! not a wire contract, whereas `xml.element_order` is, and conflating the two would bury the
//! second under the first.

use s3gate_model::json::Value;

/// One structural difference between a generated document and its golden.
#[derive(Debug, Clone, PartialEq)]
pub struct Difference {
    /// JSON path, e.g. `output.fields[Contents].type.flattened`.
    pub path: String,
    /// What the golden says.
    pub golden: String,
    /// What codegen produced.
    pub generated: String,
}

impl std::fmt::Display for Difference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: golden {} / generated {}", self.path, self.golden, self.generated)
    }
}

/// Compares a golden document with a generated one.
pub fn compare(golden: &Value, generated: &Value) -> Vec<Difference> {
    let mut out = Vec::new();
    diff("", golden, generated, &mut out);
    out
}

fn diff(path: &str, golden: &Value, generated: &Value, out: &mut Vec<Difference>) {
    match (golden, generated) {
        (Value::Object(a), Value::Object(b)) => {
            for (key, av) in a {
                let child = join(path, key);
                match b.iter().find(|(k, _)| k == key) {
                    Some((_, bv)) => diff(&child, av, bv, out),
                    None => out.push(Difference {
                        path: child,
                        golden: summarize(av),
                        generated: "absent".into(),
                    }),
                }
            }
            for (key, bv) in b {
                if !a.iter().any(|(k, _)| k == key) {
                    out.push(Difference {
                        path: join(path, key),
                        golden: "absent".into(),
                        generated: summarize(bv),
                    });
                }
            }
        }
        (Value::Array(a), Value::Array(b)) if is_named(a) || is_named(b) => diff_named(path, a, b, out),
        (Value::Array(a), Value::Array(b)) if is_strings(a) && is_strings(b) => diff_strings(path, a, b, out),
        (Value::Array(a), Value::Array(b)) => {
            let common = a.len().min(b.len());
            for i in 0..common {
                diff(&format!("{path}[{i}]"), &a[i], &b[i], out);
            }
            for (i, extra) in a.iter().enumerate().skip(common) {
                out.push(Difference {
                    path: format!("{path}[{i}]"),
                    golden: summarize(extra),
                    generated: "absent".into(),
                });
            }
            for (i, extra) in b.iter().enumerate().skip(common) {
                out.push(Difference {
                    path: format!("{path}[{i}]"),
                    golden: "absent".into(),
                    generated: summarize(extra),
                });
            }
        }
        (a, b) if a == b => {}
        (a, b) => out.push(Difference {
            path: path.to_owned(),
            golden: summarize(a),
            generated: summarize(b),
        }),
    }
}

fn diff_named(path: &str, a: &[Value], b: &[Value], out: &mut Vec<Difference>) {
    let names_a: Vec<String> = a.iter().map(name_of).collect();
    let names_b: Vec<String> = b.iter().map(name_of).collect();
    for (n, item) in names_a.iter().zip(a) {
        match names_b.iter().position(|other| other == n) {
            Some(i) => diff(&format!("{path}[{n}]"), item, &b[i], out),
            None => out.push(Difference {
                path: format!("{path}[{n}]"),
                golden: "present".into(),
                generated: "absent".into(),
            }),
        }
    }
    for (n, item) in names_b.iter().zip(b) {
        if !names_a.contains(n) {
            out.push(Difference {
                path: format!("{path}[{n}]"),
                golden: "absent".into(),
                generated: summarize(item),
            });
        }
    }
    let shared_a: Vec<&String> = names_a.iter().filter(|n| names_b.contains(n)).collect();
    let shared_b: Vec<&String> = names_b.iter().filter(|n| names_a.contains(n)).collect();
    if shared_a != shared_b {
        out.push(Difference {
            path: format!("{path}[order]"),
            golden: shared_a.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","),
            generated: shared_b.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","),
        });
    }
}

/// A list of strings is compared as a sequence *and* as a set: one inserted enum value would
/// otherwise report as thirty-eight shifted elements and hide the single real difference.
fn diff_strings(path: &str, a: &[Value], b: &[Value], out: &mut Vec<Difference>) {
    let golden: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
    let generated: Vec<&str> = b.iter().filter_map(Value::as_str).collect();
    let missing: Vec<&str> = golden.iter().copied().filter(|v| !generated.contains(v)).collect();
    let extra: Vec<&str> = generated.iter().copied().filter(|v| !golden.contains(v)).collect();
    if !missing.is_empty() {
        out.push(Difference {
            path: format!("{path}[-]"),
            golden: missing.join(", "),
            generated: "absent".into(),
        });
    }
    if !extra.is_empty() {
        out.push(Difference {
            path: format!("{path}[+]"),
            golden: "absent".into(),
            generated: extra.join(", "),
        });
    }
    let shared_golden: Vec<&str> = golden.iter().copied().filter(|v| generated.contains(v)).collect();
    let shared_generated: Vec<&str> = generated.iter().copied().filter(|v| golden.contains(v)).collect();
    if shared_golden != shared_generated {
        out.push(Difference {
            path: format!("{path}[order]"),
            golden: shared_golden.join(", "),
            generated: shared_generated.join(", "),
        });
    }
}

fn is_strings(items: &[Value]) -> bool {
    !items.is_empty() && items.iter().all(|i| matches!(i, Value::Str(_)))
}

fn is_named(items: &[Value]) -> bool {
    !items.is_empty() && items.iter().all(|i| key_of(i).is_some())
}

/// Records inside an array identify themselves by `name` (fields) or `id` (quirks, extension
/// points). Matching on that instead of the index is what keeps an inserted record from reporting
/// as a change to every record after it.
fn key_of(item: &Value) -> Option<&str> {
    item.get("name")
        .and_then(Value::as_str)
        .or_else(|| item.get("id").and_then(Value::as_str))
}

fn name_of(item: &Value) -> String {
    key_of(item).unwrap_or("?").to_owned()
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

fn summarize(value: &Value) -> String {
    let text = s3gate_model::json::write_canonical(value);
    let text = text.trim_end();
    let flat: String = text.split('\n').map(str::trim).collect::<Vec<_>>().join(" ");
    if flat.chars().count() > 90 {
        let head: String = flat.chars().take(87).collect();
        format!("{head}...")
    } else {
        flat
    }
}
