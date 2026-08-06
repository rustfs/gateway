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

//! The regular-expression subset the frozen schema's `pattern` keyword needs.
//!
//! Responsible for: compiling and matching the ECMA-262 subset that appears in
//! `case.schema.json` — anchors, character classes, groups, alternation, and the `*` `+` `?` `{n}`
//! quantifiers — and refusing anything outside it loudly. A pattern the matcher silently
//! mis-handles would turn a frozen contract into an unchecked one, so an unsupported construct is
//! a compile error rather than a best effort.
//! NOT responsible for: capture groups, back-references, lookaround, or Unicode property classes;
//! none appear in the schema and none may be added without this module being extended first.
//! Upstream: nothing. Downstream: `crate::schema`, `crate::runner` (the `--filter` glob has its
//! own matcher and does not come through here).

use core::fmt;

/// A pattern that could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError {
    /// The offending pattern.
    pub pattern: String,
    /// Why it was refused.
    pub message: String,
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported regular expression `{}`: {}", self.pattern, self.message)
    }
}

impl std::error::Error for PatternError {}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub struct Pattern {
    source: String,
    alternatives: Vec<Vec<Node>>,
}

#[derive(Debug, Clone)]
enum Node {
    Start,
    End,
    Literal(char),
    Any,
    Class { negated: bool, items: Vec<ClassItem> },
    Group(Vec<Vec<Node>>),
    Repeat { inner: Box<Node>, min: u32, max: Option<u32> },
}

#[derive(Debug, Clone)]
enum ClassItem {
    Single(char),
    Range(char, char),
    Digit,
    Word,
    Space,
}

impl Pattern {
    /// Compiles a pattern.
    ///
    /// # Errors
    ///
    /// Returns [`PatternError`] for any construct outside the supported subset.
    pub fn compile(pattern: &str) -> Result<Pattern, PatternError> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut compiler = Compiler {
            chars,
            pos: 0,
            source: pattern,
        };
        let alternatives = compiler.alternation()?;
        if compiler.pos != compiler.chars.len() {
            return Err(compiler.error("unbalanced `)`"));
        }
        Ok(Pattern {
            source: pattern.to_owned(),
            alternatives,
        })
    }

    /// The pattern text this was compiled from.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Reports whether the pattern matches anywhere in `text`.
    ///
    /// JSON Schema `pattern` is an unanchored search, which is why `\.\.` (the path-traversal
    /// guard on `relPath`) works without anchors.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        // An anchored pattern can only match at position 0, so do not scan further.
        let anchored = self.alternatives.iter().all(|alt| matches!(alt.first(), Some(Node::Start)));
        for start in 0..=chars.len() {
            for alternative in &self.alternatives {
                let mut ends = Vec::new();
                seq_ends(alternative, &chars, start, &mut ends);
                if !ends.is_empty() {
                    return true;
                }
            }
            if anchored {
                break;
            }
        }
        false
    }
}

struct Compiler<'a> {
    chars: Vec<char>,
    pos: usize,
    source: &'a str,
}

impl Compiler<'_> {
    fn error(&self, message: &str) -> PatternError {
        PatternError {
            pattern: self.source.to_owned(),
            message: message.to_owned(),
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn alternation(&mut self) -> Result<Vec<Vec<Node>>, PatternError> {
        let mut alternatives = vec![self.sequence()?];
        while self.peek() == Some('|') {
            self.pos += 1;
            alternatives.push(self.sequence()?);
        }
        Ok(alternatives)
    }

    fn sequence(&mut self) -> Result<Vec<Node>, PatternError> {
        let mut nodes = Vec::new();
        while let Some(ch) = self.peek() {
            if ch == '|' || ch == ')' {
                break;
            }
            let atom = self.atom()?;
            nodes.push(self.quantify(atom)?);
        }
        Ok(nodes)
    }

    fn quantify(&mut self, atom: Node) -> Result<Node, PatternError> {
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, None)
            }
            Some('+') => {
                self.pos += 1;
                (1, None)
            }
            Some('?') => {
                self.pos += 1;
                (0, Some(1))
            }
            Some('{') => {
                self.pos += 1;
                let min = self.integer()?;
                let max = if self.peek() == Some(',') {
                    self.pos += 1;
                    if self.peek() == Some('}') {
                        None
                    } else {
                        Some(self.integer()?)
                    }
                } else {
                    Some(min)
                };
                if self.peek() != Some('}') {
                    return Err(self.error("unterminated `{n,m}` quantifier"));
                }
                self.pos += 1;
                (min, max)
            }
            _ => return Ok(atom),
        };
        if self.peek() == Some('?') {
            return Err(self.error("lazy quantifiers are not supported"));
        }
        Ok(Node::Repeat {
            inner: Box::new(atom),
            min,
            max,
        })
    }

    fn integer(&mut self) -> Result<u32, PatternError> {
        let start = self.pos;
        while matches!(self.peek(), Some(ch) if ch.is_ascii_digit()) {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(self.error("expected a number in a `{n,m}` quantifier"));
        }
        self.chars[start..self.pos]
            .iter()
            .collect::<String>()
            .parse()
            .map_err(|_| self.error("quantifier bound is out of range"))
    }

    fn atom(&mut self) -> Result<Node, PatternError> {
        let Some(ch) = self.peek() else {
            return Err(self.error("unexpected end of pattern"));
        };
        self.pos += 1;
        match ch {
            '^' => Ok(Node::Start),
            '$' => Ok(Node::End),
            '.' => Ok(Node::Any),
            '(' => {
                if self.peek() == Some('?') {
                    return Err(self.error("only plain groups are supported"));
                }
                let alternatives = self.alternation()?;
                if self.peek() != Some(')') {
                    return Err(self.error("unterminated group"));
                }
                self.pos += 1;
                Ok(Node::Group(alternatives))
            }
            '[' => self.class(),
            '\\' => self.escape().map(|item| match item {
                ClassItem::Single(ch) => Node::Literal(ch),
                other => Node::Class {
                    negated: false,
                    items: vec![other],
                },
            }),
            '*' | '+' | '?' => Err(self.error("a quantifier must follow an atom")),
            other => Ok(Node::Literal(other)),
        }
    }

    fn class(&mut self) -> Result<Node, PatternError> {
        let negated = self.peek() == Some('^');
        if negated {
            self.pos += 1;
        }
        let mut items = Vec::new();
        loop {
            let Some(ch) = self.peek() else {
                return Err(self.error("unterminated character class"));
            };
            if ch == ']' {
                self.pos += 1;
                if items.is_empty() {
                    return Err(self.error("empty character class"));
                }
                return Ok(Node::Class { negated, items });
            }
            self.pos += 1;
            let low = if ch == '\\' { self.escape()? } else { ClassItem::Single(ch) };
            // A `-` is a range only between two single characters and never immediately before
            // the closing bracket, which is how `[...~-]` keeps its literal trailing dash.
            if let ClassItem::Single(start) = low
                && self.peek() == Some('-')
                && self.chars.get(self.pos + 1).copied() != Some(']')
            {
                self.pos += 1;
                let Some(end_ch) = self.peek() else {
                    return Err(self.error("unterminated character range"));
                };
                self.pos += 1;
                let end = if end_ch == '\\' {
                    match self.escape()? {
                        ClassItem::Single(ch) => ch,
                        _ => return Err(self.error("a class escape cannot end a range")),
                    }
                } else {
                    end_ch
                };
                if end < start {
                    return Err(self.error("character range runs backwards"));
                }
                items.push(ClassItem::Range(start, end));
                continue;
            }
            items.push(low);
        }
    }

    fn escape(&mut self) -> Result<ClassItem, PatternError> {
        let Some(ch) = self.peek() else {
            return Err(self.error("trailing backslash"));
        };
        self.pos += 1;
        match ch {
            'd' => Ok(ClassItem::Digit),
            'w' => Ok(ClassItem::Word),
            's' => Ok(ClassItem::Space),
            'n' => Ok(ClassItem::Single('\n')),
            'r' => Ok(ClassItem::Single('\r')),
            't' => Ok(ClassItem::Single('\t')),
            'D' | 'W' | 'S' | 'b' | 'B' | 'A' | 'z' | 'Z' => Err(self.error("negated and boundary escapes are not supported")),
            other => Ok(ClassItem::Single(other)),
        }
    }
}

fn class_item_matches(item: &ClassItem, ch: char) -> bool {
    match item {
        ClassItem::Single(expected) => *expected == ch,
        ClassItem::Range(low, high) => *low <= ch && ch <= *high,
        ClassItem::Digit => ch.is_ascii_digit(),
        ClassItem::Word => ch.is_alphanumeric() || ch == '_',
        ClassItem::Space => ch.is_whitespace(),
    }
}

/// Collects every position at which `nodes` can finish when started at `pos`.
///
/// Enumerating positions rather than threading a continuation is what makes termination obvious:
/// a repetition only ever recurses on a strictly larger position, so a zero-width repetition body
/// cannot loop. The sets are deduplicated at every step, which also keeps a `+` over a long string
/// linear instead of exponential.
fn seq_ends(nodes: &[Node], text: &[char], pos: usize, out: &mut Vec<usize>) {
    match nodes.split_first() {
        None => out.push(pos),
        Some((head, rest)) => {
            let mut middle = Vec::new();
            node_ends(head, text, pos, &mut middle);
            middle.sort_unstable();
            middle.dedup();
            for next in middle {
                seq_ends(rest, text, next, out);
            }
        }
    }
}

fn node_ends(node: &Node, text: &[char], pos: usize, out: &mut Vec<usize>) {
    match node {
        Node::Start => {
            if pos == 0 {
                out.push(pos);
            }
        }
        Node::End => {
            if pos == text.len() {
                out.push(pos);
            }
        }
        Node::Literal(expected) => {
            if text.get(pos) == Some(expected) {
                out.push(pos + 1);
            }
        }
        Node::Any => {
            if matches!(text.get(pos), Some(ch) if *ch != '\n') {
                out.push(pos + 1);
            }
        }
        Node::Class { negated, items } => {
            if let Some(ch) = text.get(pos) {
                let hit = items.iter().any(|item| class_item_matches(item, *ch));
                if hit != *negated {
                    out.push(pos + 1);
                }
            }
        }
        Node::Group(alternatives) => {
            for alternative in alternatives {
                seq_ends(alternative, text, pos, out);
            }
        }
        Node::Repeat { inner, min, max } => repeat_ends(inner, *min, *max, text, pos, out),
    }
}

fn repeat_ends(inner: &Node, min: u32, max: Option<u32>, text: &[char], pos: usize, out: &mut Vec<usize>) {
    if min == 0 {
        out.push(pos);
    }
    if max == Some(0) {
        return;
    }
    let mut middle = Vec::new();
    node_ends(inner, text, pos, &mut middle);
    middle.sort_unstable();
    middle.dedup();
    for next in middle {
        // A zero-width body counts as no repetition at all; without this the recursion would not
        // terminate and `(a?)*` would hang instead of matching.
        if next > pos {
            repeat_ends(inner, min.saturating_sub(1), max.map(|limit| limit - 1), text, next, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, text: &str) -> bool {
        Pattern::compile(pattern).expect("supported pattern").is_match(text)
    }

    #[test]
    fn case_ids_are_accepted_and_near_misses_are_not() {
        let pattern = "^c-[a-z0-9]+(-[a-z0-9]+)*-[0-9]{4}$";
        assert!(matches(pattern, "c-etag-0001"));
        assert!(matches(pattern, "c-object-lock-0002"));
        assert!(!matches(pattern, "c-etag-001"));
        assert!(!matches(pattern, "c-Etag-0001"));
        assert!(!matches(pattern, "x-etag-0001"));
        assert!(!matches(pattern, "c-etag-0001 "));
    }

    #[test]
    fn hex_pairs_require_an_even_length() {
        let pattern = "^([0-9a-fA-F]{2})*$";
        assert!(matches(pattern, ""));
        assert!(matches(pattern, "deadBEEF"));
        assert!(!matches(pattern, "abc"));
        assert!(!matches(pattern, "zz"));
    }

    #[test]
    fn a_trailing_dash_in_a_class_is_a_literal() {
        let pattern = "^[A-Za-z0-9!#$%&'*+.^_`|~-]+$";
        assert!(matches(pattern, "x-amz-checksum-crc32"));
        assert!(matches(pattern, "~|`"));
        assert!(!matches(pattern, "bad header"));
    }

    #[test]
    fn alternation_without_an_end_anchor_is_a_prefix_test() {
        let pattern = "^(https://|urn:)";
        assert!(matches(pattern, "https://example.test/a"));
        assert!(matches(pattern, "urn:x"));
        assert!(!matches(pattern, "http://example.test"));
    }

    #[test]
    fn an_unanchored_pattern_searches() {
        assert!(matches(r"\.\.", "goldens/../etc"));
        assert!(!matches(r"\.\.", "goldens/a.xml"));
    }

    #[test]
    fn the_instant_pattern_rejects_a_missing_zulu() {
        let pattern = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$";
        assert!(matches(pattern, "2026-01-02T03:04:05Z"));
        assert!(matches(pattern, "2026-01-02T03:04:05.000Z"));
        assert!(!matches(pattern, "2026-01-02T03:04:05"));
        assert!(!matches(pattern, "2026-01-02 03:04:05Z"));
    }

    #[test]
    fn unsupported_constructs_are_refused_rather_than_approximated() {
        assert!(Pattern::compile("(?i)abc").is_err());
        assert!(Pattern::compile("a{1,2}?").is_err());
        assert!(Pattern::compile("\\b").is_err());
        assert!(Pattern::compile("[a-").is_err());
        assert!(Pattern::compile("(ab").is_err());
        assert!(Pattern::compile("ab)").is_err());
    }
}
