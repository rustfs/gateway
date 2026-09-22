#!/usr/bin/env python3
"""Exercise signature evidence masking and regex dispatch without repository mutations."""

import ast
import re
from pathlib import Path

shell = Path(__file__).with_name("check_sig_case_coverage.sh").read_text()
inline = shell.split('"${evidence_requests[@]}" <<\'PYEOF\'\n', 1)[1].split('\nPYEOF', 1)[0]
validator = next(
    ast.literal_eval(node.value)
    for node in ast.parse(inline).body
    if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "validator" for target in node.targets)
)
scanner = compile(validator[validator.index("RAW_STRING_RE ="):validator.index("def delimiter_depth")],
                  "<signature-mask>", "exec")


class Pattern:
    def __init__(self, pattern):
        self.inner = re.compile(pattern)
        self.initials = "br" if pattern.startswith("(?:br|r)") else "b'"

    def match(self, text, offset):
        assert text[offset] in self.initials, "regex dispatched for an impossible initial character"
        return self.inner.match(text, offset)


class Regex:
    compile = staticmethod(Pattern)


def mask(text):
    namespace = {"re": Regex, "source": text, "path": "fixture.rs"}
    exec(scanner, namespace)
    return namespace["code"]


# Ordinary identifiers, lifetimes and Unicode must stay executable and avoid impossible matches.
for text in ("let alpha = 42;", "fn f<'a>(x: &'a str) {}", "let résumé = borrow;", "bravo rare b r"):
    assert mask(text) == text, text

# Evidence inside literals and comments must stay blank, with exact offsets and line breaks.
for literal in (
    '"claim"', 'b"claim"', 'c"claim"', 'r#"claim"#', 'br##"claim"##',
    "'x'", "b'x'", r"'\n'", r"'\u{10FFFD}'", r"b'\x41'", "'é'",
    '"escaped \\\" claim"', '/* nested /* claim */ rest */', '// claim\n',
):
    text = "before; " + literal + " after;"
    expected = "before; " + "".join("\n" if char == "\n" else " " for char in literal) + " after;"
    assert mask(text) == expected, literal
print("OK: signature scanner dispatch preserves literals, comments, offsets and lifetimes")
