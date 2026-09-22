#!/usr/bin/env python3
"""Check linear trait masking work and unchanged lexical rejection semantics."""

import ast
import re
from pathlib import Path

source = Path(__file__).with_name("trait_policy_scan.py").read_text()
function = next(node for node in ast.parse(source).body
                if isinstance(node, ast.FunctionDef) and node.name == "mask_rust")


class Source(str):
    def __getitem__(self, key):
        assert not (isinstance(key, slice) and key.stop is None), "copied source suffix"
        return super().__getitem__(key)


class Pattern:
    def __init__(self, pattern):
        self.inner = re.compile(pattern)

    def match(self, text, offset):
        assert text[offset] in "br", "raw regex dispatched for impossible prefix"
        return self.inner.match(text, offset)


class Regex:
    compile = staticmethod(Pattern)
    match = staticmethod(re.match)


namespace = {"re": Regex}
exec(compile(ast.Module(body=[function], type_ignores=[]), "<trait-mask>", "exec"), namespace)
mask = namespace["mask_rust"]

# Nonliteral code remains visible, including lifetime apostrophes and Unicode identifiers.
plain = Source("fn f<'a>(x: &'a str) { let résumé = borrow; }")
assert mask(plain) == plain

# Prefixing a literal exercises absolute regex offsets; code on both sides must survive.
for literal in ('r""', 'br#""#', 'r"trait Hidden {}"', 'br##"async_trait\ntrait Hidden {}"##',
                '"escaped \\\" text"', "'x'", '/* outer /* inner */ text */', '// text\n'):
    text = Source("before; " + literal + " after;")
    expected = "before; " + "".join("\n" if c == "\n" else " " for c in literal) + " after;"
    assert mask(text) == expected, literal

# Every malformed literal/comment still fails, even in files with no trait declaration.
for fragment in ('r"', 'br"', 'r#"', 'br##"', 'r#"text"', 'br##"text"#',
                 '"', 'b"', '"trailing\\', 'b"trailing\\', '/*', '/* nested /* */'):
    try:
        mask(Source("before; " + fragment))
    except ValueError:
        pass
    else:
        raise AssertionError(f"accepted malformed input: {fragment!r}")
print("OK: trait masking avoids suffix copies and preserves offsets and malformed-input rejection")
