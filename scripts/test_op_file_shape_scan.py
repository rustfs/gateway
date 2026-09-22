#!/usr/bin/env python3
"""Check operation scan work and rejection semantics; no repository files are mutated."""

import ast
import re
from pathlib import Path

source = Path(__file__).with_name("check_op_file_shape.sh").read_text()
python = source.split("<<'PYEOF'\n", 1)[1].rsplit("\nPYEOF", 1)[0]
tree = ast.parse(python)
names = {"RAW_STRING_OPEN", "CHAR_LITERAL", "OPERATION_IMPL"}
functions = {"mask", "cfg_test_spans", "operation_impls"}
nodes = [
    node for node in tree.body
    if (isinstance(node, ast.FunctionDef) and node.name in functions)
    or (isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id in names for target in node.targets
    ))
]
namespace = {"re": re}
exec(compile(ast.Module(body=nodes, type_ignores=[]), "<operation-scan>", "exec"), namespace)
scan = namespace["operation_impls"]
mask = namespace["mask"]

# Inputs lacking the required identifier must not pay for Rust lexical analysis.
def unexpected_mask(text):
    raise AssertionError("token-absent source was lexed")

namespace["mask"] = unexpected_mask
for text in ("", "fn main() {}", "impl Other for Value {}", "// ordinary prose\n"):
    assert scan(text) == [], text
namespace["mask"] = mask

# A raw-text candidate still owes full comment, literal, and test-module filtering.
for text in (
    "// impl Operation for Decoy {}\n",
    "/* impl Operation for Decoy {} */",
    'const S: &str = "impl Operation for Decoy {}";',
    'const S: &str = r#"impl Operation for Decoy {}"#;',
    "#[cfg(test)] mod tests { impl Operation for Decoy {} }",
):
    assert scan(text) == [], text
for text in (
    "impl Operation for Actual {}",
    "impl<T> Operation for Actual<T> {}",
    "#[cfg(test)] mod tests; impl Operation for Actual {}",
):
    assert scan(text) == ["Actual"], text
print("OK: operation scanner skips token-absent text and retains lexical rejection")
