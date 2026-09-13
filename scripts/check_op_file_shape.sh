#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# check_op_file_shape.sh
#
# WHAT THIS CHECKS
#   The three halves of AGENTS.md's "One Operation Per File" rule.
#
#   1. One operation per file.
#      Every `crates/core/src/ops/<stem>.rs` declares exactly one
#      `impl Operation`, its type's snake_case name is the file stem, and
#      `ops/mod.rs` mounts it. No other file under `crates/*/src/**` declares
#      one, and no `ops/shared/**` module does.
#
#   2. The `//! Shares:` declaration agrees with the use graph and with the
#      `//! Members:` list on the other end — in both directions, for both.
#
#      Lifecycle and replication must also call their shared Filter grammar from
#      production code; comments, literals and test helpers do not establish it.
#
#   3. The 800-line ceiling over the ops tree, with no allowance escape.
#
# WHY
#   Rule 1 is not about `grep`. It is the unit of parallel edit conflict: two
#   agents changing two operations produce no git conflict at all. A second
#   `impl Operation` in one file, or one hidden outside `ops/`, silently takes
#   that property away — and a file no `pub mod` mounts is compiled by nothing
#   while reading exactly like an implemented operation.
#
#   Rule 2 is the counterweight that keeps the List, Copy and Conditional
#   clusters from reproducing the s3s #499 vs #632 defect, where one rule lived
#   in two places and two fixes contradicted each other. It has three edges, and
#   this guard owns two of them:
#
#       //! Shares:  <--(a)-->  the `shared::<module>` use graph
#            |                          ^
#            |                          |
#           (b)                 check_shared_members.sh
#            |                          |
#            v                          |
#       //! Members:  <------------------
#
#     (a) and (b) are checked here; `check_shared_members.sh` checks the third.
#     Both of ours are needed. Edge (a) alone is weak in one direction, because
#     the configuration families declare their sharing as an intra-doc link —
#     `[`shared::cors`](super::shared::cors)` — which is itself a reference, so
#     a declaration can satisfy (a) by existing. Edge (b) closes exactly that
#     hole: it cannot be satisfied from one file, because the answer lives in
#     the other one. `copy_object.rs` claimed `etag` for four months while
#     `shared/etag.rs` said in prose that CopyObject deliberately was not a
#     member; (b) is what turns that disagreement into a red build.
#
#   "Reaches" means any `shared::<module>` path in the file, an intra-doc link
#   included. That is the same definition `check_shared_members.sh` uses, and
#   the two must not diverge: if one counted a doc link and the other did not,
#   the pair would demand opposite edits to the same header and no edit would
#   make both green.
#
#   Rule 3 exists because `allowances/file_size.txt` can raise the ceiling
#   anywhere else, and an operation file is the one place the answer to "it does
#   not fit" is never a higher limit: over 800 lines it is either two operations,
#   or prose that belongs in `shared/`.
#
#   None of this was enforced until rustfs/backlog#1895. Both documents said it
#   was — `scripts/README.md`'s registry row and AGENTS.md's "enforces this from
#   P1; the rule binds now" — which is the "check that cannot fail" shape
#   AGENTS.md's Measurement section lists seven prior instances of. The two
#   declarations it found on the day it was written had both been merged, green,
#   under a guard that did not exist.
#
# HOW TO EXEMPT
#   There is none, for any of the three rules, and the ops tree is deliberately
#   cut out of the one exemption that exists elsewhere (`allowances/file_size.txt`
#   may not name a path under `crates/core/src/ops/`).
#
#   A shared module used by nobody yet should carry no `//! Members:` line at
#   all — it is then not a shared contract, and nothing here asks it to be. An
#   operation that shares a rule with a family that has no module under
#   `ops/shared/` says so in prose: `//! Shares: the upload-id capability with
#   the rest of the multipart family.` Prose declares no module, and the use
#   graph then has to be empty too.
#
#   Implementations of `Operation` in tests, examples and `#[cfg(test)]` modules
#   are not covered: the trait is public, a third-party dialect operation is a
#   supported use of it, and those are not the files two agents edit in parallel.
#
# USAGE
#   scripts/check_op_file_shape.sh
#   GATEWAY_CHECK_ROOT=/path/to/repo scripts/check_op_file_shape.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$ROOT_DIR"

# These always exist. A guard whose input is missing must fail, not skip: the
# `|| exit 0` form is right for a directory that may not exist yet, and wrong
# here, where a missing ops tree means the repository moved and this guard has
# been reporting success over nothing.
source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_op_file_shape)" || exit 1
"$PYTHON" - "crates/core/src/ops" "allowances/file_size.txt" <<'PYEOF'
import pathlib
import re
import sys

ops_dir = pathlib.Path(sys.argv[1])
allowances = pathlib.Path(sys.argv[2])
shared_dir = ops_dir / "shared"
mod_file = ops_dir / "mod.rs"
CEILING = 800

status = 0


def fail(message: str) -> None:
    global status
    status = 1
    print(message, file=sys.stderr)


for required in (ops_dir, shared_dir, mod_file, allowances):
    if not required.exists():
        print(
            f"check_op_file_shape: required input is missing: {required}",
            file=sys.stderr,
        )
        raise SystemExit(1)


RAW_STRING_OPEN = re.compile(r'r(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\.|[^\\'])'")


def mask(text: str) -> str:
    """Blank out comments and literals, keeping every offset where it was.

    Everything that looks for Rust *code* reads this; everything that reads the
    module documentation reads the original. Without it `//! `impl Operation for
    MyOp`` in `op.rs`'s prose is a violation, and a `{` inside a string is a
    brace.
    """
    out = list(text)
    i = 0
    n = len(text)

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif ch == "r" and (m := RAW_STRING_OPEN.match(text, i)):
            hashes = m.group(1)
            close = text.find('"' + hashes, m.end())
            j = n if close == -1 else close + 1 + len(hashes)
            blank(i, j)
            i = j
        elif ch == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
        elif ch == "'" and (m := CHAR_LITERAL.match(text, i)):
            # A char literal. A bare `'` that does not close is a lifetime, and
            # masking from there to the next quote would swallow real code.
            j = m.end()
            blank(i, j)
            i = j
        else:
            i += 1
    return "".join(out)


def cfg_test_spans(code: str) -> list[tuple[int, int]]:
    """Every `#[cfg(test)]` item, from its attribute to the end of that item.

    An item ends at its own balanced closing brace *or* at its own terminating
    semicolon, whichever comes first. The semicolon arm is not decoration: the
    `#[cfg(test)] #[path = "x_tests.rs"] mod tests;` split this repository uses
    when a file crosses the 800-line limit never opens a brace, so searching
    ahead for a `{` walks past the whole declaration and lands on the *next*
    braced item in the file — which is then suppressed as though it were test
    code. 35 declarations in this workspace have that shape, and on the day this
    was written the resulting spans covered 25,124 bytes of production code:
    `crates/sig/src/lib.rs` hid its `pub use canonical::{ .. }` re-export list
    behind `mod full_chain_tests;`, and `crates/core/src/codec/mod.rs` hid
    `pub use crate::codec::response::{ .. }` behind `mod tests;`.

    Nothing in that suppressed text happened to be an `impl Operation`, so no
    declaration was actually missed — the property this restores is that adding
    one there cannot go unnoticed. The same defect in
    `check_cors_credentials_exclusive.sh` (rustfs/gateway#238) ran to end of file
    instead, because that scanner blanked forward rather than searching for a
    brace; both are the one shape, a bodyless item read as though it had a body.
    """
    spans = []
    for marker in re.finditer(r"#\[cfg\(test\)\]", code):
        start = code.find("{", marker.end())
        terminator = code.find(";", marker.end())
        if start == -1 and terminator == -1:
            continue
        # `code` is already masked, so a `;` inside a comment or a string cannot
        # end an item here, and a `{` inside one cannot open a body.
        if start == -1 or (terminator != -1 and terminator < start):
            spans.append((marker.start(), terminator))
            continue
        depth = 0
        end = start
        while end < len(code):
            if code[end] == "{":
                depth += 1
            elif code[end] == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        spans.append((marker.start(), end))
    return spans


OPERATION_IMPL = re.compile(
    r"\bimpl\s*(?:<[^>]*>)?\s*Operation\s+for\s+([A-Za-z_][A-Za-z0-9_]*)"
)


def operation_impls(text: str) -> list[str]:
    """Every `impl Operation for X` in real code outside a test module."""
    code = mask(text)
    spans = cfg_test_spans(code)
    found = []
    # `impl<T> Operation for Probe<T>` is still an operation declaration. Matching only
    # the bare form leaves one turn of the screw between a second operation and a guard
    # that cannot see it.
    for match in re.finditer(OPERATION_IMPL, code):
        if any(start <= match.start() <= end for start, end in spans):
            continue
        found.append(match.group(1))
    return found


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


# A `//! <Label>:` field, continued over the `//!` lines under it. It ends at the
# first blank `//!` line, at the next labelled field, at a `# ` heading, or when
# the doc block does.
FIELD_END = re.compile(
    r"^(?:#|Responsible for:|NOT responsible for:|Upstream:|Downstream:|Members:|Shares:)"
)


def doc_field(text: str, label: str) -> str | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith(f"//! {label}:"):
            continue
        collected = [line[len(f"//! {label}:") :].strip()]
        for follower in lines[index + 1 :]:
            if not follower.startswith("//!"):
                break
            body = follower[3:].strip()
            if body == "" or FIELD_END.match(body):
                break
            collected.append(body)
        return " ".join(collected)
    return None


shared_modules = {
    path.stem for path in sorted(shared_dir.glob("*.rs")) if path.stem != "mod"
}
op_files = [path for path in sorted(ops_dir.glob("*.rs")) if path.name != "mod.rs"]
op_stems = {path.stem for path in op_files}
mod_text = mask(mod_file.read_text())
mounted = set(re.findall(r"^\s*pub mod\s+([a-z_][a-z0-9_]*)\s*;", mod_text, re.M))

# -- Rule 1 -------------------------------------------------------------------

for path in op_files:
    text = path.read_text()
    impls = operation_impls(text)
    if len(impls) != 1:
        fail(
            f"{path}: declares {len(impls)} `impl Operation`, and an operation module "
            f"declares exactly one"
        )
        if len(impls) > 1:
            print(
                f"    Found: {', '.join(impls)}. Two operations in one file is the git "
                f"conflict the rule exists to prevent; give the second one its own file.",
                file=sys.stderr,
            )
    elif snake(impls[0]) != path.stem:
        fail(
            f"{path}: operation name and file name disagree: `{impls[0]}` belongs in "
            f"{ops_dir / (snake(impls[0]) + '.rs')}"
        )
    if path.stem not in mounted:
        fail(
            f"{path}: no `pub mod` in {mod_file} mounts it, so nothing compiles it"
        )
        print(
            "    An unmounted operation module is invisible to rustc and reads exactly "
            "like an implemented operation. (The opposite direction — a `pub mod` with "
            "no file — is E0583 and needs no guard.)",
            file=sys.stderr,
        )

for path in sorted(shared_dir.rglob("*.rs")):
    impls = operation_impls(path.read_text())
    if impls:
        fail(
            f"{path}: a shared contract declares `impl Operation for {impls[0]}`; "
            f"an operation belongs in {ops_dir}/<snake_name>.rs"
        )

for crate_src in sorted(pathlib.Path("crates").glob("*/src")):
    for path in sorted(crate_src.rglob("*.rs")):
        if ops_dir in path.parents or shared_dir in path.parents:
            continue
        if "generated" in path.parts:
            continue
        if path.is_symlink():
            continue
        impls = operation_impls(path.read_text())
        if impls:
            fail(
                f"{path}: declares `impl Operation` outside the ops tree: "
                f"{', '.join(impls)}"
            )
            print(
                f"    One operation per file means one place to look for it. Move it to "
                f"{ops_dir}/<snake_name>.rs, or put it behind `#[cfg(test)]` if it is a "
                f"fixture.",
                file=sys.stderr,
            )

# -- Rule 2 -------------------------------------------------------------------


def declared_modules(block: str, path: pathlib.Path) -> set[str]:
    """The `ops/shared/` modules a `//! Shares:` block names.

    Two accepted forms, and the first token decides which:

      `//! Shares: copy_source, precondition`   a list of module names
      `//! Shares: the upload-id capability …`  prose, for a family with no module

    Prose names no module unless it links one, which is what keeps a real
    declaration from being spelled as an English sentence by accident. A list
    whose first item is a module and whose fourth is not is neither form — it is
    a list with a mistake in it, and it is reported as one.
    """
    named: set[str] = set()
    leading = re.match(r"([a-z_][a-z0-9_]*(?:\s*,\s*[a-z_][a-z0-9_]*)*)", block)
    items = [item.strip() for item in leading.group(1).split(",")] if leading else []
    known = [item for item in items if item in shared_modules]
    if items == ["nothing"]:
        pass
    elif known and len(known) == len(items):
        named |= set(items)
    elif known:
        unknown = [item for item in items if item not in shared_modules]
        fail(
            f"{path}: `//! Shares:` names {', '.join('`' + item + '`' for item in unknown)}, "
            f"which is not a module under {shared_dir}"
        )
        named |= set(known)
    for link in re.finditer(r"\bshared::([a-z_][a-z0-9_]*)", block):
        module = link.group(1)
        if module in shared_modules:
            named.add(module)
        else:
            fail(
                f"{path}: `//! Shares:` links `shared::{module}`, which is not a module "
                f"under {shared_dir}"
            )
    return named


shares: dict[str, set[str]] = {}
for path in op_files:
    text = path.read_text()
    block = doc_field(text, "Shares")
    if block is None:
        fail(
            f"{path}: has no `//! Shares:` declaration; every operation module states its "
            f"shared surface, `//! Shares: nothing.` included"
        )
        shares[path.stem] = set()
        continue
    named = declared_modules(block, path)
    shares[path.stem] = named
    reached = {
        module
        for module in shared_modules
        if re.search(rf"\bshared::{module}\b", text)
    }
    for module in sorted(named - reached):
        fail(
            f"{path}: `//! Shares:` names `{module}`, which this file never reaches"
        )
        print(
            "    A declared contract that is wired into nothing is the state the "
            "declaration exists to make visible. Use it, or stop naming it.",
            file=sys.stderr,
        )
    for module in sorted(reached - named):
        fail(
            f"{path}: reaches `shared::{module}`, which its `//! Shares:` line does not name"
        )
        print(
            "    The header is where the next agent learns which rules this operation "
            "does not own alone.",
            file=sys.stderr,
        )

members: dict[str, set[str] | None] = {}
for path in sorted(shared_dir.glob("*.rs")):
    if path.name == "mod.rs":
        continue
    block = doc_field(path.read_text(), "Members")
    if block is None:
        members[path.stem] = None
        continue
    members[path.stem] = {
        snake(name.strip()) for name in block.split(",") if name.strip()
    }

for stem in sorted(shares):
    for module in sorted(shares[stem]):
        named = members.get(module)
        if named is None:
            fail(
                f"{shared_dir / (module + '.rs')}: has no `//! Members:` line, but "
                f"{ops_dir / (stem + '.rs')} declares it under `//! Shares:`"
            )
        elif stem not in named:
            fail(
                f"{ops_dir / (stem + '.rs')}: declares `//! Shares: {module}`, but "
                f"{shared_dir / (module + '.rs')}'s `Members:` does not name it"
            )
            print(
                "    The two ends of one declaration disagree. Only one of them can be "
                "right, and neither file can settle it alone — which is the whole reason "
                "the contract is written down twice.",
                file=sys.stderr,
            )

for module in sorted(members):
    named = members[module]
    if named is None:
        continue
    for stem in sorted(named):
        if stem not in op_stems:
            fail(
                f"{shared_dir / (module + '.rs')}: `Members:` names an operation with no "
                f"module: {ops_dir / (stem + '.rs')} does not exist"
            )
        elif module not in shares[stem]:
            fail(
                f"{shared_dir / (module + '.rs')}: `Members:` names `{stem}`, whose "
                f"`//! Shares:` line does not name `{module}` back"
            )

# Both DTO families must call the same production filter grammar. Unlike the
# operation-to-family documentation links above, this is an executable edge.
filter_authority = shared_dir / "rule_filter.rs"
if not filter_authority.is_file():
    fail(f"{filter_authority}: shared filter authority is missing")
for family in ("lifecycle", "replication"):
    path = shared_dir / (family + ".rs")
    if not path.is_file():
        fail(f"{path}: shared filter consumer is missing")
        continue
    code = mask(path.read_text())
    for start, end in reversed(cfg_test_spans(code)):
        code = code[:start] + " " * (end - start) + code[end:]
    if re.search(r"\bfn\s+validate_filter\s*\(", code):
        fail(f"{path}: filter grammar belongs to shared::rule_filter")
    if not re.search(r"\brule_filter\s*::\s*validate\s*\(", code):
        fail(f"{path}: must call shared::rule_filter from production code")

# -- Rule 3 -------------------------------------------------------------------

for path in sorted(ops_dir.rglob("*.rs")):
    lines = len(path.read_text().splitlines())
    if lines > CEILING:
        fail(f"{path}: {lines} lines, over the {CEILING}-line ceiling")
        print(
            "    Over the ceiling an operation file is either two operations or prose "
            "that belongs in shared/. There is no allowance for this path.",
            file=sys.stderr,
        )

for line in allowances.read_text().splitlines():
    entry = line.split("#", 1)[0].strip()
    if not entry:
        continue
    path = entry.split()[0]
    if path == str(ops_dir) or path.startswith(f"{ops_dir}/"):
        fail(
            f"{allowances}: names {path}; the ops tree has no ceiling exemption"
        )
        print(
            "    Everywhere else a reasoned, issue-linked allowance raises the limit. "
            "Here the answer to 'it does not fit' is a second file, never a higher "
            "number.",
            file=sys.stderr,
        )

raise SystemExit(status)
PYEOF
