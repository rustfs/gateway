#!/usr/bin/env bash
set -euo pipefail

# Payload negotiation is a named enum contract. Runtime downcasts can bypass
# wrappers and silently turn a missing fast path into an unobserved fallback.
#
# Three rules, in widening scope:
#   1. `fn as_any` / `.as_any()` anywhere in the repository. No exemption exists,
#      because this identifier has exactly one purpose.
#   2. Any `Any` or downcast, in any spelling, inside the payload data plane. No
#      exemption exists here either: this is the seam where a transport would
#      reach past a validating wrapper to the payload inside it.
#   3. `downcast_ref` / `downcast_mut` / `downcast_mut_pin` elsewhere in the
#      repository, with a single-point allowlist. Typed dispatch through a
#      `TypeId`-keyed map is a different thing from payload negotiation, and the
#      allowlist is what forces each such site to be named and argued for once,
#      in the open, rather than spreading unremarked.
#
# WHAT COUNTS AS THE DATA PLANE
#   Two directories -- `crates/stream/src` and `crates/http/src` -- plus any file
#   anywhere in the workspace that implements `PayloadStream` or
#   `AsyncPayloadRead`. A directory list alone is a rule about where code sits;
#   a producer or consumer of a payload is payload negotiation wherever somebody
#   puts it, and the directory form would have let a new crate implement the
#   traits and then take an allowlist entry for the downcast beside them.
#
# THE ALLOWLIST, AND HOW EMPTY IT HAS TO BE
#   rustfs/backlog#1690 says two things that cannot both hold: section 4.3 grants
#   a single-point allowlist for `Extensions` internals, and section 11.5 requires
#   the allowlist to be empty. Section 4.3 governs, and 11.5 is read as the scope
#   that makes it true and checkable: the allowlist is EMPTY INSIDE THE DATA
#   PLANE, and every entry outside it carries a written reason. The threat 11.5
#   exists to close -- a transport reaching past a validating wrapper -- lives
#   entirely in the data plane; outside it, a `TypeId`-keyed map reading back the
#   value its own `insert` boxed is dispatch, and a mismatch fails loudly instead
#   of degrading silently. The emptiness is asserted below, not asserted in prose.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

source "${SCRIPT_DIR}/lib/python.sh"
PYTHON="$(gateway_python check_no_as_any)" || exit 1

"$PYTHON" - "$ROOT_DIR" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
source = root / "crates/stream/src"
if not source.is_dir():
    print("check_no_as_any: required input is missing: crates/stream/src", file=sys.stderr)
    raise SystemExit(1)
crates = root / "crates"
if not crates.is_dir():
    print("check_no_as_any: required input is missing: crates", file=sys.stderr)
    raise SystemExit(1)
# Every workspace member, not `crates/` alone: `spikes/ext-field` is a member too, so an
# escape hatch written there is code that compiles under `--workspace` like any other.
roots = [crates] + [root / "spikes", root / "xtask"]

# The payload data plane: the crate that owns `Payload`, and the wire layer that
# produces and consumes one. Both are exemption-free.
SEALED = ("crates/stream/src", "crates/http/src")
# The bucket a file lands in when it is data plane because of what it implements rather than
# because of where it sits.
IMPLEMENTOR = "a payload producer or consumer"

allowance_file = root / "scripts/allowances/as-any-allowances.txt"
allowances = {}
# Where each entry was written, so the data-plane rejection below can still point at the line
# that has to be deleted. The rejection cannot run here: whether a path is in the data plane
# now depends on what that file implements, which is not known until the sources are read.
allowance_lines = {}
if allowance_file.is_file():
    for number, raw in enumerate(allowance_file.read_text().splitlines(), start=1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        allowance_lines[entry] = number
        allowances[entry] = raw.split("#", 1)[1].strip() if "#" in raw else ""
        if not allowances[entry]:
            print(
                f"scripts/allowances/as-any-allowances.txt:{number}: '{entry}' carries no reason; "
                "an unexplained exemption is the state this allowlist exists to prevent",
                file=sys.stderr,
            )
            raise SystemExit(1)


# Compiled once, then matched with an offset. Cutting a fresh `text[index:]` slice copies the
# whole remainder of the file on every character, which makes an otherwise linear scan
# quadratic in file length; `pattern.match(text, index)` matches at the same place without the
# copy. No pattern here carries `^`, `\A`, `\b` or a lookbehind, so anchoring at the offset is
# exactly what slicing to it already meant. Both `.end()` values are now absolute offsets into
# `text`.
RAW_STRING_RE = re.compile(r'(?:b|c)?r(#*)"')
LIFETIME_RE = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*(?!')")


def strip(text: str) -> str:
    """Blank out comments and string literals, preserving every newline.

    Both `crates/stream` and this repository's guards explain the no-downcast rule in prose
    sitting directly beside the code it governs. A guard that reports its own documentation is
    a guard somebody switches off, so the prose is removed before the scan and the line count
    is kept so a reported line still points at real code.
    """
    out = []
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end < 0 else end
            continue
        if text.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    if text[index] == "\n":
                        out.append("\n")
                    index += 1
            continue
        raw = RAW_STRING_RE.match(text, index)
        if raw:
            marker = '"' + raw.group(1)
            end = text.find(marker, raw.end())
            if end < 0:
                raise ValueError("unterminated raw string")
            out.append("\n" * text.count("\n", index, end + len(marker)))
            index = end + len(marker)
            continue
        lifetime = LIFETIME_RE.match(text, index)
        if lifetime:
            out.append(lifetime.group())
            index = lifetime.end()
            continue
        quote = index + 1 if text[index] in "bc" and index + 1 < length else index
        if text[quote] in "\"'":
            delimiter = text[quote]
            cursor = quote + 1
            while cursor < length:
                if text[cursor] == "\\":
                    cursor += 2
                elif text[cursor] == delimiter:
                    cursor += 1
                    break
                else:
                    cursor += 1
            else:
                raise ValueError("unterminated literal")
            out.append("\n" * text.count("\n", index, cursor))
            index = cursor
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


AS_ANY = re.compile(r"\bfn\s+as_any\b|\.\s*as_any\s*\(")
SEALED_DOWNCAST = re.compile(r"\bfn\s+as_any\b|\.\s*as_any\s*\(|\bdowncast\w*\b|\bAny\b")
DOWNCAST = re.compile(r"\bdowncast_(?:ref|mut|mut_pin)\b")

violations = []
scanned = 0
sealed_scanned = {prefix: 0 for prefix in SEALED}
sealed_scanned[IMPLEMENTOR] = 0

# Each half of the payload data plane is required to exist and to hold sources. Counting the
# two together would let one of them be deleted or moved while the other kept the total above
# zero, and the guard would report green over a wire layer it no longer reads.
for prefix in SEALED:
    directory = root / prefix
    if not directory.is_dir() or not any(directory.rglob("*.rs")):
        print(f"check_no_as_any: required input is missing: {prefix}", file=sys.stderr)
        raise SystemExit(1)

# Stripping comments and literals is the expensive step, and almost no file in the workspace
# contains any of these tokens at all. The raw text is a superset of the stripped text, so a
# file with no match before stripping cannot have one after: skipping those is a shortcut in
# cost only, never in coverage.
CANDIDATE = re.compile(r"as_any|downcast|\bAny\b")

# The half of the data plane a directory list cannot see: a file that implements either half
# of the payload contract is payload negotiation wherever it lives. Matching the raw text is
# enough here because an occurrence inside a comment or a string only ever widens the sealed
# set, and widening it is the safe direction.
IMPLEMENTS = re.compile(r"\bimpl\b[^\n]*\b(?:PayloadStream|AsyncPayloadRead)\b[^\n]*\bfor\b")

registered = set()
sources = sorted({path for directory in roots if directory.is_dir() for path in directory.rglob("*.rs")})
texts = {}
for path in sources:
    relative = path.relative_to(root).as_posix()
    if "/generated/" in relative or "/target/" in relative:
        continue
    try:
        texts[relative] = path.read_text()
    except (OSError, UnicodeError) as error:
        print(f"check_no_as_any: cannot read {relative}: {error}", file=sys.stderr)
        raise SystemExit(1)

implementors = {
    relative
    for relative, text in texts.items()
    if ("PayloadStream" in text or "AsyncPayloadRead" in text) and IMPLEMENTS.search(text)
}
# Fail closed. If nothing in the workspace implements either half any more, the rule below has
# quietly narrowed back to two directory names and nobody would see it in a green line.
if not implementors:
    print(
        "check_no_as_any: required input is missing: no file implements PayloadStream or "
        "AsyncPayloadRead, so the content-defined half of the data plane is empty",
        file=sys.stderr,
    )
    raise SystemExit(1)


def sealed_for(relative: str) -> str | None:
    """The data plane a file belongs to: a directory of it, or the contract it implements."""
    for prefix in SEALED:
        if relative.startswith(f"{prefix}/"):
            return prefix
    return IMPLEMENTOR if relative in implementors else None


# The allowlist rejection that had to wait for the data plane to be known.
for entry, number in sorted(allowance_lines.items(), key=lambda pair: pair[1]):
    where = sealed_for(entry.rsplit(":", 1)[0])
    if where is not None:
        print(
            f"scripts/allowances/as-any-allowances.txt:{number}: '{entry}' is inside the payload "
            f"data plane ({where}), which takes no exemptions; the negotiation seam is the whole "
            "point of the rule",
            file=sys.stderr,
        )
        raise SystemExit(1)

for relative, text in texts.items():
    scanned += 1
    sealed = sealed_for(relative)
    if sealed:
        sealed_scanned[sealed] = sealed_scanned.get(sealed, 0) + 1
    if not CANDIDATE.search(text):
        continue
    try:
        code = strip(text)
    except ValueError as error:
        print(f"check_no_as_any: cannot read {relative}: {error}", file=sys.stderr)
        raise SystemExit(1)
    pattern = SEALED_DOWNCAST if sealed else AS_ANY
    for match in pattern.finditer(code):
        line = code.count("\n", 0, match.start()) + 1
        violations.append(f"{relative}:{line}: runtime downcast escape hatch")
    if sealed:
        continue
    for match in DOWNCAST.finditer(code):
        line = code.count("\n", 0, match.start()) + 1
        registered.add(f"{relative}:{line}")
        if f"{relative}:{line}" in allowances:
            continue
        violations.append(
            f"{relative}:{line}: {match.group()} outside the payload data plane is unregistered; "
            "add it to scripts/allowances/as-any-allowances.txt with a reason, or use a named accessor"
        )

# The rule's positive half. "There is no `as_any()`" is only an argument if the named
# accessors it points at still exist; if they were removed or renamed, the guard would go on
# reporting green over a `Payload` with no negotiation surface at all.
payload = source / "payload.rs"
if not payload.is_file():
    print("check_no_as_any: required input is missing: crates/stream/src/payload.rs", file=sys.stderr)
    raise SystemExit(1)
payload_code = strip(payload.read_text())
for accessor in ("try_into_file_region", "try_as_vectored", "try_into_reader", "try_into_stream"):
    if not re.search(rf"\bpub\s+fn\s+{accessor}\b", payload_code):
        violations.append(
            f"crates/stream/src/payload.rs: the named accessor '{accessor}' is gone; banning as_any() "
            "means nothing unless the negotiation it replaced is still reachable by name"
        )

for entry in sorted(set(allowances) - registered):
    violations.append(
        f"scripts/allowances/as-any-allowances.txt: '{entry}' no longer names a downcast; "
        "a stale exemption silently covers whatever moves onto that line next"
    )

if violations:
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)

# Section 11.5 of rustfs/backlog#1690, as ruled at the top of this file: the number the issue
# wanted at zero is the data-plane one, and it is printed rather than assumed so a reader can
# see which of the two counts is the one being held at zero.
print(
    f"OK: no as_any/downcast in the payload data plane "
    f"({scanned} file(s) scanned, {sum(sealed_scanned.values())} in the data plane "
    f"of which {sealed_scanned[IMPLEMENTOR]} by what they implement; "
    f"allowlist: {len(allowances)} entries, 0 of them in the data plane)"
)
PY
