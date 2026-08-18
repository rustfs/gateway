#!/usr/bin/env bash
set -euo pipefail

# Payload negotiation is a named enum contract. Runtime downcasts can bypass
# wrappers and silently turn a missing fast path into an unobserved fallback.
#
# Three rules, in widening scope:
#   1. `fn as_any` / `.as_any()` anywhere in the repository. No exemption exists,
#      because this identifier has exactly one purpose.
#   2. Any `Any` or downcast, in any spelling, inside the payload data plane
#      (`crates/stream/src` and `crates/http/src`). No exemption exists here
#      either: this is the seam where a transport would reach past a validating
#      wrapper to the payload inside it.
#   3. `downcast_ref` / `downcast_mut` / `downcast_mut_pin` elsewhere in the
#      repository, with a single-point allowlist. Typed dispatch through a
#      `TypeId`-keyed map is a different thing from payload negotiation, and the
#      allowlist is what forces each such site to be named and argued for once,
#      in the open, rather than spreading unremarked.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if ! command -v python3 >/dev/null 2>&1; then
    printf 'check_no_as_any: required command is missing: python3\n' >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PY'
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

# The payload data plane: the crate that owns `Payload`, and the wire layer that
# produces and consumes one. Both are exemption-free.
SEALED = ("crates/stream/src", "crates/http/src")

allowance_file = root / "scripts/allowances/as-any-allowances.txt"
allowances = {}
if allowance_file.is_file():
    for number, raw in enumerate(allowance_file.read_text().splitlines(), start=1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        if entry.startswith(tuple(f"{prefix}/" for prefix in SEALED)):
            print(
                f"scripts/allowances/as-any-allowances.txt:{number}: '{entry}' is inside the payload "
                "data plane, which takes no exemptions; the negotiation seam is the whole point of the rule",
                file=sys.stderr,
            )
            raise SystemExit(1)
        allowances[entry] = raw.split("#", 1)[1].strip() if "#" in raw else ""
        if not allowances[entry]:
            print(
                f"scripts/allowances/as-any-allowances.txt:{number}: '{entry}' carries no reason; "
                "an unexplained exemption is the state this allowlist exists to prevent",
                file=sys.stderr,
            )
            raise SystemExit(1)


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
        raw = re.match(r'(?:b|c)?r(#*)"', text[index:])
        if raw:
            marker = '"' + raw.group(1)
            end = text.find(marker, index + raw.end())
            if end < 0:
                raise ValueError("unterminated raw string")
            out.append("\n" * text.count("\n", index, end + len(marker)))
            index = end + len(marker)
            continue
        lifetime = re.match(r"'[A-Za-z_][A-Za-z0-9_]*(?!')", text[index:])
        if lifetime:
            out.append(lifetime.group())
            index += lifetime.end()
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

registered = set()
for path in sorted(crates.rglob("*.rs")):
    relative = path.relative_to(root).as_posix()
    if "/generated/" in relative or "/target/" in relative:
        continue
    scanned += 1
    sealed = next((prefix for prefix in SEALED if relative.startswith(f"{prefix}/")), None)
    if sealed:
        sealed_scanned[sealed] += 1
    try:
        text = path.read_text()
    except (OSError, UnicodeError) as error:
        print(f"check_no_as_any: cannot read {relative}: {error}", file=sys.stderr)
        raise SystemExit(1)
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

print(
    f"OK: no as_any/downcast in the payload data plane "
    f"({scanned} file(s) scanned, {sum(sealed_scanned.values())} sealed; allowlist: {len(allowances)} entries)"
)
PY
