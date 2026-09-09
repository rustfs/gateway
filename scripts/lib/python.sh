#!/usr/bin/env bash
# =============================================================================
# scripts/lib/python.sh
#
# WHAT THIS DOES
#   Resolves the Python interpreter a guard runs its inline program with, and
#   refuses to hand back one below the repository floor.
#
# WHY
#   Guards parse Cargo manifests and conformance cases with `tomllib` (Python
#   3.11) and write PEP 604 unions that are evaluated at runtime (Python 3.10).
#   macOS ships /usr/bin/python3 as 3.9.6 and will for the foreseeable future,
#   so a guard that calls bare `python3` on a Mac dies in the middle of its
#   program with `ModuleNotFoundError: No module named 'tomllib'` or
#   `TypeError: unsupported operand type(s) for |` — a traceback that names the
#   symptom and not the requirement (rustfs/gateway#503, #583, #623). The floor
#   is decided once, here, and every guard that needs it fails on the version
#   with an actionable line instead.
#
# USAGE
#   source "${SCRIPT_DIR}/lib/python.sh"
#   PYTHON="$(gateway_python check_something)" || exit 1
#   "$PYTHON" - "$ROOT" <<'PY'
#   ...
#   PY
#
#   GATEWAY_PYTHON=<path>   use exactly this interpreter. It must meet the floor;
#                           an override that does not is an error, never a
#                           silent fall-through to a different interpreter.
#
#   Without the override, the first of `python3.13`, `python3.12`, `python3.11`,
#   `python3` on PATH that meets the floor is used. Nothing on PATH at all is
#   reported as `required command is missing: python3`, the line every guard's
#   missing-tool control already looks for.
# =============================================================================

# The floor is one number in one place. Raise it here and in README.md together.
GATEWAY_PYTHON_FLOOR_MAJOR=3
GATEWAY_PYTHON_FLOOR_MINOR=11

# gateway_python_version <interpreter>
# Prints `major.minor.micro` for an interpreter, or nothing when it cannot answer.
gateway_python_version() {
    "$1" -c 'import sys; sys.stdout.write("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || true
}

# gateway_python_meets_floor <major.minor.micro>
# Pure: exits 0 when the version is at or above the floor.
gateway_python_meets_floor() {
    local version="$1" major minor
    [[ "$version" =~ ^([0-9]+)\.([0-9]+)(\.[0-9]+)?$ ]] || return 1
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    ((major > GATEWAY_PYTHON_FLOOR_MAJOR)) ||
        ((major == GATEWAY_PYTHON_FLOOR_MAJOR && minor >= GATEWAY_PYTHON_FLOOR_MINOR))
}

# gateway_python <guard-name>
# Prints the interpreter path on stdout, or a diagnostic prefixed with the guard
# name on stderr and returns 1.
gateway_python() {
    local guard="${1:-gateway_python}" floor candidate found version newest newest_version
    floor="${GATEWAY_PYTHON_FLOOR_MAJOR}.${GATEWAY_PYTHON_FLOOR_MINOR}"
    if [[ -n "${GATEWAY_PYTHON:-}" ]]; then
        if ! found="$(command -v "$GATEWAY_PYTHON" 2>/dev/null)"; then
            printf '%s: GATEWAY_PYTHON names %s, which is not an executable\n' "$guard" "$GATEWAY_PYTHON" >&2
            return 1
        fi
        version="$(gateway_python_version "$found")"
        if [[ -z "$version" ]]; then
            printf '%s: GATEWAY_PYTHON names %s, which did not report a Python version\n' "$guard" "$found" >&2
            return 1
        fi
        if ! gateway_python_meets_floor "$version"; then
            printf '%s: GATEWAY_PYTHON names %s, which is Python %s; the repository floor is %s\n' \
                "$guard" "$found" "$version" "$floor" >&2
            return 1
        fi
        printf '%s\n' "$found"
        return 0
    fi
    newest=""
    newest_version=""
    for candidate in python3.13 python3.12 python3.11 python3; do
        found="$(command -v "$candidate" 2>/dev/null)" || continue
        version="$(gateway_python_version "$found")"
        [[ -n "$version" ]] || continue
        if gateway_python_meets_floor "$version"; then
            printf '%s\n' "$found"
            return 0
        fi
        if [[ -z "$newest" ]]; then
            newest="$found"
            newest_version="$version"
        fi
    done
    if [[ -z "$newest" ]]; then
        printf '%s: required command is missing: python3\n' "$guard" >&2
        return 1
    fi
    printf '%s: python3 is %s at %s; the repository floor is Python %s (tomllib, PEP 604 at runtime).\n' \
        "$guard" "$newest_version" "$newest" "$floor" >&2
    printf '  Put a newer interpreter on PATH (macOS: brew install python@3.13) or set GATEWAY_PYTHON to one.\n' >&2
    return 1
}
