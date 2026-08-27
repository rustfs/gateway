#!/usr/bin/env bash
# check_error_status_total.sh — Verify error code status mapping completeness.
#
# This script checks:
# 1. No error code maps to 5xx outside an explicit allowlist.
# 2. No unreferenced error codes exist (dead code detection).
#
# Exit 0 if all checks pass, exit 1 otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ERROR_CODES_FILE="$REPO_ROOT/generated/error_codes.json"

if [[ ! -f "$ERROR_CODES_FILE" ]]; then
    echo "ERROR: $ERROR_CODES_FILE not found. Run 'cargo xtask codegen' first."
    exit 1
fi

# Allowlist of codes that may map to 5xx.
# These are genuine server errors that clients should retry.
ALLOWLIST_5XX=(
    "InternalError"
    "ServiceUnavailable"
    "SlowDown"
    "RequestTimeout"
    "RequestTimeTooSkewed"
    "NotImplemented"
)

echo "Checking error code status mapping..."

# Check 1: No non-allowlisted code maps to 5xx.
VIOLATIONS=0
while IFS= read -r code; do
    status=$(jq -r ".codes[\"$code\"].status" "$ERROR_CODES_FILE")
    server_fault=$(jq -r ".codes[\"$code\"].server_fault" "$ERROR_CODES_FILE")
    
    if [[ "$server_fault" == "true" ]]; then
        # Check if in allowlist
        allowed=false
        for allowed_code in "${ALLOWLIST_5XX[@]}"; do
            if [[ "$code" == "$allowed_code" ]]; then
                allowed=true
                break
            fi
        done
        
        if [[ "$allowed" == "false" ]]; then
            echo "VIOLATION: $code maps to $status (5xx) but is not in allowlist"
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    fi
done < <(jq -r '.codes | keys[]' "$ERROR_CODES_FILE")

# Check 2: No unreferenced codes.
# A code is 'referenced' if it appears in:
# - An operation spec's errors.codes list
# - A conformance case's expect.error.code
# - Source code as ErrorCode::CONSTANT_NAME
UNREFERENCED=0
while IFS= read -r code; do
    constant=$(jq -r ".codes[\"$code\"].constant" "$ERROR_CODES_FILE")
    
    # Search for references in spec files
    spec_refs=$(grep -r "\"$code\"" "$REPO_ROOT/spec/operations/" 2>/dev/null | wc -l || true)
    
    # Search for references in conformance cases
    case_refs=$(grep -r "code = \"$code\"" "$REPO_ROOT/conformance/" 2>/dev/null | wc -l || true)
    
    # Search for references in source code
    src_refs=$(grep -r "ErrorCode::$constant" "$REPO_ROOT/crates/" 2>/dev/null | wc -l || true)
    
    total_refs=$((spec_refs + case_refs + src_refs))
    
    if [[ $total_refs -eq 0 ]]; then
        echo "WARNING: $code (ErrorCode::$constant) is unreferenced"
        UNREFERENCED=$((UNREFERENCED + 1))
    fi
done < <(jq -r '.codes | keys[]' "$ERROR_CODES_FILE")

# Summary
echo ""
echo "Results:"
echo "  5xx violations: $VIOLATIONS"
echo "  Unreferenced codes: $UNREFERENCED"

if [[ $VIOLATIONS -gt 0 ]]; then
    echo ""
    echo "FAIL: $VIOLATIONS error codes map to 5xx outside allowlist"
    exit 1
fi

if [[ $UNREFERENCED -gt 0 ]]; then
    echo ""
    echo "WARNING: $UNREFERENCED error codes are unreferenced (may be dead code)"
    # Don't fail for warnings, just report.
fi

echo ""
echo "OK: All error code status mappings are valid"
exit 0
