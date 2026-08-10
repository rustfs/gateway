#!/usr/bin/env bash
set -euo pipefail

# WHAT: Requires every public ServerConfig field to document both directions of its tradeoff.
# WHY: rustfs/backlog#1739 rejects tuning numbers that operators cannot safely change.
# EXEMPTIONS: None. A public tuning field without both consequences is incomplete.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${GATEWAY_CHECK_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
CONFIG="${ROOT_DIR}/crates/server/src/config.rs"

if [[ ! -f "$CONFIG" ]]; then
    printf 'check_tuning_doc: required config is missing: %s\n' "$CONFIG" >&2
    exit 1
fi

awk '
    /pub struct ServerConfig/ { in_config=1; next }
    in_config && /^}/ { in_config=0 }
    in_config && /^[[:space:]]*\/\/\// { doc = doc " " $0; next }
    in_config && /^[[:space:]]*pub [a-z0-9_]+:/ {
        field=$2; sub(":", "", field)
        up=(doc ~ /(Increasing|Enabling)/)
        down=(doc ~ /(decreasing|disabling)/)
        if (!up || !down) {
            printf "check_tuning_doc: %s lacks both increase/enable and decrease/disable consequences\n", field > "/dev/stderr"
            bad=1
        }
        count++
        doc=""
        next
    }
    in_config { doc="" }
    END {
        if (count == 0) {
            print "check_tuning_doc: no ServerConfig fields found" > "/dev/stderr"
            exit 1
        }
        if (bad) exit 1
        printf "OK: %d/%d tuning fields documented\n", count, count
    }
' "$CONFIG"
