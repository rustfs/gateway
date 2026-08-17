#!/usr/bin/env bash
set -euo pipefail

# WHAT: Maps every P7-01 acceptance id to a named executable test or deterministic guard.
# WHY: rustfs/backlog#1738 requires all 24 cases explicitly covered, not inferred from a green
# workspace suite or from a prose checklist.
# HOW TO EXEMPT: There is no exemption; replace a mapping only with equivalent executable evidence.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

cases=(
    'a-asm-0001|crates/gateway/tests/assembly.rs|fn a_complete_assembly_builds'
    'a-asm-0002|crates/gateway/tests/service_clone_allocations.rs|fn cloning_a_service_has_zero_allocations'
    'a-asm-0003|scripts/check_minimal_assembly_lines.sh|BEGIN MINIMAL ASSEMBLY'
    'a-asm-0004|crates/gateway/tests/assembly_order.rs|fn one_request_has_one_aggregate_extension_order'
    'a-asm-0005|crates/gateway/src/ext/host.rs|fn the_default_resolver_does_not_read_the_host'
    'a-asm-0006|crates/gateway/src/config.rs|fn all_eight_pipeline_stages_share_one_arc'
    'a-asm-0007|scripts/check_monomorphic_dispatch.sh|direct_after "$state"'
    'a-asm-0008|crates/gateway/tests/pipeline.rs|fn an_event_stream_and_a_document_share_one_service_exit'
    'a-asm-0009|crates/gateway/tests/assembly.rs|fn a_asm_0009_and_0010_missing_authorizer_is_refused_at_build'
    'a-asm-0010|crates/gateway/tests/assembly.rs|fn a_asm_0009_and_0010_missing_authorizer_is_refused_at_build'
    'a-asm-0011|crates/core/tests/route_table.rs|fn two_subresources_at_one_precedence_are_a_conflict'
    'a-asm-0012|crates/core/tests/registration.rs|fn an_operation_with_no_action_cannot_be_registered'
    'a-asm-0013|crates/gateway/tests/assembly.rs|fn a_third_party_name_colliding_with_an_aws_one_is_refused'
    'a-asm-0014|crates/gateway/tests/assembly.rs|fn a_third_party_name_without_a_namespace_is_refused'
    'a-asm-0015|crates/gateway/tests/assembly.rs|fn an_undeclared_shadowing_route_is_refused'
    'a-asm-0016|crates/gateway/tests/assembly.rs|fn an_empty_registry_is_refused'
    'a-asm-0017|xtask/tests/why_contract.rs|fn every_assembly_rule_has_a_why_answer'
    'a-asm-0018|scripts/check_config_load_once.sh|expected_stages='
    'a-asm-0019|crates/gateway/tests/handler_panic.rs|fn a_handler_panic_is_a_500_and_the_next_request_still_runs'
    'a-asm-0020|crates/gateway/src/adapt.rs|fn neither_adapter_can_return_an_error'
    'a-asm-0021|crates/gateway/tests/pipeline.rs|fn c_lim_0040_refusing_governor_answers_before_the_body_is_read'
    'a-asm-0022|crates/gateway/tests/assembly_order.rs|"filter_routed",'
    'a-asm-0023|scripts/check_default_doc.sh|# Security'
    'a-asm-0024|crates/gateway/tests/service_concurrency.rs|fn one_hundred_clones_answer_concurrently'
)

[[ "${#cases[@]}" -eq 24 ]] || {
    printf 'check_assembly_case_coverage: expected 24 mappings, got %s\n' "${#cases[@]}" >&2
    exit 1
}

expected=1
for mapping in "${cases[@]}"; do
    IFS='|' read -r id relative evidence <<<"$mapping"
    printf -v wanted 'a-asm-%04d' "$expected"
    [[ "$id" == "$wanted" ]] || {
        printf 'check_assembly_case_coverage: expected %s, found %s\n' "$wanted" "$id" >&2
        exit 1
    }
    file="${ROOT}/${relative}"
    [[ -f "$file" ]] || {
        printf 'check_assembly_case_coverage: mapped file is missing: %s\n' "$relative" >&2
        exit 1
    }
    grep -Fq "$id" "$file" || {
        printf 'check_assembly_case_coverage: %s is not named by %s\n' "$id" "$relative" >&2
        exit 1
    }
    grep -Fq "$evidence" "$file" || {
        printf 'check_assembly_case_coverage: %s evidence is missing from %s\n' "$id" "$relative" >&2
        exit 1
    }
    expected=$((expected + 1))
done

printf 'OK: all 24 assembly acceptance ids map to executable evidence\n'
