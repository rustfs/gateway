#!/usr/bin/env bash

# Sourced by the consolidation self-test. The process-wide allocation observer must execute
# through its standalone main, with no libtest monitor and no silently disabled Cargo target.

mut_gateway_signature_field() {
    python3 - "$1" "$2" <<'PYEOF'
from pathlib import Path
import sys
path = Path("crates/gateway/Cargo.toml")
source = path.read_text()
entry = 'name = "signature_text_allocations"\npath = "tests/signature_text_allocations.rs"\nharness = false\n'
assert source.count(entry) == 1, "signature allocation target drifted"
old, new = sys.argv[1:]
replacement = entry.replace(old, new) if old else entry + new + "\n"
path.write_text(source.replace(entry, replacement, 1))
PYEOF
}
mut_gateway_signature_disabled() { mut_gateway_signature_field '' 'test = false'; }
mut_gateway_signature_libtest() { mut_gateway_signature_field 'harness = false' 'harness = true'; }
mut_gateway_signature_feature_gated() { mut_gateway_signature_field '' 'required-features = ["server"]'; }
mut_gateway_signature_explicit_test() { mut_gateway_signature_field '' 'test = true'; }
expect_pass 'the standalone signature allocation target admits an explicit active test flag' mut_gateway_signature_explicit_test
for mutation in disabled libtest feature_gated; do
    expect_fail "the signature allocation target rejects $mutation" "mut_gateway_signature_$mutation" \
        'targets must be active with the declared harness mode and no required features'
done

mut_gateway_signature_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/Cargo.toml")
source = path.read_text()
entry = '[[test]]\nname = "signature_text_allocations"\npath = "tests/signature_text_allocations.rs"\nharness = false\n'
assert source.count(entry) == 1, "signature allocation target drifted"
path.write_text(source.replace(entry, "", 1))
PYEOF
}
expect_fail 'the standalone signature allocation target cannot be omitted' mut_gateway_signature_omitted \
    'must declare exactly the integration and socket_timing'

mut_gateway_signature_source() {
    python3 - "$1" "$2" <<'PYEOF'
from pathlib import Path
import sys
path = Path("crates/gateway/tests/signature_text_allocations.rs")
source = path.read_text()
old, new = sys.argv[1:]
assert source.count(old) == 1, "signature allocation entry drifted"
path.write_text(source.replace(old, new, 1))
PYEOF
}
mut_gateway_signature_no_entry() { mut_gateway_signature_source 'fn main()' 'fn unused_main()'; }
mut_gateway_signature_empty_entry() { mut_gateway_signature_source '    string_to_sign_owns_only_its_final_text();' ''; }
expect_fail 'the signature allocation target cannot lose its main' mut_gateway_signature_no_entry \
    'signature allocation target must have exactly one main entry'
expect_fail 'a successful empty allocation main cannot bypass the assertions' mut_gateway_signature_empty_entry \
    'signature allocation main must execute the complete allocation suite'

mut_gateway_signature_unexecuted_test() {
    cat >>crates/gateway/tests/signature_text_allocations.rs <<'RUSTEOF'

#[test]
fn silently_unexecuted() {
    panic!("this assertion must not be silently omitted");
}
RUSTEOF
}
expect_fail 'a standalone allocation target cannot silently omit a libtest test' mut_gateway_signature_unexecuted_test \
    'standalone signature allocation target may not declare unexecuted libtest tests'
