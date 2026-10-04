#!/usr/bin/env bash

# Sourced by the target-consolidation self-test: the only extra conformance target is the
# independently measured listing allocator, and neither target may silently lose its harness.
# Each rejection must name its invariant; a different rejecting branch is not evidence.

expect_allocation_failure() { run_case fail "$@"; }

mut_conformance_allocation_target_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
import re
path = Path("crates/conformance/Cargo.toml")
path.write_text(re.sub(r'\[\[test\]\]\nname = "list_allocations"\npath = "tests/list_allocations.rs"\n', '', path.read_text()))
PYEOF
}
expect_allocation_failure 'the allocation source needs its own registered target' mut_conformance_allocation_target_missing 'must declare exactly the ordinary and allocation'

mut_conformance_allocation_target_field() {
    python3 - "$1" <<'PYEOF'
from pathlib import Path
import sys
path = Path("crates/conformance/Cargo.toml")
text = path.read_text()
entry = 'name = "list_allocations"\npath = "tests/list_allocations.rs"\n'
assert entry in text
path.write_text(text.replace(entry, entry + sys.argv[1] + '\n', 1))
PYEOF
}
mut_conformance_allocation_target_active() {
    mut_conformance_allocation_target_field 'test = true'
    mut_conformance_allocation_target_field 'harness = true'
}
expect_pass 'the exact isolated allocation target admits explicit active harness flags' mut_conformance_allocation_target_active

mut_conformance_allocation_test_disabled() { mut_conformance_allocation_target_field 'test = false'; }
mut_conformance_allocation_harness_disabled() { mut_conformance_allocation_target_field 'harness = false'; }
mut_conformance_allocation_feature_gated() { mut_conformance_allocation_target_field 'required-features = ["production-transports"]'; }
expect_allocation_failure 'the allocation test target cannot be disabled' mut_conformance_allocation_test_disabled 'targets must use active harnesses without required features'
expect_allocation_failure 'the allocation test harness cannot be disabled' mut_conformance_allocation_harness_disabled 'targets must use active harnesses without required features'
expect_allocation_failure 'the allocation target cannot require a feature' mut_conformance_allocation_feature_gated 'targets must use active harnesses without required features'

mut_conformance_allocation_extra_target() {
    cat >>crates/conformance/Cargo.toml <<'TOMLEOF'

[[test]]
name = "extra"
path = "tests/list_allocations.rs"
TOMLEOF
}
expect_allocation_failure 'a third conformance target is rejected' mut_conformance_allocation_extra_target 'must declare exactly the ordinary and allocation'

mut_conformance_allocation_duplicate_target() {
    cat >>crates/conformance/Cargo.toml <<'TOMLEOF'

[[test]]
name = "list_allocations"
path = "tests/list_allocations.rs"
TOMLEOF
}
expect_allocation_failure 'a duplicate allocation registration is rejected' mut_conformance_allocation_duplicate_target 'must declare exactly the ordinary and allocation'

mut_conformance_allocation_target_alias() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/conformance/Cargo.toml")
path.write_text(path.read_text().replace('name = "list_allocations"\npath = "tests/list_allocations.rs"', 'name = "list_allocations"\npath = "tests/integration.rs"', 1))
PYEOF
}
expect_allocation_failure 'the allocation target cannot alias the ordinary harness' mut_conformance_allocation_target_alias 'targets must use the exact ordinary and allocation names and paths'

mut_conformance_allocation_source_missing() {
    rm crates/conformance/tests/list_allocations.rs
}
expect_allocation_failure 'a missing allocation source is rejected' mut_conformance_allocation_source_missing 'cannot read conformance allocation source'

mut_conformance_allocation_source_alias() {
    rm crates/conformance/tests/list_allocations.rs
    ln -s corpus.rs crates/conformance/tests/list_allocations.rs
}
expect_allocation_failure 'an allocation source symlink alias is rejected' mut_conformance_allocation_source_alias 'conformance allocation source may not be a symlink'

mut_conformance_allocation_source_disabled() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/conformance/tests/list_allocations.rs")
path.write_text('#![cfg_attr(all(), cfg(any()))]\n' + path.read_text())
PYEOF
}
expect_allocation_failure 'the allocation source cannot disable itself with cfg_attr' mut_conformance_allocation_source_disabled 'allocation source may not disable its registered harness'

mut_conformance_allocation_allocator_missing() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/conformance/tests/list_allocations.rs")
path.write_text(path.read_text().replace('#[global_allocator]', '// allocator removed', 1))
PYEOF
}
expect_allocation_failure 'the allocation target must retain its global allocator' mut_conformance_allocation_allocator_missing 'allocation harness must install its own dhat global allocator'

mut_conformance_allocation_allocator_replaced() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/conformance/tests/list_allocations.rs")
path.write_text(path.read_text().replace('static ALLOC: dhat::Alloc = dhat::Alloc;', 'static ALLOC: std::alloc::System = std::alloc::System;', 1))
PYEOF
}
expect_allocation_failure 'the allocation target must retain the dhat instrument' mut_conformance_allocation_allocator_replaced 'allocation harness must install its own dhat global allocator'

mut_conformance_allocation_library_reattachment() {
    printf '\n#[path = "../tests/list_allocations.rs"]\nmod allocation;\n' >>crates/conformance/src/lib.rs
}
expect_allocation_failure 'the allocation target cannot be reattached to the library' mut_conformance_allocation_library_reattachment 'src/lib.rs reuses a registered conformance test entry through #[path]'

mut_conformance_allocation_integration_reattachment() {
    printf '\ninclude!("list_allocations.rs");\n' >>crates/conformance/tests/integration.rs
}
expect_allocation_failure 'the allocation target cannot be reattached to the ordinary harness' mut_conformance_allocation_integration_reattachment 'conformance integration harness must register each frozen source exactly once'

mut_conformance_allocation_example_reattachment() {
    cat >>crates/conformance/Cargo.toml <<'TOMLEOF'

[[example]]
name = "allocation-alias"
path = "tests/list_allocations.rs"
TOMLEOF
}
expect_allocation_failure 'an example cannot reuse the allocation target' mut_conformance_allocation_example_reattachment 'Cargo.toml reuses a test harness as a example target'

mut_conformance_allocation_allocator_in_library() {
    printf '\n#[global_allocator]\nstatic OTHER: dhat::Alloc = dhat::Alloc;\n' >>crates/conformance/src/lib.rs
}
expect_allocation_failure 'the library cannot install the allocation instrument again' mut_conformance_allocation_allocator_in_library 'src/lib.rs installs an allocator outside the isolated harness'
