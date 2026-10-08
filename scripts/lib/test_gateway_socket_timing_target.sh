#!/usr/bin/env bash

# Sourced by the target-consolidation self-test: the only extra gateway target is the socket-timing
# suite that `cargo xtask verify --crate rustfs-gateway` runs as its own loop (rustfs/gateway#1264),
# and neither target may silently lose, share or alias a registered source. Each rejection must
# name its invariant; a different rejecting branch is not evidence.

expect_socket_timing_failure() { run_case fail "$@"; }

mut_gateway_third_target() {
    cat >>crates/gateway/Cargo.toml <<'TOMLEOF'

[[test]]
name = "third"
path = "tests/third.rs"
TOMLEOF
    cp crates/gateway/tests/integration.rs crates/gateway/tests/third.rs
}
expect_socket_timing_failure 'a third gateway test target is rejected' mut_gateway_third_target \
    'must declare exactly the integration and socket_timing'

# The layout before rustfs/gateway#1264: one target registering every source, with the socket-timing
# suites back in the integration harness under its old header. It is a complete, compilable layout,
# so only the target rule can refuse it.
mut_gateway_single_target_restored() {
    python3 - <<'PYEOF'
from pathlib import Path
import re
manifest = Path("crates/gateway/Cargo.toml")
text = manifest.read_text()
block = '\n[[test]]\nname = "socket_timing"\npath = "tests/socket_timing.rs"\n'
assert text.count(block) == 1, "socket-timing target block drifted"
manifest.write_text(text.replace(block, "", 1))
tests = Path("crates/gateway/tests")
registration = re.compile(r'#\[path = "([a-z0-9_]+)\.rs"\]\nmod \1;\n')
modules = sorted(
    registration.findall((tests / "integration.rs").read_text())
    + registration.findall((tests / "socket_timing.rs").read_text())
)
(tests / "socket_timing.rs").unlink()
harness = (tests / "integration.rs").read_text()
header = harness[: harness.index("mod support;\n") + len("mod support;\n")]
header = header.replace(
    header[header.index("//! Responsible for:") : header.index("//! NOT responsible for:")],
    "//! Responsible for: registering every gateway integration-test source in one Cargo target.\n",
)
(tests / "integration.rs").write_text(
    header + "\n" + "\n".join(f'#[path = "{module}.rs"]\nmod {module};' for module in modules) + "\n"
)
PYEOF
}
expect_socket_timing_failure 'the old single-target spelling is rejected' mut_gateway_single_target_restored \
    'must declare exactly the integration and socket_timing'

mut_gateway_duplicate_socket_timing_target() {
    cat >>crates/gateway/Cargo.toml <<'TOMLEOF'

[[test]]
name = "socket_timing"
path = "tests/socket_timing.rs"
TOMLEOF
}
expect_socket_timing_failure 'a duplicate socket-timing registration is rejected' mut_gateway_duplicate_socket_timing_target \
    'must declare exactly the integration and socket_timing'

mut_gateway_socket_timing_target_field() {
    python3 - "$1" "$2" <<'PYEOF'
from pathlib import Path
import sys
path = Path("crates/gateway/Cargo.toml")
text = path.read_text()
entry = 'name = "socket_timing"\npath = "tests/socket_timing.rs"\n'
assert text.count(entry) == 1, "socket-timing target entry drifted"
old, new = sys.argv[1], sys.argv[2]
path.write_text(text.replace(entry, entry.replace(old, new) if old else entry + new + "\n", 1))
PYEOF
}
mut_gateway_socket_timing_target_renamed() { mut_gateway_socket_timing_target_field 'name = "socket_timing"' 'name = "timing"'; }
mut_gateway_socket_timing_target_aliases_integration() {
    mut_gateway_socket_timing_target_field 'path = "tests/socket_timing.rs"' 'path = "tests/integration.rs"'
}
expect_socket_timing_failure 'the socket-timing target cannot be renamed' mut_gateway_socket_timing_target_renamed \
    'targets must use the exact integration and socket_timing names and paths'
expect_socket_timing_failure 'the socket-timing target cannot alias the integration harness' \
    mut_gateway_socket_timing_target_aliases_integration \
    'targets must use the exact integration and socket_timing names and paths'

mut_gateway_socket_timing_target_active() {
    mut_gateway_socket_timing_target_field '' 'test = true'
    mut_gateway_socket_timing_target_field '' 'harness = true'
}
mut_gateway_socket_timing_test_disabled() { mut_gateway_socket_timing_target_field '' 'test = false'; }
mut_gateway_socket_timing_harness_disabled() { mut_gateway_socket_timing_target_field '' 'harness = false'; }
mut_gateway_socket_timing_feature_gated() { mut_gateway_socket_timing_target_field '' 'required-features = ["server"]'; }
expect_pass 'the exact socket-timing target admits explicit active harness flags' mut_gateway_socket_timing_target_active
expect_socket_timing_failure 'the socket-timing target cannot be disabled' mut_gateway_socket_timing_test_disabled \
    'targets must use active harnesses without required features'
expect_socket_timing_failure 'the socket-timing harness cannot be disabled' mut_gateway_socket_timing_harness_disabled \
    'targets must use active harnesses without required features'
expect_socket_timing_failure 'the socket-timing target cannot require a feature' mut_gateway_socket_timing_feature_gated \
    'targets must use active harnesses without required features'

mut_gateway_socket_timing_registration_omitted() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/socket_timing.rs")
text = path.read_text()
entry = '#[path = "connection_teardown.rs"]\nmod connection_teardown;\n'
assert text.count(entry) == 1, "socket-timing registration drifted"
path.write_text(text.replace(entry, "", 1))
PYEOF
}
expect_socket_timing_failure 'a socket-timing suite cannot leave its harness' mut_gateway_socket_timing_registration_omitted \
    'gateway socket-timing harness must register each frozen source exactly once'

# Registered twice, a suite runs twice; moved back, it runs inside the first loop again. Both are
# compilable, so each harness must be held to its own exact list.
mut_gateway_socket_timing_suite_also_in_integration() {
    printf '#[path = "connection_teardown.rs"]\nmod connection_teardown;\n' >>crates/gateway/tests/integration.rs
}
expect_socket_timing_failure 'a socket-timing suite cannot also run in the integration target' \
    mut_gateway_socket_timing_suite_also_in_integration \
    'gateway integration harness must register each frozen source exactly once'

mut_gateway_socket_timing_suite_moved_back() {
    mut_gateway_socket_timing_registration_omitted
    printf '#[path = "connection_teardown.rs"]\nmod connection_teardown;\n' >>crates/gateway/tests/integration.rs
}
expect_socket_timing_failure 'a socket-timing suite cannot move back into the integration target' \
    mut_gateway_socket_timing_suite_moved_back \
    'gateway integration harness must register each frozen source exactly once'

mut_gateway_integration_suite_moved_to_socket_timing() {
    python3 - <<'PYEOF'
from pathlib import Path
entry = '#[path = "assembly.rs"]\nmod assembly;\n'
integration = Path("crates/gateway/tests/integration.rs")
text = integration.read_text()
assert text.count(entry) == 1, "integration registration drifted"
integration.write_text(text.replace(entry, "", 1))
socket = Path("crates/gateway/tests/socket_timing.rs")
socket.write_text(socket.read_text() + entry)
PYEOF
}
expect_socket_timing_failure 'an ordinary suite cannot move into the socket-timing target' \
    mut_gateway_integration_suite_moved_to_socket_timing \
    'gateway integration harness must register each frozen source exactly once'

mut_gateway_socket_timing_harness_missing() { rm crates/gateway/tests/socket_timing.rs; }
expect_socket_timing_failure 'a missing socket-timing harness is rejected' mut_gateway_socket_timing_harness_missing \
    'cannot read crates/gateway/tests/socket_timing.rs'

mut_gateway_example_reuses_socket_timing_harness() {
    cat >>crates/gateway/Cargo.toml <<'TOMLEOF'

[[example]]
name = "duplicate-socket-timing"
path = "tests/socket_timing.rs"
test = true
TOMLEOF
}
expect_socket_timing_failure 'a Cargo example cannot reuse the socket-timing harness' \
    mut_gateway_example_reuses_socket_timing_harness 'reuses the socket-timing harness as a example target'

mut_gateway_path_reuses_socket_timing_harness() {
    printf '\n#[cfg(test)]\n#[path = "../tests/socket_timing.rs"]\nmod duplicate_socket_timing;\n' >>crates/gateway/src/lib.rs
}
expect_socket_timing_failure 'gateway library code cannot reuse the socket-timing harness through #[path]' \
    mut_gateway_path_reuses_socket_timing_harness 'reuses the socket-timing harness through #[path]'

mut_gateway_include_reuses_socket_timing_harness() {
    printf '\ninclude!("socket_timing.rs");\n' >>crates/gateway/tests/facade_probe.rs
}
expect_socket_timing_failure 'an include cannot reuse the socket-timing harness' \
    mut_gateway_include_reuses_socket_timing_harness 'includes the socket-timing harness'

mut_gateway_symlink_reuses_socket_timing_harness() {
    ln -s ../tests/socket_timing.rs crates/gateway/src/duplicate_socket_timing.rs
}
expect_socket_timing_failure 'a gateway Rust symlink cannot reuse the socket-timing harness' \
    mut_gateway_symlink_reuses_socket_timing_harness 'aliases the socket-timing harness'

mut_gateway_socket_timing_source_disabled_by_cfg() {
    python3 - <<'PYEOF'
from pathlib import Path
path = Path("crates/gateway/tests/payload_transport.rs")
path.write_text("#![cfg(any())]\n" + path.read_text())
PYEOF
}
expect_socket_timing_failure 'a registered socket-timing source cannot disable itself with a file-level cfg' \
    mut_gateway_socket_timing_source_disabled_by_cfg 'payload_transport.rs may not disable its registered module with a file-level cfg'
