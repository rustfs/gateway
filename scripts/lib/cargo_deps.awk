# cargo_deps.awk — extract declared dependency names from a Cargo.toml.
#
# WHAT THIS DOES
#   Reads one or more Cargo.toml files and prints one line per declared
#   dependency:
#
#       <kind>\t<name>
#
#   where <kind> is `dependencies`, `dev-dependencies` or `build-dependencies`.
#   Both the inline form (`foo = { workspace = true }`) and the sub-table form
#   (`[dependencies.foo]`) are recognised, as are platform-scoped tables
#   (`[target.'cfg(unix)'.dependencies]`) and `[workspace.dependencies]`.
#
# WHY THIS EXISTS
#   Three guards (check_layer_dependencies.sh, check_ring_boundaries.sh,
#   check_no_inventory.sh) need the same answer: "which crates does this
#   manifest depend on?". Parsing it once here keeps the three guards honest
#   about the same input and avoids three subtly different greps.
#   It is deliberately NOT a general TOML parser: `cargo metadata` would be
#   the general answer but requires a resolved workspace and a network-capable
#   registry, which a Day-1 CI guard must not depend on.
#
# KNOWN LIMITATION (deliberate)
#   Inline keys are only recognised when they start at column 0, which is the
#   universal convention for TOML table keys. Continuation lines of a
#   multi-line inline table are therefore ignored rather than mistaken for
#   dependency names. If a manifest ever indents its dependency keys, this
#   guard silently under-reports; `check_layer_dependencies.sh` compensates by
#   requiring every crate directory to be registered in its allow matrix.
#
# Only POSIX-portable awk constructs are used (no [[:space:]] classes, no
# gensub), so this runs identically under macOS BWK awk and GNU awk.

function emit(name) {
    if (name ~ /^[A-Za-z0-9_.+-]+$/) {
        print kind "\t" name
    }
}

/^[ \t]*\[/ {
    hdr = $0
    sub(/^[ \t]*\[+/, "", hdr)
    sub(/\].*$/, "", hdr)
    kind = ""
    in_table = 0

    if (hdr ~ /(^|\.)dev-dependencies$/) {
        kind = "dev-dependencies"
        in_table = 1
    } else if (hdr ~ /(^|\.)build-dependencies$/) {
        kind = "build-dependencies"
        in_table = 1
    } else if (hdr ~ /(^|\.)dependencies$/) {
        kind = "dependencies"
        in_table = 1
    } else if (hdr ~ /(^|\.)(dev-dependencies|build-dependencies|dependencies)\.[A-Za-z0-9_.+-]+$/) {
        if (hdr ~ /(^|\.)dev-dependencies\./) {
            kind = "dev-dependencies"
        } else if (hdr ~ /(^|\.)build-dependencies\./) {
            kind = "build-dependencies"
        } else {
            kind = "dependencies"
        }
        n = split(hdr, parts, ".")
        emit(parts[n])
        kind = ""
    }
    next
}

in_table && /^[A-Za-z0-9_.+-]+[ \t]*=/ {
    key = $0
    sub(/[ \t]*=.*$/, "", key)
    emit(key)
}
