#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# ci_install_host_tools.sh
#
# WHAT THIS DOES
#   Installs the compilers and interpreters a job used to inherit from the
#   GitHub-hosted ubuntu image. The org sm-standard images do not ship a C
#   toolchain: compiling there failed until build-essential was installed
#   (https://github.com/rustfs/rustfs/pull/4894 — the linker `cc` was absent).
#   Ruby is the same gap for this repository: the guards are Ruby, and the
#   GitHub image is what used to provide it. The image also provides GNU
#   time at /usr/bin/time (the RSS probes spawn that path, not the shell
#   builtin), ps, and ss.
#
#   Docker is intentionally not installed here. Jobs that need a daemon run on
#   the dind-sm-standard-2 label, which is the runner that has one.
#
#   A C++ compiler is opt-in. The sm-standard image has `cc` but no `c++`, so
#   the `cc` probe below never pulls build-essential in, and cc-rs cannot
#   build C++ (libfuzzer-sys compiles libFuzzer from source: every target of
#   fuzz run 36511088057 failed on `failed to find tool "c++"`). Nothing in
#   the pull-request gate compiles C++, so only the jobs that do ask for it.
#
# USAGE
#   scripts/ci_install_host_tools.sh
#   scripts/ci_install_host_tools.sh --with-gh
#   scripts/ci_install_host_tools.sh --with-cxx
#   scripts/ci_install_host_tools.sh --target-guards  # Python and timeout only
# =============================================================================

with_gh=0
with_cxx=0
target_guards=0
for argument in "$@"; do
    case "$argument" in
        --with-gh) with_gh=1 ;;
        --with-cxx) with_cxx=1 ;;
        --target-guards) target_guards=1 ;;
        *)
            printf 'ci_install_host_tools: unknown argument %s\n' "$argument" >&2
            exit 2
            ;;
    esac
done

if [[ "$target_guards" -eq 1 && ( "$with_gh" -eq 1 || "$with_cxx" -eq 1 ) ]]; then
    printf 'ci_install_host_tools: --target-guards cannot install optional build or CLI tools\n' >&2
    exit 2
fi

if [[ "$(id -u)" -eq 0 ]]; then
    apt=(apt-get)
    as_root=(env)
else
    apt=(sudo -n apt-get)
    as_root=(sudo -n)
fi

missing=()
if [[ "$target_guards" -eq 1 ]]; then
    # These two mutation suites inspect files; they do not compile or probe the network.
    command -v python3 >/dev/null 2>&1 || missing+=(python3)
    command -v timeout >/dev/null 2>&1 || missing+=(coreutils)
else
    command -v cc >/dev/null 2>&1 || missing+=(build-essential)
    # `g++` provides the `c++` alternative cc-rs looks for.
    if [[ "$with_cxx" -eq 1 ]] && ! command -v c++ >/dev/null 2>&1; then
        missing+=(g++)
    fi
    command -v pkg-config >/dev/null 2>&1 || missing+=(pkg-config)
    command -v python3 >/dev/null 2>&1 || missing+=(python3)
    command -v ruby >/dev/null 2>&1 || missing+=(ruby)
    command -v timeout >/dev/null 2>&1 || missing+=(coreutils)
    command -v curl >/dev/null 2>&1 || missing+=(curl ca-certificates)
    # GNU time, not the shell builtin. The chunk RSS probes exec this path.
    [[ -x /usr/bin/time ]] || missing+=(time)
    command -v ps >/dev/null 2>&1 || missing+=(procps)
    command -v ss >/dev/null 2>&1 || missing+=(iproute2)
    if [[ "$with_gh" -eq 1 ]] && ! command -v gh >/dev/null 2>&1; then
        missing+=(gh)
    fi
fi

if [[ "${#missing[@]}" -eq 0 ]]; then
    printf 'ci_install_host_tools: already present\n'
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive
"${apt[@]}" update

regular=()
want_gh=0
for package in "${missing[@]}"; do
    if [[ "$package" == gh ]]; then
        want_gh=1
    else
        regular+=("$package")
    fi
done

if [[ "${#regular[@]}" -gt 0 ]]; then
    "${apt[@]}" install -y --no-install-recommends "${regular[@]}"
fi

if [[ "$want_gh" -eq 1 ]] && ! command -v gh >/dev/null 2>&1; then
    if ! "${apt[@]}" install -y --no-install-recommends gh; then
        "${apt[@]}" install -y --no-install-recommends ca-certificates curl
        curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
            | "${as_root[@]}" tee /usr/share/keyrings/githubcli-archive-keyring.gpg >/dev/null
        arch="$(dpkg --print-architecture)"
        printf 'deb [arch=%s signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n' \
            "$arch" | "${as_root[@]}" tee /etc/apt/sources.list.d/github-cli.list >/dev/null
        "${apt[@]}" update
        "${apt[@]}" install -y --no-install-recommends gh
    fi
fi

if [[ "$target_guards" -eq 1 ]]; then
    for required in python3 timeout; do
        if ! command -v "$required" >/dev/null 2>&1; then
            printf 'ci_install_host_tools: installed packages but %s is still missing\n' "$required" >&2
            exit 1
        fi
    done
fi

if [[ "$with_cxx" -eq 1 ]] && ! command -v c++ >/dev/null 2>&1; then
    printf 'ci_install_host_tools: g++ is installed but there is still no c++ on PATH\n' >&2
    exit 1
fi

printf 'ci_install_host_tools: installed %s\n' "${missing[*]}"
