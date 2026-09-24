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
# USAGE
#   scripts/ci_install_host_tools.sh
#   scripts/ci_install_host_tools.sh --with-gh
# =============================================================================

with_gh=0
case "${1:-}" in
    "") ;;
    --with-gh) with_gh=1 ;;
    *)
        printf 'ci_install_host_tools: unknown argument %s\n' "$1" >&2
        exit 2
        ;;
esac

if [[ "$(id -u)" -eq 0 ]]; then
    apt=(apt-get)
    as_root=(env)
else
    apt=(sudo -n apt-get)
    as_root=(sudo -n)
fi

missing=()
command -v cc >/dev/null 2>&1 || missing+=(build-essential)
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

printf 'ci_install_host_tools: installed %s\n' "${missing[*]}"
