#!/bin/bash
# lib.sh -- Shared invariants for the systemtest scripts.
#
# Sourced (never executed) by the scripts in this directory, like
# sshd-dropin.sh before it. Each function here single-sources an
# invariant that previously lived as a drift-prone copy:
#
#   * kv_root() + kv_path_is_confined(): the kubeconfig write/shred
#     confinement. The kubeconfig paths come from the DOWNLOADED base
#     ini (untrusted input), so the token-bearing files may only be
#     written to -- and shredded from -- an absolute path
#     canonicalized under the kubeconfig root (/root by default,
#     where the generator's defaults and the daemon's fixed paths
#     live). The write side (prepare-kubevirt.sh) and the shred side
#     (cleanup-secrets.sh) share the ONE VIRTWHO_KUBECONFIG_ROOT knob
#     and this ONE implementation: two independently-settable knobs
#     or two copies of the rule for one invariant could drift apart
#     (the copies drifted once already -- review #297 round-3
#     blocker ii -- and let the token be written where the finish
#     step would refuse to shred it).
#   * promote_job_aliases(): the [job] plan-level alias promotion
#     (review PR297-09), needed identically by run-tests.sh,
#     setup-virtwho-test.sh and generate-virtwho-ini.sh.
#   * parse_proxy_url(): the HTTPS_PROXY/HTTP_PROXY URL parse,
#     duplicated between configure-proxy.sh and prepare-kubevirt.sh.
#
# Sourcing contract: each caller resolves its own directory with
# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" and
# sources "${SCRIPT_DIR}/lib.sh", so the library is found from any
# working directory (the scripts are invoked by path from tmt, from
# other scripts and from the self-tests).

# The kubeconfig confinement root, canonicalized once for BOTH sides
# of the rule. Canonicalization matters: a trailing-slash (or
# otherwise non-canonical) operator value used to fail-closed refuse
# every path with a misleading warning; the confinement rule itself
# is unchanged. Callers capture the result into KV_ROOT, which
# kv_path_is_confined() confines against.
kv_root() {
    local root=${VIRTWHO_KUBECONFIG_ROOT:-/root}
    realpath -m -- "$root"
}

# Whether $1 is an absolute path canonicalized under $KV_ROOT (set by
# the caller via kv_root). Anything else is refused by the callers
# with a warning: no token may ever be written where the finish step
# would not shred it, and no ini-supplied path may turn the finish
# step into "shred an arbitrary file" (a /root/../ escape is ruled
# out by the canonicalization).
kv_path_is_confined() {
    case $1 in
        /*) ;;
        *) return 1 ;;
    esac
    local resolved
    resolved=$(realpath -m -- "$1" 2>/dev/null) || return 1
    case $resolved in
        "$KV_ROOT"/*) return 0 ;;
        *) return 1 ;;
    esac
}

# [job] plan-level aliases (review PR297-09): when the plan-level
# HYPERVISOR/REGISTER/RHEL_COMPOSE variable is unset, promote the
# prefixed VIRTWHO_JOB_* value into it BEFORE any ${VAR:-default}
# evaluation (the generator invocation, the ini regeneration, the
# test-file pruning, the compose resolution, the SSH-trust branch,
# the summary banner) so the alias and the scripts agree end-to-end.
# VIRTWHO_JOB_HYPERVISOR is lower-cased to match the handler list. A
# set plan-level variable is never overridden; the generator warns
# when it disagrees with the alias.
promote_job_aliases() {
    if [ -z "${HYPERVISOR:-}" ] && [ -n "${VIRTWHO_JOB_HYPERVISOR:-}" ]; then
        HYPERVISOR=$(printf '%s' "$VIRTWHO_JOB_HYPERVISOR" | tr '[:upper:]' '[:lower:]')
        export HYPERVISOR
    fi
    if [ -z "${REGISTER:-}" ] && [ -n "${VIRTWHO_JOB_REGISTER:-}" ]; then
        REGISTER="$VIRTWHO_JOB_REGISTER"
        export REGISTER
    fi
    if [ -z "${RHEL_COMPOSE:-}" ] && [ -n "${VIRTWHO_JOB_RHEL_COMPOSE:-}" ]; then
        RHEL_COMPOSE="$VIRTWHO_JOB_RHEL_COMPOSE"
        export RHEL_COMPOSE
    fi
}

# Parse a proxy URL ($1) into PROXY_HOST and PROXY_PORT. Accepts
# http://host:port, https://host:port, host:port and bare host; the
# port defaults to 3128 (the IANA-registered Squid default) when the
# string carries none. The empty/unset gating stays with the callers
# (each warns differently when HTTPS_PROXY/HTTP_PROXY is missing).
parse_proxy_url() {
    local _hostport="${1#http://}"
    _hostport="${_hostport#https://}"
    _hostport="${_hostport%/}"
    PROXY_HOST="${_hostport%%:*}"
    PROXY_PORT="${_hostport##*:}"
    # If no port was in the string, default to 3128
    if [ "$PROXY_PORT" = "$PROXY_HOST" ]; then
        PROXY_PORT=3128
    fi
}
