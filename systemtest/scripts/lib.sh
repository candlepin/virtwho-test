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
#     or two copies of the rule for one invariant could drift apart.
#   * promote_job_aliases(): the [job] plan-level alias promotion,
#     needed identically by every wrapper script.
#   * parse_proxy_url(): the HTTPS_PROXY/HTTP_PROXY URL parse,
#     duplicated between configure-proxy.sh and prepare-kubevirt.sh.
#   * detect_install_dir(): the shared test-tree root (the clone
#     target, the marker location) -- previously copy-pasted
#     verbatim in setup-virtwho-test.sh, prepare-kubevirt.sh and
#     prepare-candlepin.sh.
#   * ini_read(): the read-only configparser access every script
#     needs -- previously a drifted heredoc copy per site (strict
#     vs lenient, newline vs NUL delimitation).
#   * SSH_BASE_OPTS + ssh_exec(): the ssh transport baseline every
#     shell-side ssh invocation builds on -- previously five sites
#     each re-deriving the options, three of them with no
#     ConnectTimeout at all.
#
# Sourcing contract: each caller resolves its own directory with
# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" and
# sources "${SCRIPT_DIR}/lib.sh", so the library is found from any
# working directory (the scripts are invoked by path from tmt, from
# other scripts and from the self-tests -- the companion suite,
# branch cct-3162/selftests).

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

# [job] plan-level aliases: when the plan-level
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

# The test-tree root the prepare-phase scripts share: the clone
# target of setup-virtwho-test.sh and the marker location of
# prepare-candlepin.sh -- the clone must create the tree the marker
# lands in (the plan-ordering invariant). /usr/share/virtwho-test
# on bootc/ostree (an ostree-safe path: /opt is a symlink to /var/opt
# there and content written during the container build is hidden
# after the image deploy), /opt/virtwho-test otherwise.
# VIRTWHO_PREPARE_INSTALL_DIR overrides both -- ONE knob so a
# sandboxed clone and a sandboxed marker land in the same tree.
detect_install_dir() {
    if [ -n "${VIRTWHO_PREPARE_INSTALL_DIR:-}" ]; then
        printf '%s' "$VIRTWHO_PREPARE_INSTALL_DIR"
    elif command -v bootc &>/dev/null || [ -f /run/ostree-booted ] \
        || [ -L /ostree ]; then
        printf '%s' /usr/share/virtwho-test
    else
        printf '%s' /opt/virtwho-test
    fi
}

# ini_read <file> <section> <option>...: read ini options with
# configparser, never awk -- `key = value` spacing is
# configparser-valid but an awk ^key= match silently skips it, and
# an `=`-containing value would be truncated at the first `=`.
# ONE python invocation reads all the requested options of the
# section; the values are written to stdout NUL-delimited, in the
# order given (an ini value may itself contain a newline --
# configparser joins indented continuation lines in a hand-edited
# ini -- which a newline-delimited stream would silently shift
# into the next slot). Read back with `mapfile -d '' -t`.
# Lenient by contract: strict=False, so a duplicate option degrades
# to the callers' warning/skip paths instead of dying here; a
# missing section or option yields an empty string; a file that
# cannot be read or parsed yields all-empty output. The values are
# returned to the caller only -- the calling scripts never print
# them.
ini_read() {
    python3 - "$@" <<'PYEOF'
import configparser
import sys

path, section = sys.argv[1], sys.argv[2]
cfg = configparser.ConfigParser(interpolation=None, strict=False)
cfg.optionxform = str
try:
    cfg.read(path)
except configparser.Error:
    sys.exit(0)
for option in sys.argv[3:]:
    value = (cfg.get(section, option, fallback="")
             if cfg.has_section(section) else "")
    sys.stdout.write(value + "\0")
PYEOF
}

# --- the shared ssh transport baseline ------------------------------------
# One definition of the options every shell-side ssh invocation in
# systemtest/ builds on: no interactive host-key prompt, a BOUNDED
# connect (three of the five historical sites carried no
# ConnectTimeout at all -- an unbounded ssh connect hangs its phase
# until the farm timeout kills the job, the same LESSON-02 class as
# an unbounded curl), and a quiet log level. Auth deliberately stays
# PER-SITE: key-based callers add -o BatchMode=yes as an extra
# option, password callers wrap the invocation with
# SSHPASS=<password> sshpass -e (the password rides the environment,
# never argv; sshpass execvp's the ssh binary itself, so those sites
# splice the SSH_BASE_OPTS array instead of calling ssh_exec).
# Untrusted data (an ini-sourced guest name) rides the caller's
# stdin into a FIXED remote command string -- both shapes pass
# stdin through untouched.
SSH_BASE_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=ERROR)

# ssh_exec [<ssh-option>...] <destination> <remote-command>: run ONE
# fixed remote command over ssh with the shared baseline prepended;
# per-site extras (a -p <port>, -o BatchMode=yes) go in their normal
# ssh positions. stdin is passed through untouched and ssh's own
# exit status is returned. Password-auth callers use the sshpass
# form at their site (see SSH_BASE_OPTS above).
ssh_exec() {
    ssh "${SSH_BASE_OPTS[@]}" "$@"
}
