#!/bin/bash
# discover-guest-ips.sh -- Resolve the current address of the hypervisor
# guest for ahv/hyperv/libvirt runs and patch guest_ip in virtwho.ini.
#
# The guests inside these hypervisors receive DHCP addresses that change
# whenever the guest is rebuilt or rebooted, so a static guest_ip in the
# sanitized base ini goes stale and the suite cannot reach the guest.
# This script runs just before pytest and asks the hypervisor's own
# management plane for the guest's current address:
#
#   libvirt: hypervisor-builder's (hb) LibvirtCLI.guest_ip() -- virsh
#            domifaddr over ssh, the guest agent first, the ARP
#            table as fallback
#   hyperv:  hypervisor-builder's HypervCLI.guest_ip() -- PowerShell
#            Get-VMNetworkAdapter over ssh
#   ahv:     Prism REST API over HTTPS (basic auth)
#
# The libvirt/hyperv queries are delegated to hb (discover_guest_ips.py,
# invoked below): the knowledge of HOW to ask each hypervisor belongs
# to hb, whose PR #43 carries the hardened forms this script used to
# implement inline (the guest name rides the ssh session's stdin into
# a fixed remote command string, the PowerShell adapter list is
# post-filtered by the exact VM name, every query is bounded by a
# timeout). The ahv query STAYS in this script: hb's AHVApi cannot
# express vt's query semantics without hb-side changes (its
# get_vm_by_name splices the guest name into the Prism URL unencoded,
# and its guest_search takes the last NIC address instead of the first
# non-loopback IPv4) -- converting ahv is a hypervisor-builder
# follow-up (C5), and the hardening of the shell path below is not
# weakened in the meantime.
#
# All inputs (server, username, password, guest_name) are read from the
# ini; only the discovered guest_ip is written back -- never a
# credential. The ini is DOWNLOADED, untrusted input, so its values are
# data, never code: for libvirt/hyperv they reach hb as python
# constructor/method arguments (only the ini path and the family name
# ride discover_guest_ips.py's own command line), the ahv guest_name is
# percent-encoded for the query -- nothing from the ini is ever
# spliced into a command string or a URL. A failed discovery is a
# warning, not an error: the existing ini value is kept as the
# fallback, and the run continues;
# VIRTWHO_SKIP_IP_DISCOVERY=1 skips the discovery outright (labs with
# a known-good static guest_ip), and an overwrite of a differing
# non-empty ini value is logged as a WARNING naming both values.
#
# Usage: discover-guest-ips.sh <ini-path> <hypervisor>
#
# Runs on the booted test guest in the execute phase, after
# run-tests.sh set up the libvirt SSH trust; before pytest, so the
# session-scoped ssh_guest fixture sees the fresh value.
#
# This script never prints credential values.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

INI=${1:?usage: discover-guest-ips.sh <ini-path> <hypervisor>}
HYP=$(printf '%s' "${2:?usage: discover-guest-ips.sh <ini-path> <hypervisor>}" \
    | tr '[:upper:]' '[:lower:]')

case "$HYP" in
    ahv | hyperv | libvirt) ;;
    *)
        echo "SKIP: guest-IP discovery is not needed for hypervisor '${HYP}'"
        exit 0
        ;;
esac

if [ ! -f "$INI" ]; then
    echo "ERROR: ini file not found: ${INI}" >&2
    exit 1
fi

# Opt-out for labs with a known-good static guest_ip (e.g. multi-NIC
# guests whose management plane reports a different NIC first): skip
# the discovery entirely, keep the ini value, say so.
if [ "${VIRTWHO_SKIP_IP_DISCOVERY:-}" = "1" ]; then
    echo "SKIP: VIRTWHO_SKIP_IP_DISCOVERY is set; keeping the ini's existing guest_ip"
    exit 0
fi

discover_via_hb() {
    # libvirt/hyperv: the per-family query is hypervisor-builder's
    # (hb) job now. Its LibvirtCLI/HypervCLI guest_ip() carry the
    # hardened forms this script used to implement inline (the
    # guest name rides the ssh session's stdin into a fixed remote
    # command string, the PowerShell adapter list is post-filtered
    # by the exact VM name, the libvirt agent source falls back to
    # the ARP table) -- the knowledge of HOW to ask each hypervisor
    # belongs to hb, shared by every consumer instead of re-derived
    # per test suite. The ini values reach hb as python
    # constructor/method ARGUMENTS (server/username/password into
    # the CLI constructor, the guest name into guest_ip()): the ini
    # is downloaded, untrusted input, and nothing from it is
    # interpolated into a command string here -- only the ini path
    # and the family name ride the python command line. A failed
    # discovery (hb raising, hb answering None, missing ini values,
    # the hyperv empty-password guard) prints nothing and exits
    # non-zero: the caller's warning + fallback semantics apply
    # exactly as before. Neither the helper nor this function
    # prints credential values.
    python3 "${SCRIPT_DIR}/discover_guest_ips.py" "$INI" "$HYP"
}

set_guest_ip() {
    # Patch guest_ip of the active hypervisor's section in the ini.
    # open(path, "w") follows a symlink (Configure.save() semantics)
    # and preserves the existing file mode. The rewrite
    # re-serializes the whole file through configparser, which drops
    # comments; a malformed ini is a clean warning, not a traceback,
    # and the caller keeps the ini value on failure.
    python3 - "$INI" "$HYP" "$1" <<'PYEOF'
import configparser
import sys

path, section, value = sys.argv[1:4]
cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
try:
    cfg.read(path)
except configparser.Error as e:
    print(f"WARNING: could not parse {path} ({type(e).__name__}); "
          "not updating guest_ip", file=sys.stderr)
    sys.exit(1)
if not cfg.has_section(section):
    print(f"WARNING: no [{section}] section in {path}; not updating guest_ip",
          file=sys.stderr)
    sys.exit(1)
cfg.set(section, "guest_ip", value)
with open(path, "w") as f:
    cfg.write(f, space_around_delimiters=False)
PYEOF
}

discover_ahv() {
    # Prism REST API (v2.0): list the VMs filtered by name with NIC
    # details, match the exact VM name, take the first IPv4 its NICs
    # report. The credentials are read from the ini; they are handed to
    # curl through a config stream on stdin (-K -) so they never appear
    # in /proc/<pid>/cmdline. -k: Prism ships a self-signed certificate.
    # The guest name is percent-encoded for the query string: it is
    # ini input, and a raw '&' or '=' could split or alter the query.
    local body
    # A newline inside the username or password (configparser joins
    # indented continuation lines in a hand-edited ini, so the value
    # can carry one) cannot ride curl's config-file syntax: the stream
    # would split into a new config line and surface as a generic curl
    # parse error. Reject it by name instead -- diagnosable, and the
    # value itself is never printed.
    case "$HYP_USER$HYP_PASS" in
        *$'\n'*)
            echo "WARNING: the [ahv] username or password contains a newline; skipping ahv guest-IP discovery" >&2
            return 1
            ;;
    esac
    GUEST_NAME_ENC=$(printf '%s' "$GUEST_NAME" | python3 -c \
        'import sys, urllib.parse; print(urllib.parse.quote_from_bytes(sys.stdin.buffer.read(), safe=""))')
    # The response holds no secrets (VM names and addresses only) and
    # already lives fully in the shell variable: command substitution
    # output is not passed through execve, so its size is not bounded
    # by the kernel's per-string limit. The validator therefore reads
    # it straight from stdin -- nothing is written to disk. (The
    # script itself rides fd 3's quoted heredoc, the same
    # no-expansion shape as every other python block here; stdin
    # cannot carry both.)
    if ! body=$(printf 'user = "%s:%s"\n' "$AHV_USER_ESC" "$AHV_PASS_ESC" \
        | curl -skf --connect-timeout 10 --max-time 60 \
            --retry 2 --retry-delay 5 -K - \
            "https://${HYP_SERVER}:9440/api/nutanix/v2.0/vms/?name=${GUEST_NAME_ENC}&include_vm_nic_config=true" \
        2>/dev/null); then
        return 1
    fi
    printf '%s' "$body" | python3 /dev/fd/3 "$GUEST_NAME" 3<<'PYEOF'
import json
import sys

guest_name = sys.argv[1]
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(1)

# Each entity carries the runtime state under "status" and the name
# under "metadata"; match the exact VM name and read its NICs.
ip_found = ""
for entity in data.get("entities", []):
    vm = dict(entity.get("status", {}), **entity.get("metadata", {}))
    if vm.get("name") != guest_name:
        continue
    for nic in vm.get("vm_nics") or []:
        ip = (nic.get("ip_address") or "").strip()
        if ip and not ip.startswith("127."):
            ip_found = ip
            break
    if ip_found:
        break
print(ip_found)
PYEOF
}

# --- Read the per-hypervisor inputs from the ini ---

# The shared read-only ini access (lib.sh's ini_read): ONE python
# invocation reads all five values of the active section,
# NUL-delimited, lenient. The values are returned to the caller
# only, never printed.
mapfile -d '' -t INI_VALUES < <(ini_read "$INI" "$HYP" \
    server username password guest_name guest_ip)
HYP_SERVER=${INI_VALUES[0]:-}
HYP_USER=${INI_VALUES[1]:-}
HYP_PASS=${INI_VALUES[2]:-}
GUEST_NAME=${INI_VALUES[3]:-}
GUEST_IP_OLD=${INI_VALUES[4]:-}

# NOTE: the libvirt qemu+ssh://user@host/system URI normalization
# moved into discover_guest_ips.py (the python helper hands hb the
# bare host it connects to); the raw value here only feeds the
# missing-values gate and the ahv path, which takes the server as
# an HTTPS host name.

if [ -z "$HYP_SERVER" ] || [ -z "$HYP_USER" ] || [ -z "$GUEST_NAME" ]; then
    echo "WARNING: [${HYP}] server/username/guest_name not all set in ${INI}; skipping guest-IP discovery" >&2
    exit 0
fi

# Escape the ahv credentials for curl's config-file syntax (double
# quotes with backslash escapes) before they take the stdin detour.
AHV_USER_ESC=$(printf '%s' "$HYP_USER" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
AHV_PASS_ESC=$(printf '%s' "$HYP_PASS" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')

case "$HYP" in
    libvirt | hyperv) IP=$(discover_via_hb) || IP="" ;;
    ahv) IP=$(discover_ahv) || IP="" ;;
esac

if [ -n "$IP" ]; then
    # A wrong-IP success is visible, not silent: on a multi-NIC guest
    # the management plane may report a different NIC first, and the
    # overwrite of a previously-correct static value looks like a test
    # failure, not a discovery failure -- name both values.
    if [ -n "$GUEST_IP_OLD" ] && [ "$IP" != "$GUEST_IP_OLD" ]; then
        echo "WARNING: discovered ${HYP} guest_ip ${IP} differs from the ini value ${GUEST_IP_OLD}; overwriting the ini (set VIRTWHO_SKIP_IP_DISCOVERY=1 to keep a known-good static value)" >&2
    fi
    echo "Discovered ${HYP} guest_ip: ${IP} (ini had: ${GUEST_IP_OLD:-unset})"
    if ! set_guest_ip "$IP"; then
        echo "WARNING: guest_ip write-back failed; keeping the ini value (${GUEST_IP_OLD:-unset})" >&2
    fi
else
    echo "WARNING: could not discover the ${HYP} guest_ip; keeping the ini value (${GUEST_IP_OLD:-unset})" >&2
fi
