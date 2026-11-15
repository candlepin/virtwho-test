#!/bin/bash
# test-generate-virtwho-ini.sh -- Self-test for generate-virtwho-ini.sh
# and the tmpfs/symlink/ssh_config plumbing.
#
# All values used here are dummy (non-secret, non-real): example.invalid
# / example.com names, TEST-NET-1 addresses, all-zero UUIDs.
#
# Asserts that:
#   * env-only fallback generation works (VIRTWHO_INI_URL unset): the
#     file parses with python configparser, the expected
#     sections/options are present with the right values, sections
#     without env vars are omitted (except the core ones), the file
#     mode is 0600, and values containing newlines are rejected;
#   * a base-download + env-overlay mode works (VIRTWHO_INI_URL set to a
#     dummy base served from a file:// URL): base values survive, env
#     secrets win, env-only options are added, non-table sections of
#     the base are passed through, and the plan-level [job] preseed
#     wins over the base;
#   * a failing base download, a malformed base, an empty base and a
#     base with planted forbidden (plaintext credential-shaped) keys
#     all fail the generator loudly; an optional VIRTWHO_INI_SHA256
#     pin aborts a base that does not match it (review PR298-23);
#     sentinels in never-resolved
#     sections ([virtwho], pass-throughs) abort loudly too;
#   * @vault: sentinels in the base resolve against a local fake Vault
#     HTTP server (obviously-fake values): resolution is SELECTIVE
#     (only the active hypervisor + register sections resolve, proven
#     both in the output ini and in the fake server's request log),
#     the AppRole login and the static VAULT_TOKEN paths both work,
#     env secrets win over resolved values (and env-covered sentinels
#     are never resolved, so a Vault failure cannot block an
#     env-supplied credential -- nor does the no-credentials gate
#     fire for a fully env-covered cell), multi_hypervisors families
#     resolve (env and base-file forms, spaced/mixed-case entries,
#     whitespace outside the brackets) AND the normalized list is
#     written back into [job] multi_hypervisors (asserted on the
#     generated ini value and on the suite parser's output -- the
#     unnormalized hypervisors_list() expression from virtwho/base.py
#     -- so a spaced/mixed-case list cannot drive the wrong handler),
#     one HTTP read per secret PATH
#     (successes and failures), an
#     unresolved sentinel in an ACTIVE section hard-fails naming
#     path+key, malformed inputs (a space in a sentinel path, a
#     non-dict payload, a wrong-shape 200 envelope, a newline in a
#     value) fail cleanly without
#     tracebacks, a plaintext http:// VAULT_ADDR is refused without
#     the VAULT_ALLOW_HTTP opt-out, credentials without VAULT_ADDR
#     fail loudly, a redirecting Vault is refused (the token is never
#     re-sent to the redirect target), missing credentials with
#     unoverridden sentinels hard-fails (with the env-only escape
#     hatch named), the VIRTWHO_VAULT_REQUIRED strict knob requires
#     usable credentials (address present) for any sentinel without
#     widening the resolution
#     scope, and a sentinel-free base behaves identically with
#     credentials + strict mode set (resolver inert);
#   * the legacy KUBEVIRT_TOKEN alias survives regeneration (the new
#     VIRTWHO_KUBEVIRT_TOKEN wins when both are set);
#   * a misspelled VIRTWHO_* option triggers a stderr warning naming
#     the variable;
#   * the [job] plan-level aliases work end to end (review PR297-09):
#     VIRTWHO_JOB_HYPERVISOR wins when HYPERVISOR is unset AND feeds
#     the hypervisor-section creation (lower-cased, no spurious
#     shadow warning), VIRTWHO_JOB_REGISTER wins over the rhsm
#     default, VIRTWHO_JOB_RHEL_COMPOSE reaches [job] rhel_compose,
#     and a set plan-level variable wins over a disagreeing prefixed
#     value with a warning naming the winner;
#   * a VIRTWHO_ESX_*/VIRTWHO_VCENTER_* clash on the same option
#     warns and VIRTWHO_ESX_* wins (review PR297-13);
#   * the generator writes THROUGH a symlinked output path instead of
#     replacing the link with a regular file (review PR297-10);
#   * the single-materialization symlink survives `cp -a` (the bootc
#     writable-copy path) and configparser writes through it
#     (Configure.save() semantics);
#   * the ssh_config approach works: an IdentityFile entry pointing at
#     a tmpfs key is resolved by `ssh -G` (no connection needed), the
#     public key can be derived next to it, and the REAL
#     cleanup-secrets.sh (run against a sandboxed tree with the same
#     layout) drops the entry again (anchored to the exact line -- a
#     sibling .bak entry survives) and shreds the tmpfs files, the
#     ini-configured kubeconfig paths (only when they point under the
#     kubeconfig root -- a path outside it is refused with a warning,
#     review PR298-22), the suite's temp/ artifacts, the /etc/virt-who.d
#     uploads (review PR297-16), a regular legacy ini and the ini
#     symlinks (reviews PR297-03, PR297-05, PR297-10).
#
# Run directly: bash systemtest/scripts/test-generate-virtwho-ini.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=$(mktemp -d /dev/shm/virtwho-selftest.XXXXXX)
SSH_KEY="${WORK}/virtwho-ssh-key"
FAKE_VAULT_PID=""
REDIRECT_VAULT_PID=""
cleanup() {
    rm -rf "$WORK"
    for pid in "$FAKE_VAULT_PID" "$REDIRECT_VAULT_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_ini_value() {
    # assert_ini_value <file> <section> <option> <expected>
    python3 - "$@" <<'PYEOF'
import configparser
import sys

path, section, option, expected = sys.argv[1:5]
cfg = configparser.ConfigParser(interpolation=None)
assert cfg.read(path), f"could not parse {path}"
actual = cfg.get(section, option)
assert actual == expected, \
    f"[{section}] {option}: expected {expected!r}, got {actual!r}"
PYEOF
}

# =========================================================================
# 1) Env-only fallback generation (VIRTWHO_INI_URL unset)
# =========================================================================
TMP_INI="${WORK}/env-only.ini"
HYPERVISOR=libvirt REGISTER=rhsm RHEL_COMPOSE=RHEL-10.0-DUMMY \
VIRTWHO_VCENTER_SERVER=dummy-vcenter.example.com \
VIRTWHO_VCENTER_USERNAME=dummy-vcenter-user \
VIRTWHO_VCENTER_PASSWORD=dummy-vcenter-pass \
VIRTWHO_ESX_GUEST_IP=192.0.2.50 \
VIRTWHO_ESX_GUEST_USERNAME=dummy-guest-user \
VIRTWHO_ESX_GUEST_PASSWORD=dummy-guest-pass \
VIRTWHO_RHEVM_SERVER=dummy-rhevm.example.com \
VIRTWHO_RHEVM_USERNAME=dummy-rhevm-user \
VIRTWHO_RHEVM_PASSWORD=dummy-rhevm-pass \
VIRTWHO_LIBVIRT_SERVER=dummy-libvirt.example.com \
VIRTWHO_LIBVIRT_USERNAME=dummy-libvirt-user \
VIRTWHO_LIBVIRT_PASSWORD=dummy-libvirt-pass \
VIRTWHO_KUBEVIRT_TOKEN=dummy-kubevirt-token \
VIRTWHO_KUBEVIRT_ENDPOINT=https://dummy-kubevirt.example.com \
VIRTWHO_RHSM_SERVER=stage.example.com \
VIRTWHO_RHSM_USERNAME=dummy-rhsm-user \
VIRTWHO_RHSM_PASSWORD=dummy-rhsm-pass \
VIRTWHO_RHSM_DEFAULT_ORG=dummy-org \
VIRTWHO_SATELLITE_SERVER=dummy-satellite.example.com \
VIRTWHO_SATELLITE_USERNAME=dummy-sat-user \
VIRTWHO_SATELLITE_PASSWORD=dummy-sat-pass \
    env -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI"

# --- File mode must be 0600 ---
MODE=$(stat -c '%a' "$TMP_INI")
[ "$MODE" = "600" ] || fail "expected mode 600, got $MODE"
echo "OK: env-only mode, file mode is 0600"

# --- Parse with configparser and assert sections/options ---
python3 - "$TMP_INI" <<'PYEOF'
import configparser
import sys

path = sys.argv[1]
parser = configparser.ConfigParser()
read = parser.read(path)
assert read == [path], f"configparser could not read {path}"

# core sections are always emitted
for section in ("job", "virtwho", "rhsm", "satellite", "esx"):
    assert parser.has_section(section), f"missing core section [{section}]"

# active hypervisor section is always emitted
assert parser.has_section("libvirt"), "missing active hypervisor section [libvirt]"

# sections with env vars are emitted
for section in ("rhevm", "kubevirt"):
    assert parser.has_section(section), f"missing section [{section}]"

# sections without env vars are omitted
for section in ("hyperv", "ahv", "xen", "local"):
    assert not parser.has_section(section), f"unexpected section [{section}]"

# env values landed in the right sections/options
expected = {
    ("job", "hypervisor"): "libvirt",
    ("job", "register"): "rhsm",
    ("job", "rhel_compose"): "RHEL-10.0-DUMMY",
    ("esx", "server"): "dummy-vcenter.example.com",
    ("esx", "username"): "dummy-vcenter-user",
    ("esx", "password"): "dummy-vcenter-pass",
    ("esx", "guest_ip"): "192.0.2.50",
    ("esx", "guest_username"): "dummy-guest-user",
    ("esx", "guest_password"): "dummy-guest-pass",
    ("rhevm", "server"): "dummy-rhevm.example.com",
    ("rhevm", "username"): "dummy-rhevm-user",
    ("rhevm", "password"): "dummy-rhevm-pass",
    ("libvirt", "server"): "dummy-libvirt.example.com",
    ("libvirt", "username"): "dummy-libvirt-user",
    ("libvirt", "password"): "dummy-libvirt-pass",
    ("kubevirt", "token"): "dummy-kubevirt-token",
    ("kubevirt", "endpoint"): "https://dummy-kubevirt.example.com",
    ("kubevirt", "config_file"): "/root/kubeconfig",
    ("kubevirt", "config_file_no_cert"): "/root/kubeconfig-no-cert",
    ("rhsm", "server"): "stage.example.com",
    ("rhsm", "username"): "dummy-rhsm-user",
    ("rhsm", "password"): "dummy-rhsm-pass",
    ("rhsm", "default_org"): "dummy-org",
    ("satellite", "server"): "dummy-satellite.example.com",
    ("satellite", "username"): "dummy-sat-user",
    ("satellite", "password"): "dummy-sat-pass",
}
for (section, option), value in expected.items():
    actual = parser.get(section, option)
    assert actual == value, f"[{section}] {option}: expected {value!r}, got {actual!r}"

# every option the suite accesses must exist (empty is fine, missing is not)
required = {
    "job": ("hypervisor", "register", "rhel_compose", "rhel_compose_path",
            "multi_hypervisors"),
    "virtwho": ("server", "username", "password", "port", "package",
                "proxy_server", "proxy_port"),
    "rhsm": ("server", "username", "password", "prefix", "port",
             "default_org", "activation_key"),
    "satellite": ("server", "username", "password", "ssh_username",
                  "ssh_password", "default_org", "secondary_org",
                  "activation_key"),
    "esx": ("server", "username", "password", "ssh_username", "ssh_password",
            "ssh_ip", "esx_ip", "esx_username", "esx_password"),
}
for section, options in required.items():
    for option in options:
        assert parser.has_option(section, option), \
            f"missing required option [{section}] {option}"

print("OK: env-only configparser parse and section/option assertions passed")
PYEOF

# --- Values containing newlines are rejected ---
# A newline inside a value would be written as a literal new line and
# silently corrupt the ini; the generator must fail loudly instead.
rm -f "$TMP_INI"
if VIRTWHO_RHEVM_PASSWORD=$'line1\nline2' \
    env -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI" 2>/dev/null; then
    fail "generator accepted a value containing a newline"
fi
[ ! -e "$TMP_INI" ] || fail "generator wrote $TMP_INI despite rejecting the value"
echo "OK: newline-containing values are rejected"

# =========================================================================
# 2) Base-download + env-overlay mode (dummy base via file:// URL)
# =========================================================================
BASE_INI="${WORK}/base.ini"
cat > "$BASE_INI" <<'EOF'
; dummy sanitized base ini -- non-secret values only, all fake.
; Credential-shaped options (username/password/token/...) are
; deliberately absent: they come from the VIRTWHO_* env secrets and a
; base carrying them is rejected (see the forbidden-key case below).
[job]
hypervisor=esx
register=rhsm
rhel_compose=RHEL-9.9-DUMMY

[virtwho]
server=base-virtwho.example.com
port=22
repo=http://base-mirror.example.com/virt-who.repo
brew=http://base-brew.example.com/koji
proxy_server=base-proxy.example.com
proxy_port=3128

[rhsm]
server=base-rhsm.example.com
default_org=base-org

[esx]
server=base-esx.example.com
ssh_ip=192.0.2.10
esx_cluster=base-cluster
guest_name=base-guest.example.invalid

; a section outside the generator table: must be passed through
[beaker]
server=base-beaker.example.com
EOF

TMP_INI2="${WORK}/overlay.ini"
HYPERVISOR=libvirt REGISTER=rhsm RHEL_COMPOSE=RHEL-10.0-DUMMY \
VIRTWHO_ESX_PASSWORD=env-esx-pass \
VIRTWHO_ESX_GUEST_IP=192.0.2.51 \
VIRTWHO_RHEVM_SERVER=dummy-rhevm.example.com \
VIRTWHO_INI_URL="file://${BASE_INI}" \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI2"

MODE=$(stat -c '%a' "$TMP_INI2")
[ "$MODE" = "600" ] || fail "overlay mode: expected mode 600, got $MODE"
echo "OK: base+overlay mode, file mode is 0600"

# env secret wins over the base value
assert_ini_value "$TMP_INI2" esx password env-esx-pass
# base values survive when the env is silent
assert_ini_value "$TMP_INI2" esx server base-esx.example.com
assert_ini_value "$TMP_INI2" esx esx_cluster base-cluster
assert_ini_value "$TMP_INI2" virtwho server base-virtwho.example.com
assert_ini_value "$TMP_INI2" virtwho brew "http://base-brew.example.com/koji"
assert_ini_value "$TMP_INI2" rhsm server base-rhsm.example.com
assert_ini_value "$TMP_INI2" rhsm default_org base-org
# env-only option is added on top of the base
assert_ini_value "$TMP_INI2" esx guest_ip 192.0.2.51
# section emitted because an env var is set, value from env
assert_ini_value "$TMP_INI2" rhevm server dummy-rhevm.example.com
# plan-level [job] preseed wins over the base
assert_ini_value "$TMP_INI2" job hypervisor libvirt
assert_ini_value "$TMP_INI2" job rhel_compose RHEL-10.0-DUMMY
# non-table section of the base is passed through unchanged
assert_ini_value "$TMP_INI2" beaker server base-beaker.example.com
echo "OK: base+overlay assertions passed (env wins, base survives, pass-through)"

# --- A failing base download must fail the generator loudly ---
if VIRTWHO_INI_URL="file:///nonexistent-virtwho-base.ini" \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/nope.ini" 2>/dev/null; then
    fail "generator survived a failing base download"
fi
[ ! -e "${WORK}/nope.ini" ] || fail "generator wrote output despite failed download"
echo "OK: failing base download fails the generator"

# --- VIRTWHO_INI_SHA256 pins the downloaded base (review PR298-23) ---
# The base selects where resolved credentials are sent, so a pinned
# digest must abort a tampered/incorrect base. Unset = unpinned (the
# accepted-risk posture is documented in README.rst).
PIN_ERR="${WORK}/sha256-pin.stderr"
if VIRTWHO_INI_URL="file://${BASE_INI}" \
    VIRTWHO_INI_SHA256="0000000000000000000000000000000000000000000000000000000000000000" \
    HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/sha256-bad.ini" \
    2>"$PIN_ERR"; then
    fail "generator accepted a base ini that does not match VIRTWHO_INI_SHA256"
fi
[ ! -e "${WORK}/sha256-bad.ini" ] \
    || fail "generator wrote output despite a VIRTWHO_INI_SHA256 mismatch"
grep -q "ERROR: the downloaded base ini does not match VIRTWHO_INI_SHA256" "$PIN_ERR" \
    || fail "digest mismatch did not produce the clean pin error"
echo "OK: a VIRTWHO_INI_SHA256 mismatch aborts the generator"

GOOD_SHA256=$(sha256sum "$BASE_INI" | awk '{print $1}')
VIRTWHO_INI_URL="file://${BASE_INI}" \
    VIRTWHO_INI_SHA256="$GOOD_SHA256" \
    HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/sha256-good.ini" \
    > "${WORK}/sha256-good.stdout"
assert_ini_value "${WORK}/sha256-good.ini" esx server base-esx.example.com
grep -q "Base ini matches the VIRTWHO_INI_SHA256 pin" "${WORK}/sha256-good.stdout" \
    || fail "a matching pin produced no confirmation line"
echo "OK: a matching VIRTWHO_INI_SHA256 pin passes (and says so)"

# --- A malformed base must fail with the clean error, not a traceback ---
GARBAGE_BASE="${WORK}/garbage.ini"
printf 'this is not an ini file\nno section header here\n' > "$GARBAGE_BASE"
GARBAGE_ERR="${WORK}/garbage.stderr"
if VIRTWHO_INI_URL="file://${GARBAGE_BASE}" \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/garbage-out.ini" \
    2>"$GARBAGE_ERR"; then
    fail "generator survived a malformed base ini"
fi
grep -q "ERROR: could not parse the downloaded base ini" "$GARBAGE_ERR" \
    || fail "malformed base did not produce the clean parse error"
if grep -q "Traceback" "$GARBAGE_ERR"; then
    fail "malformed base produced a raw Python traceback"
fi
[ ! -e "${WORK}/garbage-out.ini" ] || fail "generator wrote output despite a malformed base"
echo "OK: malformed base ini fails with the clean error (no traceback)"

# --- An empty base body is a download failure, not a silent fallback ---
EMPTY_BASE="${WORK}/empty.ini"
: > "$EMPTY_BASE"
EMPTY_ERR="${WORK}/empty.stderr"
if VIRTWHO_INI_URL="file://${EMPTY_BASE}" \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/empty-out.ini" \
    2>"$EMPTY_ERR"; then
    fail "generator silently fell back to env-only on an empty base"
fi
grep -q "ERROR: the downloaded base ini is empty" "$EMPTY_ERR" \
    || fail "empty base did not produce the loud empty-body error"
[ ! -e "${WORK}/empty-out.ini" ] || fail "generator wrote output despite an empty base"
echo "OK: empty base body fails loudly (no silent env-only fallback)"

# --- A base with planted forbidden (credential-shaped) keys must abort ---
BAD_BASE="${WORK}/bad-base.ini"
cat > "$BAD_BASE" <<'EOF'
[job]
hypervisor=esx

[esx]
server=base-esx.example.com
password=PLANTED-base-password

[kubevirt]
token=PLANTED-base-token
EOF
BAD_ERR="${WORK}/forbidden.stderr"
if VIRTWHO_INI_URL="file://${BAD_BASE}" \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/forbidden.ini" \
    2>"$BAD_ERR"; then
    fail "generator accepted a base ini with planted forbidden keys"
fi
[ ! -e "${WORK}/forbidden.ini" ] \
    || fail "generator wrote output despite forbidden base keys"
grep -q "forbidden credential option: \[esx\] password" "$BAD_ERR" \
    || fail "forbidden-key error does not name [esx] password"
grep -q "forbidden credential option: \[kubevirt\] token" "$BAD_ERR" \
    || fail "forbidden-key error does not name [kubevirt] token"
grep -q "PLANTED" "$BAD_ERR" \
    && fail "forbidden-key error leaked the planted value" || true
echo "OK: base with planted forbidden keys aborts, naming section.option"

# --- An empty credential-shaped option is not a sentinel: still aborts ---
EMPTY_CRED_BASE="${WORK}/empty-cred-base.ini"
cat > "$EMPTY_CRED_BASE" <<'EOF'
[job]
hypervisor=esx

[rhsm]
server=base-rhsm.example.com
password=
EOF
EMPTY_CRED_ERR="${WORK}/empty-cred.stderr"
if VIRTWHO_INI_URL="file://${EMPTY_CRED_BASE}" \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/empty-cred.ini" \
    2>"$EMPTY_CRED_ERR"; then
    fail "generator accepted an empty credential-shaped option in the base"
fi
grep -q "forbidden credential option: \[rhsm\] password" "$EMPTY_CRED_ERR" \
    || fail "empty credential option did not produce the forbidden-key error"
echo "OK: empty credential-shaped option aborts (only @vault: values allowed)"

# --- A sentinel in a never-resolved section aborts loudly ---
# [virtwho] and the pass-through sections take their values from the
# VIRTWHO_* env; a literal @vault: string there would silently become
# the credential (the run-tests.sh merge-back only fills EMPTY
# options). The scan allows sentinels, so this check is the one that
# catches them -- even with no Vault credentials anywhere.
UNSUP_BASE="${WORK}/unsupported-base.ini"
cat > "$UNSUP_BASE" <<'EOF'
[job]
hypervisor=
register=

[virtwho]
server=base-virtwho.example.com
username=@vault:apps/cct-ci/satellite-lab:ssh_username

[esx]
server=base-esx.example.com

[nfs]
server=base-nfs.example.com
password=@vault:apps/cct-ci/satellite-lab:satellite_password
EOF
UNSUP_ERR="${WORK}/unsupported.stderr"
if HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${UNSUP_BASE}" \
    env -u VAULT_ADDR -u VAULT_TOKEN -u VAULT_ROLE_ID -u VAULT_SECRET_ID \
        -u VIRTWHO_VAULT_REQUIRED \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/unsupported.ini" \
    2>"$UNSUP_ERR"; then
    fail "a sentinel in a never-resolved section was accepted"
fi
[ ! -e "${WORK}/unsupported.ini" ] \
    || fail "generator wrote output despite an unsupported-section sentinel"
grep -q "sentinel in the unsupported section \[virtwho\] (option username)" \
    "$UNSUP_ERR" \
    || fail "the unsupported-section error does not name [virtwho] username"
grep -q "sentinel in the unsupported section \[nfs\] (option password)" \
    "$UNSUP_ERR" \
    || fail "the unsupported-section error does not name [nfs] password"
grep -q "values for this section must come from the VIRTWHO_\* environment" \
    "$UNSUP_ERR" \
    || fail "the unsupported-section error does not state the remedy"
if grep -q "Traceback" "$UNSUP_ERR"; then
    fail "the unsupported-section abort produced a raw Python traceback"
fi
echo "OK: sentinels in never-resolved sections ([virtwho], pass-throughs) abort loudly"

# =========================================================================
# 2d) Vault sentinel resolution against a local fake Vault HTTP server
# =========================================================================
# A python http.server-based fake Vault kv2 + AppRole login endpoint
# with obviously-fake values. The request log proves SELECTIVE
# resolution at the network level: only the active sections' paths are
# ever requested.
FAKE_VAULT_LOG="${WORK}/vault-requests.log"
FAKE_VAULT_PORT_FILE="${WORK}/vault-port"
python3 - "${FAKE_VAULT_LOG}" "${FAKE_VAULT_PORT_FILE}" <<'FAKEVAULTEOF' &
import http.server
import json
import sys

log_path, port_path = sys.argv[1], sys.argv[2]

# obviously-fake values only; ahv_* deliberately absent so the
# unresolved-active-sentinel case has a key missing at a live path.
# "stringy" serves a bare string (malformed payload), "multiline" a
# value with a newline (ini values must be single-line), and the
# broken path always answers HTTP 500.
SECRETS = {
    "cct-ci/virtwho-hypervisors": {
        "hyperv_username": "FAKE-vault-hyperv-username",
        "hyperv_password": "FAKE-vault-hyperv-password",
        "hyperv_guest_username": "FAKE-vault-hyperv-guest-username",
        "hyperv_guest_password": "FAKE-vault-hyperv-guest-password",
        "libvirt_username": "FAKE-vault-libvirt-username",
        "libvirt_password": "FAKE-vault-libvirt-password",
        "libvirt_guest_username": "FAKE-vault-libvirt-guest-username",
        "libvirt_guest_password": "FAKE-vault-libvirt-guest-password",
        "kubevirt_guest_username": "FAKE-vault-kubevirt-guest-username",
        "kubevirt_guest_password": "FAKE-vault-kubevirt-guest-password",
    },
    "cct-ci/candlepin/stage": {
        "username": "FAKE-vault-rhsm-username",
        "password": "FAKE-vault-rhsm-password",
    },
    "cct-ci/satellite-lab": {
        "satellite_username": "FAKE-vault-satellite-username",
        "satellite_password": "FAKE-vault-satellite-password",
        "ssh_username": "FAKE-vault-satellite-ssh-username",
        "ssh_password": "FAKE-vault-satellite-ssh-password",
        "activation_key": "FAKE-vault-satellite-activation-key",
    },
    "cct-ci/stringy": "FAKE-not-a-dict",
    "cct-ci/multiline": {
        "multiline_password": "FAKE-line1\nFAKE-line2",
    },
}
# 200 responses in the WRONG SHAPE (top-level envelope not kv2): must
# be clean "malformed Vault response" errors, not raw TypeErrors
RAW_RESPONSES = {
    "cct-ci/badshape": {"data": "FAKE-not-a-dict"},
    "cct-ci/listshape": ["FAKE", "not", "a", "dict"],
}
BROKEN_PATHS = {"cct-ci/broken"}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _record(self):
        with open(log_path, "a") as f:
            f.write("%s %s\n" % (self.command, self.path))

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._record()
        if self.path == "/v1/auth/approle/login":
            self._send(200, {"auth": {"client_token": "FAKE-vault-client-token"}})
        else:
            self._send(404, {"errors": ["not found"]})

    def do_GET(self):
        self._record()
        prefix = "/v1/apps/data/"
        if self.path.startswith(prefix):
            path = self.path[len(prefix):]
            if path in BROKEN_PATHS:
                self._send(500, {"errors": ["broken on purpose"]})
                return
            if path in RAW_RESPONSES:
                self._send(200, RAW_RESPONSES[path])
                return
            if path in SECRETS:
                self._send(200, {"data": {"data": SECRETS[path]}})
                return
        self._send(404, {"errors": ["not found"]})


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(port_path, "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
FAKEVAULTEOF
FAKE_VAULT_PID=$!
for _ in $(seq 1 50); do
    [ -s "$FAKE_VAULT_PORT_FILE" ] && break
    sleep 0.1
done
[ -s "$FAKE_VAULT_PORT_FILE" ] || fail "the fake Vault server did not start"
VAULT_TEST_ADDR="http://127.0.0.1:$(cat "$FAKE_VAULT_PORT_FILE")"
# the fake Vault is plain http (loopback): the resolver's https
# requirement is explicitly opted out for every fake-Vault case; the
# https-refusal case below opts back in with env -u
export VAULT_ALLOW_HTTP=1
echo "OK: fake Vault server running at ${VAULT_TEST_ADDR}"

# The vault_resolve module API: sentinel shape helpers
python3 - "${SCRIPT_DIR}/vault_resolve.py" <<'PYEOF'
import configparser
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("vault_resolve", sys.argv[1])
vault_resolve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vault_resolve)

assert vault_resolve.is_sentinel("@vault:p:k")
assert not vault_resolve.is_sentinel("plain")
assert not vault_resolve.is_sentinel("")
assert vault_resolve.parse_sentinel("@vault:apps/x:key") == ("apps/x", "key")
try:
    vault_resolve.parse_sentinel("@vault:nokeys")
except vault_resolve.VaultError:
    pass
else:
    raise AssertionError("malformed sentinel did not raise")

cfg = configparser.ConfigParser(interpolation=None)
cfg.read_string("[a]\nx = @vault:p:k\ny = plain\n[b]\nz = @vault:p:j\n")
assert vault_resolve.sections_with_sentinels(cfg) == {"a", "b"}

# a single-segment path (no mount) is a grammar error, not a missing
# secret: the mount is part of the sentinel grammar -- and no request
# is issued for it
resolver = vault_resolve.VaultResolver(
    environ={"VAULT_ADDR": "https://vault.example.invalid",
             "VAULT_TOKEN": "FAKE-token"})
try:
    resolver.resolve("@vault:apps:key")
except vault_resolve.VaultError as error:
    assert "invalid Vault path" in str(error), error
else:
    raise AssertionError("a single-segment sentinel path did not raise")
print("OK: vault_resolve sentinel helpers behave")
PYEOF

# Sentinel-bearing base fixture (all fake; ahv keys missing in the
# fake Vault on purpose for the unresolved-sentinel case below).
SENTINEL_BASE="${WORK}/sentinel-base.ini"
cat > "$SENTINEL_BASE" <<'EOF'
; dummy sentinel-bearing base ini -- fake values only. Credential-
; shaped options carry @vault: sentinels (the only allowed form).
[job]
hypervisor=
register=

[esx]
server=base-esx.example.com

[hyperv]
server=base-hyperv.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_username
password=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_password
guest_username=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_guest_username
guest_password=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_guest_password

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username
password=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_password

[ahv]
server=base-ahv.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:ahv_username
password=@vault:apps/cct-ci/virtwho-hypervisors:ahv_password

[kubevirt]
endpoint=https://base-kubevirt.example.com
guest_username=@vault:apps/cct-ci/virtwho-hypervisors:kubevirt_guest_username
guest_password=@vault:apps/cct-ci/virtwho-hypervisors:kubevirt_guest_password

[rhsm]
server=base-rhsm.example.com
username=@vault:apps/cct-ci/candlepin/stage:username
password=@vault:apps/cct-ci/candlepin/stage:password
default_org=base-rhsm-org

[satellite]
server=base-satellite.example.com
username=@vault:apps/cct-ci/satellite-lab:satellite_username
password=@vault:apps/cct-ci/satellite-lab:satellite_password
ssh_username=@vault:apps/cct-ci/satellite-lab:ssh_username
ssh_password=@vault:apps/cct-ci/satellite-lab:ssh_password
activation_key=@vault:apps/cct-ci/satellite-lab:activation_key
default_org=base-satellite-org
EOF

# --- Selective resolution (AppRole) + env-over-resolved precedence ---
: > "$FAKE_VAULT_LOG"
SENTINEL_OUT="${WORK}/sentinel.ini"
SENTINEL_STDOUT="${WORK}/sentinel.stdout"
HYPERVISOR=hyperv REGISTER=rhsm RHEL_COMPOSE=RHEL-10.0-DUMMY \
VIRTWHO_INI_URL="file://${SENTINEL_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_ROLE_ID=FAKE-role-id VAULT_SECRET_ID=FAKE-secret-id \
VIRTWHO_HYPERV_USERNAME=env-overrides-vault \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$SENTINEL_OUT" \
    > "$SENTINEL_STDOUT"

MODE=$(stat -c '%a' "$SENTINEL_OUT")
[ "$MODE" = "600" ] || fail "sentinel mode: expected 600, got $MODE"
# active sections resolved (env secret wins over the resolved value)
assert_ini_value "$SENTINEL_OUT" hyperv username env-overrides-vault
assert_ini_value "$SENTINEL_OUT" hyperv password FAKE-vault-hyperv-password
assert_ini_value "$SENTINEL_OUT" hyperv guest_username FAKE-vault-hyperv-guest-username
assert_ini_value "$SENTINEL_OUT" hyperv guest_password FAKE-vault-hyperv-guest-password
assert_ini_value "$SENTINEL_OUT" rhsm username FAKE-vault-rhsm-username
assert_ini_value "$SENTINEL_OUT" rhsm password FAKE-vault-rhsm-password
# plaintext of the active sections survives
assert_ini_value "$SENTINEL_OUT" hyperv server base-hyperv.example.com
assert_ini_value "$SENTINEL_OUT" rhsm default_org base-rhsm-org
# NON-active sections keep their sentinels as literals (per-cell
# exposure: the other families' credentials are never materialized)
assert_ini_value "$SENTINEL_OUT" libvirt username \
    "@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username"
assert_ini_value "$SENTINEL_OUT" ahv username \
    "@vault:apps/cct-ci/virtwho-hypervisors:ahv_username"
assert_ini_value "$SENTINEL_OUT" kubevirt guest_username \
    "@vault:apps/cct-ci/virtwho-hypervisors:kubevirt_guest_username"
assert_ini_value "$SENTINEL_OUT" satellite username \
    "@vault:apps/cct-ci/satellite-lab:satellite_username"
# network-level proof of selectivity: login + the two active paths
# requested, the non-active satellite path never touched
grep -q "POST /v1/auth/approle/login" "$FAKE_VAULT_LOG" \
    || fail "AppRole login was not performed"
grep -q "GET /v1/apps/data/cct-ci/candlepin/stage" "$FAKE_VAULT_LOG" \
    || fail "the active register path was not requested"
if grep -q "satellite-lab" "$FAKE_VAULT_LOG"; then
    fail "the non-active satellite path was requested (resolution not selective)"
fi
# ONE read per secret PATH (the four hyperv sentinels share one path)
# and ONE login, despite five resolutions in this run
GETS=$(grep -c "GET /v1/apps/data/cct-ci/virtwho-hypervisors" "$FAKE_VAULT_LOG")
[ "$GETS" = "1" ] \
    || fail "expected 1 GET for the shared path, got $GETS (per-path caching broken)"
LOGINS=$(grep -c "POST /v1/auth/approle/login" "$FAKE_VAULT_LOG")
[ "$LOGINS" = "1" ] || fail "expected exactly 1 AppRole login, got $LOGINS"
# the env-covered sentinel (username) is never resolved: 5 of 6
grep -q "Resolved 5 Vault sentinel(s) in the active section(s): hyperv, rhsm" \
    "$SENTINEL_STDOUT" \
    || fail "the resolution log line is missing or wrong"
echo "OK: selective resolution (active only), AppRole login, env wins over resolved, one read per path"

# --- register=satellite + static VAULT_TOKEN (no AppRole login) ---
: > "$FAKE_VAULT_LOG"
SAT_OUT="${WORK}/satellite.ini"
HYPERVISOR=libvirt REGISTER=satellite RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$SAT_OUT"
assert_ini_value "$SAT_OUT" libvirt username FAKE-vault-libvirt-username
assert_ini_value "$SAT_OUT" libvirt password FAKE-vault-libvirt-password
assert_ini_value "$SAT_OUT" satellite username FAKE-vault-satellite-username
assert_ini_value "$SAT_OUT" satellite password FAKE-vault-satellite-password
assert_ini_value "$SAT_OUT" satellite ssh_username FAKE-vault-satellite-ssh-username
assert_ini_value "$SAT_OUT" satellite ssh_password FAKE-vault-satellite-ssh-password
assert_ini_value "$SAT_OUT" satellite activation_key FAKE-vault-satellite-activation-key
# the rhsm register path is never requested in a satellite cell
if grep -q "candlepin/stage" "$FAKE_VAULT_LOG"; then
    fail "the non-active rhsm register path was requested"
fi
if grep -q "approle/login" "$FAKE_VAULT_LOG"; then
    fail "an AppRole login was performed with a static VAULT_TOKEN set"
fi
grep -q "GET /v1/apps/data/cct-ci/satellite-lab" "$FAKE_VAULT_LOG" \
    || fail "the active satellite path was not requested"
SAT_GETS=$(grep -c "GET /v1/apps/data/cct-ci/satellite-lab" "$FAKE_VAULT_LOG")
[ "$SAT_GETS" = "1" ] \
    || fail "expected 1 GET for the satellite path, got $SAT_GETS"
echo "OK: register-section selection (satellite) + static token path"

# --- An unresolved sentinel in an ACTIVE section hard-fails ---
UNRESOLVED_ERR="${WORK}/unresolved.stderr"
if HYPERVISOR=ahv REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_ROLE_ID=FAKE-role-id VAULT_SECRET_ID=FAKE-secret-id \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/unresolved.ini" \
    2>"$UNRESOLVED_ERR"; then
    fail "generator survived an unresolved sentinel in the active section"
fi
[ ! -e "${WORK}/unresolved.ini" ] \
    || fail "generator wrote output despite an unresolved active sentinel"
grep -q "cannot resolve the sentinel of \[ahv\] username" "$UNRESOLVED_ERR" \
    || fail "unresolved-sentinel error does not name the section.option"
grep -q "'ahv_username' not found at Vault path 'apps/cct-ci/virtwho-hypervisors'" \
    "$UNRESOLVED_ERR" \
    || fail "unresolved-sentinel error does not name the path and key"
if grep -q "Traceback" "$UNRESOLVED_ERR"; then
    fail "unresolved sentinel produced a raw Python traceback"
fi
if grep -q "FAKE-vault" "$UNRESOLVED_ERR"; then
    fail "unresolved-sentinel error leaked a resolved value"
fi
echo "OK: unresolved active sentinel hard-fails, naming path+key (no traceback)"

# --- Vault redirects are refused, never followed with the token ---
# A fake Vault that answers EVERY request with a redirect to the main
# fake Vault (which would happily resolve everything if the redirect
# were followed): the generator must refuse the redirect and fail
# instead -- proving the X-Vault-Token header is never re-sent to the
# address the response names.
REDIRECT_PORT_FILE="${WORK}/vault-redirect-port"
python3 - "$VAULT_TEST_ADDR" "$REDIRECT_PORT_FILE" <<'REDIRECTEOF' &
import http.server
import sys

target, port_path = sys.argv[1], sys.argv[2]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _redirect(self):
        self.send_response(302)
        self.send_header("Location", target + self.path)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._redirect()

    def do_POST(self):
        self._redirect()


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(port_path, "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
REDIRECTEOF
REDIRECT_VAULT_PID=$!
for _ in $(seq 1 50); do
    [ -s "$REDIRECT_PORT_FILE" ] && break
    sleep 0.1
done
[ -s "$REDIRECT_PORT_FILE" ] || fail "the redirecting fake Vault did not start"
REDIRECT_ADDR="http://127.0.0.1:$(cat "$REDIRECT_PORT_FILE")"

REDIRECT_ERR="${WORK}/redirect.stderr"
if HYPERVISOR=hyperv REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_BASE}" \
VAULT_ADDR="$REDIRECT_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/redirect.ini" \
    2>"$REDIRECT_ERR"; then
    fail "generator followed a Vault redirect instead of refusing it"
fi
[ ! -e "${WORK}/redirect.ini" ] \
    || fail "generator wrote output despite a refused redirect"
grep -q "refusing to follow" "$REDIRECT_ERR" \
    || fail "the redirect refusal error is missing"
grep -q "${REDIRECT_ADDR}/v1/apps/data" "$REDIRECT_ERR" \
    || fail "the redirect refusal does not name the configured address"
if grep -q "Traceback" "$REDIRECT_ERR"; then
    fail "the redirect refusal produced a raw Python traceback"
fi
if grep -q "FAKE-static-token" "$REDIRECT_ERR"; then
    fail "the redirect refusal leaked the token"
fi
echo "OK: Vault redirects are refused (token never re-sent to the redirect target)"

# --- An env-supplied credential survives a Vault failure ---
# [hyperv] credentials point at the always-500 path, but the
# environment covers both: the run must succeed (env values are final
# and never resolved), the healthy register path must still resolve,
# and the broken path must never be requested.
BROKEN_BASE="${WORK}/broken-base.ini"
cat > "$BROKEN_BASE" <<'EOF'
[job]
hypervisor=
register=

[hyperv]
server=base-hyperv.example.com
username=@vault:apps/cct-ci/broken:hyperv_username
password=@vault:apps/cct-ci/broken:hyperv_password

[rhsm]
server=base-rhsm.example.com
username=@vault:apps/cct-ci/candlepin/stage:username
password=@vault:apps/cct-ci/candlepin/stage:password
EOF

: > "$FAKE_VAULT_LOG"
ENVWIN_OUT="${WORK}/env-wins.ini"
HYPERVISOR=hyperv REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${BROKEN_BASE}" \
VIRTWHO_HYPERV_USERNAME=env-hyperv-user \
VIRTWHO_HYPERV_PASSWORD=env-hyperv-pass \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$ENVWIN_OUT"
assert_ini_value "$ENVWIN_OUT" hyperv username env-hyperv-user
assert_ini_value "$ENVWIN_OUT" hyperv password env-hyperv-pass
assert_ini_value "$ENVWIN_OUT" rhsm username FAKE-vault-rhsm-username
assert_ini_value "$ENVWIN_OUT" rhsm password FAKE-vault-rhsm-password
if grep -q "cct-ci/broken" "$FAKE_VAULT_LOG"; then
    fail "an env-covered sentinel was resolved (the broken path was requested)"
fi
echo "OK: env-supplied credentials survive a Vault failure (never resolved)"

# --- All active credentials env-supplied, no Vault credentials at all ---
# The no-credentials gate only fires for sentinels the environment
# does NOT override: a fully env-covered cell runs without Vault.
ENVCOVER_OUT="${WORK}/env-covered.ini"
HYPERVISOR=hyperv REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_BASE}" \
VIRTWHO_HYPERV_USERNAME=env-hyperv-user \
VIRTWHO_HYPERV_PASSWORD=env-hyperv-pass \
VIRTWHO_HYPERV_GUEST_USERNAME=env-hyperv-guest-user \
VIRTWHO_HYPERV_GUEST_PASSWORD=env-hyperv-guest-pass \
VIRTWHO_RHSM_USERNAME=env-rhsm-user \
VIRTWHO_RHSM_PASSWORD=env-rhsm-pass \
    env -u VAULT_ADDR -u VAULT_TOKEN -u VAULT_ROLE_ID -u VAULT_SECRET_ID \
        -u VIRTWHO_VAULT_REQUIRED \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$ENVCOVER_OUT"
assert_ini_value "$ENVCOVER_OUT" hyperv username env-hyperv-user
assert_ini_value "$ENVCOVER_OUT" rhsm password env-rhsm-pass
# non-active families keep their literals
assert_ini_value "$ENVCOVER_OUT" libvirt username \
    "@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username"
echo "OK: a fully env-covered cell needs no Vault credentials (gate skips env-covered sentinels)"

# --- multi_hypervisors: every family in the list is active ---
# Via the env variable (which wins), with spaces and mixed case that
# the suite's own parser would keep (' rhevm'): entries are stripped
# and lower-cased here.
: > "$FAKE_VAULT_LOG"
MULTI_OUT="${WORK}/multi-env.ini"
HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_JOB_MULTI_HYPERVISORS='[ Libvirt , Hyperv ]' \
VIRTWHO_INI_URL="file://${SENTINEL_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$MULTI_OUT"
assert_ini_value "$MULTI_OUT" libvirt username FAKE-vault-libvirt-username
assert_ini_value "$MULTI_OUT" libvirt password FAKE-vault-libvirt-password
assert_ini_value "$MULTI_OUT" hyperv username FAKE-vault-hyperv-username
assert_ini_value "$MULTI_OUT" rhsm username FAKE-vault-rhsm-username
# families outside the list keep their literals
assert_ini_value "$MULTI_OUT" ahv username \
    "@vault:apps/cct-ci/virtwho-hypervisors:ahv_username"
assert_ini_value "$MULTI_OUT" kubevirt guest_username \
    "@vault:apps/cct-ci/virtwho-hypervisors:kubevirt_guest_username"
echo "OK: multi_hypervisors (env form, spaced/mixed-case) resolves every listed family"

# Via the base file's [job] multi_hypervisors (no env variable set).
MULTI_BASE="${WORK}/multi-base.ini"
cat > "$MULTI_BASE" <<'EOF'
[job]
hypervisor=
register=
multi_hypervisors=[libvirt]

[esx]
server=base-esx.example.com

[hyperv]
server=base-hyperv.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_username
password=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_password

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username
password=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_password
EOF
MULTI_BASE_OUT="${WORK}/multi-base-out.ini"
HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${MULTI_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    env -u VIRTWHO_JOB_MULTI_HYPERVISORS \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$MULTI_BASE_OUT"
assert_ini_value "$MULTI_BASE_OUT" libvirt username FAKE-vault-libvirt-username
assert_ini_value "$MULTI_BASE_OUT" hyperv username \
    "@vault:apps/cct-ci/virtwho-hypervisors:hyperv_username"
echo "OK: multi_hypervisors (base-file form) resolves the listed family only"

# Outer whitespace around the brackets must not silently drop the
# family: str.strip("[") strips a character set from both ends, so
# ' [libvirt] ' used to keep a bracket, match no section and skip
# resolution with exit 0.
for MULTI_WS_VALUE in '[libvirt] ' ' [libvirt] '; do
    MULTI_WS_OUT="${WORK}/multi-ws.ini"
    HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
    VIRTWHO_JOB_MULTI_HYPERVISORS="$MULTI_WS_VALUE" \
    VIRTWHO_INI_URL="file://${MULTI_BASE}" \
    VAULT_ADDR="$VAULT_TEST_ADDR" \
    VAULT_TOKEN=FAKE-static-token \
        bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$MULTI_WS_OUT"
    assert_ini_value "$MULTI_WS_OUT" libvirt username FAKE-vault-libvirt-username
done
echo "OK: multi_hypervisors with whitespace outside the brackets still resolves"

# --- multi_hypervisors is written back into [job] NORMALIZED ---
# The suite re-parses [job] multi_hypervisors with its own,
# unnormalized expression (virtwho/base.py hypervisors_list()) and
# get_hypervisor_handler() compares each entry RAW against the mode
# list, falling back to the [esx] handler for anything else: for
# '[ Libvirt , Hyperv ]' the generator resolved the right credentials
# but the suite drove the WRONG handler. The generator now writes the
# normalized list into the ini after the overlay; for every form
# below, the generated ini value AND the suite parser's output (the
# expression VERBATIM from virtwho/base.py, unnormalized) are
# asserted: they must agree, and every parsed entry must be a mode
# the suite recognizes.
MULTI_NORM_CASES=(
    '[ Libvirt , Hyperv ]|[libvirt,hyperv]'
    ' [libvirt] |[libvirt]'
    '[esx,rhevm]|[esx,rhevm]'
)
for MULTI_CASE in "${MULTI_NORM_CASES[@]}"; do
    MULTI_RAW_VALUE="${MULTI_CASE%%|*}"
    MULTI_NORM_EXPECTED="${MULTI_CASE#*|}"
    MULTI_NORM_OUT="${WORK}/multi-normalized.ini"
    HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
    VIRTWHO_JOB_MULTI_HYPERVISORS="$MULTI_RAW_VALUE" \
        env -u VIRTWHO_INI_URL \
        bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$MULTI_NORM_OUT"
    python3 - "$MULTI_NORM_OUT" "$MULTI_NORM_EXPECTED" "$MULTI_RAW_VALUE" <<'PYEOF'
import configparser
import sys

path, expected, raw = sys.argv[1:4]
cfg = configparser.ConfigParser(interpolation=None)
assert cfg.read(path), f"could not parse {path}"
value = cfg.get("job", "multi_hypervisors")
assert value == expected, \
    f"[job] multi_hypervisors from {raw!r}: expected {expected!r}, got {value!r}"

# the suite's own parser, VERBATIM from virtwho/base.py
# hypervisors_list() -- it does NOT normalize the entries
parsed = value.strip("[").strip("]").split(",")
assert parsed == expected.strip("[]").split(","), \
    f"suite parser disagrees with the generated ini: {parsed!r} vs {value!r}"

# get_hypervisor_handler()'s recognized modes (esx is its fallback
# section, so it counts as recognized; anything else would silently
# drive the esx handler)
modes = {"hyperv", "rhevm", "libvirt", "kubevirt", "ahv", "local", "esx"}
for entry in parsed:
    assert entry in modes, \
        f"suite would not recognize mode {entry!r} (parsed from {value!r})"
print(f"OK: multi_hypervisors {raw!r} written back normalized as {value!r}; suite parser agrees")
PYEOF
done

# The base-file form gets the same write-back: the overlay copies the
# RAW base value, so '[ Libvirt , Hyperv ]' in the base must land in
# the ini normalized too -- and the listed family still resolves.
MULTI_NORM_BASE="${WORK}/multi-norm-base.ini"
cat > "$MULTI_NORM_BASE" <<'EOF'
[job]
hypervisor=
register=
multi_hypervisors=[ Libvirt , Hyperv ]

[esx]
server=base-esx.example.com

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username
password=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_password
EOF
MULTI_NORM_BASE_OUT="${WORK}/multi-norm-base-out.ini"
HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${MULTI_NORM_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    env -u VIRTWHO_JOB_MULTI_HYPERVISORS \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$MULTI_NORM_BASE_OUT"
assert_ini_value "$MULTI_NORM_BASE_OUT" libvirt username FAKE-vault-libvirt-username
python3 - "$MULTI_NORM_BASE_OUT" <<'PYEOF'
import configparser
import sys

path = sys.argv[1]
cfg = configparser.ConfigParser(interpolation=None)
assert cfg.read(path), path
value = cfg.get("job", "multi_hypervisors")
assert value == "[libvirt,hyperv]", \
    f"[job] multi_hypervisors (base-file form): expected '[libvirt,hyperv]', got {value!r}"

# the suite's own parser, VERBATIM from virtwho/base.py
# hypervisors_list() -- it does NOT normalize the entries
parsed = value.strip("[").strip("]").split(",")
assert parsed == ["libvirt", "hyperv"], \
    f"suite parser disagrees with the generated ini: {parsed!r} vs {value!r}"
modes = {"hyperv", "rhevm", "libvirt", "kubevirt", "ahv", "local", "esx"}
for entry in parsed:
    assert entry in modes, \
        f"suite would not recognize mode {entry!r} (parsed from {value!r})"
print("OK: multi_hypervisors (base-file form, spaced/mixed-case) written back normalized; suite parser agrees")
PYEOF


# --- A plaintext http:// VAULT_ADDR is refused without the opt-out ---
: > "$FAKE_VAULT_LOG"
HTTPS_ERR="${WORK}/https.stderr"
if HYPERVISOR=hyperv REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    env -u VAULT_ALLOW_HTTP \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/https.ini" \
    2>"$HTTPS_ERR"; then
    fail "a plaintext http:// VAULT_ADDR was accepted"
fi
grep -q "VAULT_ADDR must use https (set VAULT_ALLOW_HTTP=1 to allow plaintext)" \
    "$HTTPS_ERR" \
    || fail "the https refusal message is missing or wrong"
if [ -s "$FAKE_VAULT_LOG" ]; then
    fail "a request was made despite the https refusal"
fi
if grep -q "Traceback" "$HTTPS_ERR"; then
    fail "the https refusal produced a raw Python traceback"
fi
echo "OK: plaintext http:// VAULT_ADDR refused unless VAULT_ALLOW_HTTP is set"

# --- Malformed inputs fail with clean errors, not tracebacks ---
BADSENT_BASE="${WORK}/badsent-base.ini"
cat > "$BADSENT_BASE" <<'EOF'
[job]
hypervisor=
register=

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/bad path:username

[ahv]
server=base-ahv.example.com
username=@vault:apps/cct-ci/stringy:username

[kubevirt]
endpoint=https://base-kubevirt.example.com
guest_username=@vault:apps/cct-ci/multiline:multiline_password

[local]
server=base-local.example.com
username=@vault:apps/cct-ci/badshape:key

[xen]
server=base-xen.example.com
username=@vault:apps/cct-ci/listshape:key

[rhsm]
server=base-rhsm.example.com
EOF

# a space in the sentinel path: InvalidURL must be caught (it derives
# from HTTPException, not ValueError/OSError)
BADURL_ERR="${WORK}/badurl.stderr"
if HYPERVISOR=libvirt REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${BADSENT_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/badurl.ini" \
    2>"$BADURL_ERR"; then
    fail "a sentinel path with a space was accepted"
fi
grep -q "Vault request failed: InvalidURL" "$BADURL_ERR" \
    || fail "the InvalidURL error is missing or wrong"
if grep -q "Traceback" "$BADURL_ERR"; then
    fail "a space in the sentinel path produced a raw Python traceback"
fi
echo "OK: a space in a sentinel path fails cleanly (InvalidURL caught, no traceback)"

# a non-dict payload is a malformed response, not a missing key
BADPAYLOAD_ERR="${WORK}/badpayload.stderr"
if HYPERVISOR=ahv REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${BADSENT_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/badpayload.ini" \
    2>"$BADPAYLOAD_ERR"; then
    fail "a non-dict Vault payload was accepted"
fi
grep -q "malformed Vault response for path 'apps/cct-ci/stringy'" "$BADPAYLOAD_ERR" \
    || fail "the malformed-response error is missing or wrong"
if grep -q "not found" "$BADPAYLOAD_ERR"; then
    fail "a malformed response was misreported as a missing key"
fi
echo "OK: a non-dict Vault payload fails as a malformed response"

# a 200 whose TOP-LEVEL envelope is not the kv2 shape ({"data": "…"}
# or a bare JSON list) must also be a clean malformed error -- blind
# subscripting raised a raw TypeError here
BADSHAPE_ERR="${WORK}/badshape.stderr"
if HYPERVISOR=local REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${BADSENT_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/badshape.ini" \
    2>"$BADSHAPE_ERR"; then
    fail "a string top-level envelope was accepted"
fi
grep -q "malformed Vault response for path 'apps/cct-ci/badshape'" "$BADSHAPE_ERR" \
    || fail "the badshape malformed-response error is missing or wrong"
if grep -q "Traceback" "$BADSHAPE_ERR"; then
    fail "a string top-level envelope produced a raw Python traceback"
fi
LISTSHAPE_ERR="${WORK}/listshape.stderr"
if HYPERVISOR=xen REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${BADSENT_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/listshape.ini" \
    2>"$LISTSHAPE_ERR"; then
    fail "a JSON-list response was accepted"
fi
grep -q "malformed Vault response for path 'apps/cct-ci/listshape'" "$LISTSHAPE_ERR" \
    || fail "the listshape malformed-response error is missing or wrong"
if grep -q "Traceback" "$LISTSHAPE_ERR"; then
    fail "a JSON-list response produced a raw Python traceback"
fi
echo "OK: wrong-shape 200 envelopes (string data / bare list) fail cleanly"

# a resolved value containing a newline would corrupt the ini
BADNL_ERR="${WORK}/badnl.stderr"
if HYPERVISOR=kubevirt REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${BADSENT_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/badnl.ini" \
    2>"$BADNL_ERR"; then
    fail "a newline-containing resolved value was accepted"
fi
grep -q "contains a newline: ini values must be single-line" "$BADNL_ERR" \
    || fail "the newline rejection message is missing or wrong"
if grep -q "FAKE-line" "$BADNL_ERR"; then
    fail "the newline rejection leaked the value"
fi
echo "OK: a newline-containing resolved value is rejected (value never leaked)"

# --- One request per failing path (failure caching) ---
: > "$FAKE_VAULT_LOG"
BROKEN_ERR="${WORK}/broken.stderr"
if HYPERVISOR=hyperv REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${BROKEN_BASE}" \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    env -u VIRTWHO_HYPERV_USERNAME -u VIRTWHO_HYPERV_PASSWORD \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/broken.ini" \
    2>"$BROKEN_ERR"; then
    fail "an always-500 Vault path was accepted"
fi
grep -q "Vault request failed: HTTP 500" "$BROKEN_ERR" \
    || fail "the HTTP 500 error is missing or wrong"
# two sentinels share the broken path: exactly ONE request (the
# failure is cached per path, not retried per sentinel)
BROKEN_GETS=$(grep -c "GET /v1/apps/data/cct-ci/broken" "$FAKE_VAULT_LOG")
[ "$BROKEN_GETS" = "1" ] \
    || fail "expected 1 GET for the broken path, got $BROKEN_GETS (failure caching broken)"
echo "OK: a failing path is read once (per-path failure caching)"

# --- Credentials without VAULT_ADDR fail loudly (no default address) ---
NOADDR_ERR="${WORK}/noaddr.stderr"
if HYPERVISOR=hyperv REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_BASE}" \
VAULT_TOKEN=FAKE-static-token \
    env -u VAULT_ADDR \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/noaddr.ini" \
    2>"$NOADDR_ERR"; then
    fail "credentials without VAULT_ADDR were accepted"
fi
grep -q "Vault credentials are set but VAULT_ADDR is not" "$NOADDR_ERR" \
    || fail "the missing-address error is missing or wrong"
if grep -q "Traceback" "$NOADDR_ERR"; then
    fail "the missing-address failure produced a raw Python traceback"
fi
echo "OK: credentials without VAULT_ADDR fail loudly (no default address)"

# --- No Vault credentials with active sentinels hard-fails ---
NOCREDS_ERR="${WORK}/nocreds.stderr"
if HYPERVISOR=hyperv REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_BASE}" \
    env -u VAULT_ADDR -u VAULT_TOKEN -u VAULT_ROLE_ID -u VAULT_SECRET_ID \
        -u VIRTWHO_VAULT_REQUIRED \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/nocreds.ini" \
    2>"$NOCREDS_ERR"; then
    fail "generator ran a credentialed cell without Vault credentials"
fi
[ ! -e "${WORK}/nocreds.ini" ] \
    || fail "generator wrote output despite missing Vault credentials"
grep -q "no Vault credentials are set" "$NOCREDS_ERR" \
    || fail "missing-credentials error does not name the credentials"
grep -q "unset VIRTWHO_INI_URL" "$NOCREDS_ERR" \
    || fail "missing-credentials error does not name the env-only escape hatch"
if grep -q "Traceback" "$NOCREDS_ERR"; then
    fail "missing-credentials failure produced a raw Python traceback"
fi
echo "OK: active sentinels without credentials hard-fail (escape hatch named)"

# --- Strict knob: any sentinel requires credentials, scope stays selective ---
# A base whose ONLY sentinels sit in [libvirt] while the active cell is
# esx/rhsm: without the knob the run succeeds (non-active sentinels
# stay literal); with the knob and no credentials it fails; with the
# knob AND credentials it still does not resolve the non-active
# section (the knob never widens the per-cell exposure).
SENTINEL_ELSEWHERE="${WORK}/sentinel-elsewhere.ini"
cat > "$SENTINEL_ELSEWHERE" <<'EOF'
[job]
hypervisor=
register=

[esx]
server=base-esx.example.com

[rhsm]
server=base-rhsm.example.com
default_org=base-rhsm-org

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username
password=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_password
EOF

STRICT_OUT="${WORK}/strict-off.ini"
HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_ELSEWHERE}" \
    env -u VAULT_ADDR -u VAULT_TOKEN -u VAULT_ROLE_ID -u VAULT_SECRET_ID \
        -u VIRTWHO_VAULT_REQUIRED \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$STRICT_OUT"
assert_ini_value "$STRICT_OUT" esx server base-esx.example.com
assert_ini_value "$STRICT_OUT" libvirt username \
    "@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username"
echo "OK: non-active sentinels without credentials stay literal (knob unset)"

STRICT_ERR="${WORK}/strict-on.stderr"
if HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_ELSEWHERE}" \
VIRTWHO_VAULT_REQUIRED=1 \
    env -u VAULT_ADDR -u VAULT_TOKEN -u VAULT_ROLE_ID -u VAULT_SECRET_ID \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/strict-on.ini" \
    2>"$STRICT_ERR"; then
    fail "VIRTWHO_VAULT_REQUIRED did not require credentials"
fi
grep -q "VIRTWHO_VAULT_REQUIRED is set and the base ini carries @vault: sentinels" \
    "$STRICT_ERR" \
    || fail "strict-mode error does not name the knob"
[ ! -e "${WORK}/strict-on.ini" ] \
    || fail "generator wrote output despite strict mode without credentials"
echo "OK: strict knob requires credentials for any sentinel"

STRICT_CREDS_OUT="${WORK}/strict-creds.ini"
HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_ELSEWHERE}" \
VIRTWHO_VAULT_REQUIRED=1 \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$STRICT_CREDS_OUT"
assert_ini_value "$STRICT_CREDS_OUT" libvirt username \
    "@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username"
echo "OK: strict knob does not widen the resolution scope (non-active stays literal)"

# --- Strict mode must reject unusable credentials, not just absent ones ---
# A token without VAULT_ADDR used to satisfy the strict gate (exit 0,
# literal sentinels written); the gate now runs the resolver's own
# pre-flight checks.
STRICT_ADDR_ERR="${WORK}/strict-addr.stderr"
if HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_INI_URL="file://${SENTINEL_ELSEWHERE}" \
VIRTWHO_VAULT_REQUIRED=1 \
VAULT_TOKEN=FAKE-static-token \
    env -u VAULT_ADDR \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/strict-addr.ini" \
    2>"$STRICT_ADDR_ERR"; then
    fail "strict mode was satisfied by credentials without VAULT_ADDR"
fi
grep -q "VIRTWHO_VAULT_REQUIRED is set but the Vault credentials are unusable" \
    "$STRICT_ADDR_ERR" \
    || fail "the strict unusable-credentials error is missing"
grep -q "Vault credentials are set but VAULT_ADDR is not" "$STRICT_ADDR_ERR" \
    || fail "the strict gate does not reuse the missing-address error"
[ ! -e "${WORK}/strict-addr.ini" ] \
    || fail "generator wrote output despite unusable strict-mode credentials"
echo "OK: strict mode requires usable credentials (address present)"

# --- No-sentinel regression: credentials + strict set, plain base ---
: > "$FAKE_VAULT_LOG"
PLAIN_OUT="${WORK}/plain-with-creds.ini"
HYPERVISOR=libvirt REGISTER=rhsm RHEL_COMPOSE=RHEL-10.0-DUMMY \
VIRTWHO_ESX_PASSWORD=env-esx-pass \
VIRTWHO_INI_URL="file://${BASE_INI}" \
VIRTWHO_VAULT_REQUIRED=1 \
VAULT_ADDR="$VAULT_TEST_ADDR" \
VAULT_TOKEN=FAKE-static-token \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$PLAIN_OUT"
assert_ini_value "$PLAIN_OUT" esx password env-esx-pass
assert_ini_value "$PLAIN_OUT" esx server base-esx.example.com
assert_ini_value "$PLAIN_OUT" virtwho server base-virtwho.example.com
assert_ini_value "$PLAIN_OUT" beaker server base-beaker.example.com
if [ -s "$FAKE_VAULT_LOG" ]; then
    fail "Vault requests were made for a sentinel-free base"
fi
MODE=$(stat -c '%a' "$PLAIN_OUT")
[ "$MODE" = "600" ] || fail "plain-with-creds mode: expected 600, got $MODE"
echo "OK: sentinel-free base identical with credentials + strict set (resolver inert)"

# --- Staging/cleanup invariants: no base or tmp leftovers anywhere ---
LEFTOVERS=$(find "$WORK" -name '*.base.*' -o -name '*.tmp.*' | head -1)
[ -z "$LEFTOVERS" ] || fail "staging leftovers left behind: $LEFTOVERS"
echo "OK: no base/tmp staging leftovers in the selftest workdir"

# =========================================================================
# 2b) Legacy KUBEVIRT_TOKEN alias survives regeneration
# =========================================================================
# run-tests.sh regenerates the ini from the environment at test time;
# the legacy KUBEVIRT_TOKEN name must map onto VIRTWHO_KUBEVIRT_TOKEN
# so the token is not wiped by the regeneration.
TMP_INI_LEGACY="${WORK}/legacy-token.ini"
HYPERVISOR=kubevirt REGISTER=rhsm RHEL_COMPOSE='' \
KUBEVIRT_TOKEN=legacy-kubevirt-token \
    env -u VIRTWHO_KUBEVIRT_TOKEN -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI_LEGACY"
assert_ini_value "$TMP_INI_LEGACY" kubevirt token legacy-kubevirt-token
echo "OK: legacy KUBEVIRT_TOKEN survives regeneration"

# the new name wins when both are set
TMP_INI_BOTH="${WORK}/both-tokens.ini"
HYPERVISOR=kubevirt REGISTER=rhsm RHEL_COMPOSE='' \
KUBEVIRT_TOKEN=legacy-kubevirt-token \
VIRTWHO_KUBEVIRT_TOKEN=new-kubevirt-token \
    env -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI_BOTH"
assert_ini_value "$TMP_INI_BOTH" kubevirt token new-kubevirt-token
echo "OK: VIRTWHO_KUBEVIRT_TOKEN wins over the legacy alias"

# =========================================================================
# 2c) Misspelled VIRTWHO_* options warn on stderr
# =========================================================================
TYPO_ERR="${WORK}/typo.stderr"
HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_ESX_GUEST_IPS=192.0.2.99 \
    env -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/typo.ini" \
    2>"$TYPO_ERR"
grep -q "WARNING: ignoring VIRTWHO_\* variable(s) matching no known ini option" "$TYPO_ERR" \
    || fail "misspelled VIRTWHO_ESX_GUEST_IPS produced no warning"
grep -q "VIRTWHO_ESX_GUEST_IPS" "$TYPO_ERR" \
    || fail "warning does not name the misspelled variable"
if grep -q "^guest_ips=" "${WORK}/typo.ini"; then
    fail "misspelled option leaked into the ini"
fi
# a run with only well-formed variables must stay warning-free
CLEAN_ERR="${WORK}/clean.stderr"
HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_ESX_GUEST_IP=192.0.2.50 \
    env -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/clean.ini" \
    2>"$CLEAN_ERR"
if grep -q "WARNING: ignoring VIRTWHO" "$CLEAN_ERR"; then
    fail "clean run produced a spurious unknown-variable warning"
fi
echo "OK: misspelled VIRTWHO_* option warns on stderr; clean run stays silent"

# =========================================================================
# 2e) [job] plan-level aliases (review PR297-09)
# =========================================================================
# HYPERVISOR unset: the prefixed form wins (the preseed would
# otherwise clobber it with the esx default) AND feeds the
# hypervisor-section creation -- without the promotion, [job]
# hypervisor=libvirt with no [libvirt] section fails the whole suite
# at conftest import.
TMP_INI_JOB="${WORK}/job-alias.ini"
REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_JOB_HYPERVISOR=libvirt \
    env -u VIRTWHO_INI_URL -u HYPERVISOR \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI_JOB"
assert_ini_value "$TMP_INI_JOB" job hypervisor libvirt
if ! grep -q '^\[libvirt\]' "$TMP_INI_JOB"; then
    fail "VIRTWHO_JOB_HYPERVISOR=libvirt produced no [libvirt] section (the suite reads it at import time)"
fi
echo "OK: VIRTWHO_JOB_HYPERVISOR wins when the plan-level HYPERVISOR is unset"
echo "OK: the promoted VIRTWHO_JOB_HYPERVISOR feeds the hypervisor section ([libvirt] emitted)"

# Lower-cased promotion: VIRTWHO_JOB_HYPERVISOR=LIBVIRT must select
# libvirt, not silently fall back to the (lowercase-only) ESX handler.
TMP_INI_JOB_UC="${WORK}/job-alias-upper.ini"
JOB_ALIAS_UC_ERR="${WORK}/job-alias-upper.stderr"
REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_JOB_HYPERVISOR=LIBVIRT \
    env -u VIRTWHO_INI_URL -u HYPERVISOR \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI_JOB_UC" \
    2>"$JOB_ALIAS_UC_ERR"
assert_ini_value "$TMP_INI_JOB_UC" job hypervisor libvirt
if ! grep -q '^\[libvirt\]' "$TMP_INI_JOB_UC"; then
    fail "VIRTWHO_JOB_HYPERVISOR=LIBVIRT produced no [libvirt] section"
fi
if grep -q "shadowed" "$JOB_ALIAS_UC_ERR"; then
    fail "the promoted (lower-cased) alias was reported as shadowed by itself"
fi
echo "OK: VIRTWHO_JOB_HYPERVISOR is lower-cased (LIBVIRT selects [libvirt], no spurious shadow warning)"

# REGISTER alias: with the plan-level REGISTER unset, the alias must
# win over the rhsm default the generator would otherwise apply (the
# invocation used to hard-code REGISTER=rhsm, making the alias
# unwinnable) and must not warn about a variable nobody set.
TMP_INI_JOB_REG="${WORK}/job-alias-register.ini"
JOB_ALIAS_REG_ERR="${WORK}/job-alias-register.stderr"
HYPERVISOR=esx RHEL_COMPOSE='' \
VIRTWHO_JOB_REGISTER=satellite \
    env -u VIRTWHO_INI_URL -u REGISTER \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI_JOB_REG" \
    2>"$JOB_ALIAS_REG_ERR"
assert_ini_value "$TMP_INI_JOB_REG" job register satellite
if grep -q "VIRTWHO_JOB_REGISTER is shadowed" "$JOB_ALIAS_REG_ERR"; then
    fail "VIRTWHO_JOB_REGISTER was shadowed although the plan-level REGISTER was never set"
fi
echo "OK: VIRTWHO_JOB_REGISTER wins over the rhsm default when the plan-level REGISTER is unset"

# RHEL_COMPOSE alias: with the plan-level compose unset, the alias
# must reach [job] rhel_compose (setup-virtwho-test.sh resolves
# RESOLVED_COMPOSE from the same variable).
TMP_INI_JOB_CMP="${WORK}/job-alias-compose.ini"
HYPERVISOR=esx REGISTER=rhsm \
VIRTWHO_JOB_RHEL_COMPOSE=RHEL-10.0-DUMMY \
    env -u VIRTWHO_INI_URL -u RHEL_COMPOSE \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI_JOB_CMP"
assert_ini_value "$TMP_INI_JOB_CMP" job rhel_compose RHEL-10.0-DUMMY
echo "OK: VIRTWHO_JOB_RHEL_COMPOSE wins when the plan-level RHEL_COMPOSE is unset"

# Both set and disagreeing: the plan-level variable wins and the
# warning names it (never the values).
JOB_ALIAS_ERR="${WORK}/job-alias.stderr"
HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_JOB_HYPERVISOR=libvirt \
    env -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/job-shadow.ini" \
    2>"$JOB_ALIAS_ERR"
assert_ini_value "${WORK}/job-shadow.ini" job hypervisor esx
grep -q "VIRTWHO_JOB_HYPERVISOR is shadowed by the plan-level HYPERVISOR variable" "$JOB_ALIAS_ERR" \
    || fail "plan-level shadowing produced no warning naming the winner"
if grep -q "libvirt" "$JOB_ALIAS_ERR"; then
    fail "plan-level shadowing warning leaked a value"
fi
echo "OK: a set plan-level HYPERVISOR wins over VIRTWHO_JOB_HYPERVISOR; the warning names the winner"

# =========================================================================
# 2f) ESX/VCENTER dual-prefix clash (review PR297-13)
# =========================================================================
DUAL_ERR="${WORK}/dual-prefix.stderr"
HYPERVISOR=esx REGISTER=rhsm RHEL_COMPOSE='' \
VIRTWHO_VCENTER_SERVER=198.51.100.10 \
VIRTWHO_ESX_SERVER=198.51.100.20 \
    env -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${WORK}/dual-prefix.ini" \
    2>"$DUAL_ERR"
assert_ini_value "${WORK}/dual-prefix.ini" esx server 198.51.100.20
grep -q "VIRTWHO_ESX_\* wins" "$DUAL_ERR" \
    || fail "ESX/VCENTER clash produced no warning naming the winner"
grep -q "server" "$DUAL_ERR" \
    || fail "ESX/VCENTER clash warning does not name the option"
if grep -qE "198\.51\.100\.(10|20)" "$DUAL_ERR"; then
    fail "ESX/VCENTER clash warning leaked a value"
fi
echo "OK: an ESX/VCENTER clash warns on stderr and VIRTWHO_ESX_* wins"

# =========================================================================
# 3) Single materialization: symlink survives cp -a and writes go through
# =========================================================================
TMP_INI3="${WORK}/materialized.ini"
HYPERVISOR=esx \
VIRTWHO_VCENTER_SERVER=dummy-vcenter.example.com \
    env -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "$TMP_INI3"
TREE="${WORK}/tree"
mkdir -p "$TREE"
ln -s "$TMP_INI3" "${TREE}/virtwho.ini"

# cp -a (the bootc writable-copy path in run-tests.sh) must preserve
# the symlink, not follow it.
cp -a "$TREE" "${WORK}/tree-copy"
[ -L "${WORK}/tree-copy/virtwho.ini" ] \
    || fail "cp -a did not preserve the virtwho.ini symlink"
echo "OK: cp -a preserves the symlink (bootc copy path)"

# Configure.save() semantics: configparser opens the path with "w",
# which follows the symlink and writes to the tmpfs target.
python3 - "${WORK}/tree-copy/virtwho.ini" <<'PYEOF'
import configparser
import os
import sys

path = sys.argv[1]
assert os.path.islink(path), "virtwho.ini in the test tree must be a symlink"
cfg = configparser.ConfigParser(interpolation=None)
cfg.read(path)
assert cfg.get("esx", "server") == "dummy-vcenter.example.com"
cfg.set("esx", "server", "written-through-symlink.example.com")
with open(path, "w") as f:
    cfg.write(f, space_around_delimiters=False)
PYEOF
# the write landed in the tmpfs target ...
grep -q "written-through-symlink.example.com" "$TMP_INI3" \
    || fail "write through the symlink did not reach the tmpfs target"
# ... and the tree still holds a symlink, not a regular file
[ -L "${WORK}/tree-copy/virtwho.ini" ] || fail "symlink was replaced by a file"
[ -L "${TREE}/virtwho.ini" ] || fail "original symlink was replaced by a file"
echo "OK: configparser writes through the symlink to the tmpfs target"

# --- The generator writes THROUGH a symlinked OUTPUT (review PR297-10) ---
# Re-running the generator with the tree's symlink as OUTPUT must not
# replace the link with a regular file: it resolves the link and
# writes to the tmpfs target.
VIRTWHO_VCENTER_SERVER=written-via-symlink-output.example.com \
    env -u VIRTWHO_INI_URL \
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" "${TREE}/virtwho.ini"
[ -L "${TREE}/virtwho.ini" ] \
    || fail "generator replaced the symlinked OUTPUT with a regular file"
grep -q "written-via-symlink-output.example.com" "$TMP_INI3" \
    || fail "generator did not write through the symlink to the tmpfs target"
echo "OK: generator writes through a symlinked OUTPUT (link preserved)"

# =========================================================================
# 4) ssh_config approach: tmpfs key reached via an IdentityFile entry
# =========================================================================
SSH_CONFIG="${WORK}/ssh-config"
ssh-keygen -t rsa -N "" -f "$SSH_KEY" -C "selftest" -q
chmod 600 "$SSH_KEY"

# exactly what run-tests.sh writes (base block + tmpfs key entry)
printf 'Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile %s/known_hosts\n\n' \
    "$WORK" > "$SSH_CONFIG"
printf '  # virtwho-test tmpfs key\n  IdentityFile %s\n' \
    "$SSH_KEY" >> "$SSH_CONFIG"
chmod 600 "$SSH_CONFIG"

# the public key is derived next to the private key on tmpfs
ssh-keygen -y -f "$SSH_KEY" > "${SSH_KEY}.pub"
grep -q '^ssh-rsa ' "${SSH_KEY}.pub" || fail "could not derive the public key"
echo "OK: public key derived next to the tmpfs key"

# ssh -G resolves the config WITHOUT connecting: the IdentityFile entry
# must point ssh (and through it the virt-who daemon's qemu+ssh URIs)
# at the tmpfs key.
ssh -G -F "$SSH_CONFIG" dummy-hypervisor.example.invalid 2>/dev/null \
    | grep -qxF "identityfile ${SSH_KEY}" \
    || fail "ssh -G did not resolve the tmpfs IdentityFile entry"
echo "OK: ssh -G resolves the tmpfs IdentityFile entry"

# --- The REAL cleanup-secrets.sh, run against a sandboxed tree ---
# The cleanup script's locations are overridable via VIRTWHO_CLEANUP_*
# env vars; point them at a sandbox with the same layout as a CI guest
# so the self-test exercises the actual script (not a re-implementation
# of it) and catches mutations of the real one. The sandbox ini also
# carries [kubevirt] config_file overrides: VIRTWHO_CLEANUP_KUBECONFIGS
# is deliberately UNSET so the finish step must read the kubeconfig
# paths from the ini and shred THOSE, not just the two literals
# (review PR297-05). One override stays INSIDE the sandbox kubeconfig
# root and must be shredded; the other points OUTSIDE it (a file that
# is not a kubeconfig) and must be REFUSED with a warning -- the ini
# is downloaded input and must not aim the finish step at arbitrary
# files (review PR298-22).
SANDBOX_INI="${WORK}/virtwho.ini"
printf '[esx]\npassword=dummy-selftest-secret\n[kubevirt]\nconfig_file=%s\nconfig_file_no_cert=%s\n' \
    "${WORK}/root/kc-custom" "${WORK}/outside/important" > "$SANDBOX_INI"
chmod 600 "$SANDBOX_INI"
STAGING="${WORK}/virtwho.ini.tmp.ABCDEF"
printf 'partial\n' > "$STAGING"
mkdir -p "${WORK}/root" "${WORK}/outside"
printf 'token: dummy-selftest-sa-token\n' > "${WORK}/root/kc-custom"
chmod 644 "${WORK}/root/kc-custom"
printf 'definitely not a kubeconfig\n' > "${WORK}/outside/important"
chmod 644 "${WORK}/outside/important"
# the /etc/virt-who.d uploads (Configure.save() writes the per-mode
# config and the Hyper-V keytab there on the guest itself, carrying
# the same credentials as the shredded temp/ twins) -- shredded too
# (review PR297-16)
VIRTWHO_D_SANDBOX="${WORK}/etc-virt-who.d"
mkdir -p "$VIRTWHO_D_SANDBOX"
printf 'username=dummy-selftest-register-user\npassword=dummy-selftest-register-password\n' \
    > "${VIRTWHO_D_SANDBOX}/esx.conf"
printf 'dummy-keytab-bytes\n' > "${VIRTWHO_D_SANDBOX}/hyperv-kerberos.keytab"
TREE_DIRS=()
for tree in tree-opt tree-usr tree-var; do
    dir="${WORK}/${tree}"
    TREE_DIRS+=("$dir")
    mkdir -p "${dir}/temp"
    ln -s "$SANDBOX_INI" "${dir}/virtwho.ini"
    touch "${dir}/.virtwho-ini-generated" "${dir}/.virtwho-computed.ini"
    # the suite's own disk artifacts (review PR297-03): the per-mode
    # config carries the hypervisor password, the keytab is the
    # Hyper-V credential
    printf 'password=dummy-selftest-hypervisor-password\n' > "${dir}/temp/esx.conf"
    printf 'dummy-keytab-bytes\n' > "${dir}/temp/hyperv-kerberos.keytab"
done
# a REGULAR legacy ini (not the tmpfs symlink) must be shredded, not
# just unlinked (review PR297-10)
LEGACY_TREE="${WORK}/tree-legacy"
TREE_DIRS+=("$LEGACY_TREE")
mkdir -p "$LEGACY_TREE"
printf '[esx]\npassword=dummy-selftest-legacy-ini-password\n' > "${LEGACY_TREE}/virtwho.ini"
# a sibling IdentityFile entry (e.g. a .bak) must survive the
# anchored delete (review PR297-10)
printf '  IdentityFile %s.bak\n' "$SSH_KEY" >> "$SSH_CONFIG"

VIRTWHO_CLEANUP_SHM_DIR="$WORK" \
VIRTWHO_CLEANUP_SSH_CONFIG="$SSH_CONFIG" \
VIRTWHO_CLEANUP_TREE_DIRS="${TREE_DIRS[*]}" \
VIRTWHO_CLEANUP_KUBECONFIG_ROOT="${WORK}/root" \
VIRTWHO_CLEANUP_VIRTWHO_D_DIR="$VIRTWHO_D_SANDBOX" \
    bash "${SCRIPT_DIR}/cleanup-secrets.sh" > "${WORK}/cleanup.stdout"

# tmpfs originals and staging leftovers are shredded
for f in "$SANDBOX_INI" "$SSH_KEY" "${SSH_KEY}.pub" "$STAGING"; do
    [ ! -e "$f" ] || fail "cleanup left ${f} behind"
done
# the ini-configured kubeconfig path UNDER the kubeconfig root is
# shredded (review PR297-05); the path OUTSIDE it is refused with a
# warning naming it and survives untouched (review PR298-22)
[ ! -e "${WORK}/root/kc-custom" ] \
    || fail "cleanup left the ini-configured kubeconfig ${WORK}/root/kc-custom behind"
[ -e "${WORK}/outside/important" ] \
    || fail "cleanup shredded an ini-supplied path outside the kubeconfig root (PR298-22)"
grep -q "WARNING: refusing to shred ${WORK}/outside/important (not a kubeconfig path)" \
    "${WORK}/cleanup.stdout" \
    || fail "the refused kubeconfig path produced no warning naming it"
echo "OK: ini-configured kubeconfig path under /root is shredded; a path outside it is refused with a warning"
# ini symlinks, bookkeeping files, the suite's temp/ artifacts and
# the regular legacy ini are removed/shredded from every tree dir
for dir in "${TREE_DIRS[@]}"; do
    for f in virtwho.ini .virtwho-ini-generated .virtwho-computed.ini \
        temp/esx.conf temp/hyperv-kerberos.keytab; do
        [ ! -e "${dir}/${f}" ] || fail "cleanup left ${dir}/${f} behind"
    done
done
# the /etc/virt-who.d uploads are shredded too (review PR297-16): the
# per-mode config carries the same register credentials and the keytab
# twin the same Kerberos secret as the temp/ artifacts above
for f in "${VIRTWHO_D_SANDBOX}/esx.conf" \
    "${VIRTWHO_D_SANDBOX}/hyperv-kerberos.keytab"; do
    [ ! -e "$f" ] || fail "cleanup left the virt-who.d upload ${f} behind"
done
echo "OK: real cleanup-secrets.sh shreds the /etc/virt-who.d uploads (per-mode conf + keytab)"
# the ssh_config entry is dropped with an EXACT match while a sibling
# .bak entry and the rest of the config survive (review PR297-10)
if grep -qxF "  IdentityFile ${SSH_KEY}" "$SSH_CONFIG"; then
    fail "cleanup did not remove the exact IdentityFile entry"
fi
grep -qxF "  IdentityFile ${SSH_KEY}.bak" "$SSH_CONFIG" \
    || fail "cleanup removed the sibling .bak IdentityFile entry (delete not anchored)"
grep -q "virtwho-test tmpfs key" "$SSH_CONFIG" \
    && fail "cleanup left the tmpfs-key marker comment behind" || true
grep -q "StrictHostKeyChecking no" "$SSH_CONFIG" \
    || fail "cleanup clobbered the rest of the ssh config"
echo "OK: real cleanup-secrets.sh shreds tmpfs files + ini-configured kubeconfigs + temp/ artifacts + a regular legacy ini + the /etc/virt-who.d uploads, removes symlinks and the exact ssh_config entry"

echo "All generate-virtwho-ini self-tests passed"
