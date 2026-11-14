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
#   * base-download + env-overlay mode works (VIRTWHO_INI_URL set to a
#     dummy base served from a file:// URL): base values survive, env
#     secrets win, env-only options are added, non-table sections of
#     the base are passed through, and the plan-level [job] preseed
#     wins over the base;
#   * a failing base download, a malformed base, an empty base and a
#     base with planted forbidden (credential-shaped) keys all fail
#     the generator loudly;
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
cleanup() { rm -rf "$WORK"; }
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
# 2d) [job] plan-level aliases (review PR297-09)
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
# 2e) ESX/VCENTER dual-prefix clash (review PR297-13)
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
