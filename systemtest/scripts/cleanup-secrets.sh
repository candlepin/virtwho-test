#!/bin/bash
# cleanup-secrets.sh -- Destroy the secrets generated at test time.
#
# Runs in the TMT finish phase. This is defense-in-depth: by
# construction the virtwho.ini and the SSH key exist ONLY on tmpfs
# (/dev/shm) -- the test trees hold a SYMLINK to the ini instead of a
# copy, and the SSH key is referenced from /root/.ssh/config without
# being installed there. FOUR disk exceptions exist, all destroyed
# here: the kubevirt kubeconfigs (the virt-who daemon reads them from
# fixed paths under /root, so they are written 0600 by
# prepare-kubevirt.sh and shredded here), the suite's own artifacts
# under the tree's temp/ directory (VirtwhoHypervisorConfig writes
# temp/<mode>.conf, which carries the hypervisor password, and the
# Hyper-V path decodes temp/hyperv-kerberos.keytab there; on bootc
# that tree is the writable copy under $TMT_PLAN_DATA, which survives
# the run), the per-mode configs uploaded to /etc/virt-who.d/
# (Configure.save() uploads temp/<mode>.conf there -- run-tests.sh
# rewrites [virtwho] server to the guest's own address, so the upload
# lands on this same machine -- carrying the same hypervisor and
# register passwords, plus the Hyper-V keytab twin),
# and the copies the suite's TESTS write themselves, wherever they
# land (provenance, not location, is what makes them exceptions):
# tests/function/test_cli.py copies the per-mode config to
# /root/test_cli_config.conf to exercise `virt-who -c`, the tests
# leave suffixed and hidden variants in /etc/virt-who.d/ (esx.conf.txt,
# .test.conf.swp), and tests/upgrade/test_upgrade.py pulls the
# per-mode configs and /etc/virt-who.conf onto /tmp
# (<mode>.conf.pre/.post, virt-who.conf.pre/.post) to compare them
# across the upgrade -- all shredded here too.
# Nothing else is ever written under /opt, /usr/share or /root/.ssh.
# Still shred the tmpfs files and remove the symlinks/bookkeeping
# files so nothing outlives the run.
# Best-effort: never fails the plan.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# The containerized Candlepin destination (CCT-3155): teardown of the
# per-run pod. Best-effort and idempotent (a stage-tier run, or a run
# where the pod never deployed, finds nothing to remove). The pod's
# values are synthetic public test data, so nothing new needs
# shredding; the /etc/hosts entry and CA anchor are deliberately left
# in place (the guest is ephemeral). The pod yaml is resolved through
# the ONE shared knob VIRTWHO_CANDLEPIN_POD_YAML so the deploy side
# (prepare-candlepin.sh) and this teardown agree on the manifest a
# `podman play kube --down` will undo. VIRTWHO_CLEANUP_POD_YAML
# remains as the teardown-only override. prepare-candlepin.sh tears
# the pod down on each of its own failure paths; a pod orphaned by a
# hard kill of the prepare phase is still removed here (the --down is
# unconditional), bounded by the plan's lifetime.
VIRTWHO_CLEANUP_POD_YAML=${VIRTWHO_CLEANUP_POD_YAML:-${VIRTWHO_CANDLEPIN_POD_YAML:-${SCRIPT_DIR}/../config/candlepin-pod.yaml}}
if command -v podman > /dev/null 2>&1 && [ -r "$VIRTWHO_CLEANUP_POD_YAML" ]; then
    podman play kube --down "$VIRTWHO_CLEANUP_POD_YAML" > /dev/null 2>&1 || \
        podman pod rm -f candlepin > /dev/null 2>&1 || true
fi

# Locations, overridable so the self-test can run this REAL script
# against a sandboxed tree with the same layout (the companion
# self-test suite, branch cct-3162/selftests).
SHM_DIR=${VIRTWHO_CLEANUP_SHM_DIR:-/dev/shm}
SSH_KEY_FILE=${VIRTWHO_CLEANUP_SSH_KEY:-"${SHM_DIR}/virtwho-ssh-key"}
SSH_CONFIG_FILE=${VIRTWHO_CLEANUP_SSH_CONFIG:-/root/.ssh/config}
VIRTWHO_D_DIR=${VIRTWHO_CLEANUP_VIRTWHO_D_DIR:-/etc/virt-who.d}
TMP_DIR=${VIRTWHO_CLEANUP_TMP_DIR:-/tmp}
# The SAME knob the write side confines to (prepare-kubevirt.sh):
# one gate for both sides of the kubeconfig confinement rule, so the
# token can never be written somewhere this step would refuse to
# shred. kv_root() canonicalizes it once for both sides; the rule
# itself is kv_path_is_confined() in lib.sh.
KV_ROOT=$(kv_root)
if [ -n "${VIRTWHO_CLEANUP_TREE_DIRS:-}" ]; then
    read -ra TREE_DIRS <<< "${VIRTWHO_CLEANUP_TREE_DIRS}"
else
    TREE_DIRS=(/opt/virtwho-test /usr/share/virtwho-test
        "${TMT_PLAN_DATA:-/var/tmp}/virtwho-test")
fi
if [ -n "${VIRTWHO_CLEANUP_KUBECONFIGS:-}" ]; then
    read -ra KUBECONFIGS <<< "${VIRTWHO_CLEANUP_KUBECONFIGS}"
else
    # The prepare phase writes the kubeconfig paths CONFIGURED IN THE
    # INI ([kubevirt] config_file / config_file_no_cert -- the paths
    # are not secrets), so an overridden path must be shredded too.
    # Read them from the ini while it is still
    # readable (the tmpfs original is shredded further below -- this
    # block must stay ahead of it), falling back per-option to the
    # two literals (which are also the generator's defaults).
    KV_CONFIG_FILE=/root/kubeconfig
    KV_CONFIG_NO_CERT=/root/kubeconfig-no-cert
    INI_SRC=""
    for candidate in "${SHM_DIR}/virtwho.ini" \
        "${TMT_PLAN_DATA:-/var/tmp}/virtwho-test/virtwho.ini" \
        /opt/virtwho-test/virtwho.ini /usr/share/virtwho-test/virtwho.ini; do
        if [ -r "$candidate" ]; then
            INI_SRC=$candidate
            break
        fi
    done
    if [ -n "$INI_SRC" ]; then
        mapfile -d '' -t INI_KV < <(ini_read "$INI_SRC" kubevirt \
            config_file config_file_no_cert 2>/dev/null)
        if [ "${#INI_KV[@]}" -ge 1 ] && [ -n "${INI_KV[0]}" ]; then
            KV_CONFIG_FILE=${INI_KV[0]}
        fi
        if [ "${#INI_KV[@]}" -ge 2 ] && [ -n "${INI_KV[1]}" ]; then
            KV_CONFIG_NO_CERT=${INI_KV[1]}
        fi
    fi
    KUBECONFIGS=("$KV_CONFIG_FILE" "$KV_CONFIG_NO_CERT")
fi

shred_file() {
    local f=$1
    # -L: a dangling symlink matched by a glob holds no data, but is
    # unlinked anyway (tidiness); shred itself cannot touch it (the
    # target does not exist), the rm -f fallback removes the link.
    if [ -e "$f" ] || [ -L "$f" ]; then
        if command -v shred > /dev/null 2>&1; then
            shred -u "$f" 2> /dev/null || rm -f "$f"
        else
            rm -f "$f"
        fi
        echo "Removed ${f}"
    fi
}

# tmpfs originals -- the only places the ini and the SSH key ever land
# (removing the ini target also leaves any remaining symlinks dangling
# and harmless).
shred_file "${SHM_DIR}/virtwho.ini"
shred_file "${SSH_KEY_FILE}"
shred_file "${SSH_KEY_FILE}.pub"

# kubevirt kubeconfigs: the SA token lands on real disk here (the
# virt-who daemon reads the files from /root); they are written 0600
# and shredded now. Paths read from the DOWNLOADED base ini are
# untrusted input: a mis-published base must not
# turn this step into "shred an arbitrary file", so only absolute
# paths under the kubeconfig root (/root -- where the generator's
# defaults and the daemon's fixed paths live) are accepted, after
# canonicalization rules out a /root/../ escape; anything else is
# refused with a warning. The rule is kv_path_is_confined() from
# lib.sh -- the SAME single-sourced implementation the write side
# (prepare-kubevirt.sh) confines to. Paths given explicitly via
# VIRTWHO_CLEANUP_KUBECONFIGS are operator-supplied (companion
# self-test/CI sandboxing) and trusted as-is.
for f in "${KUBECONFIGS[@]}"; do
    if [ -n "${VIRTWHO_CLEANUP_KUBECONFIGS:-}" ] || kv_path_is_confined "$f"; then
        shred_file "$f"
    else
        echo "WARNING: refusing to shred ${f} (not a kubeconfig path)"
    fi
done

# The suite's test-side copy under /root: tests/function/test_cli.py
# copies the per-mode config (which carries the hypervisor and
# register passwords) to a fixed /root path to exercise `virt-who -c`
# against a file outside the configuration directory. It is a fixed
# suite-written path -- not ini input -- so no confinement check is
# needed; shred it under the same kubeconfig root.
shred_file "${KV_ROOT}/test_cli_config.conf"

# Defense-in-depth: staging files of a killed generator/ssh-key fetch
# (unpredictable names, sanitized content at most -- shred anyway).
for f in "${SHM_DIR}"/virtwho.ini.tmp.* "${SHM_DIR}"/virtwho.ini.base.* \
    "${SHM_DIR}"/virtwho-key-download.* "${SHM_DIR}"/virtwho-ssh-key.selftest.*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    shred_file "$f"
done

# Remove the ini from the test trees. A SYMLINK holds no data by
# construction -- removing it never touches its target (already
# shredded above) and /usr/share may be read-only on bootc guests, so
# that removal is best-effort tidiness. A REGULAR virtwho.ini (a
# legacy installed copy) does carry credentials -- shred it instead
# of just unlinking. The suite's own disk
# artifacts under temp/ are shredded too: the
# per-mode configs carry the hypervisor password and the keytab is
# the Hyper-V credential.
for dir in "${TREE_DIRS[@]}"; do
    if [ -f "$dir/virtwho.ini" ] && [ ! -L "$dir/virtwho.ini" ]; then
        shred_file "$dir/virtwho.ini"
    else
        rm -f "$dir/virtwho.ini" 2> /dev/null || true
    fi
    for f in "$dir"/temp/*.conf; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        shred_file "$f"
    done
    shred_file "$dir/temp/hyperv-kerberos.keytab"
    rmdir "$dir/temp" 2> /dev/null || true
    # non-secret bookkeeping files from the prepare phase (incl. the
    # containerized-Candlepin readiness marker of prepare-candlepin.sh
    # and the version-under-test RPM cache of setup-virtwho-test.sh)
    rm -f "$dir/.virtwho-ini-generated" "$dir/.virtwho-computed.ini" \
        "$dir/.virtwho-candlepin-ready" \
        "$dir/virt-who-under-test.rpm" 2> /dev/null || true
done

# /etc/virt-who.d/<mode>.conf: Configure.save() uploads the suite's
# temp/<mode>.conf to the guest itself (run-tests.sh rewrites
# [virtwho] server to the guest's own address, so the upload target IS
# this machine), carrying the same hypervisor and register passwords
# as the temp/ twin shredded above -- the glob also covers the
# -second.conf and oneshot variants the suite writes there. The
# suite's tests additionally leave SUFFIXED and HIDDEN variants in
# the same directory (tests/hypervisor/conftest.py renames the conf
# to esx.conf.txt; tests/function/test_service.py writes a
# .test.conf.swp) which carry the same credentials -- the extended
# globs (*.conf* and the dotfile .*.conf*) cover them, while a
# non-matching file in the directory is left alone. The Hyper-V
# keytab is uploaded to the same directory.
# nocaseglob is enabled only around these globs (and restored
# afterwards): an uppercase variant of a suite-written name (e.g.
# ESX.CONF) must not survive the sweep either.
CASE_GLOB_WAS_SET=0
shopt -q nocaseglob && CASE_GLOB_WAS_SET=1
shopt -s nocaseglob
for f in "${VIRTWHO_D_DIR}"/*.conf* "${VIRTWHO_D_DIR}"/.*.conf* \
    "${VIRTWHO_D_DIR}"/hyperv-kerberos.keytab; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    shred_file "$f"
done
[ "$CASE_GLOB_WAS_SET" = "1" ] || shopt -u nocaseglob

# The upgrade tests' /tmp copies: tests/upgrade/test_upgrade.py pulls
# the per-mode configs and /etc/virt-who.conf onto real disk in /tmp
# (<mode>.conf.pre/.post, virt-who.conf.pre/.post) to compare them
# across the upgrade -- they carry the same hypervisor and register
# passwords as the temp/ twins, so they are shredded too (same
# provenance class: suite-test-written files). The non-credential
# sysconfig copy (/tmp/virt-who.pre/.post, no .conf component) does
# not match the globs and is left to the test's own cleanup.
for f in "${TMP_DIR}"/*.conf.pre "${TMP_DIR}"/*.conf.post; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    shred_file "$f"
done

# Drop the tmpfs IdentityFile entry run-tests.sh added to root's
# ssh_config. The config holds no secrets; this only removes the
# reference to the now-shredded key (best-effort, e.g. read-only /root).
if [ -f "$SSH_CONFIG_FILE" ]; then
    # The IdentityFile delete is anchored to the full line: a prefix
    # match would also drop sibling entries like
    # IdentityFile <key>.bak.
    sed -i -e '/virtwho-test tmpfs key/d' \
        -e "\#^  IdentityFile ${SSH_KEY_FILE}\$#d" \
        "$SSH_CONFIG_FILE" 2> /dev/null || true
fi

exit 0
