#!/bin/bash
# cleanup-secrets.sh -- Destroy the secrets generated at test time.
#
# Runs in the TMT finish phase. This is defense-in-depth: by
# construction the virtwho.ini and the SSH key exist ONLY on tmpfs
# (/dev/shm) -- the test trees hold a SYMLINK to the ini instead of a
# copy, and the SSH key is referenced from /root/.ssh/config without
# being installed there. THREE disk exceptions exist, all destroyed
# here: the kubevirt kubeconfigs (the virt-who daemon reads them from
# fixed paths under /root, so they are written 0600 by
# prepare-kubevirt.sh and shredded here), the suite's own artifacts
# under the tree's temp/ directory (VirtwhoHypervisorConfig writes
# temp/<mode>.conf, which carries the hypervisor password, and the
# Hyper-V path decodes temp/hyperv-kerberos.keytab there; on bootc
# that tree is the writable copy under $TMT_PLAN_DATA, which survives
# the run), and the per-mode configs uploaded to /etc/virt-who.d/
# (Configure.save() uploads temp/<mode>.conf there -- run-tests.sh
# rewrites [virtwho] server to the guest's own address, so the upload
# lands on this same machine -- carrying the same hypervisor and
# register passwords, plus the Hyper-V keytab twin; review PR297-16).
# Nothing else is ever written under /opt, /usr/share or /root/.ssh.
# Still shred the tmpfs files and remove the symlinks/bookkeeping
# files so nothing outlives the run.
# Best-effort: never fails the plan.
set -uo pipefail

# Locations, overridable so the self-test can run this REAL script
# against a sandboxed tree with the same layout (see
# test-generate-virtwho-ini.sh).
SHM_DIR=${VIRTWHO_CLEANUP_SHM_DIR:-/dev/shm}
SSH_KEY_FILE=${VIRTWHO_CLEANUP_SSH_KEY:-"${SHM_DIR}/virtwho-ssh-key"}
SSH_CONFIG_FILE=${VIRTWHO_CLEANUP_SSH_CONFIG:-/root/.ssh/config}
VIRTWHO_D_DIR=${VIRTWHO_CLEANUP_VIRTWHO_D_DIR:-/etc/virt-who.d}
KV_ROOT=${VIRTWHO_CLEANUP_KUBECONFIG_ROOT:-/root}
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
    # are not secrets), so an overridden path must be shredded too
    # (review PR297-05). Read them from the ini while it is still
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
        mapfile -t INI_KV < <(python3 - "$INI_SRC" 2>/dev/null <<'PYEOF'
import configparser
import sys

cfg = configparser.ConfigParser(interpolation=None)
try:
    cfg.read(sys.argv[1])
except configparser.Error:
    sys.exit(0)
print(cfg.get("kubevirt", "config_file", fallback="").strip())
print(cfg.get("kubevirt", "config_file_no_cert", fallback="").strip())
PYEOF
)
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
    if [ -e "$f" ]; then
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
# untrusted input (review PR298-22): a mis-published base must not
# turn this step into "shred an arbitrary file", so only absolute
# paths under the kubeconfig root (/root -- where the generator's
# defaults and the daemon's fixed paths live) are accepted, after
# canonicalization rules out a /root/../ escape; anything else is
# refused with a warning. Paths given explicitly via
# VIRTWHO_CLEANUP_KUBECONFIGS are operator-supplied (self-test/CI
# sandboxing) and trusted as-is.
is_kubeconfig_path() {
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
for f in "${KUBECONFIGS[@]}"; do
    if [ -n "${VIRTWHO_CLEANUP_KUBECONFIGS:-}" ] || is_kubeconfig_path "$f"; then
        shred_file "$f"
    else
        echo "WARNING: refusing to shred ${f} (not a kubeconfig path)"
    fi
done

# Defense-in-depth: staging files of a killed generator/ssh-key fetch
# (unpredictable names, sanitized content at most -- shred anyway).
for f in "${SHM_DIR}"/virtwho.ini.tmp.* "${SHM_DIR}"/virtwho.ini.base.* \
    "${SHM_DIR}"/virtwho-key-download.* "${SHM_DIR}"/virtwho-ssh-key.selftest.*; do
    [ -e "$f" ] && shred_file "$f"
done

# Remove the ini from the test trees. A SYMLINK holds no data by
# construction -- removing it never touches its target (already
# shredded above) and /usr/share may be read-only on bootc guests, so
# that removal is best-effort tidiness. A REGULAR virtwho.ini (a
# legacy installed copy) does carry credentials -- shred it instead
# of just unlinking (review PR297-10). The suite's own disk
# artifacts under temp/ are shredded too (review PR297-03): the
# per-mode configs carry the hypervisor password and the keytab is
# the Hyper-V credential.
for dir in "${TREE_DIRS[@]}"; do
    if [ -f "$dir/virtwho.ini" ] && [ ! -L "$dir/virtwho.ini" ]; then
        shred_file "$dir/virtwho.ini"
    else
        rm -f "$dir/virtwho.ini" 2> /dev/null || true
    fi
    for f in "$dir"/temp/*.conf; do
        [ -e "$f" ] && shred_file "$f"
    done
    shred_file "$dir/temp/hyperv-kerberos.keytab"
    rmdir "$dir/temp" 2> /dev/null || true
    # non-secret bookkeeping files from the prepare phase
    rm -f "$dir/.virtwho-ini-generated" "$dir/.virtwho-computed.ini" \
        2> /dev/null || true
done

# /etc/virt-who.d/<mode>.conf: Configure.save() uploads the suite's
# temp/<mode>.conf to the guest itself (run-tests.sh rewrites
# [virtwho] server to the guest's own address, so the upload target IS
# this machine), carrying the same hypervisor and register passwords
# as the temp/ twin shredded above -- the glob also covers the
# -second.conf and oneshot variants the suite writes there. The
# Hyper-V keytab is uploaded to the same directory (review PR297-16).
for f in "${VIRTWHO_D_DIR}"/*.conf "${VIRTWHO_D_DIR}/hyperv-kerberos.keytab"; do
    [ -e "$f" ] && shred_file "$f"
done

# Drop the tmpfs IdentityFile entry run-tests.sh added to root's
# ssh_config. The config holds no secrets; this only removes the
# reference to the now-shredded key (best-effort, e.g. read-only /root).
if [ -f "$SSH_CONFIG_FILE" ]; then
    # The IdentityFile delete is anchored to the full line: a prefix
    # match would also drop sibling entries like
    # IdentityFile <key>.bak (review PR297-10).
    sed -i -e '/virtwho-test tmpfs key/d' \
        -e "\#^  IdentityFile ${SSH_KEY_FILE}\$#d" \
        "$SSH_CONFIG_FILE" 2> /dev/null || true
fi

exit 0
