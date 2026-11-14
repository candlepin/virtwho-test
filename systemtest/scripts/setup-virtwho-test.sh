#!/bin/bash
# setup-virtwho-test.sh -- Clone virtwho-test repo, install deps, provide
# the virtwho.ini (generated on tmpfs from the sanitized base ini +
# VIRTWHO_* secrets), and configure dynamic test parameters.
#
# This script runs in the TMT prepare phase. On bootc image-mode composes,
# TMT executes this inside a Containerfile RUN layer (no systemd, /root
# restricted). All /root writes and SSH-key operations are deferred to
# run-tests.sh (execute phase).
#
# IMPORTANT: On bootc/ostree, /opt is a symlink to /var/opt which is
# persistent state NOT replaced on image deploy. Content written to /opt
# during the container build is hidden after bootc switch + reboot.
# We clone into /usr/share/virtwho-test which IS part of the immutable
# ostree tree from the container image and is guaranteed present at boot.
set -euo pipefail

# Also export lowercase proxy vars for tools that only honor lowercase.
export http_proxy="${HTTP_PROXY:-${http_proxy:-}}"
export https_proxy="${HTTPS_PROXY:-${https_proxy:-}}"
export no_proxy="${NO_PROXY:-${no_proxy:-}}"

# [job] plan-level aliases (review PR297-09): when the plan-level
# HYPERVISOR/REGISTER/RHEL_COMPOSE variable is unset, promote the
# prefixed VIRTWHO_JOB_* value into it BEFORE any ${VAR:-default}
# evaluation below (the generator invocation, the test-file pruning,
# the compose resolution) so the alias and the scripts agree
# end-to-end. VIRTWHO_JOB_HYPERVISOR is lower-cased to match the
# handler list. A set plan-level variable is never overridden; the
# generator warns when it disagrees with the alias.
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

# Use /usr/share on bootc (persists through ostree deploy), /opt otherwise.
if command -v bootc &>/dev/null || [ -f /run/ostree-booted ] || [ -L /ostree ]; then
    INSTALL_DIR=/usr/share/virtwho-test
    echo "Image-mode detected: installing to ${INSTALL_DIR} (ostree-safe path)"
else
    INSTALL_DIR=/opt/virtwho-test
fi

git clone "${VIRTWHO_TEST_REPO:-https://github.com/VirtwhoQE/virtwho-test.git}" \
    --branch "${VIRTWHO_TEST_BRANCH:-main}" --depth 1 "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

PIP_EXTRA_ARGS=()
if pip install --help 2>&1 | grep -q -- '--root-user-action'; then
    PIP_EXTRA_ARGS+=(--root-user-action=ignore)
fi
pip install "${PIP_EXTRA_ARGS[@]}" -r requirements.txt

# virtwho.ini: generated on tmpfs by generate-virtwho-ini.sh
# -- primary mode downloads the sanitized base ini from VIRTWHO_INI_URL
# (a PLAIN, non-secret Testing Farm variable) and overlays the
# VIRTWHO_* env secrets on top (env wins); without VIRTWHO_INI_URL the
# complete ini is generated from the secrets alone.
#
# Single materialization point: the ini contains secrets, so it lives
# ONLY on tmpfs (/dev/shm/virtwho.ini, 0600) and the test tree holds a
# SYMLINK to it. The suite reads and writes through the symlink
# (Configure.save() opens the path with "w", which follows symlinks),
# and the bootc copy in run-tests.sh uses cp -a, which preserves it.
# Nothing is ever installed into the checkout itself.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" /dev/shm/virtwho.ini
ln -sfn /dev/shm/virtwho.ini "${INSTALL_DIR}/virtwho.ini"
touch "${INSTALL_DIR}/.virtwho-ini-generated"

HYP=${HYPERVISOR:-esx}

# Remove hypervisor test files that don't match the configured hypervisor
for f in "${INSTALL_DIR}"/tests/hypervisor/test_*.py; do
    htype=$(basename "$f" .py | sed 's/^test_//')
    if [[ "$htype" != "$HYP" && "$htype" != "default" && "$htype" != "${HYP}_"* ]]; then
        rm -f "$f"
        echo "Removed non-matching test file: $f"
    fi
done

# Resolve compose: if RHEL_COMPOSE is a TF alias (e.g. RHEL-10-Nightly)
# rather than a full compose ID, resolve the actual latest nightly.
# Resolution needs a compose mirror: set VIRTWHO_REPO explicitly (e.g.
# http://download.example.com/rhel) to enable it; there is no default.
RESOLVED_COMPOSE=${RHEL_COMPOSE:-}
if ! echo "$RESOLVED_COMPOSE" | grep -qP '^RHEL-\d+\.\d+\.\d+-\d+'; then
    REPO_BASE=${VIRTWHO_REPO:-}
    if [ -n "$REPO_BASE" ]; then
        RELEASE_MAJOR=$(grep -oP 'release \K\d+' /etc/redhat-release 2>/dev/null || echo "10")
        COMPOSE_ID_URL="${REPO_BASE}/rhel-${RELEASE_MAJOR}/nightly/RHEL-${RELEASE_MAJOR}/latest-RHEL-${RELEASE_MAJOR}/COMPOSE_ID"
        echo "Resolving latest compose from: ${COMPOSE_ID_URL}"
        RESOLVED_COMPOSE=$(curl -sSfL "$COMPOSE_ID_URL" 2>/dev/null || echo "")
        if [ -z "$RESOLVED_COMPOSE" ]; then
            RELEASE_VER=$(grep -oP 'release \K[\d.]+' /etc/redhat-release 2>/dev/null || echo "10.0")
            RESOLVED_COMPOSE="RHEL-${RELEASE_VER}"
            echo "WARNING: Could not resolve latest compose, falling back to ${RESOLVED_COMPOSE}"
        else
            echo "Resolved latest compose: ${RESOLVED_COMPOSE}"
        fi
    else
        echo "WARNING: VIRTWHO_REPO not set; keeping compose as-is (${RESOLVED_COMPOSE:-unset})"
    fi
fi

VIRTWHO_NEVRA=$(rpm -qa virt-who 2>/dev/null | head -1)
VIRTWHO_NEVRA=${VIRTWHO_NEVRA:-virt-who}

# Record the computed NON-SECRET values (resolved compose, virt-who
# NEVRA, gating test_rpms) in a sidecar next to the test tree.
# run-tests.sh regenerates the tmpfs ini at test time (the execute
# phase always has the secrets, and on bootc the prepare-phase tmpfs
# content does not survive the container build), then merges these
# values back; they must live outside the ini for that merge to find
# them. The sidecar holds no credentials by construction.
# The guest root account (username=root, password set by run-tests.sh)
# and the hypervisor/register preseed are handled by the generator and
# the run-tests.sh merge defaults.
python3 - "${INSTALL_DIR}/.virtwho-computed.ini" "$RESOLVED_COMPOSE" \
    "$VIRTWHO_NEVRA" "${TEST_RPMS:-}" <<'PYEOF'
import configparser
import sys

path, compose, nevra, test_rpms = sys.argv[1:5]
cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
cfg.read(path)
if not cfg.has_section("job"):
    cfg.add_section("job")
cfg.set("job", "rhel_compose", compose)
if not cfg.has_section("virtwho"):
    cfg.add_section("virtwho")
cfg.set("virtwho", "package", nevra)
cfg.set("virtwho", "test_rpms", test_rpms)
with open(path, "w") as f:
    cfg.write(f, space_around_delimiters=False)
PYEOF
chmod 600 "${INSTALL_DIR}/.virtwho-computed.ini"

# hostname/IP-dependent and SSH-key operations are deferred to run-tests.sh
# (execute phase) where the guest is fully booted and /root is writable.
echo "virtwho-test cloned to ${INSTALL_DIR} and configured (SSH trust deferred to execute phase)"

# Hypervisor-specific prepare (kubevirt only — no /root or network needed).
# Runs after the sidecar exists: discovered guest coordinates are
# appended to it (see prepare-kubevirt.sh).
if [ "$HYP" = "kubevirt" ]; then
    bash "${SCRIPT_DIR}/prepare-kubevirt.sh"
fi
