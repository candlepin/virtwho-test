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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# Also export lowercase proxy vars for tools that only honor lowercase.
export http_proxy="${HTTP_PROXY:-${http_proxy:-}}"
export https_proxy="${HTTPS_PROXY:-${https_proxy:-}}"
export no_proxy="${NO_PROXY:-${no_proxy:-}}"

# [job] plan-level aliases, single-sourced in lib.sh: promote
# VIRTWHO_JOB_* into the plan-level variables BEFORE any
# ${VAR:-default} evaluation below (the generator invocation, the
# test-file pruning, the compose resolution) so the alias and the
# scripts agree end-to-end.
promote_job_aliases

# The shared test-tree root (lib.sh): /usr/share on bootc (persists
# through ostree deploy), /opt otherwise.
# VIRTWHO_PREPARE_INSTALL_DIR overrides both for the self-test
# sandbox (the companion suite, branch cct-3162/selftests) and the
# local fmf dry run -- the SAME knob
# prepare-candlepin.sh uses for its marker location, so a sandboxed
# clone and a sandboxed marker land in the same tree (the
# plan-ordering invariant: the clone must create the tree the
# marker goes into).
INSTALL_DIR=$(detect_install_dir)
if [ "$INSTALL_DIR" = /usr/share/virtwho-test ]; then
    echo "Image-mode detected: installing to ${INSTALL_DIR} (ostree-safe path)"
fi

git clone "${VIRTWHO_TEST_REPO:-https://github.com/VirtwhoQE/virtwho-test.git}" \
    --branch "${VIRTWHO_TEST_BRANCH:-main}" --depth 1 "${INSTALL_DIR}"
cd "${INSTALL_DIR}"
# Head observability: which virtwho-test commit this tree is (the
# run log is where a watcher looks for it).
echo "virtwho-test checkout: $(git rev-parse HEAD 2>/dev/null || echo unknown)"

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
# Record the NEVRA only when a real one resolves (rpm -qa prints
# nothing when virt-who is not installed): a bare-name placeholder
# would clobber a correct base-ini value through the merge override.

# --- version-under-test RPM cache ----------------------------------
# The suite's package tests must examine and reinstall THE VERSION
# UNDER TEST, never whatever the currently-enabled content repos
# serve: once a destination is registered, the host's content source
# does not carry virt-who (the container tier's pod repo serves no
# virt-who packages) and repo-based installs fail. Precedence:
# TEST_RPMS always wins (manual overrides, PR-build testing, gated
# release builds); without it the version under test is the RHEL
# compose's own virt-who that install-deps.sh already installed.
# Both cases are captured HERE -- after install-deps.sh ran, BEFORE
# any registration can switch the host's content sources -- as a
# plain RPM file in the tree root; the sidecar below records its
# path, run-tests.sh merges it into the ini, and the suite's
# virtwho_install_under_test() installs from it with every repo
# disabled. Best-effort by design: a failed cache is a loud WARNING
# and an empty sidecar value -- the tests then fall back to the
# TEST_RPMS URL (gating mode) or the enabled repos (hand-run local
# suites).
UNDERTTEST_RPM=""
UNDERTTEST_CACHE="${INSTALL_DIR}/virt-who-under-test.rpm"
if [ -n "${TEST_RPMS:-}" ]; then
    # TEST_RPMS is a space-separated URL list the cct-gate pipeline
    # builds from the Brew UMB message; cache the virt-who one (curl
    # rides the environment proxy, the same path install-deps.sh's
    # dnf install of TEST_RPMS uses).
    for url in ${TEST_RPMS}; do
        case "${url##*/}" in
            virt-who-*.rpm)
                if curl -fsSL --retry 3 --retry-delay 5 \
                        --connect-timeout 10 --max-time 300 \
                        -o "$UNDERTTEST_CACHE" "$url"; then
                    UNDERTTEST_RPM="$UNDERTTEST_CACHE"
                    echo "Cached the version-under-test RPM from TEST_RPMS (${url##*/})"
                else
                    echo "WARNING: could not cache the TEST_RPMS virt-who RPM (${url##*/}); the package tests will install from the TEST_RPMS URL at test time" >&2
                fi
                break
                ;;
        esac
    done
    if [ -z "$UNDERTTEST_RPM" ]; then
        echo "WARNING: TEST_RPMS carries no virt-who RPM URL; no version-under-test cache was written" >&2
    fi
else
    # No TEST_RPMS: the version under test is the compose's own
    # virt-who (installed by install-deps.sh). `dnf download` fetches
    # the very same package from the still-enabled compose repos
    # regardless of its installed state; --downloadonly is the
    # fallback for guests whose dnf lacks the download plugin.
    if dnf download --destdir="${INSTALL_DIR}" virt-who \
            >/dev/null 2>&1 \
            || dnf -y install --downloadonly \
                    --downloaddir="${INSTALL_DIR}" virt-who \
                    >/dev/null 2>&1; then
        for downloaded in "${INSTALL_DIR}"/virt-who-*.rpm; do
            [ -e "$downloaded" ] || continue
            mv -f "$downloaded" "$UNDERTTEST_CACHE"
            UNDERTTEST_RPM="$UNDERTTEST_CACHE"
            echo "Cached the version-under-test RPM from the compose repos ($(rpm -qp --qf '%{name}-%{version}-%{release}.%{arch}' "$UNDERTTEST_CACHE" 2>/dev/null || echo virt-who))"
            break
        done
    fi
    if [ -z "$UNDERTTEST_RPM" ]; then
        echo "WARNING: could not cache the compose's virt-who RPM; the package tests will fall back to the enabled repos at test time" >&2
    fi
fi

# Record the computed NON-SECRET values (resolved compose, virt-who
# NEVRA, gating test_rpms, the version-under-test RPM cache) in a
# sidecar next to the test tree.
# run-tests.sh regenerates the tmpfs ini at test time (the execute
# phase always has the secrets, and on bootc the prepare-phase tmpfs
# content does not survive the container build), then merges these
# values back; they must live outside the ini for that merge to find
# them. The sidecar holds no credentials by construction.
# The guest root account (username=root, password set by run-tests.sh)
# and the hypervisor/register preseed are handled by the generator and
# the run-tests.sh merge defaults.
python3 - "${INSTALL_DIR}/.virtwho-computed.ini" "$RESOLVED_COMPOSE" \
    "$VIRTWHO_NEVRA" "${TEST_RPMS:-}" "$UNDERTTEST_RPM" <<'PYEOF'
import configparser
import sys

path, compose, nevra, test_rpms, undertest_rpm = sys.argv[1:6]
cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
cfg.read(path)
if not cfg.has_section("job"):
    cfg.add_section("job")
cfg.set("job", "rhel_compose", compose)
if not cfg.has_section("virtwho"):
    cfg.add_section("virtwho")
# the NEVRA is recorded ONLY when a real one resolved: an absent
# option keeps the base-ini value through the run-tests.sh merge,
# while a placeholder would clobber it
if nevra:
    cfg.set("virtwho", "package", nevra)
cfg.set("virtwho", "test_rpms", test_rpms)
cfg.set("virtwho", "undertest_rpm", undertest_rpm)
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
