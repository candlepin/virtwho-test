#!/bin/bash
# run-tests.sh -- Execute the virtwho-test pytest suite and copy artifacts
# to TMT_PLAN_DATA for preservation.
set -euo pipefail

# [job] plan-level aliases (review PR297-09): when the plan-level
# HYPERVISOR/REGISTER/RHEL_COMPOSE variable is unset, promote the
# prefixed VIRTWHO_JOB_* value into it BEFORE any ${VAR:-default}
# evaluation below (the ini regeneration, the libvirt SSH-trust
# branch, the summary banner) so the alias and the scripts agree
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

is_bootc() {
  # Check IMAGE_MODE env var first (set by the TMT plan / Jenkins job),
  # then fall back to probing bootc. The env var is the most reliable
  # signal because bootc status output format varies across versions.
  case "${IMAGE_MODE:-}" in
    1|true|yes|on|TRUE|True|YES) return 0 ;;
  esac
  command -v bootc > /dev/null && \
  bootc status --format=humanreadable 2>/dev/null | grep -q 'image'
}

# On bootc guests the filesystem is immutable. The prepare phase clones the
# test repo into /usr/share/virtwho-test (ostree-safe) or /opt/virtwho-test
# (standard). For bootc, copy to a writable location so we can modify
# virtwho.ini, write artifacts, and create SSH keys.
if is_bootc; then
  # Locate the test directory — /usr/share/virtwho-test is the ostree-safe
  # path used by setup-virtwho-test.sh on bootc; /opt/virtwho-test is the
  # legacy fallback.
  BOOTC_SOURCE=""
  for candidate in /usr/share/virtwho-test /opt/virtwho-test; do
    if [ -d "$candidate" ]; then
      BOOTC_SOURCE="$candidate"
      break
    fi
  done
  if [ -z "$BOOTC_SOURCE" ]; then
    echo "ERROR: bootc detected but virtwho-test not found at /usr/share/virtwho-test or /opt/virtwho-test"
    echo "The prepare phase may have failed. Check the TMT container build logs."
    exit 1
  fi
  WRITABLE_DIR="${TMT_PLAN_DATA:-/var/tmp}/virtwho-test"
  echo "Image-mode: copying ${BOOTC_SOURCE} to writable ${WRITABLE_DIR}"
  rm -rf "$WRITABLE_DIR"
  cp -a "$BOOTC_SOURCE" "$WRITABLE_DIR"
  VIRTWHO_TEST_DIR="$WRITABLE_DIR"
else
  VIRTWHO_TEST_DIR="/opt/virtwho-test"
fi
readonly VIRTWHO_TEST_DIR

# --- Runtime SSH setup (runs in execute phase for both standard and image-mode) ---
# setup-ssh.sh (prepare) only modifies sshd_config. Everything that needs
# systemd or /root writability happens here.
echo "Setting up SSH for localhost testing..."
mkdir -p /root/.ssh && chmod 700 /root/.ssh
printf 'Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /root/.ssh/known_hosts\n\n' > /root/.ssh/config
chmod 600 /root/.ssh/config
# NOTE: the libvirt section below appends an IdentityFile entry pointing
# at the tmpfs SSH key; it holds no secret itself.

# Ensure password auth is enabled (RHEL 10+ drop-in configs may override sshd_config)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=sshd-dropin.sh
source "${SCRIPT_DIR}/sshd-dropin.sh"

echo "redhat" | passwd --stdin root
ssh-keygen -A 2>/dev/null || true
systemctl restart sshd

GUEST_IP=$(hostname -I | awk '{print $1}')
GUEST_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
if echo "$GUEST_HOSTNAME" | grep -qE 'localhost|unused|openshift'; then
    GUEST_HOSTNAME="virtwho-$(head /dev/urandom | tr -dc a-z0-9 | head -c8).redhat.com"
    hostnamectl set-hostname "$GUEST_HOSTNAME"
fi
grep -q "$GUEST_IP" /etc/hosts || echo "$GUEST_IP $GUEST_HOSTNAME" >> /etc/hosts

# --- Runtime virtwho.ini fixups (deferred from setup-virtwho-test.sh) ---
# Server IP and SSH trust require the guest to be booted with /root writable.
cd "${VIRTWHO_TEST_DIR}"

# If the ini was generated from the base ini + VIRTWHO_* secrets,
# regenerate it at test time: the execute phase always has the Testing
# Farm environment, and on bootc the prepare phase ran inside a
# container build whose /dev/shm content did not survive into the
# booted guest. The tmpfs original is shredded by cleanup-secrets.sh
# in the tmt finish step.
if [ -f .virtwho-ini-generated ]; then
    echo "Regenerating virtwho.ini on tmpfs (base ini + VIRTWHO_* secrets)"
    bash "${SCRIPT_DIR}/generate-virtwho-ini.sh" /dev/shm/virtwho.ini
    # Merge back the values computed in earlier phases (recorded in the
    # non-secret sidecar .virtwho-computed.ini): the virt-who NEVRA and
    # test_rpms, the compose resolved by setup-virtwho-test.sh, and the
    # kubevirt guest coordinates discovered by prepare-kubevirt.sh.
    # Env-provided values always win (except the resolved compose, which
    # is strictly better than the raw alias re-read from the env). The
    # guest root account (username/password, set by this script) is
    # filled in as a default when the env provides none.
    python3 - /dev/shm/virtwho.ini .virtwho-computed.ini <<'PYEOF'
import configparser
import sys

new = configparser.ConfigParser(interpolation=None)
new.optionxform = str
new.read(sys.argv[1])
computed = configparser.ConfigParser(interpolation=None)
computed.optionxform = str
computed.read(sys.argv[2])

def fallback(section, option, default):
    if not new.has_section(section):
        return
    if new.get(section, option, fallback=""):
        return
    if computed.has_option(section, option) and computed.get(section, option):
        new.set(section, option, computed.get(section, option))
    elif default is not None:
        new.set(section, option, default)

fallback("virtwho", "username", "root")
fallback("virtwho", "password", "redhat")
fallback("virtwho", "package", None)
fallback("virtwho", "test_rpms", None)
# rhel_compose: setup-virtwho-test.sh resolved the TF alias (e.g.
# RHEL-10-Nightly) to the real compose ID; prefer that over the raw
# alias re-read from the environment.
if computed.has_option("job", "rhel_compose") and computed.get("job", "rhel_compose"):
    if not new.has_section("job"):
        new.add_section("job")
    new.set("job", "rhel_compose", computed.get("job", "rhel_compose"))
for option in ("guest_ip", "guest_port"):
    fallback("kubevirt", option, None)

with open(sys.argv[1], "w") as f:
    new.write(f, space_around_delimiters=False)
PYEOF

    # Single materialization point: the test tree holds ONLY
    # a symlink to the tmpfs ini. The suite reads and writes through it
    # (Configure.save() opens the path with "w", which follows the
    # symlink), so the secrets never leave tmpfs. cp -a above preserved
    # the symlink created by setup-virtwho-test.sh; recreate it
    # defensively (ln -sfn is idempotent).
    ln -sfn /dev/shm/virtwho.ini virtwho.ini
    INI_FILE=/dev/shm/virtwho.ini
else
    INI_FILE=virtwho.ini
fi

# Fix up the ini with configparser, never sed/awk (review PR297-12):
# `server = <ip>` (spaces around the delimiter) does not match a
# ^server= regex, awk -F= truncates values containing '=', and sed -i
# on a symlink path would replace the link with a regular file.
# configparser reads and rewrites THROUGH the path (open "w" follows
# symlinks), exactly like the merge block above.
python3 - "$INI_FILE" "$GUEST_IP" <<'PYEOF'
import configparser
import sys

path, guest_ip = sys.argv[1], sys.argv[2]
cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
if not cfg.read(path):
    raise SystemExit("could not parse %s" % path)
if cfg.has_section("virtwho"):
    cfg.set("virtwho", "server", guest_ip)
with open(path, "w") as f:
    cfg.write(f, space_around_delimiters=False)
PYEOF

HYP=${HYPERVISOR:-esx}
if [ "$HYP" = "libvirt" ]; then
    # Read the hypervisor coordinates from the same ini path the
    # fixup above wrote ($INI_FILE -- the tmpfs target when the
    # marker branch ran), with configparser so values containing '='
    # survive (review PR297-12; the old awk read the literal
    # virtwho.ini instead of $INI_FILE).
    mapfile -t HYP_CREDS < <(python3 - "$INI_FILE" "$HYP" <<'PYEOF'
import configparser
import sys

path, section = sys.argv[1], sys.argv[2]
cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
cfg.read(path)
for option in ("server", "username", "password"):
    print(cfg.get(section, option, fallback="")
          if cfg.has_section(section) else "")
PYEOF
)
    HYP_SERVER=${HYP_CREDS[0]:-}
    HYP_USER=${HYP_CREDS[1]:-}
    HYP_PASS=${HYP_CREDS[2]:-}
    # Accept the hypervisor password directly from the
    # VIRTWHO_<HYPERVISOR>_PASSWORD secret when the ini has none.
    if [ -z "$HYP_PASS" ]; then
        HYP_PASS_VAR="VIRTWHO_$(printf '%s' "$HYP" | tr '[:lower:]-' '[:upper:]_')_PASSWORD"
        if [ -n "${!HYP_PASS_VAR:-}" ]; then
            HYP_PASS="${!HYP_PASS_VAR}"
            echo "Using hypervisor password from ${HYP_PASS_VAR}"
        fi
    fi
    if [ -n "$HYP_SERVER" ]; then
        echo "Setting up SSH trust to $HYP hypervisor at $HYP_SERVER"
        ssh-keyscan -p 22 "$HYP_SERVER" >> /root/.ssh/known_hosts 2>&1 || true

        if [ -n "${CCT_SSH_KEY_B64:-}" ]; then
            echo "Using injected SSH key (CCT_SSH_KEY_B64)"
            # Decode to tmpfs (0600). The subshell umask makes the
            # redirect create the key mode 0600 from the first byte:
            # there is no world-readable window between creation and
            # the chmod below, and a crash mid-decode cannot leave a
            # world-readable key behind (review PR297-11). The tmpfs
            # copy is shredded by cleanup-secrets.sh in the tmt
            # finish step.
            SSH_KEY_TMP=/dev/shm/virtwho-ssh-key
            ( umask 077 && printf '%s' "$CCT_SSH_KEY_B64" | base64 -d > "$SSH_KEY_TMP" )
            chmod 600 "$SSH_KEY_TMP"
        elif [ -n "${CCT_SSH_KEY_URL:-}" ]; then
            # LEGACY transition path, kept for backward compatibility:
            # .testing-farm.yaml still injects CCT_SSH_KEY_URL. Retire
            # this branch once the URL is replaced by CCT_SSH_KEY_B64.
            echo "Fetching SSH key from CCT_SSH_KEY_URL (legacy transition path)"
            # Download to a tmpfs staging file (unpredictable name), then
            # install 0600 to the final tmpfs path; the tmpfs copy is
            # shredded by cleanup-secrets.sh in the tmt finish step.
            SSH_KEY_TMP=/dev/shm/virtwho-ssh-key
            KEY_DL=$(mktemp /dev/shm/virtwho-key-download.XXXXXX)
            curl -fsSL --retry 3 --retry-delay 10 --connect-timeout 5 \
                -o "$KEY_DL" "$CCT_SSH_KEY_URL"
            install -m 600 "$KEY_DL" "$SSH_KEY_TMP"
            rm -f "$KEY_DL"
        else
            echo "Generating ephemeral SSH keypair on tmpfs"
            # The key lives ONLY on tmpfs (never /root/.ssh/id_rsa):
            # ssh reaches it through the ssh_config entry below.
            SSH_KEY_TMP=/dev/shm/virtwho-ssh-key
            rm -f "$SSH_KEY_TMP" "$SSH_KEY_TMP.pub"
            ssh-keygen -t rsa -N "" -f "$SSH_KEY_TMP" -C "virtwho-qe" -q
        fi
        # Derive the public key next to it on tmpfs.
        ssh-keygen -y -f "$SSH_KEY_TMP" > "${SSH_KEY_TMP}.pub"

        # Point ssh at the tmpfs key via ssh_config instead of
        # installing it into /root/.ssh. Both the ssh CLI and the
        # virt-who daemon (its qemu+ssh:// URIs resolve through root's
        # ssh_config) pick the key up from the entry below; the systemd
        # daemon cannot use an ssh-agent, which is why the key must
        # exist as a root-readable file -- tmpfs + this config entry is
        # the design. The entry carries no secret; cleanup-secrets.sh
        # removes it in the finish step.
        printf '  # virtwho-test tmpfs key\n  IdentityFile %s\n' \
            "$SSH_KEY_TMP" >> /root/.ssh/config

        # The injected/CI keys are already authorized on the hypervisor;
        # only the ephemeral key needs ssh-copy-id (and the hypervisor
        # password for it). sshpass -e with SSHPASS set only for this
        # command keeps the password off the process list.
        if [ -z "${CCT_SSH_KEY_B64:-}" ] && [ -z "${CCT_SSH_KEY_URL:-}" ] \
            && [ -n "$HYP_PASS" ]; then
            SSHPASS="$HYP_PASS" sshpass -e ssh-copy-id -i "${SSH_KEY_TMP}.pub" \
                -o StrictHostKeyChecking=no "${HYP_USER:-root}@${HYP_SERVER}" || true
        fi

        # The key is never copied to /root/.ssh/virtwho-qe: nothing in
        # the repo reads those copies on the test runner (the provision
        # flow creates its own key on the hosts it builds), and copying
        # the key to disk would defeat the tmpfs-only design.

        ssh -o StrictHostKeyChecking=no -o BatchMode=yes \
            "${HYP_USER:-root}@${HYP_SERVER}" hostname \
            && echo "SSH to $HYP_SERVER: OK" \
            || echo "WARNING: SSH to $HYP_SERVER failed (tests may fail)"
    fi
fi

# --- Image-mode-specific adjustments ---
if is_bootc; then
  echo "Image-mode (bootc) detected"

  if command -v podman > /dev/null; then
    podman pull images.paas.redhat.com/rhsmqe/rhsm-squid:latest 2>/dev/null || true
  fi

  # Auto-exclude image-mode-incompatible tests. Extract any existing -m
  # expression from PYTEST_ADDOPTS, combine it with "not notImageMode",
  # and pass the result as a separate quoted -m argument to pytest.
  # NOTE: The -m extraction below only handles a single unquoted token
  # (e.g. "-m gating"). Compound expressions like '-m "tier1 and gating"'
  # are not supported — set IMAGEMODE_PYTEST_MARKER to override.
  if [ -n "${IMAGEMODE_PYTEST_MARKER:-}" ]; then
    IMAGEMODE_MARKER="${IMAGEMODE_PYTEST_MARKER}"
  elif echo "${PYTEST_ADDOPTS:-}" | grep -qE '\-m[[:space:]]'; then
    EXISTING_MARKER=$(echo "$PYTEST_ADDOPTS" | sed -E 's/.*-m[[:space:]]+([^[:space:]]+).*/\1/')
    IMAGEMODE_MARKER="(${EXISTING_MARKER}) and not notImageMode"
    PYTEST_ADDOPTS=$(echo "${PYTEST_ADDOPTS}" | sed -E 's/[[:space:]]*-m[[:space:]]+[^[:space:]]+//')
  else
    IMAGEMODE_MARKER="not notImageMode"
  fi
  export PYTEST_ADDOPTS
  export IMAGEMODE_MARKER
  echo "PYTEST_ADDOPTS adjusted for image-mode: ${PYTEST_ADDOPTS:-} -m '${IMAGEMODE_MARKER}'"
fi

cd "${VIRTWHO_TEST_DIR}"

echo "=========================================="
echo "Running virt-who regression tests"
echo "=========================================="
echo "Hypervisor: ${HYPERVISOR:-esx}"
echo "Register:   ${REGISTER:-rhsm}"
echo "Compose:    ${RHEL_COMPOSE:-unknown}"
echo "Image-mode: $(is_bootc && echo yes || echo no)"
echo "=========================================="

MARKER_ARGS=()
if [ -n "${IMAGEMODE_MARKER:-}" ]; then
  MARKER_ARGS=(-m "${IMAGEMODE_MARKER}")
fi

IGNORE_ARGS=()
if is_bootc; then
  # test_hypervisors_state.py imports hypervisor package which writes a log
  # file at import time — fails on the read-only bootc filesystem during
  # collection before markers can deselect it.
  IGNORE_ARGS=(--ignore=tests/others/test_hypervisors_state.py)
fi

set +e
pytest tests/ \
    --tb=short \
    --junit-xml="${TMT_TEST_DATA}/junit.xml" \
    --html="${TMT_TEST_DATA}/report.html" \
    --self-contained-html \
    -v -s \
    ${PYTEST_ADDOPTS:-} \
    "${MARKER_ARGS[@]}" \
    "${IGNORE_ARGS[@]}"
TEST_EXIT_CODE=$?
set -e

echo ""
echo "=========================================="
echo "Test Execution Complete"
echo "Exit Code: ${TEST_EXIT_CODE}"
echo "=========================================="

if [ -n "${TMT_PLAN_DATA:-}" ]; then
    for artifact in junit.xml report.html; do
        if [ -f "${TMT_TEST_DATA}/${artifact}" ]; then
            cp "${TMT_TEST_DATA}/${artifact}" "${TMT_PLAN_DATA}/" || true
            echo "Copied ${artifact} to TMT_PLAN_DATA"
        fi
    done
fi

exit $TEST_EXIT_CODE
