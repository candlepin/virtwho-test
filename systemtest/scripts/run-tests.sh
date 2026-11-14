#!/bin/bash
# run-tests.sh -- Execute the virtwho-test pytest suite and copy artifacts
# to TMT_PLAN_DATA for preservation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# [job] plan-level aliases (review PR297-09), single-sourced in
# lib.sh: promote VIRTWHO_JOB_* into the plan-level variables BEFORE
# any ${VAR:-default} evaluation below (the ini regeneration, the
# libvirt SSH-trust branch, the summary banner) so the alias and the
# scripts agree end-to-end.
promote_job_aliases

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
# shellcheck source=sshd-dropin.sh
source "${SCRIPT_DIR}/sshd-dropin.sh"

# Set the guest root password the suite itself uses (the virt-who
# host IS this guest): take the VIRTWHO_VIRTWHO_PASSWORD secret when
# delivered, otherwise generate a random per-run value -- there is no
# default, so nothing published can log in as root here. The value
# reaches passwd via stdin and the ini merge below via the
# environment, never argv.
if [ -n "${VIRTWHO_VIRTWHO_PASSWORD:-}" ]; then
    GUEST_ROOT_PASS="$VIRTWHO_VIRTWHO_PASSWORD"
    echo "Using the guest root password from VIRTWHO_VIRTWHO_PASSWORD"
else
    GUEST_ROOT_PASS=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
    echo "Generated a random per-run guest root password (no default)"
fi
printf '%s\n' "$GUEST_ROOT_PASS" | passwd --stdin root
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
    # guest root account (username=root and the per-run password set
    # above -- from VIRTWHO_VIRTWHO_PASSWORD or randomly generated,
    # never a published default) is filled in as a default when the env
    # provides none. The password reaches this merge via the
    # environment (never argv), like the kubevirt token.
    GUEST_ROOT_PASS="$GUEST_ROOT_PASS" python3 - /dev/shm/virtwho.ini .virtwho-computed.ini <<'PYEOF'
import configparser
import os
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
fallback("virtwho", "password", os.environ.get("GUEST_ROOT_PASS"))
fallback("virtwho", "package", None)
fallback("virtwho", "test_rpms", None)
# the version-under-test RPM cache path (the run-#7 content-gap fix):
# setup-virtwho-test.sh records it in the sidecar so the package
# tests can reinstall the version under test with every repo
# disabled -- never from the destination's content repo.
fallback("virtwho", "undertest_rpm", None)
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
# Normalize: the case gate below (and the handler list generally) is
# lowercase; an env-supplied AHV/Hyper-V/LibVirt must not silently
# skip discovery (the generator lower-cases the same value).
HYP=$(printf '%s' "$HYP" | tr '[:upper:]' '[:lower:]')
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

# --- Per-run guest-IP discovery (ahv/hyperv/libvirt) ---
# The guests inside these hypervisors receive DHCP addresses, so a
# static guest_ip in the sanitized base ini goes stale. Resolve the
# current address from the hypervisor's own management plane and patch
# guest_ip in the ini; the ini value is kept when discovery fails.
# Runs after the libvirt SSH-trust setup above so key-based ssh is
# available, and before pytest so the ssh_guest fixture (which connects
# to guest_ip at session setup) sees the fresh value. ANY failure of
# the discovery (non-zero exit, a parse error on a hand-edited ini) is
# a warning naming the fallback -- never a run-aborting error under
# set -e: the ini's existing guest_ip is kept and pytest still runs.
# Hard failures stay reserved for the documented fail-closed cases in
# the generator (no credentials + active sentinels), which runs in the
# prepare phase, before this script.
case "$HYP" in
    ahv | hyperv | libvirt)
        if ! bash "${SCRIPT_DIR}/discover-guest-ips.sh" "$INI_FILE" "$HYP"; then
            echo "WARNING: guest-IP discovery failed; keeping the ini's existing guest_ip and continuing" >&2
        fi
        ;;
esac

# --- pod-destination proxy bypass (the build-#179 class) -----------
# The tmt environment exports HTTPS_PROXY to every command and sets
# no no_proxy anywhere. The suite's own connections to the per-run
# Candlepin pod that run IN THIS PROCESS'S ENVIRONMENT -- the RHSM
# class's requests calls, anything else honoring the proxy env vars
# -- would be routed through the proxy, which can never reach the
# guest's own pod ports (the exact shape that killed the #179
# readiness probe one layer down: connection-level 000 while the
# pod was fully healthy). In container mode ONLY, append the
# pod-host names to no_proxy/NO_PROXY (both spellings, any existing
# values preserved): external egress keeps the proxy -- the podman
# image pulls ride it, and the stage tier (whose server REQUIRES
# the proxy) is untouched because the export never runs there. The
# stage server must NEVER appear in this list.
# subscription-manager's guest-side connections do not read this
# process's environment at all: they run through ssh with rhsm.conf
# as their only proxy source, which is why configure-proxy.sh skips
# the rhsm.conf proxy in container mode (same defect class, other
# surface).
JOB_DESTINATION=$(python3 - "$INI_FILE" <<'PYEOF'
import configparser
import sys

cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
cfg.read(sys.argv[1])
print(cfg.get("job", "destination", fallback="").strip().lower())
PYEOF
)
if [ "$JOB_DESTINATION" = "container" ]; then
    POD_HOSTS="localhost,127.0.0.1,candlepin"
    no_proxy="${no_proxy:+${no_proxy},}${POD_HOSTS}"
    NO_PROXY="${NO_PROXY:+${NO_PROXY},}${POD_HOSTS}"
    export no_proxy NO_PROXY
    echo "Container destination: bypassing the proxy for the pod hosts (${POD_HOSTS}); external egress keeps the proxy"
fi

# --- Image-mode-specific adjustments ---
if is_bootc; then
  echo "Image-mode (bootc) detected"

  if command -v podman > /dev/null; then
    # The bad-proxy container image comes from the environment; there
    # is no default (an internal registry literal does not belong in a
    # public repo). The pre-pull is best-effort.
    if [ -n "${VIRTWHO_SQUID_IMAGE:-}" ]; then
      podman pull "$VIRTWHO_SQUID_IMAGE" 2>/dev/null || true
    else
      echo "VIRTWHO_SQUID_IMAGE not set; skipping the bad-proxy container image pre-pull"
    fi
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

# --- vacuous-green guard (rhsm-qe LESSON-04) -----------------------------
# A pipeline run whose ini selects the container destination must not
# report green when the tier was silently absent: assert the readiness
# marker BEFORE pytest starts. The guard reads the ini's [job] tier
# record (not the env), so hand-written inis without the option keep
# the old contract and satellite cells are exempt; bootc
# container-build contexts keep the conftest skip (prepare
# legitimately runs there without a runtime podman).
if ! is_bootc; then
    bash "${SCRIPT_DIR}/assert-candlepin-tier.sh" "$INI_FILE" "${VIRTWHO_TEST_DIR}"
fi

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
# -rs (review QA-02): the short-test-summary lists every skip with
# its FULL reason -- the two destination skip classes (marker-absent
# vs guest-unreachable vs untrusted-CA) truncate to the same console
# prefix without it, and the Jenkins console is what the run evidence
# review reads.
pytest tests/ \
    --tb=short \
    --junit-xml="${TMT_TEST_DATA}/junit.xml" \
    --html="${TMT_TEST_DATA}/report.html" \
    --self-contained-html \
    -v -s -rs \
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
