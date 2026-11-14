#!/bin/bash
# prepare-candlepin.sh -- Deploy the containerized Candlepin
# destination (CCT-3155) on the test guest.
#
# Runs in the TMT prepare phase (after configure-proxy.sh and AFTER
# setup-virtwho-test.sh -- the ORDER is load-bearing: the clone step
# creates the INSTALL_DIR tree, and this script's readiness marker
# lands in that tree's root. Deploying first would leave a non-empty
# INSTALL_DIR (pod config + marker) into which setup-virtwho-test.sh's
# `git clone` then exits 128 and fails the whole prepare phase -- the
# plan-ordering invariant in systemtest/selftest/test_plan_script_modes.py
# pins the order) when the destination knob selects the container tier
# (VIRTWHO_DESTINATION=container, the default). The script resolves
# every file it reads (the pod manifest, the container overlay, lib.sh)
# from its own SCRIPT_DIR -- the tmt plan's checkout, NOT the cloned
# tree -- so it has no dependency on the clone; only the marker path
# shares the clone's root, where all three readers look (tests/
# conftest.py, assert-candlepin-tier.sh via run-tests.sh's
# VIRTWHO_TEST_DIR, and cleanup-secrets.sh's tree sweep). The
# destination tier removes the stage-credential/stage-endpoint
# problem class from the default test path: every destination call
# the suite and virt-who make goes to a per-run Candlepin pod on
# localhost, carrying only SYNTHETIC pre-baked test data (the public
# ghcr.io/candlepin images -- public-by-design, no registry
# credentials, nothing for cleanup-secrets.sh to destroy).
#
# What it does:
#   1. pulls the two digest-pinned images (ghcr.io is public; the
#      pins live in systemtest/config/candlepin-pod.yaml and are
#      mirrored as the defaults below -- the selftest asserts the two
#      stay in sync)
#   2. deploys the pod (podman play kube; the app's hostPort 8443 is
#      >1024, so no privileged ports, no sysctls, no SELinux changes)
#   3. waits for HTTP 200 on GET /candlepin/status (every curl
#      bounded by --max-time; on timeout the last pod log lines are
#      dumped for triage -- rhsm-qe LESSON-02)
#   4. adapts the configure-host.sh sequence for root podman on the
#      guest: /etc/hosts entry for "candlepin" (the pod certificate's
#      SAN), the pod's CA into /etc/rhsm/ca and the system trust
#      store (both upstream CA file names probed -- the candlepin
#      4.8.0 rename class), then verifies
#      https://candlepin:8443/candlepin/status WITH full TLS
#      verification (proving the trust install)
#   5. probes the pinned image's baked test-data contract (the
#      synthetic account authenticates, the baked org exists and
#      supports SCA, the hypervisor capabilities are advertised --
#      rhsm-qe LESSON-03); drift is a loud skip naming what drifted.
#      There is deliberately NO content/repo endpoint probe: the pod
#      carries no repo container (virt-who tests reporting, not
#      content consumption -- the run-#7 follow-up ruling), and the
#      tier's [rhsm] baseurl points at the deliberately-unbound
#      localhost:8080 so content access stays local (no external
#      egress, no CDN fallback) and fails bounded (verified live:
#      connection refused in ~1 s; register is unaffected -- the
#      registration round-trip was proven with no repo container
#      running)
#   5b. ACTIVATES Simple Content Access on the baked org (the run-#6
#       register gap): the baked org's ACTIVE contentAccessMode is
#       'entitlement' (verified live; rhsm-qe documents the same
#       baked default and its flip-flops between image generations),
#       and RHEL-10's subscription-manager refuses username/password
#       registration into an entitlement-mode org -- the client gates
#       on the org's ACTIVE mode, while the contract probe above only
#       proved the LIST contains org_environment (the probe-vs-
#       register asymmetry that caused build #180's SCA rejections).
#       Mirroring rhsm-qe's setContentAccesModeBeforeSuite (their
#       suite setup runs the same PUT for every org they register
#       against, with the register credentials -- no admin needed;
#       the suite's own rhsm.sca() is the same call): a PUT
#       /owners/{org} setting contentAccessMode=org_environment as
#       the tier's synthetic account, then a STRICT re-verification
#       (a fresh org read asserting the ACTIVE mode IS
#       org_environment) before the marker. Failure is a loud skip,
#       never a marker
#   6. writes the .virtwho-candlepin-ready marker into the root of
#      the tree the clone step created (INSTALL_DIR, where all three
#      readers look) -- tests/conftest.py reads it: without the marker the
#      destination-coupled tests SKIP LOUDLY instead of failing
#      confusingly or passing vacuously (and run-tests.sh FAILS the
#      run outright via assert-candlepin-tier.sh -- rhsm-qe LESSON-04).
#
# Skip, never hard-fail: when the tier is not selected, or podman /
# the images are unavailable (including the bootc container-build
# prepare context, which has no running podman), the script exits 0
# with a LOUD stderr warning and writes NO marker -- the suite then
# knows the destination is absent. Teardown is cleanup-secrets.sh's
# `podman play kube --down` (best-effort, idempotent).
#
# Proxy scoping (the run-#5 / build-#179 defect class): the tmt
# environment exports HTTPS_PROXY to every command and sets no
# no_proxy anywhere, so an un-bypassed curl to
# https://localhost:8443 is routed to the proxy -- which can never
# reach the guest's own pod ports. In #179 the readiness probe read
# connection-level 000 for the full 180 s window while the pod was
# fully healthy (Tomcat up in 32 s, proven by the triage pod logs
# the timeout dumps). Every curl in this script is POD-FACING (the
# readiness probe and TLS verification on localhost/candlepin:8443,
# the data-contract probes) and therefore carries `--noproxy '*'`:
# the bypass is per-command, never an exported environment variable,
# so the proxy KEEPS applying to everything else -- the podman pulls
# of the pinned ghcr.io images deliberately ride it (#179 proved
# they work through it). There is NO external curl in this script;
# if one is ever added it must NOT carry the bypass.
#
# Knobs (all plain non-secret values):
#   VIRTWHO_DESTINATION     container (default) | stage (skip)
#   VIRTWHO_CP_APP_IMAGE    override the candlepin-app image ref
#   VIRTWHO_CP_DB_IMAGE     override the candlepin-db image ref
#   VIRTWHO_CANDLEPIN_POD_YAML    pod manifest (self-test override)
#   VIRTWHO_CANDLEPIN_HOSTS_FILE  hosts file (default /etc/hosts)
#   VIRTWHO_CANDLEPIN_CA_DIR      rhsm CA dir (default /etc/rhsm/ca)
#   VIRTWHO_CANDLEPIN_ANCHOR_DIR  ca-trust anchors (default
#                                 /etc/pki/ca-trust/source/anchors)
#   VIRTWHO_CANDLEPIN_APP_CONTAINER  app container name for podman cp
#   VIRTWHO_CANDLEPIN_TIMEOUT   readiness timeout seconds (default 180)
#   VIRTWHO_CANDLEPIN_PULL_TIMEOUT   per-attempt podman pull timeout
#                                 seconds (default 300; a stalled pull
#                                 counts as a failed attempt and feeds
#                                 the skip path, never a hung prepare)
#   VIRTWHO_PREPARE_INSTALL_DIR  marker location (self-test override)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# [job] plan-level aliases, same as every wrapper: REGISTER decides
# whether the candlepin destination is in play at all.
promote_job_aliases

DESTINATION=${VIRTWHO_DESTINATION:-container}
REGISTER=$(printf '%s' "${REGISTER:-rhsm}" | tr '[:upper:]' '[:lower:]')

# Mirror the path detection in prepare-kubevirt.sh: use /usr/share on
# bootc (ostree-safe), /opt otherwise. VIRTWHO_PREPARE_INSTALL_DIR
# overrides both for the self-test sandbox.
if [ -n "${VIRTWHO_PREPARE_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$VIRTWHO_PREPARE_INSTALL_DIR"
elif command -v bootc &>/dev/null || [ -f /run/ostree-booted ] || [ -L /ostree ]; then
    INSTALL_DIR=/usr/share/virtwho-test
else
    INSTALL_DIR=/opt/virtwho-test
fi
MARKER="${INSTALL_DIR}/.virtwho-candlepin-ready"

# A stale marker (e.g. a re-run after a failed deploy) must not lie
# to the suite: remove it up front, write it back only on success.
rm -f "$MARKER"

if [ "$DESTINATION" != "container" ]; then
    echo "SKIP: VIRTWHO_DESTINATION=${DESTINATION}; the containerized Candlepin destination is not deployed (the [rhsm] values of the selected tier apply)"
    exit 0
fi

if [ "$REGISTER" != "rhsm" ]; then
    echo "SKIP: REGISTER=${REGISTER}; the containerized Candlepin destination only serves the rhsm register tier"
    exit 0
fi

# --- digest-pinned image refs -------------------------------------------
# Defaults mirror systemtest/config/candlepin-pod.yaml (the canonical
# record; the selftest asserts the two agree). Refresh deliberately,
# in BOTH places, and note the date in the yaml header.
POD_YAML=${VIRTWHO_CANDLEPIN_POD_YAML:-${SCRIPT_DIR}/../config/candlepin-pod.yaml}
DEFAULT_APP_IMAGE="ghcr.io/candlepin/candlepin-app@sha256:bba274fd2af841bcf15ef5d975f4d99902a58e1599eae6e95017d4f2ac3751a3"
DEFAULT_DB_IMAGE="ghcr.io/candlepin/candlepin-db@sha256:4bf8b27d20fa77d2afff60723ce2ed5058e2337cbf26b2db81f116fe956b5d5b"
APP_IMAGE=${VIRTWHO_CP_APP_IMAGE:-$DEFAULT_APP_IMAGE}
DB_IMAGE=${VIRTWHO_CP_DB_IMAGE:-$DEFAULT_DB_IMAGE}

# --- skip checks (loud, never a hard failure of the run) ----------------
if ! command -v podman > /dev/null 2>&1; then
    echo "WARNING: podman is not available; the containerized Candlepin destination is NOT deployed -- the destination-coupled tests will SKIP (this is the expected behavior on bootc container-build prepare contexts and minimal guests)" >&2
    exit 0
fi

if [ ! -r "$POD_YAML" ]; then
    echo "WARNING: the candlepin pod manifest is not readable at ${POD_YAML}; the containerized Candlepin destination is NOT deployed -- the destination-coupled tests will SKIP" >&2
    exit 0
fi

# --- bootc container-build guard (review OPS-01) --------------------------
# In a bootc image-mode compose, the TMT prepare phase runs inside a
# Containerfile RUN layer: no systemd, no runtime podman socket, and
# the guest that would run the tests does not exist yet. Deploying
# there would only pull ~1-1.5 GB of dead images into the image layer
# (the class install-deps.sh already guards its squid pre-pull
# against). Mirroring that guard: skip the deploy with a loud warning
# and no marker. The state string (not just the exit code) is what is
# checked: `systemctl is-system-running` exits 1 both for a degraded
# live guest and for a container build, and a degraded-but-usable
# guest must still get its destination deployed (the vacuous-green
# guard would rightly fail such a run otherwise).
SYSTEM_STATE=$(systemctl is-system-running 2>/dev/null || true)
case "$SYSTEM_STATE" in
    running | degraded) ;;
    *)
        echo "WARNING: systemd is not running (state: '${SYSTEM_STATE:-none}' -- a bootc container-build prepare context?); the containerized Candlepin destination is NOT deployed -- the destination-coupled tests will SKIP (only a booted guest with systemd gets the per-run pod)" >&2
        exit 0
        ;;
esac

# --- deploy --------------------------------------------------------------
# Pre-pull with retries (better errors than a play-kube pull failure;
# ghcr.io is public, no credentials). An unreachable registry means
# the images are unavailable: skip loudly, do not fail the run.
# Each pull attempt is bounded by timeout (review EM-03, the
# CCT-2222 class one layer down): a stalled pull counts as a FAILED
# attempt and feeds the retry/skip path -- never a prepare phase that
# hangs until the Testing Farm timeout kills the job.
PULL_TIMEOUT=${VIRTWHO_CANDLEPIN_PULL_TIMEOUT:-300}
pull_image() {
    local image=$1 attempt
    for attempt in 1 2 3; do
        if timeout "$PULL_TIMEOUT" podman pull "$image" > /dev/null 2>&1; then
            echo "Pulled ${image}"
            return 0
        fi
        echo "WARNING: pull of ${image} failed (attempt ${attempt}/3, per-attempt timeout ${PULL_TIMEOUT}s)" >&2
        sleep 5
    done
    return 1
}

if ! pull_image "$APP_IMAGE" || ! pull_image "$DB_IMAGE"; then
    echo "WARNING: the digest-pinned candlepin images could not be pulled; the containerized Candlepin destination is NOT deployed -- the destination-coupled tests will SKIP" >&2
    exit 0
fi

# Idempotence: a leftover pod from an earlier attempt would make
# play kube fail; tear it down first (best-effort, like the finish
# step).
if podman pod exists candlepin 2> /dev/null; then
    echo "A candlepin pod already exists; tearing it down before redeploying"
    podman play kube --down "$POD_YAML" > /dev/null 2>&1 || \
        podman pod rm -f candlepin > /dev/null 2>&1 || true
fi

# Env-var image overrides (e.g. testing a refresh before repinning):
# substitute them into a temp copy of the manifest -- the vendored
# yaml stays the canonical digest record.
PLAY_YAML=$POD_YAML
if [ "$APP_IMAGE" != "$DEFAULT_APP_IMAGE" ] || [ "$DB_IMAGE" != "$DEFAULT_DB_IMAGE" ]; then
    PLAY_YAML=$(mktemp /tmp/candlepin-pod.XXXXXX.yaml)
    sed -e "s|${DEFAULT_APP_IMAGE}|${APP_IMAGE}|" \
        -e "s|${DEFAULT_DB_IMAGE}|${DB_IMAGE}|" \
        "$POD_YAML" > "$PLAY_YAML"
    echo "Deploying with image override(s): $( [ "$APP_IMAGE" != "$DEFAULT_APP_IMAGE" ] && echo app ) $( [ "$DB_IMAGE" != "$DEFAULT_DB_IMAGE" ] && echo db )"
fi

echo "Deploying the candlepin pod (${PLAY_YAML})"
if ! podman play kube "$PLAY_YAML"; then
    echo "WARNING: podman play kube failed; the containerized Candlepin destination is NOT deployed -- the destination-coupled tests will SKIP" >&2
    rm -f "$PLAY_YAML"
    exit 0
fi
[ "$PLAY_YAML" = "$POD_YAML" ] || rm -f "$PLAY_YAML"

# --- readiness -----------------------------------------------------------
# rhsm-qe LESSON-02: readiness means HTTP 200, not a successful TCP
# connect. A bare `curl -f`-less probe exits 0 on ANY HTTP status (a
# 503 during app warmup would pass readiness), and without --max-time
# a port that stays bound while its server is slow blocks the loop
# body forever (their CCT-2222: a two-hour Jenkins hang on exactly
# this). The substrate's own provision.sh wait-api phase requires
# HTTP 200 the same way.
TIMEOUT=${VIRTWHO_CANDLEPIN_TIMEOUT:-180}
echo "Waiting for the candlepin pod to answer HTTP 200 on /status (up to ${TIMEOUT}s)"
waited=0
while true; do
    http_code=$(curl -sk -o /dev/null -w '%{http_code}' --noproxy '*' \
        --connect-timeout 5 --max-time 10 \
        https://localhost:8443/candlepin/status 2> /dev/null || true)
    if [ "$http_code" = "200" ]; then
        break
    fi
    if [ "$waited" -ge "$TIMEOUT" ]; then
        echo "WARNING: the candlepin pod did not answer HTTP 200 on https://localhost:8443/candlepin/status within ${TIMEOUT}s (last code: ${http_code:-none}) -- the containerized Candlepin destination is NOT deployed -- the destination-coupled tests will SKIP" >&2
        # rhsm-qe embeds the last container-log lines in the readiness
        # failure: that is what makes such a skip triable from the
        # Jenkins log alone.
        echo "--- last pod log lines (triage) ---" >&2
        podman pod logs --tail 50 candlepin >&2 || true
        podman play kube --down "$POD_YAML" > /dev/null 2>&1 || true
        exit 0
    fi
    sleep 5
    waited=$((waited + 5))
done
echo "Candlepin answers HTTP 200 on https://localhost:8443/candlepin/status"

# --- host configuration (configure-host.sh, adapted for root podman) ----
HOSTS_FILE=${VIRTWHO_CANDLEPIN_HOSTS_FILE:-/etc/hosts}
CA_NAME=candlepin-ca-bundle.pem
CA_DIR=${VIRTWHO_CANDLEPIN_CA_DIR:-/etc/rhsm/ca}
ANCHOR_DIR=${VIRTWHO_CANDLEPIN_ANCHOR_DIR:-/etc/pki/ca-trust/source/anchors}
APP_CONTAINER=${VIRTWHO_CANDLEPIN_APP_CONTAINER:-candlepin-candlepin-app}
CA_PATH="${CA_DIR}/${CA_NAME}"
ANCHOR_PATH="${ANCHOR_DIR}/${CA_NAME}"

# /etc/hosts entry: the ini's [rhsm] server=candlepin must resolve,
# and the name is in the pod certificate's SANs (so TLS verifies).
if grep -qE "^127\.0\.0\.1[[:space:]]+candlepin([[:space:]]|$)" "$HOSTS_FILE" 2>/dev/null; then
    echo "candlepin is already in ${HOSTS_FILE}, skipping"
else
    echo "127.0.0.1 candlepin" >> "$HOSTS_FILE"
    echo "Added candlepin to ${HOSTS_FILE}"
fi

# CA trust: copy the pod's CA out, install it into /etc/rhsm/ca
# (where subscription-manager's connection picks it up) and the
# system trust store (update-ca-trust is a stub-able PATH command;
# restorecon is best-effort when present).
#
# rhsm-qe LESSON (dd285006a): the upstream CA file was renamed at
# candlepin 4.8.0 (candlepin-ca.crt -> candlepin-ca-bundle.crt). The
# digest pin keeps today's image fixed, but the next deliberate
# refresh may target either name generation: try the current bundle
# name first, fall back to the pre-4.8.0 name (the same refresh-guard
# class as the data-contract probe below).
CA_TMP=$(mktemp /tmp/candlepin-ca.XXXXXX)
trap 'rm -f "$CA_TMP" "${CONTRACT_STATUS_TMP:-}" "${CONTRACT_OWNERS_TMP:-}" "${CONTRACT_SCA_TMP:-}"' EXIT
CA_SRC=""
for ca_candidate in \
    /etc/candlepin/certs/candlepin-ca-bundle.crt \
    /etc/candlepin/certs/candlepin-ca.crt; do
    if podman cp "${APP_CONTAINER}:${ca_candidate}" "$CA_TMP" 2> /dev/null; then
        CA_SRC=$ca_candidate
        break
    fi
done
if [ -z "$CA_SRC" ]; then
    echo "WARNING: could not copy the candlepin CA out of ${APP_CONTAINER} (neither /etc/candlepin/certs/candlepin-ca-bundle.crt nor /etc/candlepin/certs/candlepin-ca.crt exists there -- a refresh to a renamed CA layout?) -- the containerized Candlepin destination is NOT trusted/verified -- the destination-coupled tests will SKIP" >&2
    # Review OPS-02: the pod is already deployed at this point; a bare
    # exit would orphan it until the finish step. Tear it down here
    # too (best-effort, idempotent -- the same call cleanup-secrets.sh
    # makes), keeping prepare's failure paths symmetric.
    podman play kube --down "$POD_YAML" > /dev/null 2>&1 || true
    exit 0
fi
echo "Copied the candlepin CA from ${APP_CONTAINER}:${CA_SRC}"
install -D -o root -g root -m 0644 "$CA_TMP" "$CA_PATH"
mkdir -p "$ANCHOR_DIR"
ln -sf "$CA_PATH" "$ANCHOR_PATH"
# Review QA-03: update-ca-trust was the one external command without
# a guard -- on a minimal guest without the ca-certificates tooling
# its exit 127 would violate this script's own skip-never-hard-fail
# contract. Guard it: when the tool is absent the destination cannot
# be verified, so skip loudly (no marker) and tear the pod down. The
# final TLS-verified curl below remains the real gate on normal
# guests.
if command -v update-ca-trust > /dev/null 2>&1; then
    update-ca-trust
else
    echo "WARNING: update-ca-trust is not available on this guest; the pod CA cannot be installed into the system trust store -- the containerized Candlepin destination is NOT verified -- the destination-coupled tests will SKIP" >&2
    podman play kube --down "$POD_YAML" > /dev/null 2>&1 || true
    exit 0
fi
if command -v restorecon > /dev/null 2>&1; then
    restorecon "$CA_PATH" 2> /dev/null || true
fi
echo "Installed the candlepin CA (${CA_PATH} + ${ANCHOR_PATH})"

# Final verification WITH TLS and hostname checking: this is the
# exact connection shape virt-who and the suite's server-side checks
# use (server=candlepin, port=8443, prefix=/candlepin). --max-time
# bounds the whole transfer (rhsm-qe CCT-2222), not just the connect;
# --noproxy '*' keeps the pod-facing connection off the pipeline's
# HTTPS_PROXY (the build #179 class -- see the header).
if ! curl -sSf -o /dev/null --noproxy '*' --connect-timeout 10 \
    --max-time 10 https://candlepin:8443/candlepin/status; then
    echo "WARNING: https://candlepin:8443/candlepin/status failed TLS/hostname verification after the CA install -- the containerized Candlepin destination is NOT verified -- the destination-coupled tests will SKIP" >&2
    # Review OPS-02: symmetric teardown here too (see the CA-copy
    # failure path above).
    podman play kube --down "$POD_YAML" > /dev/null 2>&1 || true
    exit 0
fi
echo "Verified https://candlepin:8443/candlepin/status (TLS, hostname, trust)"

# --- data-contract probe (rhsm-qe LESSON-03) ------------------------------
# The digest pins guard the image BITS; this probe guards the baked
# TEST-DATA contract (the synthetic account authenticates, the baked
# org exists and supports SCA, the hypervisor capabilities are
# advertised). rhsm-qe was bitten by exactly this drift class
# (401-on-register from a credential mismatch, then a testuser vs
# testuser1 rename between image generations); a mistaken refresh to
# a data-changed image must fail HERE -- one loud prepare-phase
# diagnosis naming WHAT drifted -- instead of surfacing as per-test
# 401s and missing-org errors dozens of steps from the cause.
#
# The account is read from the tier's ini overlay (the single source
# of the contract; the value is synthetic public test data, but it
# rides curl's stdin config stream, never argv -- the same rule the
# discovery scripts follow). The probe queries the baked org itself
# (GET /owners/{org}): the global /owners listing is admin-only on
# the real image, but the synthetic account holds OWNER access on
# the org -- 200 with the org payload proves both the authentication
# and the org's existence in one request (verified against the live
# pinned image; a wrong credential answers 401).
#
# There is deliberately NO content-endpoint probe anymore (the
# run-#7 follow-up): the pod carries no repo container, and the
# tier's [rhsm] baseurl intentionally points at the unbound
# localhost:8080 (local, no external egress, bounded failure --
# see the header). Probing it would assert on a port that is dead
# by design.
CONTAINER_INI="${SCRIPT_DIR}/../config/virtwho-container.ini"
mapfile -t CONTRACT < <(python3 - "$CONTAINER_INI" <<'PYEOF'
import configparser
import sys

cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
cfg.read(sys.argv[1])
for option in ("username", "password", "default_org"):
    print(cfg.get("rhsm", option, fallback=""))
PYEOF
)
CP_USER=${CONTRACT[0]:-}
CP_PASS=${CONTRACT[1]:-}
CP_ORG=${CONTRACT[2]:-}
CONTRACT_STATUS_TMP=$(mktemp /tmp/candlepin-contract-status.XXXXXX)
CONTRACT_OWNERS_TMP=$(mktemp /tmp/candlepin-contract-owners.XXXXXX)
status_code=$(curl -sk -o "$CONTRACT_STATUS_TMP" -w '%{http_code}' \
    --noproxy '*' --connect-timeout 10 --max-time 30 \
    https://candlepin:8443/candlepin/status 2> /dev/null || true)
owners_code=$(printf 'user = "%s:%s"\n' "$CP_USER" "$CP_PASS" \
    | curl -s -o "$CONTRACT_OWNERS_TMP" -w '%{http_code}' \
        --noproxy '*' --connect-timeout 10 --max-time 30 -K - \
        "https://candlepin:8443/candlepin/owners/${CP_ORG}" \
        2> /dev/null || true)
# The validator names WHAT drifted, never credential values; an empty
# output means the contract holds.
CONTRACT_DRIFT=$(CP_ORG="$CP_ORG" python3 - \
    "$status_code" "$owners_code" \
    "$CONTRACT_STATUS_TMP" "$CONTRACT_OWNERS_TMP" <<'PYEOF' || true
import json
import os
import sys

status_code, owners_code, status_path, owners_path = \
    sys.argv[1:5]
org = os.environ["CP_ORG"]
drift = []

if status_code != "200":
    drift.append(f"the status endpoint answered HTTP {status_code or 'none'}")
else:
    try:
        with open(status_path) as f:
            status = json.load(f)
        capabilities = json.dumps(status.get("managerCapabilities") or [])
        if "hypervisor" not in capabilities.lower():
            drift.append("the hypervisor capability is no longer "
                         "advertised by the status endpoint")
    except ValueError:
        drift.append("the status endpoint no longer answers JSON")

if owners_code != "200":
    drift.append(f"the synthetic test account did not authenticate "
                 f"against the baked org query "
                 f"(HTTP {owners_code or 'none'})")
else:
    try:
        with open(owners_path) as f:
            owner = json.load(f)
    except ValueError:
        drift.append("the baked org query no longer answers JSON")
        owner = {}
    if not isinstance(owner, dict) or owner.get("key") != org:
        drift.append(f"the baked org '{org}' is not visible to the "
                     "synthetic test account")
    else:
        modes = owner.get("contentAccessModeList", "")
        if isinstance(modes, str):
            modes = [m.strip() for m in modes.split(",")]
        if "org_environment" not in modes:
            drift.append(f"the baked org '{org}' no longer supports "
                         "org_environment content access")

print("; ".join(drift))
PYEOF
)
if [ -n "$CONTRACT_DRIFT" ]; then
    echo "WARNING: the pinned image's test-data contract drifted (${CONTRACT_DRIFT}; image ${APP_IMAGE}) -- the containerized Candlepin destination is NOT deployed -- the destination-coupled tests will SKIP" >&2
    podman play kube --down "$POD_YAML" > /dev/null 2>&1 || true
    exit 0
fi
echo "Verified the pinned image's test-data contract (account, org, SCA mode, hypervisor capabilities)"

# --- SCA activation (the run-#6 register gap, build #180) ------------------
# The register path the suite uses (subscription-manager register
# --org=<org> --username --password, no activation key) is refused by
# RHEL-10's subscription-manager unless the org's ACTIVE
# contentAccessMode is org_environment -- the client queries the org
# and gates on the ACTIVE mode, while the contract probe above proved
# only that the LIST contains org_environment (the asymmetry that
# made #180's register tests fail while the probe passed). rhsm-qe
# hits exactly this against the same container family and solves it
# in their suite setup (setContentAccesModeBeforeSuite: a PUT
# /owners/{org} per register org, with the register credentials --
# verified live: the tier's synthetic account holds the permission on
# the baked org; no admin credential is needed or used). The PUT is
# idempotent; the credential rides curl's stdin config stream exactly
# like the probe above, and the bypass/bounds are the pod-facing
# standing rules.
CONTRACT_SCA_TMP=$(mktemp /tmp/candlepin-contract-sca.XXXXXX)
sca_put_code=$(printf 'user = "%s:%s"\n' "$CP_USER" "$CP_PASS" \
    | curl -s -o /dev/null -w '%{http_code}' --noproxy '*' \
        --connect-timeout 10 --max-time 30 -K - \
        -H 'Content-Type: application/json' \
        -X PUT --data '{"contentAccessMode":"org_environment"}' \
        "https://candlepin:8443/candlepin/owners/${CP_ORG}" \
        2> /dev/null || true)
sca_get_code=$(printf 'user = "%s:%s"\n' "$CP_USER" "$CP_PASS" \
    | curl -s -o "$CONTRACT_SCA_TMP" -w '%{http_code}' \
        --noproxy '*' --connect-timeout 10 --max-time 30 -K - \
        "https://candlepin:8443/candlepin/owners/${CP_ORG}" \
        2> /dev/null || true)
# STRICT: the re-read must show the ACTIVE mode IS org_environment --
# a contains-only check is exactly the asymmetry that caused #180
# (the validator names the drift, never credential values).
SCA_DRIFT=$(CP_ORG="$CP_ORG" python3 - \
    "$sca_put_code" "$sca_get_code" "$CONTRACT_SCA_TMP" <<'PYEOF' || true
import json
import os
import sys

put_code, get_code, verify_path = sys.argv[1:4]
org = os.environ["CP_ORG"]
drift = []

if put_code != "200":
    drift.append(f"setting the org's content access mode answered "
                 f"HTTP {put_code or 'none'}")
else:
    active = None
    if get_code != "200":
        drift.append(f"re-reading the org after the set answered "
                     f"HTTP {get_code or 'none'}")
    else:
        try:
            with open(verify_path) as f:
                active = json.load(f).get("contentAccessMode")
        except ValueError:
            drift.append("the org query after the set no longer "
                         "answers JSON")
    if active != "org_environment":
        drift.append(f"the org '{org}' active content access mode is "
                     f"{active!r}, not 'org_environment' (username/"
                     "password registration requires the ACTIVE mode)")

print("; ".join(drift))
PYEOF
)
if [ -n "$SCA_DRIFT" ]; then
    echo "WARNING: the baked org could not be switched to Simple Content Access (${SCA_DRIFT}; image ${APP_IMAGE}) -- the containerized Candlepin destination is NOT deployed -- the destination-coupled tests will SKIP" >&2
    podman play kube --down "$POD_YAML" > /dev/null 2>&1 || true
    exit 0
fi
echo "Activated Simple Content Access for the baked org (register requires the org's ACTIVE mode, verified by re-read)"

# --- the marker (the suite's destination-absent skip reads it) -----------
mkdir -p "$INSTALL_DIR"
touch "$MARKER"
echo "Containerized Candlepin destination is ready (marker: ${MARKER})"
