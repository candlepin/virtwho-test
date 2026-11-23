#!/bin/bash
# prepare-candlepin.sh -- Deploy the containerized Candlepin
# destination (CCT-3155) on the test guest.
#
# Runs in the TMT prepare phase, AFTER setup-virtwho-test.sh -- the
# ORDER is load-bearing: the clone step creates the INSTALL_DIR tree,
# and this script's readiness marker lands in that tree's root.
# Deploying first would leave a non-empty INSTALL_DIR (pod config +
# marker) into which setup-virtwho-test.sh's `git clone` then exits
# 128 and fails the whole prepare phase (the plan-ordering invariant
# the companion selftest suite, branch cct-3162/selftests, pins via
# its test_plan_script_modes.py).
# The script resolves every file it reads (the pod manifest, the
# container overlay, lib.sh) from its own SCRIPT_DIR -- the tmt
# plan's checkout, NOT the cloned tree -- so it has no dependency on
# the clone; only the marker path shares the clone's root, where all
# three readers look (tests/conftest.py, assert-candlepin-tier.sh via
# run-tests.sh's VIRTWHO_TEST_DIR, and cleanup-secrets.sh's tree
# sweep). The destination tier removes the stage-credential/
# stage-endpoint problem class from the default test path: every
# destination call goes to a per-run Candlepin pod on localhost
# carrying only SYNTHETIC pre-baked test data (public ghcr.io
# images, public-by-design, no registry credentials, nothing for
# cleanup-secrets.sh to destroy).
#
# What it does:
#   1. pulls the two digest-pinned images (ghcr.io is public; the
#      pins live in systemtest/config/candlepin-pod.yaml and are
#      mirrored as the defaults below -- the companion selftest
#      suite, cct-3162/selftests, asserts the two stay in sync)
#   2. deploys the pod (podman play kube; the app's hostPort 8443 is
#      >1024, so no privileged ports, no sysctls, no SELinux changes)
#   3. waits for HTTP 200 on GET /candlepin/status (every curl
#      bounded by --max-time; on timeout the last pod log lines are
#      dumped for triage)
#   4. configures the host: /etc/hosts entry for "candlepin" (the
#      pod certificate's SAN), the pod's CA into /etc/rhsm/ca and the
#      system trust store (both upstream CA file names probed -- the
#      CA file was renamed at candlepin 4.8.0), then verifies
#      https://candlepin:8443/candlepin/status WITH full TLS
#      verification
#   5. probes the pinned image's baked test-data contract (the
#      synthetic account authenticates, the baked org exists and
#      supports SCA, the hypervisor capabilities are advertised);
#      drift is a loud skip naming what drifted. There is
#      deliberately NO content/repo endpoint probe: the pod carries
#      no repo container and the tier's [rhsm] baseurl points at the
#      deliberately-unbound localhost:8080 (see the yaml header)
#   5b. ACTIVATES Simple Content Access on the baked org: its baked
#       ACTIVE contentAccessMode is 'entitlement', and RHEL-10's
#       subscription-manager refuses username/password registration
#       into an entitlement-mode org (it gates on the org's ACTIVE
#       mode, not the mode LIST -- the contract probe only proves the
#       LIST). A PUT /owners/{org} setting
#       contentAccessMode=org_environment as the tier's synthetic
#       account, then a STRICT re-verification (a fresh org read
#       asserting the ACTIVE mode IS org_environment) before the
#       marker. Failure is a loud skip, never a marker
#   6. writes the .virtwho-candlepin-ready marker into the root of
#      the tree the clone step created -- tests/conftest.py reads it:
#      without the marker the destination-coupled tests SKIP LOUDLY
#      instead of failing confusingly or passing vacuously (and
#      run-tests.sh FAILS the run outright via
#      assert-candlepin-tier.sh).
#
# Skip, never hard-fail: when the tier is not selected, or podman /
# the images are unavailable (including the bootc container-build
# prepare context, which has no running podman), the script exits 0
# with a LOUD stderr warning and writes NO marker -- the suite then
# knows the destination is absent. Teardown is cleanup-secrets.sh's
# `podman play kube --down` (best-effort, idempotent).
#
# Proxy scoping: the tmt environment exports HTTPS_PROXY to every
# command and sets no no_proxy anywhere, so an un-bypassed curl to
# https://localhost:8443 would be routed to the proxy -- which can
# never reach the guest's own pod ports. Every curl in this script is
# pod-facing and therefore carries `--noproxy '*'`: the bypass is
# per-command, never an exported environment variable, so the proxy
# KEEPS applying to everything else (the podman pulls of the pinned
# images ride it). There is NO external curl in this script; if one
# is ever added it must NOT carry the bypass.
#
# Knobs (all plain non-secret values):
#   VIRTWHO_DESTINATION     container (default) | stage (skip)
#   VIRTWHO_CP_APP_IMAGE    override the candlepin-app image ref
#   VIRTWHO_CP_DB_IMAGE     override the candlepin-db image ref
#   VIRTWHO_CANDLEPIN_POD_YAML    pod manifest (self-test override,
#                                 companion suite cct-3162/selftests)
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
#   VIRTWHO_PREPARE_INSTALL_DIR  marker location (self-test override,
#                                 companion suite cct-3162/selftests)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# [job] plan-level aliases, same as every wrapper: REGISTER decides
# whether the candlepin destination is in play at all.
promote_job_aliases

DESTINATION=${VIRTWHO_DESTINATION:-container}
REGISTER=$(printf '%s' "${REGISTER:-rhsm}" | tr '[:upper:]' '[:lower:]')

# The shared test-tree root (lib.sh's detect_install_dir): /usr/share
# on bootc (ostree-safe), /opt otherwise. VIRTWHO_PREPARE_INSTALL_DIR
# overrides both for the self-test sandbox (the companion suite,
# branch cct-3162/selftests).
INSTALL_DIR=$(detect_install_dir)
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
# record; the companion selftest suite, cct-3162/selftests, asserts
# the two agree). Refresh deliberately,
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

# --- bootc container-build guard ------------------------------------------
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
# Each pull attempt is bounded by timeout: a stalled pull counts as
# a FAILED attempt and feeds the retry/skip path -- never a prepare
# phase that hangs until the Testing Farm timeout kills the job.
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

# The no-orphaned-pod invariant in ONE place: best-effort,
# idempotent teardown of the deployed pod (the same call
# cleanup-secrets.sh makes, with the pod-rm fallback for a
# half-created pod a failed play kube can leave behind).
teardown_pod() {
    podman play kube --down "$POD_YAML" > /dev/null 2>&1 || \
        podman pod rm -f candlepin > /dev/null 2>&1 || true
}

# skip_tier <warning>: the loud-skip idiom every post-deploy failure
# path shares -- warn on stderr (the caller's text names WHAT
# failed), tear the deployed pod down symmetrically, exit 0 (skip,
# never a hard failure of the run), no marker written.
skip_tier() {
    echo "WARNING: $1 -- the destination-coupled tests will SKIP" >&2
    teardown_pod
    exit 0
}

# accumulate_drift <var> <argv...>: run ONE python drift validator
# and capture its '; '-joined drift output into the named variable.
# The validator body (python, unchanged per probe: it names WHAT
# drifted, never a credential value) arrives as this function's
# stdin heredoc; *argv* are passed through to it. An empty output
# means the checked contract holds -- the caller then skip_tiers on
# a non-empty value. A crashing validator is tolerated (|| true,
# exactly like the former inline invocations): the empty result
# holds the loud skip, never a hard prepare failure.
accumulate_drift() {
    local var=$1
    shift
    printf -v "$var" '%s' \
        "$(CP_ORG="$CP_ORG" python3 - "$@" || true)"
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
    teardown_pod
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
    # only the temp override copy is removed -- the vendored yaml is
    # the canonical record (and cleanup-secrets.sh needs it for --down)
    [ "$PLAY_YAML" = "$POD_YAML" ] || rm -f "$PLAY_YAML"
    skip_tier "podman play kube failed; the containerized Candlepin destination is NOT deployed"
fi
[ "$PLAY_YAML" = "$POD_YAML" ] || rm -f "$PLAY_YAML"

# --- readiness -----------------------------------------------------------
# Readiness means HTTP 200, not a successful TCP connect: a probe
# without -f exits 0 on ANY HTTP status (a 503 during app warmup
# would pass readiness), and without --max-time a bound-but-slow
# port blocks the loop body forever.
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
        # the last container-log lines make the skip triable from
        # the run log alone
        echo "--- last pod log lines (triage) ---" >&2
        podman pod logs --tail 50 candlepin >&2 || true
        teardown_pod
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
# restorecon is best-effort when present). The upstream CA file name
# changed at candlepin 4.8.0 (candlepin-ca.crt ->
# candlepin-ca-bundle.crt): probe the current bundle name first, fall
# back to the pre-4.8.0 name so a deliberate image refresh survives
# either name generation.
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
    # symmetric teardown: the pod is already deployed at this point;
    # a bare exit would orphan it until the finish step
    skip_tier "could not copy the candlepin CA out of ${APP_CONTAINER} (neither /etc/candlepin/certs/candlepin-ca-bundle.crt nor /etc/candlepin/certs/candlepin-ca.crt exists there -- a refresh to a renamed CA layout?) -- the containerized Candlepin destination is NOT trusted/verified"
fi
echo "Copied the candlepin CA from ${APP_CONTAINER}:${CA_SRC}"
install -D -o root -g root -m 0644 "$CA_TMP" "$CA_PATH"
mkdir -p "$ANCHOR_DIR"
ln -sf "$CA_PATH" "$ANCHOR_PATH"
# update-ca-trust needs its absence guarded: on a minimal guest
# without the ca-certificates tooling its exit 127 would violate
# this script's own skip-never-hard-fail contract. When the tool is
# absent the destination cannot be verified, so skip loudly (no
# marker) and tear the pod down. The final TLS-verified curl below
# remains the real gate on normal guests.
if command -v update-ca-trust > /dev/null 2>&1; then
    update-ca-trust
else
    skip_tier "update-ca-trust is not available on this guest; the pod CA cannot be installed into the system trust store -- the containerized Candlepin destination is NOT verified"
fi
if command -v restorecon > /dev/null 2>&1; then
    restorecon "$CA_PATH" 2> /dev/null || true
fi
echo "Installed the candlepin CA (${CA_PATH} + ${ANCHOR_PATH})"

# Final verification WITH TLS and hostname checking: this is the
# exact connection shape virt-who and the suite's server-side checks
# use (server=candlepin, port=8443, prefix=/candlepin). --max-time
# bounds the whole transfer, not just the connect; --noproxy '*'
# keeps the pod-facing connection off the pipeline's HTTPS_PROXY
# (see the header).
if ! curl -sSf -o /dev/null --noproxy '*' --connect-timeout 10 \
    --max-time 10 https://candlepin:8443/candlepin/status; then
    # symmetric teardown here too (see the CA-copy failure path above)
    skip_tier "https://candlepin:8443/candlepin/status failed TLS/hostname verification after the CA install -- the containerized Candlepin destination is NOT verified"
fi
echo "Verified https://candlepin:8443/candlepin/status (TLS, hostname, trust)"

# --- data-contract probe ----------------------------------------------
# The digest pins guard the image BITS; this probe guards the baked
# TEST-DATA contract (the synthetic account authenticates, the baked
# org exists and supports SCA, the hypervisor capabilities are
# advertised). A refresh to a data-changed image must fail HERE --
# one loud prepare-phase diagnosis naming WHAT drifted -- instead of
# surfacing as per-test 401s and missing-org errors dozens of steps
# from the cause. The account is read from the tier's ini overlay
# (the single source of the contract; the value is synthetic public
# test data, but it rides curl's stdin config stream, never argv).
# The probe queries the baked org itself (GET /owners/{org}): the
# synthetic account holds OWNER access on the org, so a 200 with the
# org payload proves both the authentication and the org's existence
# in one request. There is deliberately NO content-endpoint probe:
# the pod carries no repo container and the tier's [rhsm] baseurl
# intentionally points at the unbound localhost:8080 (dead by
# design -- see the yaml header).
CONTAINER_INI="${SCRIPT_DIR}/../config/virtwho-container.ini"
mapfile -d '' -t CONTRACT < <(ini_read "$CONTAINER_INI" rhsm \
    username password default_org)
CP_USER=${CONTRACT[0]:-}
CP_PASS=${CONTRACT[1]:-}
CP_ORG=${CONTRACT[2]:-}
CONTRACT_STATUS_TMP=$(mktemp /tmp/candlepin-contract-status.XXXXXX)
CONTRACT_OWNERS_TMP=$(mktemp /tmp/candlepin-contract-owners.XXXXXX)
# no insecure flags below: the CA is installed and the verified
# probe above already proved TLS works at this point (only the
# bounded pre-TLS readiness loop may carry -k)
status_code=$(curl -s -o "$CONTRACT_STATUS_TMP" -w '%{http_code}' \
    --noproxy '*' --connect-timeout 10 --max-time 30 \
    https://candlepin:8443/candlepin/status 2> /dev/null || true)
owners_code=$(printf 'user = "%s:%s"\n' "$CP_USER" "$CP_PASS" \
    | curl -s -o "$CONTRACT_OWNERS_TMP" -w '%{http_code}' \
        --noproxy '*' --connect-timeout 10 --max-time 30 -K - \
        "https://candlepin:8443/candlepin/owners/${CP_ORG}" \
        2> /dev/null || true)
# The validator names WHAT drifted, never credential values; an empty
# output means the contract holds.
accumulate_drift CONTRACT_DRIFT \
    "$status_code" "$owners_code" \
    "$CONTRACT_STATUS_TMP" "$CONTRACT_OWNERS_TMP" <<'PYEOF'
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
if [ -n "$CONTRACT_DRIFT" ]; then
    skip_tier "the pinned image's test-data contract drifted (${CONTRACT_DRIFT}; image ${APP_IMAGE}) -- the containerized Candlepin destination is NOT deployed"
fi
echo "Verified the pinned image's test-data contract (account, org, SCA mode, hypervisor capabilities)"

# --- SCA activation ------------------------------------------------------
# RHEL-10's subscription-manager refuses username/password
# registration into an org whose ACTIVE contentAccessMode is not
# org_environment (the client gates on the ACTIVE mode; the contract
# probe above only proves the LIST contains it). The PUT is
# idempotent and uses the tier's synthetic account (which holds the
# permission on the baked org; no admin credential is needed or
# used); the credential rides curl's stdin config stream exactly like
# the probe above, and the bypass/bounds are the pod-facing standing
# rules.
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
# a contains-only check repeats the probe-vs-register asymmetry (the
# validator names the drift, never credential values).
accumulate_drift SCA_DRIFT \
    "$sca_put_code" "$sca_get_code" "$CONTRACT_SCA_TMP" <<'PYEOF'
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
if [ -n "$SCA_DRIFT" ]; then
    skip_tier "the baked org could not be switched to Simple Content Access (${SCA_DRIFT}; image ${APP_IMAGE}) -- the containerized Candlepin destination is NOT deployed"
fi
echo "Activated Simple Content Access for the baked org (register requires the org's ACTIVE mode, verified by re-read)"

# --- the marker (the suite's destination-absent skip reads it) -----------
mkdir -p "$INSTALL_DIR"
touch "$MARKER"
echo "Containerized Candlepin destination is ready (marker: ${MARKER})"
