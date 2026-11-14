"""Prepare/teardown self-tests (CCT-3155) for the containerized
Candlepin destination scripts.

Exercises the REAL systemtest/scripts/prepare-candlepin.sh and the
pod-teardown half of the REAL cleanup-secrets.sh inside throwaway
/dev/shm sandboxes with PATH-injected command stubs: no podman, no
network, no root. Every value is a dummy; the image refs under
assertion are the digest-pinned PUBLIC ghcr.io test images (and the
script-default-vs-yaml drift guard keeps the pins single-sourced).

Run: python -m pytest systemtest/selftest/ -v
"""

import http.server
import os
import re
import ssl
import subprocess
import threading
from pathlib import Path

import pytest
from _utils import (
    REPO_ROOT,
    SCRIPTS_DIR,
    run,
    write_executable,
)

PREPARE = SCRIPTS_DIR / "prepare-candlepin.sh"
CLEANUP = SCRIPTS_DIR / "cleanup-secrets.sh"
POD_YAML = REPO_ROOT / "systemtest" / "config" / "candlepin-pod.yaml"

PODMAN_STUB = """\
#!/bin/bash
# Fake podman: record every invocation and simulate the subcommands
# prepare-candlepin.sh and cleanup-secrets.sh use.
printf '%s\\n' "$*" >> "${FAKE_PODMAN_LOG:?}"
case "$1" in
  pull)
    [ -n "${FAKE_PODMAN_FAIL_PULL:-}" ] && exit 1
    exit 0
    ;;
  pod)
    # "pod exists" answers from the environment (default: no pod);
    # "pod logs" succeeds silently (the readiness triage dump)
    if [ "$2" = "exists" ]; then
      exit "${FAKE_PODMAN_POD_EXISTS:-1}"
    fi
    exit 0
    ;;
  play)
    # "play kube --down <yaml>": record which yaml was used
    exit 0
    ;;
  cp)
    # "cp container:path dest": model the CA-file rename class --
    # succeed only when the source file name is among
    # FAKE_PODMAN_CA_FILES (default: both upstream names exist; an
    # explicitly EMPTY value means neither does)
    src="$2"
    base="${src##*/}"
    ok=0
    for f in ${FAKE_PODMAN_CA_FILES-candlepin-ca-bundle.crt candlepin-ca.crt}; do
      [ "$f" = "$base" ] && ok=1
    done
    if [ "$ok" != "1" ]; then
      exit 1
    fi
    dest="${!#}"
    printf 'FAKE candlepin CA\\n' > "$dest"
    exit 0
    ;;
esac
exit 0
"""

# The healthy baked-data contract of the pinned images (public
# synthetic test data, mirroring bin/deployment/test_data.json of
# candlepin-container-unofficial: the snowwhite org supports both
# content access modes; /status advertises the hypervisor
# capabilities the phase-0 spike observed). The baked ACTIVE mode of
# snowwhite is entitlement (verified live against the pinned image;
# rhsm-qe documents the same baked default) -- the run-#6 register
# gap the SCA-activation step exists to close.
STUB_STATUS_BODY = (
    '{"result":true,"version":"TEST",'
    '"managerCapabilities":['
    '{"id":1,"name":"cores"},'
    '{"id":2,"name":"hypervisors_async"},'
    '{"id":3,"name":"hypervisors_heartbeat"}]}'
)
STUB_OWNERS_BODY = (
    '{"id":"4028","key":"snowwhite","displayName":"Snow White",'
    '"contentAccessModeList":"entitlement,org_environment",'
    '"contentAccessMode":"entitlement"}'
)
# The org AFTER the SCA-activation PUT (the strict re-verification
# read): the ACTIVE mode flipped to org_environment, the list
# unchanged -- what the real server answers once the set took.
STUB_SCA_OWNERS_BODY = (
    '{"id":"4028","key":"snowwhite","displayName":"Snow White",'
    '"contentAccessModeList":"entitlement,org_environment",'
    '"contentAccessMode":"org_environment"}'
)

# A plain (non-f-) string: the __BODY__ tokens below are replaced
# after definition so the JSON braces need no escaping.
CURL_STUB = """\
#!/bin/bash
# Fake curl: record the invocation; answer the -w http code and
# per-URL JSON bodies from the environment (defaults: HTTP 200 and
# the healthy baked-data contract). Only the %{http_code} -w
# placeholder is ever used by the scripts under test. The org URL is
# STATEFUL like a real server: the SCA-activation PUT (run-#6) flips
# a state file on success, and every later GET on the org then
# answers the post-set body (the ACTIVE mode flipped) -- the first
# GET still sees the baked entitlement-active state.
printf '%s\\n' "$*" >> "${FAKE_CURL_LOG:?}"
DEFAULT_STATUS='__STATUS_BODY__'
DEFAULT_OWNERS='__OWNERS_BODY__'
SCA_SET_OWNERS='__SCA_OWNERS_BODY__'
out=""
dest="/dev/null"
code="${FAKE_CURL_HTTP_CODE:-200}"
args=("$@")
i=0
for arg in "$@"; do
  case "$arg" in
    -o) dest="${args[$((i+1))]:-}" ;;
    https://*/status)
      code="${FAKE_CURL_STATUS_CODE:-$code}"
      out="${FAKE_CURL_STATUS_BODY:-$DEFAULT_STATUS}" ;;
    https://*/owners*)
      # the SCA-activation PUT to the org (run-#6): answer from the
      # env and, on success, flip the stub's org state so the strict
      # post-set verification GET reflects the new ACTIVE mode (what
      # a real server does); before any PUT the org GETs answer the
      # baked entitlement-active contract
      case "$*" in
        *PUT*)
          code="${FAKE_CURL_PUT_CODE:-200}"
          out="${FAKE_CURL_PUT_BODY:-$SCA_SET_OWNERS}"
          if [ "$code" = "200" ] && [ -n "${FAKE_CURL_STATE:-}" ]; then
            : > "$FAKE_CURL_STATE"
          fi
          ;;
        *)
          if [ -n "${FAKE_CURL_STATE:-}" ] && [ -e "${FAKE_CURL_STATE:-}" ]; then
            code="${FAKE_CURL_SCA_VERIFY_CODE:-200}"
            out="${FAKE_CURL_SCA_VERIFY_BODY:-$SCA_SET_OWNERS}"
          else
            code="${FAKE_CURL_OWNERS_CODE:-$code}"
            out="${FAKE_CURL_OWNERS_BODY:-$DEFAULT_OWNERS}"
          fi
          ;;
      esac ;;
  esac
  i=$((i+1))
done
if [ -n "$dest" ] && [ "$dest" != "/dev/null" ]; then
  printf '%s\\n' "$out" > "$dest"
fi
printf '%s\\n' "$code"
# the final TLS-verified curl runs with -f: an exit-code knob lets
# the tests simulate its failure (the OPS-02 teardown path)
exit "${FAKE_CURL_EXIT_CODE:-0}"
""".replace("__STATUS_BODY__", STUB_STATUS_BODY).replace(
    "__OWNERS_BODY__", STUB_OWNERS_BODY).replace(
    "__SCA_OWNERS_BODY__", STUB_SCA_OWNERS_BODY)



CA_TRUST_STUB = """\
#!/bin/bash
# Fake update-ca-trust: record the invocation, succeed.
printf 'update-ca-trust\\n' >> "${FAKE_CA_TRUST_LOG:?}"
exit 0
"""

# Fake timeout(1) (review EM-03): record the invocation, then run
# the command exactly like the real one -- prepare-candlepin.sh
# bounds each podman pull with it, and the recording is what makes
# the bound observable. FAKE_TIMEOUT_FAIL=1 simulates a stalled pull
# (the timeout firing): a failed bound counts as a failed attempt.
TIMEOUT_STUB = """\
#!/bin/bash
duration="$1"
shift
printf '%s %s\\n' "$duration" "$*" >> "${FAKE_TIMEOUT_LOG:?}"
if [ -n "${FAKE_TIMEOUT_FAIL:-}" ]; then
  exit 124
fi
exec "$@"
"""

# Fake systemctl (review OPS-01): answer `is-system-running` from
# the environment so the bootc-build guard is testable in every
# state (running/degraded proceed; anything else, including an
# empty answer, skips the deploy).
SYSTEMCTL_STUB = """\
#!/bin/bash
if [ "$1" = "is-system-running" ]; then
  # ${VAR-default} (not ${VAR:-default}): an explicitly EMPTY state
  # must stay empty -- that is the container-build answer class
  state="${FAKE_SYSTEMCTL_STATE-running}"
  printf '%s\\n' "$state"
  case "$state" in
    running) exit 0 ;;
    *) exit 1 ;;
  esac
fi
exit 0
"""

INSTALL_STUB = """\
#!/bin/bash
# Fake install: -D dir/file creation without the root ownership
# (the real script runs as root on the guest; the selftest does not).
src=""
dest=""
mode=0644
while [ $# -gt 0 ]; do
  case "$1" in
    -D) ;;
    -m) mode="$2"; shift ;;
    -o|-g) shift ;;
    *) if [ -z "$src" ]; then src="$1"; else dest="$1"; fi ;;
  esac
  shift
done
mkdir -p "$(dirname "$dest")"
cp "$src" "$dest"
chmod "$mode" "$dest"
exit 0
"""


@pytest.fixture
def stubbed(sandbox):
    """A sandbox with the podman/curl/update-ca-trust/install stubs
    on PATH and the destination knob overrides pointing inside it."""
    bin_dir = sandbox / "bin"
    bin_dir.mkdir()
    write_executable(bin_dir / "podman", PODMAN_STUB)
    write_executable(bin_dir / "curl", CURL_STUB)
    write_executable(bin_dir / "update-ca-trust", CA_TRUST_STUB)
    write_executable(bin_dir / "install", INSTALL_STUB)
    write_executable(bin_dir / "timeout", TIMEOUT_STUB)
    write_executable(bin_dir / "systemctl", SYSTEMCTL_STUB)
    install_dir = sandbox / "install"
    hosts = sandbox / "hosts"
    hosts.touch()
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_PODMAN_LOG": str(sandbox / "podman.log"),
        "FAKE_CURL_LOG": str(sandbox / "curl.log"),
        # the curl stub's org-state file (created by a successful
        # SCA-activation PUT; absent = the baked entitlement state)
        "FAKE_CURL_STATE": str(sandbox / "curl-org-state"),
        "FAKE_CA_TRUST_LOG": str(sandbox / "ca-trust.log"),
        "FAKE_TIMEOUT_LOG": str(sandbox / "timeout.log"),
        "VIRTWHO_PREPARE_INSTALL_DIR": str(install_dir),
        "VIRTWHO_CANDLEPIN_HOSTS_FILE": str(hosts),
        "VIRTWHO_CANDLEPIN_CA_DIR": str(sandbox / "rhsm-ca"),
        "VIRTWHO_CANDLEPIN_ANCHOR_DIR": str(sandbox / "anchors"),
        "VIRTWHO_CANDLEPIN_TIMEOUT": "5",
        "REGISTER": "rhsm",
    }
    ns = type("Stubs", (), {})()
    ns.sandbox = sandbox
    ns.env = env
    ns.bin_dir = bin_dir
    ns.install_dir = install_dir
    ns.hosts = hosts
    return ns


def run_prepare(stubs, *, env=None, unset=("VIRTWHO_DESTINATION",)):
    merged = dict(stubs.env)
    if env:
        merged.update(env)
    return run(["bash", PREPARE], env=merged, unset=unset)


def yaml_images():
    """The digest-pinned image refs of the vendored pod manifest."""
    text = POD_YAML.read_text()
    return re.findall(r"^\s*image:\s*(\S+)", text, re.MULTILINE)


class TestPrepareSuccess:
    def test_full_deploy_writes_marker_and_configures_host(self, stubbed):
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        marker = stubbed.install_dir / ".virtwho-candlepin-ready"
        assert marker.exists(), "the readiness marker was not written"
        # two digest-pinned pulls (the refs of the vendored yaml) and
        # the play kube deploy, in the podman log
        log = (stubbed.sandbox / "podman.log").read_text()
        for image in yaml_images():
            assert f"pull {image}" in log, f"{image} was not pulled"
        assert "play kube" in log
        # the /etc/hosts entry for the certificate SAN name
        assert "127.0.0.1 candlepin" in stubbed.hosts.read_text().splitlines()
        # the CA landed in the (overridden) rhsm CA dir and the
        # ca-trust anchor is a symlink to it; update-ca-trust ran
        ca = (stubbed.sandbox / "rhsm-ca" / "candlepin-ca-bundle.pem")
        assert ca.read_text() == "FAKE candlepin CA\n"
        anchor = (stubbed.sandbox / "anchors" / "candlepin-ca-bundle.pem")
        assert anchor.is_symlink()
        assert (stubbed.sandbox / "ca-trust.log").exists()
        # the final verification used the TLS-verified name+URL the
        # suite and virt-who use
        curl_log = (stubbed.sandbox / "curl.log").read_text()
        assert "https://candlepin:8443/candlepin/status" in curl_log
        assert "Containerized Candlepin destination is ready" in proc.stdout

    def test_hosts_entry_is_idempotent(self, stubbed):
        stubbed.hosts.write_text("127.0.0.1 candlepin\n")
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        assert stubbed.hosts.read_text().count("candlepin") == 1, \
            "the hosts entry was duplicated"

    def test_existing_pod_is_torn_down_before_redeploy(self, stubbed):
        # FAKE_PODMAN_POD_EXISTS=0: a leftover pod from an earlier
        # attempt must not break play kube
        proc = run_prepare(stubbed, env={"FAKE_PODMAN_POD_EXISTS": "0"})
        assert proc.returncode == 0, proc.stderr
        log = (stubbed.sandbox / "podman.log").read_text()
        assert "play kube --down" in log, \
            "a pre-existing pod was not torn down first"

    def test_stale_marker_is_removed_on_failure(self, stubbed):
        # a marker from an earlier run must not survive a deploy
        # that ends up skipping (the suite must never be lied to)
        marker = stubbed.install_dir / ".virtwho-candlepin-ready"
        stubbed.install_dir.mkdir(parents=True, exist_ok=True)
        marker.touch()
        proc = run_prepare(stubbed, env={"VIRTWHO_DESTINATION": "stage"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert not marker.exists(), \
            "a stale readiness marker survived a skipped deploy"

    def test_image_override_substitutes_into_a_temp_manifest(self, stubbed):
        override = "ghcr.io/candlepin/candlepin-app@sha256:" + "f" * 64
        proc = run_prepare(stubbed,
                           env={"VIRTWHO_CP_APP_IMAGE": override})
        assert proc.returncode == 0, proc.stderr
        log = (stubbed.sandbox / "podman.log").read_text()
        assert f"pull {override}" in log, \
            "the image override was not pulled"
        # the substituted manifest is a TEMP copy: play kube must not
        # have run the vendored yaml, and the vendored file keeps the
        # canonical pins untouched
        assert f"play kube {POD_YAML}" not in log, \
            "play kube ran the vendored manifest despite an override"
        assert re.search(r"play kube /tmp/candlepin-pod\.", log), \
            "the override was not substituted into a temp manifest"
        assert override not in POD_YAML.read_text()


class TestPrepareSkips:
    def test_stage_destination_skips(self, stubbed):
        proc = run_prepare(stubbed, env={"VIRTWHO_DESTINATION": "stage"},
                           unset=())
        assert proc.returncode == 0, proc.stderr
        assert "SKIP: VIRTWHO_DESTINATION=stage" in proc.stdout
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()
        assert not (stubbed.sandbox / "podman.log").exists(), \
            "podman was invoked although the tier is not container"

    def test_satellite_register_skips(self, stubbed):
        proc = run_prepare(stubbed, env={"REGISTER": "satellite"})
        assert proc.returncode == 0, proc.stderr
        assert "SKIP: REGISTER=satellite" in proc.stdout
        assert not (stubbed.sandbox / "podman.log").exists()

    def test_missing_podman_skips_loudly(self, sandbox):
        # a PATH without podman (and without the stubs): the skip
        # must be a LOUD stderr warning, never a failure, and no
        # marker may be written
        bin_dir = sandbox / "minimal-bin"
        bin_dir.mkdir()
        for name in ("bash", "rm", "tr", "dirname", "grep", "sed",
                     "mktemp", "mkdir", "sleep", "touch", "ln"):
            target = Path("/usr/bin") / name
            if target.exists():
                os.symlink(target, bin_dir / name)
        install_dir = sandbox / "install"
        hosts = sandbox / "hosts"
        hosts.touch()
        proc = run(["bash", PREPARE], env={
            "PATH": str(bin_dir),
            "VIRTWHO_PREPARE_INSTALL_DIR": str(install_dir),
            "VIRTWHO_CANDLEPIN_HOSTS_FILE": str(hosts),
            "REGISTER": "rhsm"},
            unset=("VIRTWHO_DESTINATION",))
        assert proc.returncode == 0, proc.stderr
        assert "WARNING: podman is not available" in proc.stderr
        assert "will SKIP" in proc.stderr
        assert not (install_dir / ".virtwho-candlepin-ready").exists()

    def test_unpullable_images_skip_loudly(self, stubbed):
        proc = run_prepare(stubbed, env={"FAKE_PODMAN_FAIL_PULL": "1"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "could not be pulled" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()


class TestReadinessSemantics:
    """rhsm-qe LESSON-02: readiness means HTTP 200 on a bounded curl,
    never 'the TCP port answered something'."""

    def test_readiness_requires_http_200(self, stubbed):
        # a bound port answering 503 must NOT pass readiness (the
        # class their b76aecba7 commit worked around); the skip names
        # the last code and dumps the pod logs for triage
        proc = run_prepare(stubbed, env={
            "FAKE_CURL_HTTP_CODE": "503",
            "VIRTWHO_CANDLEPIN_TIMEOUT": "0"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "did not answer HTTP 200" in proc.stderr
        assert "last code: 503" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()
        log = (stubbed.sandbox / "podman.log").read_text()
        assert "pod logs --tail 50 candlepin" in log, \
            "the readiness timeout did not dump the pod logs"
        assert "play kube --down" in log, \
            "the failed deploy was not torn down"

    def test_every_curl_is_bounded(self, stubbed):
        # the CCT-2222 class: --connect-timeout bounds only the TCP
        # connect; every curl the script runs must also carry
        # --max-time so a bound-but-slow port cannot hang prepare
        # until the Testing Farm timeout kills the job
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        lines = (stubbed.sandbox / "curl.log").read_text().splitlines()
        assert lines, "no curl invocation was recorded"
        unbounded = [line for line in lines if "--max-time" not in line]
        assert not unbounded, f"unbounded curl invocation(s): {unbounded}"


class TestProxyBypass:
    """The build-#179 defect class: the tmt environment exports
    HTTPS_PROXY to every command and sets no no_proxy, so an
    un-bypassed pod-facing curl routes through the proxy -- which can
    never reach the guest's own pod ports. In #179 the readiness
    probe read connection-level 000 for the full 180 s window while
    the pod was fully healthy (Tomcat up in 32 s, per the triage pod
    logs). Every curl in the script is pod-facing and must carry the
    per-command bypass; the proxy itself is KEPT for external egress
    (the podman pulls ride it)."""

    def test_every_pod_facing_curl_carries_the_bypass(self, stubbed):
        # behavioral pin via the recording curl stub: every curl the
        # script ran (readiness, TLS verification, the data-contract
        # probes) carries --noproxy '*' (the stub logs the joined
        # argv, so the quoted '*' arrives as a bare star -- the
        # source-level pin below asserts the quoted form)
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        lines = (stubbed.sandbox / "curl.log").read_text().splitlines()
        assert lines, "no curl invocation was recorded"
        missing = [line for line in lines if "--noproxy" not in line]
        assert not missing, \
            f"curl invocation(s) without the proxy bypass: {missing}"

    def test_every_curl_in_the_source_carries_the_bypass(self):
        # source-level pin (grep-able): every curl invocation in the
        # script text carries --noproxy. All of the script's curls
        # are pod-facing BY DESIGN; an external curl must never be
        # added without revisiting this invariant (and must not
        # carry the bypass).
        joined = PREPARE.read_text().replace("\\\n", " ")
        code_lines = [line for line in joined.splitlines()
                      if not line.lstrip().startswith("#")]
        curl_lines = [line for line in code_lines
                      if re.search(r"\bcurl\b", line)]
        assert curl_lines, "no curl invocation found in the script"
        missing = [line for line in curl_lines if "--noproxy" not in line]
        assert not missing, \
            f"curl invocation(s) without the proxy bypass: {missing}"

    def test_the_script_never_touches_the_proxy_environment(self):
        # the bypass is per-command ON PURPOSE: the proxy environment
        # must stay untouched so external egress (the podman pulls of
        # the pinned images) keeps riding the proxy -- run #5 proved
        # the pulls work through it while the probe did not. An
        # exported no_proxy would also leak into every child process
        # (unlike the scoped per-command flag).
        text = PREPARE.read_text()
        assert not re.search(
            r"(?im)^\s*(export\s+)?[a-z_]*proxy[a-z_0-9]*\s*=", text), \
            "the script must not assign or export proxy environment " \
            "variables (the bypass is per-command)"


class _PodStandInHandler(http.server.BaseHTTPRequestHandler):
    """Answers HTTP 200 on any GET: the stand-in for the pod's
    /candlepin/status endpoint."""

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestReadinessUnderHostileProxy:
    """The exact #179 failure shape, hermetically pinned: a REAL
    curl, a REAL local TLS server standing in for the pod's 8443,
    and an UNREACHABLE proxy in the environment. The readiness probe
    must reach the server through the per-command bypass; without it
    the probe reads connection-level 000 for the whole window while
    the server answers 200."""

    @pytest.fixture
    def pod_stand_in(self, sandbox):
        """A real TLS server on 127.0.0.1:8443 (the hardcoded
        readiness target) answering 200, with a throwaway
        self-signed certificate (the readiness probe runs -sk)."""
        cert = sandbox / "pod-stand-in.crt"
        key = sandbox / "pod-stand-in.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-nodes", "-keyout", str(key), "-out", str(cert),
             "-days", "1", "-subj", "/CN=localhost",
             "-addext",
             "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True, timeout=60)
        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 8443), _PodStandInHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server.socket = context.wrap_socket(server.socket,
                                            server_side=True)
        thread = threading.Thread(target=server.serve_forever,
                                  daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()

    @pytest.fixture
    def real_curl_stubs(self, sandbox):
        """The deploy stubs on PATH with the REAL curl (no curl
        stub): the readiness probe's actual network behavior is the
        subject. HOME/CURL_HOME/XDG_CONFIG_HOME point into the
        sandbox so a developer's ~/.curlrc cannot skew the probe,
        and the environment carries an UNREACHABLE proxy in both
        spellings with no no_proxy -- the pipeline's exact shape,
        made hostile."""
        bin_dir = sandbox / "bin"
        bin_dir.mkdir()
        write_executable(bin_dir / "podman", PODMAN_STUB)
        write_executable(bin_dir / "install", INSTALL_STUB)
        write_executable(bin_dir / "systemctl", SYSTEMCTL_STUB)
        write_executable(bin_dir / "timeout", TIMEOUT_STUB)
        write_executable(bin_dir / "update-ca-trust", CA_TRUST_STUB)
        for name in ("bash", "rm", "tr", "dirname", "grep", "sed",
                     "mktemp", "mkdir", "sleep", "touch", "ln",
                     "curl", "python3"):
            target = Path("/usr/bin") / name
            if target.exists():
                os.symlink(target, bin_dir / name)
        empty_home = sandbox / "empty-home"
        empty_home.mkdir()
        hosts = sandbox / "hosts"
        hosts.touch()
        env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "HOME": str(empty_home),
            "CURL_HOME": str(empty_home),
            "XDG_CONFIG_HOME": str(empty_home),
            "FAKE_PODMAN_LOG": str(sandbox / "podman.log"),
            "FAKE_CA_TRUST_LOG": str(sandbox / "ca-trust.log"),
            "FAKE_TIMEOUT_LOG": str(sandbox / "timeout.log"),
            "VIRTWHO_PREPARE_INSTALL_DIR": str(sandbox / "install"),
            "VIRTWHO_CANDLEPIN_HOSTS_FILE": str(hosts),
            "VIRTWHO_CANDLEPIN_CA_DIR": str(sandbox / "rhsm-ca"),
            "VIRTWHO_CANDLEPIN_ANCHOR_DIR": str(sandbox / "anchors"),
            "VIRTWHO_CANDLEPIN_TIMEOUT": "5",
            "REGISTER": "rhsm",
            # the hostile proxy: unreachable on purpose, both
            # spellings, no no_proxy -- the #179 environment shape
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "http_proxy": "http://127.0.0.1:9",
        }
        ns = type("RealCurlStubs", (), {})()
        ns.sandbox = sandbox
        ns.env = env
        ns.hosts = hosts
        ns.install_dir = sandbox / "install"
        return ns

    def test_readiness_reaches_the_pod_through_the_bypass(
            self, pod_stand_in, real_curl_stubs):
        proc = run(["bash", PREPARE], env=real_curl_stubs.env,
                   unset=("VIRTWHO_DESTINATION",))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        # readiness PASSED through the hostile proxy: the /etc/hosts
        # entry is written only AFTER the readiness loop succeeds,
        # and no readiness warning fired
        assert "127.0.0.1 candlepin" \
            in real_curl_stubs.hosts.read_text().splitlines(), \
            "readiness did not pass under the hostile proxy " \
            "(the #179 shape): " + proc.stderr
        assert "did not answer HTTP 200" not in proc.stderr
        # the run then stops at the TLS-verification stand-in
        # boundary: the `candlepin` name does not resolve in this
        # sandbox (and the stand-in certificate is untrusted), which
        # is PAST readiness -- and no marker may be written there
        assert "failed TLS/hostname verification" in proc.stderr
        assert not (real_curl_stubs.install_dir /
                    ".virtwho-candlepin-ready").exists()


class TestDataContractProbe:
    """rhsm-qe LESSON-03: the pinned image's baked test-data contract
    is probed before the marker, so drift is one loud prepare-phase
    diagnosis instead of per-test 401s dozens of steps later."""

    def test_healthy_contract_probes_owners_off_argv(self, stubbed):
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        assert "test-data contract" in proc.stdout
        curl_log = (stubbed.sandbox / "curl.log").read_text()
        owners_lines = [line for line in curl_log.splitlines()
                        if "/owners" in line]
        assert owners_lines, "the probe never queried the owners listing"
        # the synthetic credential rode curl's stdin config stream,
        # never the command line (/proc visibility)
        assert " -K - " in owners_lines[0]
        assert " -u " not in owners_lines[0]

    def test_the_probe_never_queries_the_dead_content_endpoint(
            self, stubbed):
        # run-#7 follow-up: the pod has NO repo container, so the
        # contract probe must NOT query any content endpoint -- the
        # tier's [rhsm] baseurl points at the deliberately-unbound
        # localhost:8080 (hermetic, no external egress; content
        # operations fail bounded and locally by design). A curl to
        # that port would hang or error against a dead endpoint and
        # wrongly skip the deploy.
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        curl_log = (stubbed.sandbox / "curl.log").read_text()
        assert "localhost:8080" not in curl_log, \
            "the probe queried the dead content endpoint"
        assert "RPM-GPG-KEY" not in curl_log, \
            "the probe queried a repo-container artifact"
        assert "Containerized Candlepin destination is ready" \
            in proc.stdout

    def test_no_content_probe_in_the_source(self):
        # source-level pin (grep-able): prepare-candlepin.sh must
        # not reference the repo container or its GPG-key artifact
        # at all -- the run-#7 follow-up removed the container, and
        # a reintroduced content probe would target a port that is
        # dead by design
        text = PREPARE.read_text()
        assert "RPM-GPG-KEY" not in text, \
            "prepare-candlepin.sh still probes a content endpoint"
        assert "candlepin-repo" not in text, \
            "prepare-candlepin.sh still references the repo container"
        assert "VIRTWHO_CP_REPO_IMAGE" not in text, \
            "the removed repo-image knob is back"

    def test_auth_drift_skips_loudly(self, stubbed):
        # their e6b2b16e0 class: the baked account no longer matches
        # the image's users -> 401 -> loud skip naming the drift
        proc = run_prepare(stubbed, env={"FAKE_CURL_OWNERS_CODE": "401"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "test-data contract drifted" in proc.stderr
        assert "did not authenticate" in proc.stderr
        assert "HTTP 401" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()

    def test_missing_org_skips_loudly(self, stubbed):
        # the baked org vanished from (or is invisible to) the
        # account -- the rhsm-qe name-drift class
        proc = run_prepare(stubbed, env={
            "FAKE_CURL_OWNERS_BODY":
                '{"key":"admin",'
                '"contentAccessModeList":"entitlement,org_environment"}'})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "is not visible to the synthetic test account" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()

    def test_missing_sca_mode_skips_loudly(self, stubbed):
        # snowwhite lost org_environment -> the SCA test would fail
        # far from the cause
        proc = run_prepare(stubbed, env={
            "FAKE_CURL_OWNERS_BODY":
                '{"key":"snowwhite",'
                '"contentAccessModeList":"entitlement"}'})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "no longer supports" in proc.stderr
        assert "org_environment" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()

    def test_missing_hypervisor_capability_skips_loudly(self, stubbed):
        # /status stopped advertising the hypervisor capabilities the
        # phase-0 spike verified -> virt-who's check-in surface is gone
        proc = run_prepare(stubbed, env={
            "FAKE_CURL_STATUS_BODY":
                '{"managerCapabilities":[{"name":"cores"}]}'})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "hypervisor capability" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()


class TestScaActivation:
    """The run-#6 register gap (build #180): RHEL-10's
    subscription-manager gates username/password registration on the
    org's ACTIVE contentAccessMode, while the contract probe only
    proved the LIST contains org_environment -- the probe-vs-register
    asymmetry. prepare now ACTIVATES SCA on the baked org (rhsm-qe's
    setContentAccesModeBeforeSuite shape: a PUT /owners/{org} with
    the tier's register credentials, verified live to hold the
    permission) and STRICTLY re-verifies the ACTIVE mode with a
    fresh org read before the marker."""

    def test_sca_set_put_fires_off_argv(self, stubbed):
        # the PUT fires with the right shape: -X PUT to the baked
        # org, the body setting org_environment, the credential on
        # curl's stdin config stream (never the command line) and
        # the bypass/bounds of every pod-facing curl
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        curl_log = (stubbed.sandbox / "curl.log").read_text()
        put_lines = [line for line in curl_log.splitlines()
                     if "-X PUT" in line and "/owners" in line]
        assert put_lines, "the SCA-activation PUT never fired"
        assert len(put_lines) == 1, \
            "more than one SCA-activation PUT fired"
        assert "org_environment" in put_lines[0], \
            "the PUT body does not set org_environment"
        assert " -K - " in put_lines[0], \
            "the PUT credential did not ride the stdin config stream"
        assert " -u " not in put_lines[0], \
            "the PUT credential leaked onto the command line"
        assert "Activated Simple Content Access" in proc.stdout
        assert (stubbed.install_dir /
                ".virtwho-candlepin-ready").exists()

    def test_sca_put_not_reached_when_contract_probe_skips(self, stubbed):
        # ordering: the SCA-activation step runs only AFTER the
        # contract probe passed -- an auth drift (401 on the FIRST
        # org read) must skip at the probe with NO PUT fired (the
        # step never touches a destination that already failed the
        # contract)
        proc = run_prepare(stubbed, env={"FAKE_CURL_OWNERS_CODE": "401"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "did not authenticate" in proc.stderr
        curl_log = (stubbed.sandbox / "curl.log").read_text()
        assert not any("-X PUT" in line for line in curl_log.splitlines()), \
            "the SCA-activation PUT fired although the contract probe failed"

    def test_sca_put_payload_is_exactly_the_mode_set(self, stubbed):
        # the PUT body sets exactly contentAccessMode=org_environment
        # -- a typo'd or wrong mode would silently leave the org
        # un-registerable (the #180 class, one edit away)
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        curl_log = (stubbed.sandbox / "curl.log").read_text()
        put_lines = [line for line in curl_log.splitlines()
                     if "-X PUT" in line and "/owners" in line]
        assert put_lines, "the SCA-activation PUT never fired"
        assert '--data {"contentAccessMode":"org_environment"}' \
            in put_lines[0], \
            "the PUT payload is not exactly the org_environment mode set"

    def test_sca_put_failure_skips_loudly(self, stubbed):
        # the PUT is refused (e.g. the account lost the permission on
        # an image refresh): loud skip naming the SCA switch, never a
        # marker, and the deployed pod comes down (the OPS-02 rule)
        proc = run_prepare(stubbed, env={"FAKE_CURL_PUT_CODE": "403"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "could not be switched to Simple Content Access" \
            in proc.stderr
        assert "HTTP 403" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()
        log = (stubbed.sandbox / "podman.log").read_text()
        assert "play kube --down" in log, \
            "the SCA-put failure path orphaned the pod"

    def test_active_mode_not_sca_after_set_skips_loudly(self, stubbed):
        # the asymmetry class itself: the PUT answered 200 but the
        # strict re-read shows the ACTIVE mode is still entitlement
        # (the contains-vs-active gap that caused #180's register
        # rejections) -> loud skip naming the ACTIVE mode, no marker
        proc = run_prepare(stubbed, env={
            "FAKE_CURL_SCA_VERIFY_BODY": STUB_OWNERS_BODY})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "could not be switched to Simple Content Access" \
            in proc.stderr
        assert "active content access mode is" in proc.stderr
        assert "entitlement" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()

    def test_sca_verify_read_failure_skips_loudly(self, stubbed):
        # the strict re-read itself fails (connection/API error
        # after a successful PUT): the activation is UNPROVEN, so the
        # destination must not be declared ready
        proc = run_prepare(stubbed, env={"FAKE_CURL_SCA_VERIFY_CODE": "500"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "could not be switched to Simple Content Access" \
            in proc.stderr
        assert "re-reading the org" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()


class TestCaPathFallback:
    """rhsm-qe LESSON (dd285006a): the upstream CA file was renamed at
    candlepin 4.8.0; both name generations must keep working."""

    def test_renamed_ca_falls_back(self, stubbed):
        # the bundle name is gone from the image, the pre-4.8.0 name
        # remains: the deploy must succeed via the fallback
        proc = run_prepare(stubbed,
                           env={"FAKE_PODMAN_CA_FILES": "candlepin-ca.crt"})
        assert proc.returncode == 0, proc.stderr
        assert (stubbed.install_dir /
                ".virtwho-candlepin-ready").exists()
        log = (stubbed.sandbox / "podman.log").read_text()
        assert "candlepin-ca-bundle.crt" in log, \
            "the current bundle name was not tried first"
        assert "candlepin-ca.crt" in log, \
            "the pre-4.8.0 name was not tried as a fallback"
        # the installed anchor name is ours, independent of the
        # in-container source name
        ca = (stubbed.sandbox / "rhsm-ca" / "candlepin-ca-bundle.pem")
        assert ca.read_text() == "FAKE candlepin CA\n"

    def test_missing_ca_names_skip_loudly(self, stubbed):
        # neither name exists (an unknown future rename): a loud skip
        # naming both probed paths, never a marker
        proc = run_prepare(stubbed, env={"FAKE_PODMAN_CA_FILES": ""})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "could not copy the candlepin CA" in proc.stderr
        assert "candlepin-ca-bundle.crt" in proc.stderr
        assert "candlepin-ca.crt" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()
        # review OPS-02: the pod was already deployed at this point;
        # the failure path must tear it down itself instead of
        # orphaning it until the finish step
        log = (stubbed.sandbox / "podman.log").read_text()
        assert "play kube --down" in log, \
            "the CA-copy failure path orphaned the pod"

    def test_tls_verify_failure_tears_the_pod_down(self, stubbed):
        # review OPS-02, the symmetric path: the final TLS-verified
        # curl fails after the CA install -> loud skip, no marker, and
        # the deployed pod comes down (not orphaned until finish)
        proc = run_prepare(stubbed, env={"FAKE_CURL_EXIT_CODE": "1"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "failed TLS/hostname verification" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()
        log = (stubbed.sandbox / "podman.log").read_text()
        assert "play kube --down" in log, \
            "the TLS-verify failure path orphaned the pod"


class TestBootcBuildContextGuard:
    """Review OPS-01: a prepare phase without systemd (the bootc
    Containerfile RUN layer) must skip the deploy instead of pulling
    ~1-1.5 GB of dead images into the image layer."""

    def test_no_systemd_skips_loudly(self, stubbed):
        proc = run_prepare(stubbed, env={"FAKE_SYSTEMCTL_STATE": "offline"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "systemd is not running" in proc.stderr
        assert "will SKIP" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()
        assert not (stubbed.sandbox / "podman.log").exists(), \
            "images were pulled although systemd is not running"

    def test_container_build_state_answer_skips(self, stubbed):
        # the literal Containerfile-RUN answer class: systemctl
        # errors with no state line at all
        proc = run_prepare(stubbed, env={"FAKE_SYSTEMCTL_STATE": ""})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "systemd is not running" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()

    def test_degraded_guest_still_deploys(self, stubbed):
        # the false-red protection: `systemctl is-system-running`
        # exits 1 for a degraded live guest too, and such a guest
        # must still get its destination (the vacuous-green guard
        # would fail the run on a missing marker otherwise)
        proc = run_prepare(stubbed, env={"FAKE_SYSTEMCTL_STATE": "degraded"})
        assert proc.returncode == 0, proc.stderr
        assert (stubbed.install_dir /
                ".virtwho-candlepin-ready").exists()


class TestPullBounded:
    """Review EM-03: every podman pull is bounded by timeout(1) -- a
    stalled pull counts as a failed attempt and feeds the skip path,
    never a hung prepare (the CCT-2222 class one layer down)."""

    def test_every_pull_is_bounded(self, stubbed):
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        log = (stubbed.sandbox / "timeout.log").read_text()
        for image in yaml_images():
            assert f"300 podman pull {image}" in log, \
                f"the pull of {image} is not bounded by timeout(1)"

    def test_pull_timeout_knob_is_honored(self, stubbed):
        proc = run_prepare(stubbed,
                           env={"VIRTWHO_CANDLEPIN_PULL_TIMEOUT": "7"})
        assert proc.returncode == 0, proc.stderr
        log = (stubbed.sandbox / "timeout.log").read_text()
        assert log.splitlines()[0].startswith("7 podman pull "), \
            "VIRTWHO_CANDLEPIN_PULL_TIMEOUT did not bound the pulls"

    def test_stalled_pull_counts_as_failed_attempt(self, stubbed):
        # the timeout firing (exit 124) must behave exactly like a
        # failed pull: three attempts, then the loud skip, no marker
        proc = run_prepare(stubbed, env={"FAKE_TIMEOUT_FAIL": "1"})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "could not be pulled" in proc.stderr
        assert "per-attempt timeout" in proc.stderr
        assert not (stubbed.install_dir /
                    ".virtwho-candlepin-ready").exists()
        log = (stubbed.sandbox / "podman.log")
        assert not log.exists() or "play kube" not in log.read_text(), \
            "a stalled pull must not reach the deploy"


class TestUpdateCaTrustGuard:
    """Review QA-03: update-ca-trust was the one external command
    without a guard -- on a minimal guest its exit 127 would violate
    the script's own skip-never-hard-fail contract."""

    def test_missing_update_ca_trust_skips_loudly(self, sandbox):
        # a PATH with the deploy stubs but WITHOUT update-ca-trust:
        # returncode 0, a WARNING naming the tool, no marker, and the
        # already-deployed pod torn down (same shape as the
        # missing-podman test)
        bin_dir = sandbox / "stub-bin"
        bin_dir.mkdir()
        write_executable(bin_dir / "podman", PODMAN_STUB)
        write_executable(bin_dir / "curl", CURL_STUB)
        write_executable(bin_dir / "install", INSTALL_STUB)
        write_executable(bin_dir / "systemctl", SYSTEMCTL_STUB)
        for name in ("bash", "rm", "tr", "dirname", "grep", "sed",
                     "mktemp", "mkdir", "sleep", "touch", "ln",
                     "timeout", "python3"):
            target = Path("/usr/bin") / name
            if target.exists():
                os.symlink(target, bin_dir / name)
        # NO update-ca-trust on the PATH, by construction
        install_dir = sandbox / "install"
        hosts = sandbox / "hosts"
        hosts.touch()
        proc = run(["bash", PREPARE], env={
            "PATH": str(bin_dir),
            "FAKE_PODMAN_LOG": str(sandbox / "podman.log"),
            "FAKE_CURL_LOG": str(sandbox / "curl.log"),
            "FAKE_TIMEOUT_LOG": str(sandbox / "timeout.log"),
            "FAKE_SYSTEMCTL_STATE": "running",
            "VIRTWHO_PREPARE_INSTALL_DIR": str(install_dir),
            "VIRTWHO_CANDLEPIN_HOSTS_FILE": str(hosts),
            "VIRTWHO_CANDLEPIN_CA_DIR": str(sandbox / "rhsm-ca"),
            "VIRTWHO_CANDLEPIN_ANCHOR_DIR": str(sandbox / "anchors"),
            "VIRTWHO_CANDLEPIN_TIMEOUT": "5",
            "REGISTER": "rhsm"},
            unset=("VIRTWHO_DESTINATION",))
        assert proc.returncode == 0, proc.stderr
        assert "update-ca-trust is not available" in proc.stderr
        assert "will SKIP" in proc.stderr
        assert not (install_dir / ".virtwho-candlepin-ready").exists()
        log = (sandbox / "podman.log").read_text()
        assert "play kube --down" in log, \
            "the update-ca-trust failure path orphaned the pod"


class TestPinDriftGuard:
    def test_script_defaults_match_the_vendored_yaml(self):
        # the digest pins are single-sourced in the vendored
        # candlepin-pod.yaml; the script's DEFAULT_*_IMAGE literals
        # must mirror them exactly or an env override would sed the
        # wrong ref
        text = PREPARE.read_text()
        defaults = re.findall(
            r'^DEFAULT_(APP|DB)_IMAGE="(\S+)"', text, re.MULTILINE)
        assert len(defaults) == 2, \
            "prepare-candlepin.sh lost one of its DEFAULT_*_IMAGE pins"
        script_refs = {ref for _, ref in defaults}
        assert script_refs == set(yaml_images()), \
            "the script's image pins drifted from the vendored yaml"


class TestTwoContainerPod:
    """The run-#7 follow-up design: the pod is app + db only. There
    is no repo container -- virt-who tests virt-who's reporting, not
    content consumption, and the package tests' version under test
    comes from TEST_RPMS or the compose (never the destination's
    content repo). The tier's [rhsm] baseurl stays pointed at the
    deliberately-unbound localhost:8080: content access stays local
    (no CDN fallback, no external egress) and fails bounded."""

    def test_the_pod_manifest_has_no_repo_container(self):
        text = POD_YAML.read_text()
        assert "candlepin-repo" not in text, \
            "the pod manifest still deploys a repo container"
        assert "containerPort: 8080" not in text, \
            "the pod manifest still binds the content port"
        assert "hostPort: 8080" not in text, \
            "the pod manifest still publishes the content port"

    def test_the_pod_is_exactly_two_images(self):
        images = yaml_images()
        assert len(images) == 2, \
            f"the pod should be app + db (2 images), got {images}"
        assert any("candlepin-app" in i for i in images)
        assert any("candlepin-db" in i for i in images)

    def test_only_two_pulls_happen(self, stubbed):
        # behavioral: the deploy pulls exactly the two images of the
        # vendored manifest (the bonus of the removal: one less ghcr
        # pull exposed to the concurrent-pull stalls of run #7)
        proc = run_prepare(stubbed)
        assert proc.returncode == 0, proc.stderr
        log = (stubbed.sandbox / "podman.log").read_text()
        pulls = [line for line in log.splitlines()
                 if line.startswith("pull ")]
        assert len(pulls) == 2, \
            f"expected exactly 2 image pulls, got {pulls}"


class TestTeardown:
    @pytest.fixture
    def cleanup_sandbox(self, sandbox):
        """A tree with the marker file, swept by the REAL
        cleanup-secrets.sh with a stub podman on PATH."""
        bin_dir = sandbox / "bin"
        bin_dir.mkdir()
        write_executable(bin_dir / "podman", PODMAN_STUB)
        tree = sandbox / "tree"
        tree.mkdir()
        (tree / ".virtwho-candlepin-ready").touch()
        (tree / ".virtwho-ini-generated").touch()
        env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "FAKE_PODMAN_LOG": str(sandbox / "podman.log"),
            "VIRTWHO_CLEANUP_SHM_DIR": str(sandbox / "shm"),
            "VIRTWHO_CLEANUP_SSH_KEY": str(sandbox / "shm" / "key"),
            "VIRTWHO_CLEANUP_SSH_CONFIG": str(sandbox / "ssh-config"),
            "VIRTWHO_CLEANUP_VIRTWHO_D_DIR": str(sandbox / "etc-d"),
            "VIRTWHO_CLEANUP_TMP_DIR": str(sandbox / "tmp"),
            "VIRTWHO_CLEANUP_TREE_DIRS": str(tree),
            "VIRTWHO_CLEANUP_KUBECONFIGS": str(sandbox / "no-kubeconfig"),
            "VIRTWHO_KUBECONFIG_ROOT": str(sandbox / "root"),
            "VIRTWHO_CLEANUP_POD_YAML": str(POD_YAML),
        }
        ns = type("CleanupSandbox", (), {})()
        ns.sandbox = sandbox
        ns.env = env
        ns.tree = tree
        return ns

    def _run_cleanup(self, cleanup):
        proc = run(["bash", CLEANUP], env=cleanup.env)
        assert proc.returncode == 0, proc.stderr
        return proc

    def test_teardown_runs_play_kube_down(self, cleanup_sandbox):
        self._run_cleanup(cleanup_sandbox)
        log = (cleanup_sandbox.sandbox / "podman.log").read_text()
        assert f"play kube --down {POD_YAML}" in log, \
            "the candlepin pod was not torn down by the finish step"
        # the marker is non-secret bookkeeping: removed with the
        # other prepare-phase files
        assert not (cleanup_sandbox.tree /
                    ".virtwho-candlepin-ready").exists()

    def test_teardown_is_idempotent(self, cleanup_sandbox):
        # a second finish run (e.g. a retried plan) finds no pod and
        # must still exit 0
        self._run_cleanup(cleanup_sandbox)
        self._run_cleanup(cleanup_sandbox)
        log = (cleanup_sandbox.sandbox / "podman.log").read_text()
        assert log.count("play kube --down") == 2, \
            "the teardown was not invoked on the second run"

    def test_teardown_shares_the_prepare_pod_yaml_knob(self,
                                                       cleanup_sandbox):
        # review DEV-07: VIRTWHO_CANDLEPIN_POD_YAML is the ONE knob
        # both sides resolve the pod manifest through -- a deploy
        # from a sandbox manifest must be torn down by the same
        # manifest without setting a second, drift-prone
        # teardown-only variable
        shared_yaml = cleanup_sandbox.sandbox / "shared-candlepin.yaml"
        shared_yaml.write_text(POD_YAML.read_text())
        env = dict(cleanup_sandbox.env)
        env.pop("VIRTWHO_CLEANUP_POD_YAML")
        env["VIRTWHO_CANDLEPIN_POD_YAML"] = str(shared_yaml)
        proc = run(["bash", CLEANUP], env=env)
        assert proc.returncode == 0, proc.stderr
        log = (cleanup_sandbox.sandbox / "podman.log").read_text()
        assert f"play kube --down {shared_yaml}" in log, \
            "the teardown did not resolve the pod manifest through " \
            "the shared VIRTWHO_CANDLEPIN_POD_YAML knob"
