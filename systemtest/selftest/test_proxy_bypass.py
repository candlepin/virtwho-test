"""Proxy-bypass wiring self-tests (the build-#179 class, CCT-3155).

The tmt environment exports HTTPS_PROXY to every command and sets
no no_proxy anywhere. The pipeline's image pulls RIDE the proxy
(proven in run #5: squid reaches the public registries), but every
POD-FACING connection must bypass it, because the proxy can never
route back to the test guest's own pod ports. In run #5 (build
#179) the un-bypassed readiness probe read connection-level 000 for
the full 180 s window while the pod was fully healthy (Tomcat up in
32 s, proven by the triage pod logs) -- the defect this round fixes
at every surface at once:

  * prepare-candlepin.sh: every curl carries --noproxy '*' (all of
    them are pod-facing; pinned in test_prepare_candlepin.py,
    including a behavioral hostile-proxy case with the REAL curl)
  * run-tests.sh: in container mode the suite's process environment
    gains no_proxy/NO_PROXY for the pod hosts before pytest -- the
    RHSM class's requests calls honor the env vars -- pinned here
  * configure-proxy.sh: in container mode the rhsm.conf proxy is
    NOT configured (subscription-manager's guest-side commands run
    through ssh with rhsm.conf as their only proxy source -- they do
    not inherit the pytest environment, so the no_proxy export
    cannot reach them) -- pinned here BEHAVIORALLY, against the real
    script with a stubbed subscription-manager
  * prepare-kubevirt.sh: the same tier gate on the kubevirt guest
    VM's proxy configuration -- pinned here at the source level
  * tests/hypervisor/test_default.py: the guestids curl bypasses
    the proxy for the destination host in container mode -- pinned
    here at the source level

The proxy itself is KEPT for external egress everywhere else: the
stage tier's subscription-manager proxy configuration is unchanged,
and none of the bypass lists may ever contain an external host (the
stage server requires the proxy -- the preprod lockdown traversal).

Run: python -m pytest systemtest/selftest/ -v
"""

import os

import pytest
from _utils import REPO_ROOT, SCRIPTS_DIR, run, write_executable

RUN_TESTS = SCRIPTS_DIR / "run-tests.sh"
CONFIGURE_PROXY = SCRIPTS_DIR / "configure-proxy.sh"
PREPARE_KUBEVIRT = SCRIPTS_DIR / "prepare-kubevirt.sh"
TEST_DEFAULT = REPO_ROOT / "tests" / "hypervisor" / "test_default.py"

# A TEST-NET-1 dummy (RFC 5737): the stubbed subscription-manager
# must be seen configuring exactly this host:port, proving the
# parse-and-pass behavior without any real proxy identifier.
DUMMY_PROXY = "http://192.0.2.10:3128"

SUBMAN_STUB = """\
#!/bin/bash
# Fake subscription-manager: record every invocation, succeed.
printf '%s\\n' "$*" >> "${FAKE_SUBMAN_LOG:?}"
exit 0
"""

# Silent no-op stand-ins for the two tail commands that touch the
# real filesystem (mkdir /backup, cp of /etc/rhsm/rhsm.conf): the
# selftest must stay hermetic -- no host mutations. Their absence of
# effect is covered by the `|| true` guards in the real script; the
# tail's execution itself is proven by the recorded unregister/clean
# invocations of the subscription-manager stub.
MKDIR_STUB = """\
#!/bin/bash
exit 0
"""

CP_STUB = """\
#!/bin/bash
exit 0
"""


class TestRunTestsProxyBypass:
    """run-tests.sh (which cannot run hermetically -- it restarts
    sshd and needs a provisioned guest) is pinned at the source
    level, the same approach the other run-tests.sh contracts
    use."""

    def test_container_mode_appends_the_pod_hosts_before_pytest(self):
        text = RUN_TESTS.read_text()
        # gated on the tier read from the INI (the single source of
        # the tier record -- the same value assert-candlepin-tier.sh
        # and tests/conftest.py gate on), never the environment
        assert 'if [ "$JOB_DESTINATION" = "container" ]; then' in text
        assert 'cfg.get("job", "destination"' in text
        # the bypass list is EXACTLY the pod hosts (both spellings
        # exported, existing values preserved) -- the stage server
        # must never appear in it
        assert 'POD_HOSTS="localhost,127.0.0.1,candlepin"' in text
        assert 'no_proxy="${no_proxy:+${no_proxy},}${POD_HOSTS}"' in text
        assert 'NO_PROXY="${NO_PROXY:+${NO_PROXY},}${POD_HOSTS}"' in text
        assert "export no_proxy NO_PROXY" in text
        # BEFORE pytest, so every suite connection inherits it
        assert text.index("POD_HOSTS=") < text.index("pytest tests/"), \
            "the pod-host bypass must be exported before pytest starts"


class TestConfigureProxyTierGate:
    """configure-proxy.sh writes the proxy into rhsm.conf for the
    STAGE tier only. In container mode subscription-manager must
    reach the per-run pod directly: rhsm.conf is its only proxy
    source (its commands run through ssh, not this process's
    environment), and a proxy can never resolve or route the
    guest's own pod ports -- configuring it would deterministically
    break every registration of the container tier (the #179 class,
    one layer up from the readiness probe)."""

    @pytest.fixture
    def proxy_sandbox(self, sandbox):
        bin_dir = sandbox / "bin"
        bin_dir.mkdir()
        write_executable(bin_dir / "subscription-manager", SUBMAN_STUB)
        write_executable(bin_dir / "mkdir", MKDIR_STUB)
        write_executable(bin_dir / "cp", CP_STUB)
        env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "FAKE_SUBMAN_LOG": str(sandbox / "subman.log"),
            "REGISTER": "rhsm",
            "HTTPS_PROXY": DUMMY_PROXY,
        }
        ns = type("ProxySandbox", (), {})()
        ns.sandbox = sandbox
        ns.env = env
        ns.log = sandbox / "subman.log"
        return ns

    def test_container_mode_skips_the_rhsm_conf_proxy(self, proxy_sandbox):
        # VIRTWHO_DESTINATION unset -> the generator's default
        # (container) applies here too
        proc = run(["bash", CONFIGURE_PROXY], env=proxy_sandbox.env)
        assert proc.returncode == 0, proc.stderr
        assert "SKIP: VIRTWHO_DESTINATION=container" in proc.stdout
        log = proxy_sandbox.log.read_text().splitlines()
        assert not any("proxy_hostname" in line for line in log), \
            "the rhsm.conf proxy was configured in container mode"
        # the unregister/clean tail is unchanged (stage-tier
        # behavior; the backup stand-ins keep the run hermetic)
        assert any("unregister" in line for line in log)
        assert any("clean" in line for line in log)

    def test_stage_mode_configures_the_proxy(self, proxy_sandbox):
        proc = run(["bash", CONFIGURE_PROXY],
                   env=dict(proxy_sandbox.env,
                            VIRTWHO_DESTINATION="stage"))
        assert proc.returncode == 0, proc.stderr
        assert "Configured rhsm.conf proxy: 192.0.2.10:3128" \
            in proc.stdout
        log = proxy_sandbox.log.read_text()
        assert "--server.proxy_hostname=192.0.2.10" in log
        assert "--server.proxy_port=3128" in log


class TestSuiteSideBypassWiring:
    """Source-level pins for the remaining suite-side surfaces (the
    kubevirt guest-VM proxy setup cannot run hermetically -- it
    sshes into a cluster guest; the guestids curl runs on a
    provisioned guest)."""

    def test_kubevirt_guest_proxy_is_tier_gated(self):
        text = PREPARE_KUBEVIRT.read_text()
        assert '"${VIRTWHO_DESTINATION:-container}" = "container"' \
            in text
        # the gate precedes (and so guards) the guest proxy
        # configuration
        assert text.index("VIRTWHO_DESTINATION:-container") \
            < text.index("--server.proxy_hostname="), \
            "the kubevirt guest proxy must be behind the tier gate"
        assert "no guest VM proxy is configured" in text

    def test_default_guestids_curl_bypasses_the_pod_host(self):
        text = TEST_DEFAULT.read_text()
        assert 'getattr(config.job, "destination", "") ' \
               '== "container"' in text
        assert "--noproxy {register_data['server']}" in text, \
            "the guestids curl lost its container-tier proxy bypass"
