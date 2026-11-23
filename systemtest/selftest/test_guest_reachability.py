"""Guest-reachability skip self-tests (CCT-3155).

prepare-candlepin.sh configures ONLY the pod host: the destination
name resolves there via /etc/hosts and the pod CA is trusted there.
A remote guest registering against the same serverurl (the sm_guest
flow -- the gating test_default.py tests and the upgrade suite) has
neither, and a kubevirt cluster guest may have no egress route at
all. The tests SKIP loudly when a probe FROM the guest cannot reach
the destination, until trust is distributed to routable guests (the
documented follow-up).

The probe helpers live in the leaf module virtwho/destination.py
(loaded here by file path -- importing the full package would
read/write the guest-side virtwho.ini at its fixed path); the
tests/conftest.py wiring cannot be imported for the same reason and
is pinned by source-level contract checks instead.

Run: python -m pytest systemtest/selftest/ -v
"""

import importlib.util

import pytest
from _utils import REPO_ROOT

DESTINATION_PY = REPO_ROOT / "virtwho" / "destination.py"
CONFTEST = REPO_ROOT / "tests" / "conftest.py"


def load_destination_module():
    """Load virtwho/destination.py by file path, bypassing the
    package __init__ (hermetic: no ini is read or written)."""
    spec = importlib.util.spec_from_file_location(
        "virtwho_destination_under_test", DESTINATION_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestStatusUrl:
    def test_container_shape(self):
        dest = load_destination_module()
        assert dest.status_url("candlepin", "8443", "/candlepin") \
            == "https://candlepin:8443/candlepin/status"

    def test_stage_defaults_shape(self):
        dest = load_destination_module()
        assert dest.status_url("subscription.example.com", "", "") \
            == "https://subscription.example.com:443/subscription/status"


class TestGuestProbeCommand:
    def test_bounded_on_both_ends(self):
        # --connect-timeout bounds only the TCP connect; a
        # bound-but-slow port must not hang the probe (and thereby
        # the test session) forever
        dest = load_destination_module()
        cmd = dest.guest_probe_command(
            "https://candlepin:8443/candlepin/status")
        assert "--connect-timeout 5" in cmd
        assert "--max-time 10" in cmd

    def test_default_probe_verifies_tls(self):
        # the FIRST-stage probe runs WITHOUT -k -- the exact TLS
        # shape subscription-manager uses; the register's connection
        # must verify, not just route. The -w %{http_code} payload
        # feeds the 200 check.
        dest = load_destination_module()
        cmd = dest.guest_probe_command(
            "https://candlepin:8443/candlepin/status")
        assert " -k " not in cmd
        assert "-w '%{http_code}'" in cmd
        assert cmd.endswith("https://candlepin:8443/candlepin/status")

    def test_second_stage_probe_is_insecure(self):
        # the retry stage (run only after the verified probe fails)
        # adds -k: it exists to CLASSIFY the failure as a trust gap
        # rather than a routing one
        dest = load_destination_module()
        cmd = dest.guest_probe_command(
            "https://candlepin:8443/candlepin/status", insecure=True)
        assert " -k " in cmd
        assert "--connect-timeout 5" in cmd
        assert "--max-time 10" in cmd

    def test_url_is_shell_quoted(self):
        # the URL is assembled from ini values (downloaded, untrusted
        # input) into a command string that runs on the guest -- a
        # crafted value must stay ONE argument
        dest = load_destination_module()
        cmd = dest.guest_probe_command("https://h/x;rm -rf /")
        assert "'https://h/x;rm -rf /'" in cmd
        # a benign URL stays unquoted (readable command log lines)
        cmd = dest.guest_probe_command("https://candlepin:8443/x")
        assert cmd.endswith("https://candlepin:8443/x")

    def test_timeouts_are_parameters(self):
        dest = load_destination_module()
        cmd = dest.guest_probe_command("https://example.invalid/status",
                                       connect_timeout=3, max_time=7)
        assert "--connect-timeout 3" in cmd
        assert "--max-time 7" in cmd

    def test_non_int_timeouts_are_rejected(self):
        # a string timeout would silently build a broken curl
        # invocation; reject it at construction time
        dest = load_destination_module()
        for bad in ("5", 5.5, None, True):
            with pytest.raises(TypeError):
                dest.guest_probe_command("https://example.invalid/status",
                                         connect_timeout=bad)
            with pytest.raises(TypeError):
                dest.guest_probe_command("https://example.invalid/status",
                                         max_time=bad)

    def test_bypass_proxy_scopes_to_the_destination_host(self):
        # the build-#179 class, guest-side: the guest's environment
        # may carry the pipeline's HTTPS_PROXY, and the probe target
        # is the per-run pod -- the bypass must cover the DESTINATION
        # HOST ONLY (the guest keeps the proxy for its other
        # egress), and must be off by default so a probe of an
        # external destination (the stage tier, which REQUIRES the
        # proxy) is never silently bypassed
        dest = load_destination_module()
        cmd = dest.guest_probe_command(
            "https://candlepin:8443/candlepin/status", bypass_proxy=True)
        assert "--noproxy candlepin" in cmd
        cmd = dest.guest_probe_command(
            "https://candlepin:8443/candlepin/status")
        assert "--noproxy" not in cmd

    def test_bypass_proxy_rejects_a_hostless_url(self):
        # construction-time rejection, like the int-timeout rule: a
        # bypass on a URL without a host would silently build a
        # broken curl invocation
        dest = load_destination_module()
        with pytest.raises(ValueError):
            dest.guest_probe_command("not-a-url", bypass_proxy=True)


class TestProbeReachable:
    def test_http_200_means_reachable(self):
        dest = load_destination_module()
        assert dest.probe_reachable(0, "200") is True
        assert dest.probe_reachable(0, " 200\n") is True

    def test_anything_else_means_unreachable(self):
        dest = load_destination_module()
        # an answering-but-warming server (their b76aecba7 class), a
        # name-resolution failure, a routed-but-wrong server
        assert dest.probe_reachable(0, "503") is False
        assert dest.probe_reachable(0, "000") is False
        assert dest.probe_reachable(6, "000") is False
        assert dest.probe_reachable(1, "") is False


class TestProbeOutcome:
    """Review DEV-03: the two-stage classification -- a verified 200
    is fully usable; an insecure-only 200 is a TRUST gap with its own
    skip reason; anything else is unreachable."""

    def test_verified_200_is_trusted(self):
        dest = load_destination_module()
        assert dest.probe_outcome((0, "200"), (0, "200")) \
            == dest.PROBE_TRUSTED

    def test_insecure_only_200_is_an_untrusted_ca(self):
        # curl exit 60 = peer certificate verification failure
        dest = load_destination_module()
        assert dest.probe_outcome((60, "000"), (0, "200")) \
            == dest.PROBE_UNTRUSTED_CA

    def test_both_failing_is_unreachable(self):
        # a name-resolution failure fails both stages identically
        dest = load_destination_module()
        assert dest.probe_outcome((6, "000"), (6, "000")) \
            == dest.PROBE_UNREACHABLE

    def test_unprobed_second_stage_cannot_fake_trusted(self):
        # the conftest's placeholder for the un-run second stage must
        # never classify as reachable on its own
        dest = load_destination_module()
        assert dest.probe_outcome((6, "000"), (1, "")) \
            == dest.PROBE_UNREACHABLE


class TestConftestWiring:
    """Source-level pins: sm_guest must probe from the guest and skip
    loudly on failure, gated exactly like candlepin_destination_absent
    (an inline copy that drifted would compile fine and silently
    re-break the kubevirt x container cell)."""

    def test_sm_guest_probes_and_skips_loudly(self):
        text = CONFTEST.read_text()
        assert "def candlepin_guest_unreachable(sm):" in text
        # both stages carry the destination-host proxy bypass (the
        # build-#179 class, guest-side)
        assert "guest_probe_command(url, bypass_proxy=True)" in text
        assert "probe_reachable(*verified)" in text
        assert "pytest.skip(unreachable)" in text

    def test_the_probe_is_two_stage(self):
        # the verified (no -k) probe first, the insecure retry only
        # on its failure, and the outcome classified
        text = CONFTEST.read_text()
        assert "guest_probe_command(url, insecure=True, " \
            "bypass_proxy=True)" in text
        assert "probe_outcome(verified, insecure)" in text

    def test_probe_gated_like_the_destination_absent_skip(self):
        text = CONFTEST.read_text()
        # both skip helpers must gate on REGISTER and the ini's
        # destination record -- the probe must never fire on the
        # stage tier or satellite cells
        assert text.count('if REGISTER != "rhsm":') == 2
        assert text.count(
            'getattr(config.job, "destination", "") != "container"') == 2

    def test_skip_reasons_name_both_limitations(self):
        # the two classes must be distinguishable in the console:
        # the trust gap and the routing gap each get their own reason
        text = CONFTEST.read_text()
        assert "its CA is not trusted on the guest" in text
        assert "not reachable from the guest" in text
        assert "documented follow-up" in text
