"""Prefix-awareness self-tests (CCT-3155) for the three former
"/subscription" hardcode sites.

The containerized Candlepin destination serves its API under
/candlepin on port 8443; stage RHSM serves /subscription on 443.
Three sites previously hardcoded the prefix (and two omitted the
port), which silently produced zero send-counts and wrong URLs
against any non-/subscription destination:

  * virtwho/register.py -- the RHSM API base URL
  * virtwho/runner.py -- send_number()'s log-line prefix
  * tests/hypervisor/test_default.py -- the guestids curl

They now share the pure helpers of virtwho/destination.py. That
module is a deliberate leaf (no virtwho imports), so it is loaded
HERE directly by file path: importing the full package would
read/write the guest-side virtwho.ini at its fixed path
(virtwho/settings.py instantiates Configure at import time) and is
not hermetic. The three call sites themselves cannot be imported
here for the same reason -- they are pinned by source-level
contract checks instead (the same approach the wrapper-script
credential contracts use).
"""

import importlib.util

from _utils import REPO_ROOT

DESTINATION_PY = REPO_ROOT / "virtwho" / "destination.py"


def load_destination_module():
    """Load virtwho/destination.py by file path, bypassing the
    package __init__ (hermetic: no ini is read or written)."""
    spec = importlib.util.spec_from_file_location(
        "virtwho_destination_under_test", DESTINATION_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestNormalizePrefix:
    def test_empty_prefix_defaults_per_tier(self):
        dest = load_destination_module()
        assert dest.normalize_prefix("", "rhsm") == "/subscription"
        assert dest.normalize_prefix("", "rhsm_sw") == "/subscription"
        assert dest.normalize_prefix("", "satellite") == "/rhsm"
        assert dest.normalize_prefix("") == "/subscription"

    def test_configured_prefix_wins(self):
        dest = load_destination_module()
        assert dest.normalize_prefix("/candlepin") == "/candlepin"
        assert dest.normalize_prefix("/candlepin", "satellite") \
            == "/candlepin"
        assert dest.normalize_prefix("/rhsm", "satellite") == "/rhsm"

    def test_slash_shapes_are_canonicalized(self):
        # review DEV-05: the ini is hand-editable input -- a prefix
        # without the leading slash would fuse onto the port
        # (https://host:8443candlepin) and a trailing slash would
        # double up (/candlepin//status). All three shapes must
        # normalize to the same single-slash form.
        dest = load_destination_module()
        assert dest.normalize_prefix("candlepin") == "/candlepin"
        assert dest.normalize_prefix("candlepin/") == "/candlepin"
        assert dest.normalize_prefix("/candlepin/") == "/candlepin"
        assert dest.normalize_prefix(" candlepin ") == "/candlepin"

    def test_slash_only_prefix_falls_back_to_tier_default(self):
        # a value that is nothing BUT slashes (or whitespace) is
        # empty in meaning: the tier default applies, never "/"
        dest = load_destination_module()
        assert dest.normalize_prefix("/", "rhsm") == "/subscription"
        assert dest.normalize_prefix("//", "satellite") == "/rhsm"
        assert dest.normalize_prefix("  ") == "/subscription"

    def test_api_base_survives_the_shapes(self):
        # the end-to-end effect: every shape of the container prefix
        # builds the same URL (no port fusion, no double slash)
        dest = load_destination_module()
        for prefix in ("candlepin", "candlepin/", "/candlepin/",
                       " /candlepin "):
            assert dest.api_base("candlepin", "8443", prefix) \
                == "https://candlepin:8443/candlepin"


class TestNormalizePort:
    def test_empty_or_missing_defaults_to_443(self):
        dest = load_destination_module()
        assert dest.normalize_port("") == "443"
        assert dest.normalize_port(None) == "443"
        assert dest.normalize_port("   ") == "443"

    def test_configured_port_passes_through(self):
        dest = load_destination_module()
        assert dest.normalize_port("8443") == "8443"
        assert dest.normalize_port(8443) == "8443"
        assert dest.normalize_port(" 8443 ") == "8443"


class TestApiBase:
    def test_container_shape(self):
        # the spike-verified URL: host candlepin, port 8443, prefix
        # /candlepin -- exactly what virt-wo connected to
        dest = load_destination_module()
        assert dest.api_base("candlepin", "8443", "/candlepin") \
            == "https://candlepin:8443/candlepin"

    def test_stage_defaults_shape(self):
        dest = load_destination_module()
        assert dest.api_base("subscription.example.com", "", "") \
            == "https://subscription.example.com:443/subscription"

    def test_satellite_defaults_shape(self):
        dest = load_destination_module()
        assert dest.api_base("satellite.example.com", "", "",
                             "satellite") \
            == "https://satellite.example.com:443/rhsm"


class TestHardcodeSiteContracts:
    """Source-level pins: the three sites route through the helpers
    and the hardcoded literals are gone (an inline literal would
    compile fine and silently regress the container tier)."""

    def test_register_py_uses_api_base(self):
        text = (REPO_ROOT / "virtwho" / "register.py").read_text()
        assert "from virtwho.destination import api_base" in text
        assert "api_base(register.server, register.port, " \
            "register.prefix)" in text
        assert 'f"https://{register.server}/subscription"' not in text

    def test_runner_py_uses_normalize_prefix(self):
        text = (REPO_ROOT / "virtwho" / "runner.py").read_text()
        assert "from virtwho.destination import normalize_prefix" in text
        assert "normalize_prefix(" in text
        assert 'prefix = "/subscription"' not in text
        assert 'prefix = "/rhsm"' not in text

    def test_test_default_py_uses_api_base(self):
        text = (REPO_ROOT / "tests" / "hypervisor" /
                "test_default.py").read_text()
        assert "from virtwho.destination import api_base" in text
        assert "api_base(register_data['server'], " \
            "register_data['port'], register_data['prefix'])" in text
        assert "/subscription/" not in text

    def test_conftest_skip_reads_marker_and_destination(self):
        # the loud destination-absent skip: [job] destination must
        # select it and the marker file must gate it
        text = (REPO_ROOT / "tests" / "conftest.py").read_text()
        assert "candlepin_destination_absent" in text
        assert ".virtwho-candlepin-ready" in text
        assert 'destination", "") != "container"' in text
