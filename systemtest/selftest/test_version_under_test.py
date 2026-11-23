"""Version-under-test self-tests.

Owner ruling: TEST_RPMS always has precedence -- it carries manual
overrides, PR-build testing, or gated release builds. When testing a
RHEL compose, the compose's OWN virt-who version must be used. In
both cases the test environment installs the version under test
(plus test deps) BEFORE tests start, so the destination's content
repo (the container tier's pod repo) must NEVER be the source for
the package under test: once registration works through the
container tier, the host's content access switches to the pod's
repo, which serves no virt-who packages.

Pinned here:

  * the prepare-phase cache of setup-virtwho-test.sh (source level:
    the TEST_RPMS branch wins, the compose-repo fallback, the
    sidecar record) -- the script is too heavy for a hermetic
    behavioral run (git clone + pip install);
  * the sidecar's NEVRA recording (only when a real one resolves);
  * the ini plumbing (the sidecar value, the run-tests.sh merge
    override for the version-under-test trio, the virtwho package
    export);
  * the two fixed tests' source resolution (source level);
  * virtwho_install_under_test() BEHAVIORALLY: a sandboxed copy of
    the virtwho package (so its config writes stay inside the
    sandbox) plus a recording fake ssh proves the exact dnf command
    for every precedence case and the failure raise.

Every value is an RFC 2606/5737 dummy; the real TEST_RPMS URLs are
internal brew identifiers and never appear in this repository.

Run: python -m pytest systemtest/selftest/ -v
"""

import pytest
from _utils import (
    MINIMAL_INI,
    REPO_ROOT,
    SCRIPTS_DIR,
    read_ini,
    run,
    run_fake_ssh_driver,
)

SETUP = SCRIPTS_DIR / "setup-virtwho-test.sh"
RUN_TESTS = SCRIPTS_DIR / "run-tests.sh"
INSTALL_DEPS = SCRIPTS_DIR / "install-deps.sh"
TEST_INFO = REPO_ROOT / "tests" / "package" / "test_info.py"
TEST_INSTALL_UNINSTALL = (
    REPO_ROOT / "tests" / "package" / "test_install_uninstall.py"
)
BASE_PY = REPO_ROOT / "virtwho" / "base.py"
INIT_PY = REPO_ROOT / "virtwho" / "__init__.py"

# A TEST-RPM URL of the exact SHAPE the pipelines deliver (brew
# download host, virt-who nevra basename) with every identifier
# replaced by RFC 2606 dummies.
DUMMY_TEST_RPMS = (
    "https://brew.example.invalid/brewroot/work/tasks/1/1/"
    "virt-who-1.32.1-1.dummy.el10.noarch.rpm"
)
DUMMY_CACHE = "/opt/virtwho-test/virt-who-under-test.rpm"

# Runs virtwho_install_under_test() against a recording fake ssh
# inside a sandboxed copy of the virtwho package (the shared harness
# in _utils.run_fake_ssh_driver sets up the sandbox, writes the
# minimal ini and parses this protocol). argv: the tree, the
# TEST_RPMS value, the undertest cache value, and whether the fake
# rpm database reports virt-wo installed ("1") or not ("0").
HELPER_DRIVER = """\
import sys

sys.path.insert(0, sys.argv[1])
import virtwho
import virtwho.base as base


class FakeSSH:
    def __init__(self, installed):
        self.commands = []
        self.installed = installed

    def runcmd(self, cmd):
        self.commands.append(cmd)
        if self.installed:
            return 0, "virt-who-1.32.1-2.el10.noarch"
        return 1, "package virt-who is not installed"


def main():
    # the ini-plumbing read: what the module computed at import
    init_value = virtwho.VIRTWHO_UNDERTEST_RPM
    ssh = FakeSSH(installed=sys.argv[4] == "1")
    base.TEST_RPMS = sys.argv[2]
    base.VIRTWHO_UNDERTEST_RPM = sys.argv[3]
    raised = "no"
    message = ""
    try:
        base.virtwho_install_under_test(ssh)
    except base.FailException as exc:
        raised = "yes"
        message = str(exc)
    print("INIT:" + init_value)
    print("RAISED:" + raised)
    print("MESSAGE:" + message)
    for command in ssh.commands:
        print("CMD:" + command)


main()
"""


class TestUnderTestCacheWiring:
    """The prepare-phase cache: where the precedence is realized."""

    def test_the_cache_takes_test_rpms_first(self):
        # the precedence: the cache step must gate on
        # TEST_RPMS BEFORE anything else -- a flip (the compose
        # download running even in gating mode) would cache the
        # compose's virt-who while a gated build is under test
        text = SETUP.read_text()
        anchor = (
            'UNDERTTEST_CACHE="${INSTALL_DIR}/virt-who-under-test.rpm"\n'
            'if [ -n "${TEST_RPMS:-}" ]; then'
        )
        assert anchor in text, \
            "the version-under-test cache no longer takes TEST_RPMS " \
            "first (the precedence ruling)"
        # and the TEST_RPMS download must come before the compose
        # fallback inside the cache step
        assert text.index("curl -fsSL --retry 3 --retry-delay 5") \
            < text.index('dnf download --destdir="${INSTALL_DIR}" '
                         "virt-who"), \
            "the compose download no longer follows the TEST_RPMS branch"

    def test_the_sidecar_records_the_nevra_only_when_real(self):
        # the placeholder corner: a host without virt-who installed
        # (rpm -qa prints nothing) must not record a bare-name
        # placeholder -- it would clobber a correct base-ini NEVRA
        # through the merge override. The option stays absent and
        # the base value stands.
        text = SETUP.read_text()
        assert "VIRTWHO_NEVRA=${VIRTWHO_NEVRA:-virt-who}" not in text, \
            "the setup script records a placeholder NEVRA again"
        assert 'if nevra:\n    cfg.set("virtwho", "package", nevra)' \
            in text, \
            "the sidecar no longer records the NEVRA conditionally"

    def test_the_ini_and_merge_plumbing(self):
        # the cache path must reach the suite: the sidecar records
        # it, run-tests.sh merges it back into the regenerated ini,
        # and the package exports it for virtwho_install_under_test
        setup_text = SETUP.read_text()
        assert 'cfg.set("virtwho", "undertest_rpm", undertest_rpm)' \
            in setup_text, "the sidecar no longer records the cache path"
        assert 'override("virtwho", "undertest_rpm")' \
            in RUN_TESTS.read_text(), \
            "run-tests.sh no longer merges the cache path into the ini"
        assert 'VIRTWHO_UNDERTEST_RPM = getattr(config.virtwho, ' \
            '"undertest_rpm", "")' in INIT_PY.read_text(), \
            "virtwho/__init__.py no longer exports the cache path"
        # the prepare-phase install itself (verified, documented):
        # install-deps.sh installs TEST_RPMS when set, else the
        # compose's virt-who -- before any test starts
        deps_text = INSTALL_DEPS.read_text()
        assert 'if [[ -n "${TEST_RPMS:-}" ]]; then' in deps_text \
            and "dnf -y install virt-who" in deps_text, \
            "install-deps.sh lost the prepare-phase install of the " \
            "version under test"


class TestPackageTestSources:
    """The two package tests read the version under test, never the
    destination's content repos (source level: they need a live
    guest to run)."""

    def test_the_arch_test_reads_the_version_under_test(self):
        # comments are stripped: the historical explanation may NAME
        # the old repoquery shape, the CODE must not use it
        text = TEST_INFO.read_text()
        code = "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith("#"))
        assert "dnf repoquery" not in code, \
            "the arch test queries the enabled repos again (the " \
            "destination's content repo serves no virt-who)"
        assert "rpm -qp --qf" in code and "rpm -q --qf" in code, \
            "the arch test no longer reads the version-under-test " \
            "RPM / the installed package"
        assert "VIRTWHO_UNDERTEST_RPM" in code, \
            "the arch test lost the version-under-test wiring"

    def test_by_dnf_reinstalls_the_version_under_test(self):
        # scope the pins to the by-dnf test's own body: the by-rpm
        # test below it keeps its own (file-based) shapes
        text = TEST_INSTALL_UNINSTALL.read_text()
        start = text.index("def test_install_uninstall_by_dnf")
        end = text.index("def test_install_uninstall_by_rpm")
        body = text[start:end]
        assert "virtwho_install_under_test(ssh_host)" in body, \
            "the by-dnf test no longer reinstalls the version " \
            "under test through the precedence helper"
        assert 'package_install(ssh_host, "virt-who")' not in body, \
            "the by-dnf test installs from the enabled repos again"
        # the by-rpm test keeps its own file-based shape
        assert 'package_install(ssh_host, "virt-who", rpm=rpm_path)' \
            in text, "the by-rpm test lost its rpm-file install shape"


class TestInstallUnderTestHelper:
    """virtwho_install_under_test(), behaviorally: a sandboxed copy
    of the virtwho package (its Configure writes the ini inside the
    sandbox) and a recording fake ssh prove the exact dnf command
    of every precedence case."""

    @pytest.fixture
    def helper(self, sandbox):
        """A one-call runner: runs the install helper's recording
        driver against a sandboxed copy of the virtwho package,
        optionally with a cache value in the ini to prove the
        import-time plumbing (the shared _utils.run_fake_ssh_driver
        does the sandbox setup and the output-protocol parsing)."""
        def _run(*, ini=MINIMAL_INI, test_rpms="", undertest="",
                 installed="1"):
            return run_fake_ssh_driver(
                sandbox, HELPER_DRIVER,
                [test_rpms, undertest, installed], ini=ini)
        return _run

    def test_test_rpms_wins_over_the_cache(self, helper):
        # the ruling's letter: when TEST_RPMS is set it WINS, even
        # over a cached rpm -- and the install carries
        # --disablerepo='*' so the destination's (broken) content
        # repo cannot even break the metadata refresh
        result = helper(test_rpms=DUMMY_TEST_RPMS,
                        undertest=DUMMY_CACHE)
        assert result["raised"] == "no"
        install = result["cmds"][0]
        assert DUMMY_TEST_RPMS in install, \
            f"TEST_RPMS did not win the install: {install}"
        assert "--disablerepo='*'" in install and \
            "--allowerasing" in install, \
            f"the install is not repo-independent: {install}"

    def test_the_cached_compose_rpm_is_used_when_no_test_rpms(
            self, helper):
        # no TEST_RPMS: the version under test is the compose's own
        # virt-who the prepare phase cached; the ini plumbing
        # carried the path into the module at import time
        ini = MINIMAL_INI.replace(
            "undertest_rpm=", f"undertest_rpm={DUMMY_CACHE}")
        result = helper(ini=ini, undertest=DUMMY_CACHE)
        assert result["init"] == DUMMY_CACHE, \
            "the ini's undertest_rpm did not reach the module"
        install = result["cmds"][0]
        assert DUMMY_CACHE in install and \
            "--disablerepo='*'" in install, \
            f"the cached compose rpm was not used: {install}"
        assert DUMMY_TEST_RPMS not in install

    def test_the_enabled_repos_are_the_last_resort(self, helper):
        # neither TEST_RPMS nor a cache (the hand-run local-suite
        # shape): a plain repo install, deliberately WITHOUT
        # --disablerepo (the local developer's repos are the source
        # there; the tmt flow always has a cache or TEST_RPMS)
        result = helper()
        assert result["raised"] == "no"
        assert result["cmds"][0] == \
            "dnf -y install --allowerasing virt-who", \
            f"unexpected fallback install: {result['cmds'][0]}"

    def test_a_failed_install_raises(self, helper):
        # the fake rpm database reports virt-who absent after the
        # install: the helper must raise (never a silent no-op)
        result = helper(test_rpms=DUMMY_TEST_RPMS, installed="0")
        assert result["raised"] == "yes"
        assert "version under test" in result["message"], \
            f"the failure does not name the version under test: " \
            f"{result['message']}"


# --- the sidecar merge override -------------------------------------------

# The invocation line of the REAL ini-merge heredoc in run-tests.sh
# (the same behavioral-extraction pattern as the password-flow pin
# in test_generate_virtwho_ini.py: the block is pulled from the
# live script, never a drifted copy).
MERGE_MARKER = ('GUEST_ROOT_PASS="$GUEST_ROOT_PASS" python3 - '
                '/dev/shm/virtwho.ini .virtwho-computed.ini '
                "<<'PYEOF'")

# The regression input shape: a base ini whose [virtwho]
# section statically carries an OLDER compose's version-under-test
# values (the auto-services base ini is published once and lags
# the compose a run actually tests). Every identifier is an RFC
# 2606/5737 dummy.
STALE_BASE_INI = """\
[job]
hypervisor=libvirt
register=rhsm
rhel_compose=RHEL-10.0-DUMMY
rhel_compose_path=

[virtwho]
server=192.0.2.10
username=
password=
package=virt-who-1.31.28-1.el9.noarch
test_rpms=https://brew.example.invalid/old/virt-who-1.31.28-1.el9.noarch.rpm
undertest_rpm=/opt/virtwho-test/virt-who-under-test.OLD.rpm
"""

# The sidecar setup-virtwho-test.sh writes for the compose under
# test (non-empty computed values).
COMPUTED_SIDECAR = """\
[job]
rhel_compose=RHEL-10.4-DUMMY

[virtwho]
package=virt-who-1.32.1-2.el10.noarch
test_rpms=https://brew.example.invalid/new/virt-who-1.32.1-1.dummy.el10.noarch.rpm
undertest_rpm=/opt/virtwho-test/virt-who-under-test.rpm
"""

# The nightly shape: the sidecar carries the options a run without
# TEST_RPMS records as EMPTY values (computed ground truth -- they
# must CLEAR the stale base values), while the NEVRA is ABSENT (the
# setup script records it only when a real one resolves).
NIGHTLY_SIDECAR = """\
[job]
rhel_compose=

[virtwho]
test_rpms=
undertest_rpm=
"""


class TestSidecarMergeOverride:
    """The sidecar merge, behaviorally: the version-under-test trio
    (package, test_rpms, undertest_rpm) and the resolved compose
    OVERRIDE the base ini's values when the computed sidecar
    carries them -- they are ground truth about what this run
    tests, while the base ini is the statically published
    VIRTWHO_INI_URL file whose values can lag the compose actually
    under test. Presence-based: a sidecar option that exists but is
    EMPTY clears the stale base value; an option the sidecar does
    not carry at all keeps the base (the hand-run local shape, and
    the setup script's record-only-when-real rule for the NEVRA).
    The REAL merge heredoc is extracted from run-tests.sh and
    executed against dummy inis in a /dev/shm sandbox."""

    @pytest.fixture
    def merge(self, sandbox):
        """Extract the REAL merge block from run-tests.sh; return a
        one-call runner (base ini text, sidecar text) -> the parsed
        merged ini."""
        lines = RUN_TESTS.read_text().splitlines()
        starts = [i for i, line in enumerate(lines)
                  if MERGE_MARKER in line]
        assert len(starts) == 1, \
            "could not extract the ini-merge heredoc from run-tests.sh"
        end = next(i for i in range(starts[0] + 1, len(lines))
                   if lines[i] == "PYEOF")
        merge_py = sandbox / "merge.py"
        merge_py.write_text(
            "\n".join(lines[starts[0] + 1:end]) + "\n")
        assert merge_py.stat().st_size > 0

        def _run(base_text, sidecar_text):
            new = sandbox / "new.ini"
            new.write_text(base_text)
            sidecar = sandbox / "computed.ini"
            sidecar.write_text(sidecar_text)
            proc = run(["python3", merge_py, new, sidecar],
                       env={"GUEST_ROOT_PASS": "dummy-selftest-pass"})
            assert proc.returncode == 0, proc.stderr
            return read_ini(new)

        return _run

    def test_computed_values_override_a_stale_base(self, merge):
        # the regression shape: the computed sidecar values
        # must WIN over the base ini's stale statically published
        # ones -- the empty-only fallback used to keep the stale
        # values and poison every version expectation
        cfg = merge(STALE_BASE_INI, COMPUTED_SIDECAR)
        assert cfg.get("virtwho", "package") \
            == "virt-who-1.32.1-2.el10.noarch", \
            "the computed virt-who NEVRA did not override the " \
            "stale base-ini value"
        assert cfg.get("virtwho", "test_rpms") \
            == "https://brew.example.invalid/new/" \
               "virt-who-1.32.1-1.dummy.el10.noarch.rpm", \
            "the computed gating test_rpms did not override the " \
            "stale base-ini value"
        assert cfg.get("virtwho", "undertest_rpm") \
            == "/opt/virtwho-test/virt-who-under-test.rpm", \
            "the computed undertest RPM path did not override the " \
            "stale base-ini value"
        # the rhel_compose override keeps working through the shared
        # helper
        assert cfg.get("job", "rhel_compose") == "RHEL-10.4-DUMMY", \
            "the resolved compose no longer overrides the raw alias"

    def test_an_empty_sidecar_value_clears_the_stale_base(self, merge):
        # the nightly shape: the sidecar records the EMPTY values of
        # a run without TEST_RPMS (and a failed cache) -- computed
        # ground truth that must CLEAR the stale published values,
        # the one direction the non-empty-only rule was blind to
        cfg = merge(STALE_BASE_INI, NIGHTLY_SIDECAR)
        assert cfg.get("virtwho", "test_rpms") == "", \
            "an empty computed test_rpms did not clear the stale " \
            "base-ini value"
        assert cfg.get("virtwho", "undertest_rpm") == "", \
            "an empty computed undertest_rpm did not clear the " \
            "stale base-ini value"
        # an option the sidecar does not carry keeps the base value
        # (the NEVRA is recorded only when a real one resolves)
        assert cfg.get("virtwho", "package") \
            == "virt-who-1.31.28-1.el9.noarch", \
            "an absent sidecar option cleared the base-ini value"
        # rhel_compose keeps the non-empty rule: an unresolved
        # compose records empty and keeps the base/alias value
        assert cfg.get("job", "rhel_compose") == "RHEL-10.0-DUMMY", \
            "an empty computed rhel_compose cleared the base value"

    def test_an_absent_sidecar_keeps_the_base(self, merge):
        # the hand-run local shape: no sidecar at all -- every base
        # value stands, and the credential defaults still apply
        cfg = merge(STALE_BASE_INI, "")
        assert cfg.get("virtwho", "package") \
            == "virt-who-1.31.28-1.el9.noarch"
        assert cfg.get("virtwho", "test_rpms") \
            == "https://brew.example.invalid/old/" \
               "virt-who-1.31.28-1.el9.noarch.rpm"
        assert cfg.get("virtwho", "undertest_rpm") \
            == "/opt/virtwho-test/virt-who-under-test.OLD.rpm"
        assert cfg.get("job", "rhel_compose") == "RHEL-10.0-DUMMY"

    def test_credentials_keep_their_fallback_semantics(self, merge):
        # username/password are NOT computed ground truth: an empty
        # base value is still filled from the defaults (root and
        # the per-run environment password), never overridden by
        # the sidecar and never invented when both are empty
        cfg = merge(STALE_BASE_INI, COMPUTED_SIDECAR)
        assert cfg.get("virtwho", "username") == "root"
        assert cfg.get("virtwho", "password") == "dummy-selftest-pass"
        sidecar_no_creds = COMPUTED_SIDECAR.split("[virtwho]")[0] \
            + "[virtwho]\npackage=virt-who-1.32.1-2.el10.noarch\n"
        cfg = merge(STALE_BASE_INI, sidecar_no_creds)
        assert cfg.get("virtwho", "username") == "root"
        assert cfg.get("virtwho", "password") == "dummy-selftest-pass"
