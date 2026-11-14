"""Version-under-test self-tests (the run-#7 content-gap fix).

Owner ruling (2026-11-21): TEST_RPMS always has precedence -- it
carries manual overrides, PR-build testing, or gated release
builds. When testing a RHEL compose, the compose's OWN virt-who
version must be used. In both cases the test environment installs
the version under test (plus test deps) BEFORE tests start, so the
destination's content repo (the container tier's pod repo) must
NEVER be the source for the package under test -- the run-#7
regression (build #181): once registration worked through the
container tier, the host's content access switched to the pod's
repo, which serves no virt-who packages, and the repo-based package
tests (test_shipped_in_supported_arch,
test_install_uninstall_by_dnf) failed.

Pinned here:

  * the prepare-phase cache of setup-virtwho-test.sh (source level:
    the TEST_RPMS branch wins, the compose-repo fallback, the
    sidecar record) -- the script is too heavy for a hermetic
    behavioral run (git clone + pip install);
  * the ini plumbing (the sidecar value, the run-tests.sh merge
    fallback, the virtwho package export);
  * the two fixed tests' source resolution (source level);
  * virtwho_install_under_test() BEHAVIORALLY: a sandboxed copy of
    the virtwho package (so its config writes stay inside the
    sandbox) plus a recording fake ssh proves the exact dnf command
    for every precedence case and the failure raise.

Every value is an RFC 2606/5737 dummy; the real TEST_RPMS URLs are
internal brew identifiers and never appear in this repository.

Run: python -m pytest systemtest/selftest/ -v
"""

import shutil
import sys

import pytest
from _utils import REPO_ROOT, SCRIPTS_DIR, run

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

# The minimal ini the virtwho package needs at import time (the
# generated guest ini always carries these table options; a bare
# sandbox import would otherwise crash on the first missing one).
MINIMAL_INI = """\
[job]
hypervisor=libvirt
register=rhsm
rhel_compose=RHEL-10.0-DUMMY
rhel_compose_path=

[virtwho]
package=virt-who-1.32.1-2.el10.noarch
test_rpms=
undertest_rpm=
"""

# Runs virtwho_install_under_test() against a recording fake ssh
# inside a sandboxed copy of the virtwho package. argv: the tree,
# the TEST_RPMS value, the undertest cache value, and whether the
# fake rpm database reports virt-wo installed ("1") or not ("0").
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
        # the precedence (owner ruling): the cache step must gate on
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

    def test_the_ini_and_merge_plumbing(self):
        # the cache path must reach the suite: the sidecar records
        # it, run-tests.sh merges it back into the regenerated ini,
        # and the package exports it for virtwho_install_under_test
        setup_text = SETUP.read_text()
        assert 'cfg.set("virtwho", "undertest_rpm", undertest_rpm)' \
            in setup_text, "the sidecar no longer records the cache path"
        assert 'fallback("virtwho", "undertest_rpm", None)' \
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
    """The two run-#7 tests read the version under test, never the
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
            "run-#7 regression: the destination's content repo " \
            "serves no virt-who)"
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
            "the by-dnf test installs from the enabled repos again " \
            "(the run-#7 regression)"
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
        """A one-call runner: copies the virtwho package into the
        sandbox, writes the minimal ini (optionally with a cache
        value to prove the import-time plumbing), runs the driver."""
        pkg_root = sandbox / "pkg"

        def _run(*, ini=MINIMAL_INI, test_rpms="", undertest="",
                 installed="1"):
            shutil.copytree(
                REPO_ROOT / "virtwho", pkg_root / "virtwho",
                ignore=shutil.ignore_patterns("__pycache__"))
            # the ini lives at the package tree's ROOT (the sibling
            # of the virtwho/ dir -- where the guest's symlink to
            # /dev/shm/virtwho.ini points)
            (pkg_root / "virtwho.ini").write_text(ini)
            driver = sandbox / "driver.py"
            driver.write_text(HELPER_DRIVER)
            proc = run([sys.executable, str(driver), str(pkg_root),
                        test_rpms, undertest, installed])
            assert proc.returncode == 0, proc.stderr
            lines = proc.stdout.splitlines()
            return {
                "cmds": [line[4:] for line in lines
                         if line.startswith("CMD:")],
                "init": next(line[5:] for line in lines
                             if line.startswith("INIT:")),
                "raised": next(line[7:] for line in lines
                               if line.startswith("RAISED:")),
                "message": next(line[8:] for line in lines
                                if line.startswith("MESSAGE:")),
            }

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
