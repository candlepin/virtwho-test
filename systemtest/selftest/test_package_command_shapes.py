"""The package-test fixes around the version-under-test
precedence, pinned.

The dep-cleaning dnf5 uninstall starved the repo-less reinstall of
the version under test (test_install_uninstall_by_dnf -- and the
cascade left the suite without virt-who), the by-rpm test
downloaded its rpm from the destination's by-design-dead content
repo (test_install_uninstall_by_rpm), and the arch query captured
the compose-signed rpm's GPG NOKEY stderr as the arch value
(test_shipped_in_supported_arch). The sidecar-merge half of the
fix is pinned in test_version_under_test.py
(TestSidecarMergeOverride); this module pins the package-test
half:

  * package_uninstall()'s dep-safe shape (behavioral: a sandboxed
    copy of the virtwho package plus a recording fake ssh proves
    the exact command for the keep_deps path AND that every other
    consumer's historical command is unchanged);
  * virtwho_download_under_test()'s precedence (behavioral, the
    same recording-fake-ssh battery pattern as
    virtwho_install_under_test() in test_version_under_test.py, on
    the shared _utils.run_fake_ssh_driver harness);
  * the two tests' wiring (source level: they need a live guest):
    the dep-safe uninstall call, the UNCONDITIONAL finally
    reinstall (the cascade guard) and the by-rpm cache-sourcing;
  * the arch query's stdout-only capture (source level).

Every value is an RFC 2606/5737 dummy. Run:
python -m pytest systemtest/selftest/ -v
"""

import pytest
from _utils import REPO_ROOT, run_fake_ssh_driver

TEST_INSTALL_UNINSTALL = (
    REPO_ROOT / "tests" / "package" / "test_install_uninstall.py"
)
TEST_INFO = REPO_ROOT / "tests" / "package" / "test_info.py"
BASE_PY = REPO_ROOT / "virtwho" / "base.py"

DUMMY_CACHE = "/opt/virtwho-test/virt-who-under-test.rpm"

# A TEST-RPM URL of the exact SHAPE the pipelines deliver (brew
# download host, virt-who nevra basename) with every identifier
# replaced by RFC 2606 dummies.
DUMMY_TEST_RPMS = (
    "https://brew.example.invalid/brewroot/work/tasks/1/1/"
    "virt-who-1.32.1-1.dummy.el10.noarch.rpm"
)

# Runs the base.py helpers against a recording fake ssh inside a
# sandboxed copy of the virtwho package (the shared harness in
# _utils.run_fake_ssh_driver sets up the sandbox, writes the minimal
# ini and parses this protocol). argv: the tree, the mode, the
# TEST_RPMS value, the undertest cache value, whether the fake rpm
# database reports virt-wo installed ("1") or not ("0"), and whether
# the fake cp succeeds ("1") or fails ("0").
DRIVER = """\
import sys

sys.path.insert(0, sys.argv[1])
import virtwho.base as base


class FakeSSH:
    def __init__(self, installed, cp_ok):
        self.commands = []
        self.installed = installed
        self.cp_ok = cp_ok

    def runcmd(self, cmd):
        self.commands.append(cmd)
        if cmd.startswith("rpm -qa"):
            if self.installed:
                return 0, "virt-who-1.32.1-2.el10.noarch"
            return 1, "package virt-who is not installed"
        if cmd.startswith("cp "):
            if self.cp_ok:
                return 0, ""
            return 1, "cp: cannot stat"
        if cmd.startswith("curl "):
            # the TEST_RPMS download path of
            # virtwho_download_under_test: succeed like a healthy
            # fetch (a failure case is exercised through cp_ok's
            # analogue below)
            return 0, ""
        if cmd.startswith("ls "):
            # dnf_download_pkg's listing: the first rpm in the dir
            return 0, (cmd.split()[1].rsplit("/", 1)[0]
                       + "/virt-who-1.32.1-2.el10.noarch.rpm")
        return 0, ""


def main():
    mode = sys.argv[2]
    base.TEST_RPMS = sys.argv[3]
    base.VIRTWHO_UNDERTEST_RPM = sys.argv[4]
    ssh = FakeSSH(sys.argv[5] == "1", sys.argv[6] == "1")
    raised = "no"
    message = ""
    path = ""
    try:
        if mode == "uninstall-depsafe":
            base.package_uninstall(ssh, "virt-who", keep_deps=True)
        elif mode == "uninstall-default":
            base.package_uninstall(ssh, "virt-who")
        elif mode == "uninstall-rpm":
            base.package_uninstall(
                ssh, "virt-who", rpm="virt-who-1.32.1-2.el10.noarch")
        else:
            path = base.virtwho_download_under_test(
                ssh, "/tmp/dummy-destdir")
    except base.FailException as exc:
        raised = "yes"
        message = str(exc)
    print("RAISED:" + raised)
    print("MESSAGE:" + message)
    print("PATH:" + path)
    for command in ssh.commands:
        print("CMD:" + command)


main()
"""


@pytest.fixture
def driver(sandbox):
    """A one-call runner: runs the recording driver against a
    sandboxed copy of the virtwho package for the given mode (the
    shared _utils.run_fake_ssh_driver does the sandbox setup and the
    output-protocol parsing)."""
    def _run(mode, test_rpms="", undertest="", installed="0",
             cp_ok="1"):
        return run_fake_ssh_driver(
            sandbox, DRIVER,
            [mode, test_rpms, undertest, installed, cp_ok])
    return _run


class TestUninstallCommandShapes:
    """package_uninstall(), behaviorally: the dep-safe path for the
    by-dnf test and the unchanged historical shapes every other
    consumer relies on."""

    def test_the_dep_safe_uninstall_disables_requirement_cleaning(
            self, driver):
        # dnf5 (RHEL-10) removes automatically-installed dependencies
        # together with the package
        # (clean_requirements_on_remove), which starved the
        # repo-less reinstall of the version under test -- the
        # by-dnf path must disable the cleaning
        result = driver("uninstall-depsafe", installed="0")
        assert result["raised"] == "no", result["message"]
        assert result["cmds"][0] == (
            "yum remove -y --setopt=clean_requirements_on_remove=False"
            " virt-who"), \
            f"the dep-safe uninstall command changed: {result['cmds'][0]}"

    def test_the_default_uninstall_keeps_the_historical_command(
            self, driver):
        # every other consumer (and any external caller) keeps the
        # plain historical remove -- the flag is strictly opt-in
        result = driver("uninstall-default", installed="0")
        assert result["raised"] == "no", result["message"]
        assert result["cmds"][0] == "yum remove -y virt-who", \
            f"the default uninstall command changed: {result['cmds'][0]}"

    def test_the_rpm_uninstall_keeps_the_historical_command(
            self, driver):
        # the by-rpm test's rpm -e --nodeps shape is untouched
        result = driver("uninstall-rpm", installed="0")
        assert result["raised"] == "no", result["message"]
        assert result["cmds"][0] == \
            "rpm -e virt-who-1.32.1-2.el10.noarch --nodeps", \
            f"the rpm uninstall command changed: {result['cmds'][0]}"

    def test_a_failed_uninstall_raises(self, driver):
        # the fake rpm database still reports virt-who installed
        # after the remove: the helper must raise (the old `is True`
        # guard could never fire -- package_check returns a NEVRA
        # string or False, never True -- so a failed uninstall used
        # to pass silently)
        result = driver("uninstall-default", installed="1")
        assert result["raised"] == "yes", \
            "a failed uninstall did not raise"
        assert "Failed to uninstall virt-who" in result["message"], \
            f"the failure does not name the package: " \
            f"{result['message']}"


class TestDownloadUnderTest:
    """virtwho_download_under_test(), behaviorally: the by-rpm
    test's rpm source -- the TEST_RPMS URL and the undertest cache
    first, the enabled repos only as the hand-run local fallback,
    mirroring virtwho_install_under_test()'s precedence."""

    def test_test_rpms_is_downloaded_when_set(self, driver):
        # the gating shape without an undertest cache (a failed
        # prepare-phase curl leaves the sidecar empty): the TEST_RPMS
        # URL is the source, with the same bounded-retry curl the
        # prepare-phase cache uses -- the enabled repos (the
        # container tier's dead pod repo) must not be reached
        result = driver("download", test_rpms=DUMMY_TEST_RPMS)
        assert result["raised"] == "no", result["message"]
        assert result["cmds"] == [
            "mkdir -p /tmp/dummy-destdir",
            ("curl -fsSL --retry 3 --retry-delay 5 "
             "--connect-timeout 10 --max-time 300 "
             "-o /tmp/dummy-destdir/virt-who-1.32.1-1.dummy.el10"
             f".noarch.rpm {DUMMY_TEST_RPMS}"),
        ], f"unexpected TEST_RPMS download commands: {result['cmds']}"
        assert result["path"] == (
            "/tmp/dummy-destdir/"
            "virt-who-1.32.1-1.dummy.el10.noarch.rpm"), \
            f"unexpected downloaded rpm path: {result['path']}"

    def test_test_rpms_wins_over_the_cache(self, driver):
        # the precedence mirrors virtwho_install_under_test():
        # TEST_RPMS first, even when a cache exists (they hold the
        # same rpm in a healthy gating run; the URL is the ruling's
        # letter)
        result = driver("download", test_rpms=DUMMY_TEST_RPMS,
                        undertest=DUMMY_CACHE)
        assert result["raised"] == "no", result["message"]
        assert any(cmd.startswith("curl -fsSL") for cmd
                   in result["cmds"]), \
            f"TEST_RPMS did not win the download: {result['cmds']}"
        assert not any(cmd.startswith("cp ") for cmd
                       in result["cmds"]), \
            "the cache was copied although TEST_RPMS is set"

    def test_test_rpms_without_a_virt_who_url_raises(self, driver):
        # a gating list without a virt-who rpm cannot source the
        # by-rpm test: a loud failure naming TEST_RPMS, never a
        # silent fall-through to the enabled repos
        result = driver(
            "download",
            test_rpms="https://brew.example.invalid/other-1.0-1"
                      ".noarch.rpm")
        assert result["raised"] == "yes", \
            "a TEST_RPMS list without a virt-who URL did not raise"
        assert "TEST_RPMS" in result["message"], \
            f"the failure does not name TEST_RPMS: " \
            f"{result['message']}"
        assert not any(cmd.startswith("dnf download")
                       for cmd in result["cmds"]), \
            "the missing virt-who URL silently fell back to the repos"

    def test_the_undertest_cache_is_copied_guest_locally(self, driver):
        # the cache holds the version under test (the TEST_RPMS rpm
        # in gating mode, the compose's own virt-who otherwise);
        # the registered container-tier host's only enabled repo is
        # the pod's dead content repo, so the copy must be the
        # primary path
        result = driver("download", undertest=DUMMY_CACHE)
        assert result["raised"] == "no", result["message"]
        assert result["cmds"] == [
            "mkdir -p /tmp/dummy-destdir",
            f"cp -f {DUMMY_CACHE} /tmp/dummy-destdir/",
        ], f"unexpected cache-sourcing commands: {result['cmds']}"
        assert result["path"] == \
            "/tmp/dummy-destdir/virt-who-under-test.rpm", \
            f"unexpected rpm path: {result['path']}"

    def test_the_enabled_repos_are_the_last_resort(self, driver):
        # no cache (the hand-run local-suite shape): the historical
        # repo download remains as the fallback
        result = driver("download")
        assert result["raised"] == "no", result["message"]
        assert any(cmd.startswith("dnf download -y "
                                 "--destdir=/tmp/dummy-destdir virt-who")
                   for cmd in result["cmds"]), \
            f"the repo-download fallback is gone: {result['cmds']}"
        assert result["path"] == \
            "/tmp/dummy-destdir/virt-who-1.32.1-2.el10.noarch.rpm", \
            f"unexpected fallback rpm path: {result['path']}"

    def test_a_failed_cache_copy_raises(self, driver):
        # the cache file is missing at test time: a loud failure
        # naming the version-under-test RPM, never a silent
        # fallback to the dead destination repo
        result = driver("download", undertest=DUMMY_CACHE, cp_ok="0")
        assert result["raised"] == "yes"
        assert "version-under-test RPM" in result["message"], \
            f"the failure does not name the version-under-test " \
            f"RPM: {result['message']}"
        assert not any(cmd.startswith("dnf download")
                       for cmd in result["cmds"]), \
            "a failed cache copy silently fell back to the repos"


class TestPackageTestWiring:
    """The two tests' own wiring (source level: they need a live
    guest to run)."""

    @staticmethod
    def _slices():
        text = TEST_INSTALL_UNINSTALL.read_text()
        start_dnf = text.index("def test_install_uninstall_by_dnf")
        start_rpm = text.index("def test_install_uninstall_by_rpm")
        dnf_part = text[start_dnf:start_rpm]
        rpm_part = text[start_rpm:]
        return dnf_part, dnf_part[dnf_part.index("finally:"):], \
            rpm_part, rpm_part[rpm_part.index("finally:"):]

    def test_by_dnf_uses_the_dep_safe_uninstall(self):
        dnf_part, _, _, _ = self._slices()
        assert 'package_uninstall(ssh_host, "virt-who", ' \
               'keep_deps=True)' in dnf_part, \
            "the by-dnf test no longer keeps virt-who's " \
            "dependencies through the remove (the reinstall " \
            "starvation)"

    def test_by_dnf_finally_reinstalls_unconditionally(self):
        # the cascade guard: the finally reinstalls the version
        # under test UNCONDITIONALLY (no presence or TEST_RPMS
        # condition) -- a virt-who-less suite cascades into every
        # later test
        _, dnf_finally, _, _ = self._slices()
        assert "virtwho_install_under_test(ssh_host)" in dnf_finally, \
            "the by-dnf teardown no longer reinstalls the version " \
            "under test"
        assert "package_check" not in dnf_finally, \
            "the by-dnf teardown reinstalls conditionally again " \
            "(the cascade: a failed body left the suite without " \
            "virt-who)"

    def test_by_rpm_sources_the_undertest_cache(self):
        _, _, rpm_body, _ = self._slices()
        assert "virtwho_download_under_test(ssh_host, file_path)" \
            in rpm_body, \
            "the by-rpm test no longer sources its rpm from the " \
            "undertest cache"
        assert "dnf_download_pkg(" not in rpm_body, \
            "the by-rpm test downloads from the enabled repos again"

    def test_by_rpm_finally_reinstalls_through_the_helper(self):
        # the same cascade guard as by-dnf: the teardown restores
        # the version under test through the precedence helper,
        # never a plain repo install
        _, _, _, rpm_finally = self._slices()
        assert "virtwho_install_under_test(ssh_host)" in rpm_finally, \
            "the by-rpm teardown no longer reinstalls the version " \
            "under test through the precedence helper"
        assert 'package_install(ssh_host, "virt-who")' \
            not in rpm_finally, \
            "the by-rpm teardown installs from the enabled repos " \
            "again"

    def test_the_arch_query_discards_stderr(self):
        # runcmd returns stderr when the command produced any
        # (virtwho/ssh.py), and the compose-signed cached rpm greets
        # rpm -qp with a GPG NOKEY warning on stderr -- the arch
        # queries must discard stderr explicitly so a warning can
        # never become the parsed arch value
        text = TEST_INFO.read_text()
        assert ("f\"rpm -qp --qf '%{{arch}}' {VIRTWHO_UNDERTEST_RPM} "
                "2>/dev/null\"") in text, \
            "the cached-rpm arch query no longer discards stderr"
        assert '"rpm -q --qf \'%{arch}\' virt-who 2>/dev/null"' \
            in text, \
            "the installed-package arch query no longer discards " \
            "stderr"

    def test_the_helpers_exist_in_base(self):
        # wiring smoke: the helpers the tests call are imported
        # from virtwho.base (an import drift fails here with a
        # named message instead of a collection error)
        text = BASE_PY.read_text()
        assert "def virtwho_download_under_test(ssh, dest_dir):" \
            in text, "virtwho.base lost virtwho_download_under_test"
        assert "def package_uninstall(ssh, pkg_name, rpm=False, " \
               "keep_deps=False):" in text, \
            "virtwho.base lost the keep_deps uninstall parameter"
