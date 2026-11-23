"""Vacuous-green guard self-tests (CCT-3155) for
assert-candlepin-tier.sh and its run-tests.sh wiring.

Every failure mode of prepare-candlepin.sh is a loud SKIP by design
(bootc container-build contexts need that), so a run where the
container tier was silently absent (no podman, unreachable registry,
readiness timeout, contract drift) would otherwise report green with
mass skips. The guard fails such runs: run-tests.sh asserts the
readiness marker BEFORE pytest starts whenever the generated ini
records [job] destination=container.

The guard reads the ini (the single source of the tier record, the
same values tests/conftest.py gates on), never the environment:
hand-written inis without [job] destination keep the old contract,
and satellite cells (which never deploy the pod) are exempt.

Run: python -m pytest systemtest/selftest/ -v
"""

from _utils import REPO_ROOT, SCRIPTS_DIR, run

ASSERT_TIER = SCRIPTS_DIR / "assert-candlepin-tier.sh"
RUN_TESTS = SCRIPTS_DIR / "run-tests.sh"
MARKER_NAME = ".virtwho-candlepin-ready"


def write_ini(sandbox, *, destination, register="rhsm"):
    """A generated-ini stand-in recording the [job] tier fields."""
    lines = ["[job]", "hypervisor=libvirt", f"register={register}"]
    if destination is not None:
        lines.append(f"destination={destination}")
    ini = sandbox / "virtwho.ini"
    ini.write_text("\n".join(lines) + "\n")
    return ini


def run_guard(sandbox, ini, *, marker):
    tree = sandbox / "tree"
    tree.mkdir(exist_ok=True)
    if marker:
        (tree / MARKER_NAME).touch()
    return run(["bash", ASSERT_TIER, ini, tree])


class TestVacuousGreenGuard:
    def test_missing_marker_fails_the_run(self, sandbox):
        # the exact vacuous-green class: destination=container, the
        # tier never deployed -> the RUN fails loudly, not green
        ini = write_ini(sandbox, destination="container")
        proc = run_guard(sandbox, ini, marker=False)
        assert proc.returncode == 1
        assert MARKER_NAME in proc.stderr
        assert "FAIL the run" in proc.stderr
        assert "prepare-phase" in proc.stderr

    def test_present_marker_passes(self, sandbox):
        ini = write_ini(sandbox, destination="container")
        proc = run_guard(sandbox, ini, marker=True)
        assert proc.returncode == 0, proc.stderr
        assert MARKER_NAME in proc.stdout

    def test_stage_destination_is_exempt(self, sandbox):
        # the stage tier never has a marker; that is not a failure
        ini = write_ini(sandbox, destination="stage")
        proc = run_guard(sandbox, ini, marker=False)
        assert proc.returncode == 0, proc.stderr
        assert "ERROR" not in proc.stderr

    def test_satellite_register_is_exempt(self, sandbox):
        # satellite cells never deploy the candlepin pod
        ini = write_ini(sandbox, destination="container",
                        register="satellite")
        proc = run_guard(sandbox, ini, marker=False)
        assert proc.returncode == 0, proc.stderr

    def test_handwritten_ini_without_destination_is_exempt(self, sandbox):
        # no [job] destination option: the old contract (the conftest
        # skip remains the defense-in-depth for such inis)
        ini = write_ini(sandbox, destination=None)
        tree = sandbox / "tree"
        tree.mkdir()
        proc = run(["bash", ASSERT_TIER, ini, tree])
        assert proc.returncode == 0, proc.stderr

    def test_run_tests_invokes_the_guard_before_pytest(self):
        # source-level pin (run-tests.sh cannot run hermetically): the
        # guard runs before pytest, and bootc container-build contexts
        # keep the conftest skip instead of the hard failure
        text = RUN_TESTS.read_text()
        assert "assert-candlepin-tier.sh" in text
        assert "if ! is_bootc; then" in text
        assert text.index("assert-candlepin-tier.sh") \
            < text.index("pytest tests/"), \
            "the guard must assert the marker BEFORE pytest starts"

    def test_marker_path_matches_prepare_and_conftest(self):
        # the three readers of the marker must agree on its location:
        # prepare writes <install-dir>/.virtwho-candlepin-ready, the
        # guard checks <test-tree>/.virtwho-candlepin-ready and
        # conftest resolves it relative to the test tree root
        prepare = (SCRIPTS_DIR / "prepare-candlepin.sh").read_text()
        conftest = (REPO_ROOT / "tests" / "conftest.py").read_text()
        assert 'MARKER="${INSTALL_DIR}/.virtwho-candlepin-ready"' in prepare
        assert '".virtwho-candlepin-ready"' in conftest
