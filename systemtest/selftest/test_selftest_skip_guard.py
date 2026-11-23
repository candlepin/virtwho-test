"""Self-tests for the selftest job's own vacuous-green guard.

`python -m pytest systemtest/selftest/ -v` (the Lint selftest job)
exits 0 on all-pass AND on a mass-skip: nothing protected the job
against a session whose tests silently skipped themselves. The guard
lives in systemtest/selftest/conftest.py (a pytest_runtest_logreport
recorder + a pytest_sessionfinish audit that raises SystemExit(1)
when a skip appears outside the justified set) and its
classification is the pure helper _utils.unexpected_skips() -- pinned
here.

The justified set, stated as data:
  * on a REAL checkout (where the Lint job runs): NOTHING may skip;
  * inside the mutation battery's git-less tree copy: exactly the
    two git-mode guard tests of test_plan_script_modes.py (they need
    the git index; the battery tar-copy has no .git).

Run: python -m pytest systemtest/selftest/ -v
"""

from _utils import (
    JUSTIFIED_SKIPS_GITLESS,
    unexpected_skips,
)

RECORD = ("systemtest/selftest/test_example.py::TestX::test_y",
          "some recorded reason")


class TestUnexpectedSkips:
    def test_no_records_means_no_problems(self):
        assert unexpected_skips([], gitless=False) == []
        assert unexpected_skips([], gitless=True) == []

    def test_gitless_justified_skips_pass(self):
        # the mutation battery's legitimate pair: the git-mode guard
        # needs the git index a tar-copy does not have
        reason = ("not a git work tree (mutation-battery copy)")
        records = [(nodeid, reason)
                   for nodeid in JUSTIFIED_SKIPS_GITLESS]
        assert unexpected_skips(records, gitless=True) == []

    def test_any_skip_is_unexpected_on_a_real_checkout(self):
        # where the Lint job runs, nothing at all may skip -- even
        # the git-less pair (a real checkout HAS a .git index)
        records = [(nodeid, "why is this skipping on a real tree?")
                   for nodeid in JUSTIFIED_SKIPS_GITLESS]
        assert len(unexpected_skips(records, gitless=False)) == 2

    def test_an_unjustified_skip_is_flagged_with_its_reason(self):
        problems = unexpected_skips([RECORD], gitless=True)
        assert problems == [RECORD], (
            "the guard must name the unjustified skip (nodeid AND "
            "reason) so the failure is actionable")

    def test_nodeid_matching_is_suffix_based(self):
        # nodeids vary with the invocation root (systemtest/selftest/
        # vs a bare directory run); the justified entries match by
        # suffix
        nodeid = "some/other/prefix/" + JUSTIFIED_SKIPS_GITLESS[0]
        assert unexpected_skips(
            [(nodeid, "git-less copy")], gitless=True) == []
