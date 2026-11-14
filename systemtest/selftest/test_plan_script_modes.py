"""Git-mode guard (CCT-3155): every script the tmt plans invoke
directly must carry git mode 100755, and the prepare-step ORDER must
keep the virtwho-test clone ahead of the candlepin deploy.

Jenkins run #4 (on 5a76f23) aborted deterministically on all four
cells: prepare-candlepin.sh was committed with git mode 100644, and
the fmf plan's `script: ./systemtest/scripts/prepare-candlepin.sh`
hands the path to tmt, which execs it -- exit 126, permission
denied, zero tests run. Nothing else could catch the class: the
selftests invoke the scripts via `bash <script>` (no exec bit
needed), shellcheck only reads the file, and the phase-0 spike ran
it by hand. This guard parses every .fmf file for direct
`script:`/`test:` invocations and asserts the git index mode of each
target is 100755.

The ordering invariant (review C1, cycle-3 -- found independently by
three blind reviewers and empirically demonstrated twice): when the
plan ran prepare-candlepin.sh BEFORE setup-virtwho-test.sh, a
successful deploy created /opt/virtwho-test plus the readiness
marker, and the subsequent `git clone` into the now-non-empty
directory exited 128 -- tmt prepare failed on every standard
container-tier cell, exactly one gate after the destination itself
started working. The clone must run first; the marker then lands in
the cloned tree's root where all three readers already look. The
invariant below parses the fmf prepare-step order directly (no git
index needed, so it also runs inside the mutation battery's git-less
tree copy -- which is what lets the battery's plan-order-revert
mutation be caught).

Skipped inside the mutation battery's git-less tree copy (the MODE
guard needs the git index; the battery tar-copy has no .git) -- it
runs on every real checkout, which is where the Lint workflow
executes it.

Run: python -m pytest systemtest/selftest/ -v
"""

import re
import subprocess

import pytest
from _utils import REPO_ROOT

requires_git = pytest.mark.skipif(
    not (REPO_ROOT / ".git").exists(),
    reason="not a git work tree (mutation-battery copy); the mode "
           "guard needs the git index and runs on real checkouts")

# The two prepare steps whose ORDER is load-bearing (review C1):
# the clone creates the tree; the deploy writes its readiness marker
# into that tree's root. Deploy-first breaks the clone (exit 128 on
# the non-empty dir).
CLONE_STEP = "setup-virtwho-test.sh"
DEPLOY_STEP = "prepare-candlepin.sh"


def plan_prepare_scripts(fmf_path):
    """The script paths of a plan's prepare steps, IN ORDER.

    Parses the `prepare:` block of an .fmf file: every
    `script: <path>` line between the top-level `prepare:` key and
    the next top-level key, in file order (tmt executes prepare
    steps in exactly this order).
    """
    scripts = []
    in_prepare = False
    for line in fmf_path.read_text().splitlines():
        if line and not line[0].isspace():
            in_prepare = line.rstrip() == "prepare:"
            continue
        if in_prepare:
            match = re.match(r"^\s*script:\s*(\S+)", line)
            if match:
                scripts.append(match.group(1))
    return scripts


def plan_invoked_scripts():
    """Every (fmf file, repo-relative path) the plans invoke directly,
    from `script: ./path` (prepare/finish steps) and `test: ./path`
    (discover steps) entries. Plan-level paths are tree-root
    relative; test-metadata paths (e.g. systemtest/tests/bootc) are
    relative to their own .fmf directory -- resolve both."""
    refs = []
    for fmf in sorted(REPO_ROOT.rglob("*.fmf")):
        if ".git" in fmf.parts or not fmf.is_file():
            continue
        for match in re.finditer(
                r"^\s*(?:script|test):\s*\./(\S+)", fmf.read_text(),
                re.MULTILINE):
            rel = match.group(1)
            for base in (fmf.parent, REPO_ROOT):
                candidate = base / rel
                if candidate.is_file():
                    refs.append((fmf, candidate.relative_to(REPO_ROOT)))
                    break
    return refs


def git_index_mode(path):
    """The git index mode of *path* ('100755'/'100644'), or None when
    untracked / not in a work tree."""
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-s", "--", path],
        capture_output=True, text=True, timeout=60, check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return proc.stdout.split()[0]


@requires_git
class TestPlanScriptModes:
    def test_the_plans_do_reference_scripts(self):
        # the guard must not silently drift into parsing nothing
        refs = plan_invoked_scripts()
        assert refs, "no script:/test: references found in any .fmf"

    def test_every_directly_invoked_script_is_executable(self):
        refs = plan_invoked_scripts()
        bad = []
        for fmf, rel in refs:
            mode = git_index_mode(rel)
            if mode != "100755":
                bad.append(f"{rel}: git mode {mode or 'UNTRACKED'} "
                           f"(referenced by {fmf.relative_to(REPO_ROOT)})")
        assert not bad, (
            "plan-invoked script(s) without the exec bit -- tmt execs "
            "them directly, so a 100644 script is the deterministic "
            "exit-126 abort of Jenkins run #4:\n  "
            + "\n  ".join(bad))


class TestPlanPrepareOrder:
    """The plan-ordering invariant (review C1): in every plan that
    has both steps, the virtwho-test CLONE must precede the
    candlepin DEPLOY. No git index is read here, so this also runs
    (and catches the plan-order-revert mutation) inside the
    mutation battery's git-less tree copy."""

    def test_clone_precedes_candlepin_deploy(self):
        checked = 0
        problems = []
        for fmf in sorted(REPO_ROOT.rglob("*.fmf")):
            if ".git" in fmf.parts or not fmf.is_file():
                continue
            scripts = plan_prepare_scripts(fmf)
            if not any(DEPLOY_STEP in s for s in scripts):
                continue
            checked += 1
            clone_positions = [i for i, s in enumerate(scripts)
                               if CLONE_STEP in s]
            deploy_positions = [i for i, s in enumerate(scripts)
                                if DEPLOY_STEP in s]
            if not clone_positions:
                problems.append(
                    f"{fmf.relative_to(REPO_ROOT)}: deploys the "
                    f"candlepin destination but has no {CLONE_STEP} "
                    f"prepare step (the marker needs the cloned tree)")
            elif clone_positions[0] > deploy_positions[0]:
                problems.append(
                    f"{fmf.relative_to(REPO_ROOT)}: {DEPLOY_STEP} "
                    f"(step {deploy_positions[0] + 1}) runs BEFORE "
                    f"{CLONE_STEP} (step {clone_positions[0] + 1}) -- "
                    f"a successful deploy leaves a non-empty install "
                    f"dir + marker and the subsequent git clone exits "
                    f"128, failing tmt prepare on every standard "
                    f"container-tier cell")
        assert checked, (
            "no plan was found deploying the candlepin destination; "
            "the ordering guard parsed nothing (drift?)")
        assert not problems, "\n  ".join([""] + problems)
