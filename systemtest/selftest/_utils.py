"""Shared helpers for the host-side self-tests (systemtest/selftest).

Pure, pytest-free helpers used by conftest.py and the test modules.
The scripts under test stay BASH -- these helpers only invoke them
hermetically: mktemp sandboxes under /dev/shm (tmpfs, so the
secret-bearing inis never touch real disk), `env -u`-style variable
hygiene and PATH-injected command stubs. All values used by the
tests are dummies (non-secret, non-real): example.com /
example.invalid names, TEST-NET-1/2/3 addresses, FAKE-* payloads.
"""

import configparser
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# The REAL scripts under test, resolved relative to this file so a
# copied (e.g. mutation-tested) tree is exercised as-is, never a
# drifted copy.
SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"

# The repository root (for the source-level contract checks).
REPO_ROOT = SCRIPTS_DIR.parents[1]

# Like the bash self-tests before it, the suite sandboxes under
# /dev/shm: the generated inis carry dummy credentials and must never
# land on real disk.
SHM_DIR = "/dev/shm"


def shm_workdir():
    """A fresh unpredictable sandbox directory under /dev/shm."""
    return Path(tempfile.mkdtemp(prefix="virtwho-selftest.", dir=SHM_DIR))


# The name families the scripts under test read as knobs: removed
# from the ambient environment by run_env() unless a test explicitly
# provides them (see there).
_AMBIENT_KNOB_PREFIXES = ("VIRTWHO_", "VAULT_")
_AMBIENT_KNOB_NAMES = (
    "KUBEVIRT_TOKEN", "HYPERVISOR", "REGISTER", "RHEL_COMPOSE",
    # proxy environment: ambient proxy settings are exactly the
    # environment-leakage class the knob stripping exists for (a
    # developer shell or CI host proxy must not skew outcomes); the
    # with-proxy behaviors set the variables EXPLICITLY, which
    # always wins over the stripping
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
)


def run_env(env=None, unset=()):
    """The ambient environment with knob hygiene and overrides.

    The knob families the scripts under test read (VIRTWHO_*, VAULT_*,
    KUBEVIRT_TOKEN, HYPERVISOR, REGISTER, RHEL_COMPOSE -- the last
    covers VIRTWHO_INI_SHA256 through the prefix -- and the proxy
    environment variables, whose ambient values must not leak into
    the proxy-bypass pins) are removed from the
    AMBIENT environment first: an ambient value on the CI host or in a
    developer shell must not skew outcomes. Then the explicitly listed
    `unset` names (the python equivalent of `env -u NAME ...`), then
    the overrides on top. An override whose value is None removes the
    variable too, so parametrized matrices can express "set" and
    "unset" in one dict -- a test that names a knob explicitly always
    wins over the default-unset.
    """
    merged = dict(os.environ)
    for name in list(merged):
        if name.startswith(_AMBIENT_KNOB_PREFIXES) \
                or name in _AMBIENT_KNOB_NAMES:
            merged.pop(name)
    for name in unset:
        merged.pop(name, None)
    if env:
        for name, value in env.items():
            if value is None:
                merged.pop(name, None)
            else:
                merged[name] = str(value)
    return merged


def run(cmd, env=None, unset=(), cwd=None):
    """Run a command with captured output; never raises on failure.

    Real assertions and failure messages are the tests' job -- this
    helper only keeps the invocation hermetic. A hung script (e.g. a
    stub waiting on stdin that never arrives) fails the run after the
    bounded timeout instead of hanging the suite.
    """
    argv = [str(part) for part in cmd]
    return subprocess.run(
        argv,
        env=run_env(env, unset),
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )


def write_executable(path, text):
    """Write a stub script and make it executable."""
    path.write_text(text)
    os.chmod(path, 0o755)
    return path


def read_ini(path):
    """Parse an ini file with configparser (never awk)."""
    cfg = configparser.ConfigParser(interpolation=None)
    read = cfg.read(str(path))
    assert read, f"configparser could not read {path}"
    return cfg


def assert_ini_value(path, section, option, expected):
    """Assert an ini value with a real failure message."""
    cfg = read_ini(path)
    assert cfg.has_option(section, option), \
        f"missing ini option [{section}] {option}"
    actual = cfg.get(section, option)
    assert actual == expected, \
        f"[{section}] {option}: expected {expected!r}, got {actual!r}"


def ini_value(path, section, option):
    """An ini value, or the empty string when absent."""
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(str(path))
    return cfg.get(section, option, fallback="")


def file_mode(path):
    """The file mode as the symbolic string stat -c '%a' prints it."""
    return format(stat.S_IMODE(os.stat(path).st_mode), "o")


def assert_mode(path, expected):
    """Assert a file mode, e.g. assert_mode(ini, "600")."""
    actual = file_mode(path)
    assert actual == expected, \
        f"{path}: expected mode {expected}, got {actual}"


def rmtree(path):
    """Best-effort recursive removal (sandbox teardown)."""
    shutil.rmtree(path, ignore_errors=True)


# --- the selftest job's own vacuous-green guard -------------------------
# The Lint selftest job exits 0 on all-pass AND on a mass-skip (the
# exit-5 no-tests-collected protection covers only the empty-tree
# case). These helpers classify every recorded skip against the ONE
# justified set, so a conftest hook can fail the session when skips
# appear that nobody justified. Pure functions on plain data -- the
# classification itself is pinned by test_selftest_skip_guard.py.

# The only ever-justified skips, keyed by whether the tree is a
# git-less copy (the mutation battery's tar-copy has no .git index,
# so the two git-mode guard tests legitimately skip there; on a real
# checkout -- where the Lint job runs -- NOTHING may skip).
_mode_guard = ("test_plan_script_modes.py::TestPlanScriptModes::"
               "test_the_plans_do_reference_scripts")
_mode_guard_2 = ("test_plan_script_modes.py::TestPlanScriptModes::"
                 "test_every_directly_invoked_script_is_executable")
JUSTIFIED_SKIPS_GITLESS = (_mode_guard, _mode_guard_2)


def unexpected_skips(skip_records, gitless):
    """The (nodeid, reason) pairs nobody justified.

    *skip_records* is an iterable of (nodeid, reason) tuples as
    recorded from pytest skip reports. A record is justified when its
    nodeid ends with one of the allowed entries for the mode
    (gitless vs real checkout). The result preserves input order.
    """
    allowed = JUSTIFIED_SKIPS_GITLESS if gitless else ()
    return [
        (nodeid, reason)
        for nodeid, reason in skip_records
        if not any(nodeid.endswith(entry) for entry in allowed)
    ]


# --- the recording fake-ssh driver harness --------------------------------
# Shared by test_package_command_shapes.py and test_version_under_test.py
# (the two behavioral modules that run virtwho/base.py helpers against
# a recording FakeSSH inside a sandboxed copy of the virtwho package).
# The driver scripts themselves stay module-local -- their recorded
# command sets and printed fields are mode-specific -- but the sandbox
# setup, the minimal ini the virtwho package needs at import time and
# the KEY:VALUE output protocol are one contract, enforced once here
# instead of edited in lockstep across two files.

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


def run_fake_ssh_driver(sandbox, driver_text, args, ini=MINIMAL_INI):
    """Run a recording fake-ssh driver and parse its output.

    Copies the virtwho package into the sandbox (the ini lives at the
    tree root, the sibling of the virtwho/ dir, so the package's
    Configure writes stay inside the sandbox), writes the driver
    text, runs it with the tree path plus *args* as its argv and
    asserts it exited 0. The output protocol every recording driver
    speaks is one ``FIELD:value`` line per printed scalar plus the
    ``CMD:`` lines of the recorded command log; the return value is
    a dict keyed by the lower-cased field names (``raised``,
    ``message``, ``path``, ``init``, ...) with the commands collected
    under ``cmds``.
    """
    pkg_root = sandbox / "pkg"
    shutil.copytree(
        REPO_ROOT / "virtwho", pkg_root / "virtwho",
        ignore=shutil.ignore_patterns("__pycache__"))
    (pkg_root / "virtwho.ini").write_text(ini)
    driver = sandbox / "driver.py"
    driver.write_text(driver_text)
    proc = run([sys.executable, str(driver), str(pkg_root), *args])
    assert proc.returncode == 0, proc.stderr
    result = {
        "cmds": [line[4:] for line in proc.stdout.splitlines()
                 if line.startswith("CMD:")],
    }
    for line in proc.stdout.splitlines():
        if line.startswith("CMD:"):
            continue
        field, _, value = line.partition(":")
        result[field.lower()] = value
    return result
