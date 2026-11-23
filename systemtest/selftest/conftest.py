"""Fixtures for the virtwho-test host-side self-tests (systemtest/selftest).

The tests under this directory exercise the REAL bash scripts of
systemtest/scripts/ (generate-virtwho-ini.sh, discover-guest-ips.sh,
cleanup-secrets.sh, prepare-kubevirt.sh, install-deps.sh and the
run-tests.sh behaviors that can run hermetically) inside throwaway
sandboxes under /dev/shm, with PATH-injected command stubs and a
loopback fake Vault where needed: no network egress, no real
credentials -- every value is an RFC 2606/5737 dummy.

This is a host-side harness, deliberately placed OUTSIDE tests/:
tests/conftest.py carries session-scoped guest fixtures (ssh_guest
and friends) that would break collection on a CI host. The Testing
Farm guest plan (systemtest/plans/regression.fmf) discovers its
tests via `how: shell` and only ever runs `pytest tests/` through
run-tests.sh, so this directory is never collected there.
"""

import http.server
import json
import threading

import pytest

# Register _utils for assertion rewriting BEFORE importing it, so the
# plain asserts inside the helpers (assert_ini_value, assert_mode and
# friends) fail with real introspected messages instead of a bare
# traceback (register_assert_rewrite only affects modules imported
# after the call).
pytest.register_assert_rewrite("_utils")

# (imported after register_assert_rewrite on purpose -- see above)
from _utils import REPO_ROOT, rmtree, shm_workdir, unexpected_skips

# --- the selftest job's own vacuous-green guard -------------------------
# `python -m pytest systemtest/selftest/ -v` (the Lint selftest job)
# exits 0 on all-pass AND on a mass-skip: a collection-level mishap
# that silently skipped the whole suite would still be green. The
# hooks below record every skip and fail the session when one
# appears outside the justified set (see _utils.unexpected_skips:
# nothing may skip on a real checkout; the mutation battery's
# git-less copies legitimately skip the two git-mode guard tests).

_SKIP_RECORDS = []


def pytest_runtest_logreport(report):
    if report.outcome != "skipped" or report.when == "teardown":
        return
    if getattr(report, "wasxfail", False):
        return  # an xfail landing as skip is a pass, not a skip
    reason = ""
    longrepr = report.longrepr
    # a skip's longrepr is a (path, lineno, reason) tuple
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        reason = str(longrepr[2])
    elif longrepr is not None:
        reason = str(longrepr)
    _SKIP_RECORDS.append((report.nodeid, reason))


def pytest_sessionfinish(session, exitstatus):
    if exitstatus != 0:
        return  # already red; the skip audit would only add noise
    problems = unexpected_skips(
        _SKIP_RECORDS, gitless=not (REPO_ROOT / ".git").exists())
    if not problems:
        return
    lines = "\n  ".join(
        f"{nodeid}: {reason or '(no reason recorded)'}"
        for nodeid, reason in problems)
    # Loud, and RED: the session summary already printed green counts,
    # so this prints the contradiction and forces a failing exit.
    print(
        f"\nSELFTEST VACUOUS-GREEN GUARD: {len(problems)} unexpected "
        f"skip(s) in a session that exited 0 -- the selftest job must "
        f"not pass on skipped work. Justify the skip (add it to "
        f"_utils.unexpected_skips' allowed set) or fix the cause:\n"
        f"  {lines}\n")
    raise SystemExit(1)


@pytest.fixture
def sandbox():
    """A fresh mktemp sandbox under /dev/shm (tmpfs), removed after."""
    work = shm_workdir()
    try:
        yield work
    finally:
        rmtree(work)


class _FakeVaultHandler(http.server.BaseHTTPRequestHandler):
    """A Vault kv2 + AppRole login endpoint with obviously-fake values."""

    def log_message(self, *args):
        pass

    def _record(self):
        self.server.vault.requests.append(f"{self.command} {self.path}")

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._record()
        if self.path == "/v1/auth/approle/login":
            self._send(200, {"auth": {"client_token": "FAKE-vault-client-token"}})
        else:
            self._send(404, {"errors": ["not found"]})

    def do_GET(self):
        self._record()
        prefix = "/v1/apps/data/"
        if self.path.startswith(prefix):
            path = self.path[len(prefix):]
            remaining = self.server.vault.flaky_reset_counts.get(path, 0)
            if remaining > 0 or path in self.server.vault.always_reset_paths:
                # close the connection WITHOUT a response: the client
                # sees a connection-level failure (RemoteDisconnected),
                # the transient class the resolver's bounded retry is
                # for (flaky_reset_counts is a countdown -- the first N
                # requests to the path fail, then the server recovers)
                if remaining > 0:
                    self.server.vault.flaky_reset_counts[path] = remaining - 1
                self.close_connection = True
                return
            if path in self.server.vault.forbidden_paths:
                self._send(403, {"errors": ["forbidden"]})
                return
            if path in self.server.vault.broken_paths:
                self._send(500, {"errors": ["broken on purpose"]})
                return
            if path in self.server.vault.raw_responses:
                self._send(200, self.server.vault.raw_responses[path])
                return
            if path in self.server.vault.secrets:
                self._send(200, {"data": {"data": self.server.vault.secrets[path]}})
                return
        self._send(404, {"errors": ["not found"]})


class FakeVault:
    """A loopback stand-in for the Vault server.

    Obviously-fake values only; the ahv_* keys are deliberately
    absent so the unresolved-active-sentinel case has a key missing
    at a live path; "stringy" serves a bare string (malformed
    payload), "multiline" a value with a newline, and the broken
    path always answers HTTP 500. Every request is recorded so the
    tests can prove SELECTIVE resolution at the network level.
    """

    def __init__(self):
        self.requests = []
        # connection-level failure simulation for the bounded-retry
        # tests: flaky_reset_counts maps a path to the number of its
        # FIRST requests that fail (then it recovers);
        # always_reset_paths fails every request; forbidden_paths
        # answers HTTP 403 (an auth failure: the server ANSWERED, so
        # it must never be retried)
        self.flaky_reset_counts = {}
        self.always_reset_paths = set()
        self.forbidden_paths = set()
        self.secrets = {
            "cct-ci/virtwho-hypervisors": {
                "hyperv_username": "FAKE-vault-hyperv-username",
                "hyperv_password": "FAKE-vault-hyperv-password",
                "hyperv_guest_username": "FAKE-vault-hyperv-guest-username",
                "hyperv_guest_password": "FAKE-vault-hyperv-guest-password",
                "libvirt_username": "FAKE-vault-libvirt-username",
                "libvirt_password": "FAKE-vault-libvirt-password",
                "libvirt_guest_username": "FAKE-vault-libvirt-guest-username",
                "libvirt_guest_password": "FAKE-vault-libvirt-guest-password",
                "kubevirt_guest_username": "FAKE-vault-kubevirt-guest-username",
                "kubevirt_guest_password": "FAKE-vault-kubevirt-guest-password",
            },
            "cct-ci/candlepin/stage": {
                "username": "FAKE-vault-rhsm-username",
                "password": "FAKE-vault-rhsm-password",
            },
            "cct-ci/satellite-lab": {
                "satellite_username": "FAKE-vault-satellite-username",
                "satellite_password": "FAKE-vault-satellite-password",
                "ssh_username": "FAKE-vault-satellite-ssh-username",
                "ssh_password": "FAKE-vault-satellite-ssh-password",
                "activation_key": "FAKE-vault-satellite-activation-key",
            },
            "cct-ci/stringy": "FAKE-not-a-dict",
            "cct-ci/multiline": {
                "multiline_password": "FAKE-line1\nFAKE-line2",
            },
        }
        # 200 responses in the WRONG SHAPE (top-level envelope not
        # kv2): must be clean "malformed Vault response" errors, not
        # raw TypeErrors
        self.raw_responses = {
            "cct-ci/badshape": {"data": "FAKE-not-a-dict"},
            "cct-ci/listshape": ["FAKE", "not", "a", "dict"],
        }
        self.broken_paths = {"cct-ci/broken"}
        self._server = http.server.HTTPServer(("127.0.0.1", 0), _FakeVaultHandler)
        self._server.vault = self
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def addr(self):
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def reset(self):
        """Forget the request log (per-test selectivity proofs)."""
        self.requests.clear()

    def count(self, request_prefix):
        """Requests whose "<METHOD> <path>" starts with the prefix."""
        return sum(1 for r in self.requests if r.startswith(request_prefix))

    def requested(self, fragment):
        """Whether any request path contains the fragment."""
        return any(fragment in r for r in self.requests)

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture(scope="session")
def fake_vault():
    """The loopback fake Vault (plain http; every fake-Vault test
    explicitly opts in via VAULT_ALLOW_HTTP=1, the same opt-out the
    resolver offers for loopback/self-test servers)."""
    vault = FakeVault()
    try:
        yield vault
    finally:
        vault.shutdown()


@pytest.fixture
def redirect_vault(fake_vault):
    """A fake Vault that answers EVERY request with a redirect to the
    main fake Vault (which would happily resolve everything if the
    redirect were followed): the generator must refuse the redirect
    and fail instead -- proving the auth token is never re-sent to
    the address the response names."""
    target = fake_vault.addr

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _redirect(self):
            self.send_response(302)
            self.send_header("Location", target + self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            self._redirect()

        def do_POST(self):
            self._redirect()

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
