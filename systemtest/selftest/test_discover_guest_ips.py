"""Pytest self-test for discover-guest-ips.sh and its
hypervisor-builder (hb) query helper discover_guest_ips.py.

All values used here are dummy (non-secret, non-real): example.com
names and TEST-NET-1 addresses. The hypervisor side is faked at two
layers, hermetically (no network access, no real credentials):

  * libvirt/hyperv: a FAKE hypervisor-builder package, first on the
    helper's PYTHONPATH -- its LibvirtCLI/HypervCLI classes record
    their constructor arguments and guest_ip() calls (JSON lines in
    a file) and replay canned addresses. The vt side is pinned
    through this seam: the ini values reach hb as python data, the
    qemu+ssh:// URI is normalized before the constructor, an empty
    hyperv password never constructs the CLI at all, and a failed
    discovery keeps the ini value. The hardened QUERY forms
    themselves (the guest name on the ssh session's stdin, the
    PowerShell exact-name post-filter, the agent-then-arp fallback)
    moved INTO hb with this conversion -- their protection lives in
    hb's own test suite (tests/test_guest_ip.py in
    hypervisor-builder), not here;
  * ahv: unchanged from the bash suite -- PATH-injected curl stubs
    replay a canned Prism response and record the query.

Covers, behavior-first:
  * per-family discovery (libvirt/hyperv through the fake hb CLI,
    ahv Prism JSON with exact name match and empty NIC addresses
    skipped);
  * the write-back matrix: guest_ip lands in the ini, other values
    preserved, write through a symlink, mode kept, configparser-valid
    `key = value` spacing, malformed ini (duplicate option) degrading
    to a warning;
  * the abort/gate matrix: failed discovery keeps the ini value and
    exits 0 with a stderr warning, unsupported hypervisors are a
    no-op, a missing ini fails loudly, VIRTWHO_SKIP_IP_DISCOVERY=1
    skips with a message, a differing non-empty ini value is
    overwritten with a WARNING naming both values, and hyperv never
    attempts the hb query with an empty password;
  * the data-transport checks: the ini-sourced values ride into hb
    as python constructor/method arguments (never a command string
    or an URL -- the vt-side injection surface is gone by
    construction, pinned here), and the ahv guest_name is
    percent-encoded with the credentials on curl's stdin config
    stream;
  * the shell-ssh retirement: the libvirt/hyperv discovery makes NO
    shell ssh call anymore (the queries ride hb's own transport) --
    a reintroduced shell query would re-open the command-injection
    surface this conversion removed;
  * run-tests.sh guards its discovery invocation (source-pinned,
    like the password-flow checks).

Run: python -m pytest systemtest/selftest/ -v
"""

import json
import os
import re
import subprocess

import pytest
from _utils import (
    SCRIPTS_DIR,
    assert_ini_value,
    assert_mode,
    run_env,
    write_executable,
)

DISCOVER = SCRIPTS_DIR / "discover-guest-ips.sh"

# --- Fake hypervisor access ------------------------------------------------
# (the ahv curl stub is a verbatim port of the bash suite's; the
# libvirt/hyperv ssh stubs are gone with the shell queries -- the
# fake hb package below replaces them, and the ssh stub that remains
# exists only to PROVE no shell ssh happens anymore)

SSH_STUB = """\
#!/bin/bash
# Marker-only fake ssh: the libvirt/hyperv discovery queries ride
# hypervisor-builder's own transport now, so this stub must never
# run. When FAKE_SSH_MARKER is set, every invocation touches the
# file, so a checkpoint can prove ssh was NOT called at all.
[ -n "${FAKE_SSH_MARKER:-}" ] && touch "${FAKE_SSH_MARKER}"
echo "fake ssh: the guest-IP discovery must not shell out to ssh" >&2
exit 255
"""

CURL_STUB = """\
#!/bin/bash
# Fake curl: drain the stdin config stream (the real curl reads the
# credentials from there) and replay a canned Prism response. The
# response contains a non-matching VM and a NIC with an empty address
# so the parser's filtering is exercised.
# FAKE_CURL_MODE=record: record the received arguments (the URL
# included) for the injection checkpoint, and the stdin config stream
# too when FAKE_CURL_STDIN_FILE is set (the credential-transport
# checkpoint); then replay the response.
if [ "${FAKE_CURL_MODE:-}" = "record" ]; then
    cat > "${FAKE_CURL_STDIN_FILE:-/dev/null}"
    printf '%s\\n' "$*" > "${FAKE_CURL_RECORD_FILE}"
else
    cat > /dev/null
fi
if [ "${FAKE_CURL_MODE:-}" = "fail" ]; then
    exit 22
fi
printf '{"entities": ['
printf '{"metadata": {"name": "other-guest"}, "status": {"vm_nics": [{"ip_address": "192.0.2.90"}]}}, '
printf '{"metadata": {"name": "selftest-ahv-guest"}, "status": {"vm_nics": [{"ip_address": ""}, {"ip_address": "192.0.2.70"}]}}'
printf ']}\\n'
"""

# The fake hypervisor-builder CLI module, generated per family: the
# class name must match the real import path
# (hypervisor.virt.<family>.<family>cli) because the helper imports
# exactly that, and PYTHONPATH shadowing is what swaps the real
# pip-installed hb for this fake -- the CLI layer is faked, never
# the network (no paramiko, no ssh, no requests).
FAKE_CLI_TEMPLATE = '''\
"""Fake hypervisor-builder CLI class (generated by the self-test).

Records the constructor arguments and the guest_ip call as JSON
lines into FAKE_HB_RECORD_FILE, and answers from FAKE_HB_IP /
FAKE_HB_MODE: "" (the default) replays the canned address, "none"
makes guest_ip return None (a failed discovery), "fail" makes it
raise (an hb-level error). Dummy values only.
"""
import json
import os


def _record(event):
    path = os.environ.get("FAKE_HB_RECORD_FILE")
    if path:
        with open(path, "a") as handle:
            handle.write(json.dumps(event) + "\\n")


class {cls}:
    default_ip = "{ip}"

    def __init__(self, server, ssh_user, ssh_passwd):
        _record(dict(event="init", cls="{cls}", server=server,
                     ssh_user=ssh_user, ssh_passwd=ssh_passwd))
        self.server = server

    def guest_ip(self, guest_name):
        _record(dict(event="guest_ip", cls="{cls}",
                     guest_name=guest_name))
        mode = os.environ.get("FAKE_HB_MODE", "")
        if mode == "fail":
            raise RuntimeError("fake hb: discovery failed")
        if mode == "none":
            return None
        return os.environ.get("FAKE_HB_IP") or self.default_ip
'''

# --- A dummy ini with all three supported sections -----------------------

STANDARD_INI_TEXT = """\
[job]
hypervisor=libvirt

[virtwho]
server=192.0.2.1

[libvirt]
server=dummy-libvirt.example.com
username=dummy-libvirt-user
password=dummy-libvirt-pass
guest_name=selftest-libvirt-guest
guest_ip=192.0.2.99
guest_username=dummy-guest-user
guest_password=dummy-guest-pass

[hyperv]
server=dummy-hyperv.example.com
username=dummy-hyperv-user
password=dummy-hyperv-pass
guest_name=selftest-hyperv-guest
guest_ip=192.0.2.99
guest_username=dummy-guest-user
guest_password=dummy-guest-pass

[ahv]
server=dummy-ahv.example.com
username=dummy-ahv-user
password=dummy-ahv-pass
guest_name=selftest-ahv-guest
guest_ip=192.0.2.99
guest_username=dummy-guest-user
guest_password=dummy-guest-pass
"""


def make_ini(path):
    path.write_text(STANDARD_INI_TEXT)
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def stub_bin(sandbox):
    bin_dir = sandbox / "bin"
    bin_dir.mkdir()
    for name, text in (("ssh", SSH_STUB), ("curl", CURL_STUB)):
        write_executable(bin_dir / name, text)
    return bin_dir


@pytest.fixture
def fake_hb(sandbox):
    """A fake hypervisor-builder package shadowing the real one on
    PYTHONPATH: the helper imports hypervisor.virt.libvirt.
    libvirtcli.LibvirtCLI / hypervisor.virt.hyperv.hypervcli.
    HypervCLI, and this package answers those imports with the
    recording fakes. The canned addresses match the old ssh stubs
    (libvirt 192.0.2.50, hyperv 192.0.2.60) so the gate and
    write-back expectations carry over unchanged."""
    root = sandbox / "fakehb"
    pkg = root / "hypervisor" / "virt"
    for family, cls, ip in (
        ("libvirt", "LibvirtCLI", "192.0.2.50"),
        ("hyperv", "HypervCLI", "192.0.2.60"),
    ):
        family_dir = pkg / family
        family_dir.mkdir(parents=True)
        module = family_dir / f"{family}cli.py"
        module.write_text(
            FAKE_CLI_TEMPLATE.format(cls=cls, ip=ip))
    # the package markers the import chain walks through
    for init_dir in (root / "hypervisor", pkg,
                     pkg / "libvirt", pkg / "hyperv"):
        (init_dir / "__init__.py").write_text("")
    return root


def hb_events(record_path):
    """The JSON-line events the fake hb CLI recorded."""
    return [json.loads(line)
            for line in record_path.read_text().splitlines()]


@pytest.fixture
def discover(sandbox, stub_bin, fake_hb):
    """Run the REAL discover-guest-ips.sh with the curl/ssh stubs
    first on PATH and the fake hypervisor-builder first on
    PYTHONPATH."""
    def _discover(ini, family, *, env=None, unset=()):
        full = run_env(env, unset)
        full["PATH"] = f"{stub_bin}{os.pathsep}{full.get('PATH', '')}"
        full["PYTHONPATH"] = (
            f"{fake_hb}{os.pathsep}{full.get('PYTHONPATH', '')}")
        # bounded timeout: a hung script fails the run instead of
        # hanging the suite
        return subprocess.run(
            ["bash", str(DISCOVER), str(ini), family],
            env=full, capture_output=True, text=True, check=False,
            timeout=300)
    return _discover


# --- Per-family discovery parsing ----------------------------------------

class TestDiscoveryParsing:
    def test_libvirt_ip_from_hb_written_back(self, sandbox, discover):
        # the fake hb CLI answers 192.0.2.50; the write-back and the
        # preservation of the other options are the vt-side contract
        ini = make_ini(sandbox / "libvirt.ini")
        proc = discover(ini, "libvirt")
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.50")
        # other options are preserved
        assert_ini_value(ini, "libvirt", "guest_name",
                         "selftest-libvirt-guest")
        assert_ini_value(ini, "libvirt", "password", "dummy-libvirt-pass")
        assert_ini_value(ini, "virtwho", "server", "192.0.2.1")

    def test_hyperv_ip_from_hb_written_back(self, sandbox, discover):
        ini = make_ini(sandbox / "hyperv.ini")
        proc = discover(ini, "hyperv")
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "hyperv", "guest_ip", "192.0.2.60")
        assert_ini_value(ini, "hyperv", "guest_name",
                         "selftest-hyperv-guest")

    def test_qemu_ssh_uri_normalized_to_bare_host(self, sandbox,
                                                  discover):
        # a qemu+ssh://user@host/system URI in [libvirt] server must
        # be normalized before it reaches hb: the fake CLI records
        # the server it was CONSTRUCTED with, and that must be the
        # BARE host, never the scheme/userinfo/path
        ini = make_ini(sandbox / "libvirt-uri.ini")
        text_ = ini.read_text().replace(
            "server=dummy-libvirt.example.com",
            "server=qemu+ssh://dummy-libvirt.example.com/system")
        ini.write_text(text_)
        record = sandbox / "hb-record.jsonl"
        proc = discover(ini, "libvirt",
                        env={"FAKE_HB_RECORD_FILE": str(record)})
        assert proc.returncode == 0, proc.stderr
        init = hb_events(record)[0]
        assert init["event"] == "init", \
            "the fake hb CLI was never constructed"
        assert init["server"] == "dummy-libvirt.example.com", \
            "hb did not receive the bare host as the server " \
            "(URI normalization broken)"
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.50")

    def test_ahv_prism_json_exact_match_empty_skipped(self, sandbox,
                                                      discover):
        # the canned response holds a non-matching VM and a NIC with
        # an empty address: the parser must filter both
        ini = make_ini(sandbox / "ahv.ini")
        proc = discover(ini, "ahv")
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "ahv", "guest_ip", "192.0.2.70")
        assert_ini_value(ini, "ahv", "guest_name", "selftest-ahv-guest")


# --- The abort/gate matrix -----------------------------------------------

class TestDiscoveryGates:
    @pytest.mark.parametrize("family,stub_env", [
        pytest.param("ahv", {"FAKE_CURL_MODE": "fail"}, id="curl-fail"),
        pytest.param("libvirt", {"FAKE_HB_MODE": "fail"}, id="hb-error"),
        pytest.param("libvirt", {"FAKE_HB_MODE": "none"}, id="hb-none"),
    ])
    def test_failed_discovery_keeps_ini_and_warns(self, sandbox, discover,
                                                  family, stub_env):
        # the run must not die because a lab guest is unreachable
        # (an hb-level error or a None answer included), and the
        # failure output must not leak the credential values
        ini = make_ini(sandbox / f"fail-{family}.ini")
        proc = discover(ini, family, env=stub_env)
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, family, "guest_ip", "192.0.2.99")
        assert f"WARNING: could not discover the {family} guest_ip; " \
            "keeping the ini value" in proc.stderr, \
            f"the {family} discovery failure produced no warning on stderr"
        assert f"dummy-{family}-pass" not in proc.stdout + proc.stderr, \
            f"the {family} discovery failure leaked the password value"

    def test_unsupported_hypervisor_is_noop(self, sandbox, discover):
        ini = make_ini(sandbox / "noop.ini")
        proc = discover(ini, "esx")
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.99")

    def test_missing_ini_fails_loudly(self, sandbox, discover):
        # a usage error, not a silent skip
        proc = discover(sandbox / "does-not-exist.ini", "libvirt")
        assert proc.returncode != 0, \
            "discovery survived a missing ini file"

    def test_hyperv_empty_password_skips_query(self, sandbox, discover):
        # no empty-password query attempt: hb's transport would fall
        # back to an ssh-agent attempt instead of the ini credential,
        # which this suite's hardening rules out -- the CLI must not
        # be constructed at all; the ini value is kept with the
        # warning
        ini = make_ini(sandbox / "hyperv-nopass.ini")
        text = ini.read_text().replace("password=dummy-hyperv-pass",
                                       "password=")
        ini.write_text(text)
        record = sandbox / "hb-record.jsonl"
        proc = discover(ini, "hyperv",
                        env={"FAKE_HB_RECORD_FILE": str(record)})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert_ini_value(ini, "hyperv", "guest_ip", "192.0.2.99")
        assert not record.exists(), \
            "hyperv discovery constructed the hb CLI although the " \
            "password is empty"
        assert "WARNING: could not discover the hyperv guest_ip; " \
            "keeping the ini value" in proc.stderr, \
            "the empty-password hyperv run produced no fallback warning"

    def test_skip_knob_keeps_ini_value(self, sandbox, discover):
        # opt-out for labs with a known-good static guest_ip
        ini = make_ini(sandbox / "skip-knob.ini")
        proc = discover(ini, "libvirt",
                        env={"VIRTWHO_SKIP_IP_DISCOVERY": "1"})
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.99")
        assert "SKIP: VIRTWHO_SKIP_IP_DISCOVERY is set; keeping the " \
            "ini's existing guest_ip" in proc.stdout, \
            "the discovery opt-out produced no skip message"

    def test_ahv_newline_credential_named_warning(self, sandbox, discover):
        # a hand-edited ini can carry a multi-line value (configparser
        # joins indented continuation lines with a newline): such a
        # credential cannot ride curl's config-file syntax and must be
        # rejected with a NAMED warning (diagnosable), not a generic
        # curl parse error; the ini value is kept, exit 0
        ini = make_ini(sandbox / "ahv-newline.ini")
        text_ = ini.read_text().replace(
            "password=dummy-ahv-pass", "password=dummy-ahv-\n    pass")
        ini.write_text(text_)
        proc = discover(ini, "ahv")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "WARNING: the [ahv] username or password contains a " \
            "newline; skipping ahv guest-IP discovery" in proc.stderr, \
            "a newline-containing ahv credential produced no named warning"
        assert "WARNING: could not discover the ahv guest_ip; " \
            "keeping the ini value" in proc.stderr
        assert_ini_value(ini, "ahv", "guest_ip", "192.0.2.99")
        assert "dummy-ahv" not in proc.stderr, \
            "the newline rejection leaked the credential value"

    def test_overwrite_warning_names_both_values(self, sandbox, discover):
        # a wrong-IP success must be visible, not silent
        ini = make_ini(sandbox / "differ.ini")
        proc = discover(ini, "libvirt")
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.50")
        assert "WARNING: discovered libvirt guest_ip 192.0.2.50 differs " \
            "from the ini value 192.0.2.99; overwriting the ini" \
            in proc.stderr, \
            "an overwrite of a non-empty ini guest_ip produced no " \
            "warning naming both values"

    def test_same_value_discovery_no_overwrite_warning(self, sandbox,
                                                       discover):
        # the overwrite warning fires only on a DIFFERING non-empty
        # ini value: a discovery that agrees with the ini must be a
        # plain informational line (a spurious warning would train
        # operators to ignore the real ones)
        ini = make_ini(sandbox / "same-value.ini")
        text_ = ini.read_text().replace("guest_ip=192.0.2.99",
                                        "guest_ip=192.0.2.50")
        ini.write_text(text_)
        proc = discover(ini, "libvirt")
        assert proc.returncode == 0, proc.stderr
        assert "WARNING: discovered libvirt guest_ip" not in proc.stderr, \
            "a discovery matching the ini value emitted an overwrite warning"
        assert "Discovered libvirt guest_ip: 192.0.2.50 " \
            "(ini had: 192.0.2.50)" in proc.stdout


# --- The write-back matrix -----------------------------------------------

class TestWriteBack:
    def test_write_through_symlink_mode_preserved(self, sandbox, discover):
        # the tmpfs single-materialization setup: the tree holds a
        # symlink to the ini
        target = make_ini(sandbox / "materialized.ini")
        tree = sandbox / "tree"
        tree.mkdir()
        link = tree / "virtwho.ini"
        link.symlink_to(target)
        proc = discover(link, "libvirt")
        assert proc.returncode == 0, proc.stderr
        assert link.is_symlink(), "symlink was replaced by a regular file"
        assert re.search(r"^guest_ip=192\.0\.2\.50$", target.read_text(),
                         re.MULTILINE), \
            "write through the symlink did not reach the ini target"
        assert_mode(target, "600")

    def test_configparser_spacing_parsed(self, sandbox, discover):
        # `key = value` spacing is configparser-valid; the ini read
        # is configparser-based, never awk
        ini = sandbox / "spaced.ini"
        ini.write_text(
            "[job]\n"
            "hypervisor = libvirt\n\n"
            "[libvirt]\n"
            "server = dummy-libvirt.example.com\n"
            "username = dummy-libvirt-user\n"
            "password = dummy-libvirt-pass\n"
            "guest_name = selftest libvirt guest\n"
            "guest_ip = 192.0.2.99\n")
        os.chmod(ini, 0o600)
        proc = discover(ini, "libvirt")
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.50")
        assert_ini_value(ini, "libvirt", "guest_name",
                         "selftest libvirt guest")

    def test_malformed_ini_writeback_is_warning(self, sandbox, discover):
        # a duplicate option makes the strict write-back parser
        # refuse the whole file (the lenient reads still succeed, so
        # the discovery itself works): the write-back must be a
        # clean warning, the ini value kept, exit 0 -- no traceback
        # abort
        ini = make_ini(sandbox / "duplicate-option.ini")
        with ini.open("a") as f:
            f.write("guest_ip=192.0.2.98\n")
        proc = discover(ini, "libvirt")
        assert proc.returncode == 0, \
            "a malformed ini aborted the discovery (must be a warning, " \
            "not an error)"
        assert "WARNING: could not parse" in proc.stderr
        assert "WARNING: guest_ip write-back failed; keeping the ini " \
            "value" in proc.stderr
        assert re.search(r"^guest_ip=192\.0\.2\.99$", ini.read_text(), re.MULTILINE),\
            "the malformed-ini run modified the ini value it must keep"
        assert "Traceback" not in proc.stderr


# --- The data-transport checks ---------------------------------------------


class TestHbDataTransport:
    """The ini values reach hypervisor-builder as python data:
    server/username/password into the CLI constructor, the guest
    name into guest_ip(). Nothing from the ini is interpolated into
    a command string or an URL by the vt side -- the injection
    surface of the former shell queries moved INTO hb, whose own
    test suite pins the stdin transport and the exact-name filter
    (tests/test_guest_ip.py in hypervisor-builder); these pins
    guard the vt side of the seam."""

    def test_ini_values_reach_hb_as_arguments(self, sandbox, discover):
        ini = make_ini(sandbox / "data-transport.ini")
        record = sandbox / "hb-record.jsonl"
        proc = discover(ini, "libvirt",
                        env={"FAKE_HB_RECORD_FILE": str(record)})
        assert proc.returncode == 0, proc.stderr
        events = hb_events(record)
        init = next(e for e in events if e["event"] == "init")
        assert init["server"] == "dummy-libvirt.example.com"
        assert init["ssh_user"] == "dummy-libvirt-user"
        assert init["ssh_passwd"] == "dummy-libvirt-pass"
        call = next(e for e in events if e["event"] == "guest_ip")
        assert call["guest_name"] == "selftest-libvirt-guest"
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.50")

    def test_odd_guest_name_rides_as_data(self, sandbox, discover):
        # a guest_name containing a single quote and a touch
        # command: in the former shell queries a splice into a
        # command string would execute it; through the hb seam the
        # name is a python argument end-to-end, so nothing can
        # execute it and the name must arrive verbatim
        probe = sandbox / "injprobe"
        probe.mkdir()
        name = f"selftest-guest'; touch {probe}/INJECTED; echo '"
        ini = make_ini(sandbox / "odd-name.ini")
        ini.write_text(ini.read_text().replace(
            "guest_name=selftest-hyperv-guest", f"guest_name={name}"))
        record = sandbox / "hb-record.jsonl"
        proc = discover(ini, "hyperv",
                        env={"FAKE_HB_RECORD_FILE": str(record)})
        assert proc.returncode == 0, proc.stderr
        assert not (probe / "INJECTED").exists(), \
            "a quoted guest_name executed commands somewhere on the " \
            "way to hb (injection)"
        call = next(e for e in hb_events(record)
                    if e["event"] == "guest_ip")
        assert call["guest_name"] == name, \
            "the guest_name did not reach guest_ip() verbatim as data"
        # the discovery still works end-to-end for the odd-but-valid
        # name: the IP is written back and the name survives as data
        assert_ini_value(ini, "hyperv", "guest_ip", "192.0.2.60")
        assert_ini_value(ini, "hyperv", "guest_name", name)


class TestInjectionChecks:
    """The ahv injection checks (the ahv query stays in the shell);
    the libvirt/hyperv twins retired with the shell queries -- see
    TestHbDataTransport and hb's own test suite."""

    @pytest.fixture
    def payload(self, sandbox):
        """A guest_name containing a single quote and a touch command:
        spliced into a URL it would alter the query; percent-encoded
        it cannot."""
        probe = sandbox / "injprobe"
        probe.mkdir()
        return probe, f"selftest-guest'; touch {probe}/INJECTED; echo '"

    def test_ahv_guest_name_percent_encoded(self, sandbox, discover,
                                             payload):
        probe, name = payload
        ini = make_ini(sandbox / "injection-ahv.ini")
        ini.write_text(ini.read_text().replace(
            "guest_name=selftest-ahv-guest", f"guest_name={name}"))
        curl_args = probe / "curl-args"
        proc = discover(ini, "ahv",
                        env={"FAKE_CURL_MODE": "record",
                             "FAKE_CURL_RECORD_FILE": str(curl_args)})
        assert proc.returncode == 0, proc.stderr
        args = curl_args.read_text()
        assert name not in args, \
            "the raw guest_name was spliced into the Prism query string"
        assert "name=selftest-guest%27%3B%20touch" in args, \
            "the Prism query does not carry the percent-encoded guest name"
        # the canned response matches no VM with this name: a warning,
        # the ini value kept, the run continues
        assert_ini_value(ini, "ahv", "guest_ip", "192.0.2.99")

    def test_ahv_credentials_on_stdin_config_stream(self, sandbox,
                                                    discover):
        # the Prism credentials ride to curl through its STDIN config
        # stream (-K -) and never its command line, so they cannot
        # appear in /proc/<pid>/cmdline -- a regression to -u/--user
        # argv would put them on the process list
        ini = make_ini(sandbox / "cred-transport.ini")
        curl_args = sandbox / "cred-curl-args"
        curl_stdin = sandbox / "cred-curl-stdin"
        proc = discover(ini, "ahv",
                        env={"FAKE_CURL_MODE": "record",
                             "FAKE_CURL_RECORD_FILE": str(curl_args),
                             "FAKE_CURL_STDIN_FILE": str(curl_stdin)})
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "ahv", "guest_ip", "192.0.2.70")
        args = curl_args.read_text()
        assert "dummy-ahv-pass" not in args, \
            "the ahv password appeared in the curl command line " \
            "(would be visible in /proc)"
        assert "dummy-ahv-user" not in args, \
            "the ahv username appeared in the curl command line"
        assert 'user = "dummy-ahv-user:dummy-ahv-pass"' \
            in curl_stdin.read_text(), \
            "the ahv credentials did not reach curl through the stdin " \
            "config stream"


# --- run-tests.sh guards its discovery invocation -------------------------

class TestRunTestsGuard:
    def test_discovery_invocation_is_guarded(self):
        # run-tests.sh itself cannot run hermetically (it restarts
        # sshd and runs pytest), so the guard is pinned at the source
        # level, like the password-flow checks
        run_tests = (SCRIPTS_DIR / "run-tests.sh").read_text()
        assert 'if ! bash "${SCRIPT_DIR}/discover-guest-ips.sh" ' \
            '"$INI_FILE" "$HYP"; then' in run_tests, \
            "run-tests.sh no longer guards the discovery invocation"
        assert "WARNING: guest-IP discovery failed; keeping the ini" \
            in run_tests, \
            "run-tests.sh discovery guard lost its fallback warning"


# --- the shell-ssh retirement and the shared ssh transport baseline -------

class TestSharedSshBaseline:
    """The libvirt/hyperv discovery queries ride hypervisor-builder's
    own transport now, so they make NO shell ssh call anymore -- a
    reintroduced shell query would re-open the command-injection
    surface the hb conversion removed (behaviorally pinned below via
    the marker ssh stub). The shell ssh sites that REMAIN in
    systemtest/ still build on lib.sh's SSH_BASE_OPTS/ssh_exec
    baseline: one definition of the options every shell-side ssh
    invocation builds on, with a bounded connect on every site
    (three of the five historical sites carried no ConnectTimeout at
    all -- the same LESSON-02 class as an unbounded curl). The
    source-level pins cover lib.sh's single definition and the
    non-hermetic sites that splice it."""

    def test_discovery_makes_no_shell_ssh(self, sandbox, discover):
        # the marker ssh stub touches FAKE_SSH_MARKER on EVERY
        # invocation: after a libvirt and a hyperv discovery run
        # through the fake hb, the marker must not exist
        marker = sandbox / "ssh.marker"
        for family in ("libvirt", "hyperv"):
            ini = make_ini(sandbox / f"nossh-{family}.ini")
            proc = discover(ini, family,
                            env={"FAKE_SSH_MARKER": str(marker)})
            assert proc.returncode == 0, proc.stderr
            assert not marker.exists(), \
                f"the {family} discovery shelled out to ssh (the " \
                "query must ride hypervisor-builder's transport)"

    def test_the_baseline_is_single_sourced_in_lib_sh(self):
        # the baseline is defined exactly once, in lib.sh, and
        # ssh_exec prepends it; a ConnectTimeout drop anywhere is one
        # edit, caught here and by the mutation battery's
        # ssh-baseline-connect-timeout entry
        lib = (SCRIPTS_DIR / "lib.sh").read_text()
        assert ("SSH_BASE_OPTS=(-o StrictHostKeyChecking=no "
                "-o ConnectTimeout=10 -o LogLevel=ERROR)") in lib, \
            "lib.sh lost the shared ssh options baseline (or its " \
            "bounded connect)"
        assert 'ssh "${SSH_BASE_OPTS[@]}" "$@"' in lib, \
            "ssh_exec no longer prepends the shared baseline"

    def test_the_non_hermetic_ssh_sites_splice_the_baseline(self):
        # run-tests.sh's ssh-copy-id and key probe,
        # prepare-kubevirt.sh's guest-proxy ssh: they cannot run in
        # the sandbox (they need a provisioned guest), so their
        # wiring to the shared baseline is pinned at the source level
        for script, shape in (
            ("run-tests.sh", '"${SSH_BASE_OPTS[@]}"'),
            ("run-tests.sh", "ssh_exec -o BatchMode=yes"),
            ("prepare-kubevirt.sh", '"${SSH_BASE_OPTS[@]}"'),
        ):
            text = (SCRIPTS_DIR / script).read_text()
            assert shape in text, \
                f"{script} no longer builds its ssh calls on the " \
                "shared baseline ({shape} missing)"
