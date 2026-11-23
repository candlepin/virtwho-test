"""Pytest self-test for discover-guest-ips.sh (the pytest conversion
of the former test-discover-guest-ips.sh checkpoint script).

All values used here are dummy (non-secret, non-real): example.com
names and TEST-NET-1 addresses. The hypervisor side is faked with
PATH-injected ssh/sshpass/curl stubs that replay canned output (fake
DHCP data), so no network access and no real credentials are
involved. The stubs keep their exact recording semantics from the
bash suite: the recording ssh stub hands the received command to a
REAL shell with the received stdin attached (a payload spliced into
the command string would actually execute and be caught), and the
recording curl stub captures both its arguments and its stdin config
stream.

Covers, behavior-first:
  * per-family discovery parsing (libvirt domifaddr with the sshpass
    fallback and the key-based path and the ARP fallback, hyperv
    PowerShell output with IPv4 over IPv6, ahv Prism JSON with exact
    name match and empty NIC addresses skipped);
  * the write-back matrix: guest_ip lands in the ini, other values
    preserved, write through a symlink, mode kept, configparser-valid
    `key = value` spacing, malformed ini (duplicate option) degrading
    to a warning;
  * the abort/gate matrix: failed discovery keeps the ini value and
    exits 0 with a stderr warning, unsupported hypervisors are a
    no-op, a missing ini fails loudly, VIRTWHO_SKIP_IP_DISCOVERY=1
    skips with a message, a differing non-empty ini value is
    overwritten with a WARNING naming both values, and hyperv never
    attempts ssh with an empty password;
  * the injection checks: the ini-sourced guest_name is remote DATA,
    never remote code (libvirt/hyperv stdin transport with a fixed
    command string, the exact-name post-filter, ahv percent-encoding)
    and the ahv credentials ride to curl on its stdin config stream,
    never its command line;
  * the shared ssh transport baseline (lib.sh's SSH_BASE_OPTS /
    ssh_exec): every ssh the discovery makes carries the bounded,
    non-interactive, quiet options -- one definition, not five;
  * run-tests.sh guards its discovery invocation (source-pinned,
    like the password-flow checks).

Run: python -m pytest systemtest/selftest/ -v
"""

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

# --- Fake hypervisor access: ssh/sshpass/curl stubs on PATH --------------
# (verbatim ports of the bash suite's stubs; the FAKE_* environment
# knobs drive their behavior)

SSH_STUB = """\
#!/bin/bash
# Fake ssh for the self-test: replay canned hypervisor output based on
# the remote command (the last argument).
cmd="${*: -1}"

# FAKE_SSH_MARKER: when set, touch the file on EVERY invocation, so a
# checkpoint can prove ssh was NOT called at all.
[ -n "${FAKE_SSH_MARKER:-}" ] && touch "${FAKE_SSH_MARKER}"

# FAKE_SSH_DEST_FILE: when set, record the destination argument
# (second-to-last: user@host) for the URI-normalization checkpoint.
[ -n "${FAKE_SSH_DEST_FILE:-}" ] && printf '%s\n' "${@: -2:1}" > "${FAKE_SSH_DEST_FILE}"

# FAKE_SSH_MODE=down: simulate an unreachable hypervisor.
if [ "${FAKE_SSH_MODE:-}" = "down" ]; then
    exit 255
fi

# FAKE_SSH_MODE=record: behave like a real sshd for the injection
# checkpoint -- record the received command string and stdin, then
# hand the command to a REAL shell with the stdin attached. A payload
# spliced into the command string would actually execute here (and
# be caught); a name riding on stdin as data cannot. The full argv
# is recorded too (the shared ssh-baseline checkpoint: the options
# ssh was invoked with).
if [ "${FAKE_SSH_MODE:-}" = "record" ]; then
    cat > "${FAKE_SSH_RECORD_DIR}/stdin"
    printf '%s\\n' "$*" > "${FAKE_SSH_RECORD_DIR}/argv"
    printf '%s\\n' "$cmd" > "${FAKE_SSH_RECORD_DIR}/cmd"
    bash -c "$cmd" < "${FAKE_SSH_RECORD_DIR}/stdin" \\
        > /dev/null 2>&1 || true
    printf ' vnet1      52:54:00:aa:bb:dd    ipv4         192.0.2.50/24\\n'
    exit 0
fi

# Simulate "no key trust" for BatchMode unless explicitly allowed, so
# the password (sshpass) fallback path is exercised by default.
if [[ "$*" == *BatchMode=yes* && "${FAKE_SSH_ALLOW_BATCH:-}" != "1" ]]; then
    exit 255
fi

if [[ "$cmd" == *"virsh domifaddr"* ]]; then
    if [[ "$cmd" == *"--source agent"* ]]; then
        # FAKE_SSH_MODE=agent-empty: guest agent present but no address.
        if [ "${FAKE_SSH_MODE:-}" = "agent-empty" ]; then
            exit 0
        fi
        printf ' Name       MAC address    Protocol     Address\\n'
        printf -- '----------------------------------------------------------\\n'
        printf ' vnet0      52:54:00:aa:bb:cc    ipv4         127.0.0.1/8\\n'
        printf ' vnet1      52:54:00:aa:bb:dd    ipv4         192.0.2.50/24\\n'
    elif [[ "$cmd" == *"--source arp"* ]]; then
        printf ' vnet1      52:54:00:aa:bb:dd    ipv4         192.0.2.51/24\\n'
    else
        echo "fake ssh: unexpected domifaddr source in: $cmd" >&2
        exit 1
    fi
elif [[ "$cmd" == *"Get-VMNetworkAdapter"* ]]; then
    # IPv4 first, IPv6 second (what PowerShell prints for a guest NIC).
    printf '{192.0.2.60 fe80::abcd}\\n'
else
    echo "fake ssh: unexpected command: $cmd" >&2
    exit 1
fi
"""

SSHPASS_STUB = """\
#!/bin/bash
# Fake sshpass: drop the -e flag and run the wrapped command (the
# password arrives via SSHPASS, which this stub ignores).
shift
exec "$@"
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
    for name, text in (("ssh", SSH_STUB), ("sshpass", SSHPASS_STUB),
                       ("curl", CURL_STUB)):
        write_executable(bin_dir / name, text)
    return bin_dir


@pytest.fixture
def discover(sandbox, stub_bin):
    """Run the REAL discover-guest-ips.sh with the stubs first on PATH."""
    def _discover(ini, family, *, env=None, unset=()):
        full = run_env(env, unset)
        full["PATH"] = f"{stub_bin}{os.pathsep}{full.get('PATH', '')}"
        # bounded timeout: a hung script fails the run instead of
        # hanging the suite
        return subprocess.run(
            ["bash", str(DISCOVER), str(ini), family],
            env=full, capture_output=True, text=True, check=False,
            timeout=300)
    return _discover


# --- Per-family discovery parsing ----------------------------------------

class TestDiscoveryParsing:
    def test_libvirt_sshpass_fallback_loopback_excluded(self, sandbox,
                                                        discover):
        # the guest loopback reported by the agent source is excluded
        ini = make_ini(sandbox / "libvirt.ini")
        proc = discover(ini, "libvirt")
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.50")
        # other options are preserved
        assert_ini_value(ini, "libvirt", "guest_name",
                         "selftest-libvirt-guest")
        assert_ini_value(ini, "libvirt", "password", "dummy-libvirt-pass")
        assert_ini_value(ini, "virtwho", "server", "192.0.2.1")

    def test_libvirt_key_based_ssh(self, sandbox, discover):
        ini = make_ini(sandbox / "libvirt-key.ini")
        proc = discover(ini, "libvirt",
                        env={"FAKE_SSH_ALLOW_BATCH": "1"})
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.50")

    def test_qemu_ssh_uri_normalized_to_bare_host(self, sandbox, discover):
        # a qemu+ssh://user@host/system URI in [libvirt] server must
        # be normalized before the ssh call: the stub receives the
        # BARE host as the destination, never the scheme/userinfo/path
        ini = make_ini(sandbox / "libvirt-uri.ini")
        text_ = ini.read_text().replace(
            "server=dummy-libvirt.example.com",
            "server=qemu+ssh://dummy-libvirt.example.com/system")
        ini.write_text(text_)
        dest = sandbox / "ssh-dest"
        proc = discover(ini, "libvirt",
                        env={"FAKE_SSH_DEST_FILE": str(dest)})
        assert proc.returncode == 0, proc.stderr
        assert dest.read_text().splitlines() == \
            ["dummy-libvirt-user@dummy-libvirt.example.com"], \
            "ssh did not receive the bare host as user@host " \
            "(URI normalization broken)"
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.50")

    def test_libvirt_arp_fallback(self, sandbox, discover):
        # the guest agent reports nothing: the ARP source is used
        ini = make_ini(sandbox / "libvirt-arp.ini")
        proc = discover(ini, "libvirt", env={"FAKE_SSH_MODE": "agent-empty"})
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.51")

    def test_hyperv_powershell_ipv4_preferred(self, sandbox, discover):
        ini = make_ini(sandbox / "hyperv.ini")
        proc = discover(ini, "hyperv")
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, "hyperv", "guest_ip", "192.0.2.60")
        assert_ini_value(ini, "hyperv", "guest_name",
                         "selftest-hyperv-guest")

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
        pytest.param("libvirt", {"FAKE_SSH_MODE": "down"}, id="ssh-down"),
    ])
    def test_failed_discovery_keeps_ini_and_warns(self, sandbox, discover,
                                                  family, stub_env):
        # the run must not die because a lab guest is unreachable
        ini = make_ini(sandbox / f"fail-{family}.ini")
        proc = discover(ini, family, env=stub_env)
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(ini, family, "guest_ip", "192.0.2.99")
        assert f"WARNING: could not discover the {family} guest_ip; " \
            "keeping the ini value" in proc.stderr, \
            f"the {family} discovery failure produced no warning on stderr"

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

    def test_hyperv_empty_password_skips_ssh(self, sandbox, discover):
        # no empty-password login attempt: the ini value is kept with
        # the warning
        ini = make_ini(sandbox / "hyperv-nopass.ini")
        text = ini.read_text().replace("password=dummy-hyperv-pass",
                                       "password=")
        ini.write_text(text)
        marker = sandbox / "hyperv-nopass.marker"
        proc = discover(ini, "hyperv",
                        env={"FAKE_SSH_MARKER": str(marker)})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert_ini_value(ini, "hyperv", "guest_ip", "192.0.2.99")
        assert not marker.exists(), \
            "hyperv discovery attempted ssh although the password is empty"
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
        # a duplicate option makes configparser refuse the whole
        # file: the write-back must be a clean warning, the ini value
        # kept, exit 0 -- no traceback abort
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


# --- The injection checks -------------------------------------------------


class TestInjectionChecks:
    @pytest.fixture
    def payload(self, sandbox):
        """A guest_name containing a single quote and a touch command:
        spliced into a command string it would execute and leave the
        marker; riding on stdin as data it cannot."""
        probe = sandbox / "injprobe"
        probe.mkdir()
        return probe, f"selftest-guest'; touch {probe}/INJECTED; echo '"

    def test_libvirt_guest_name_is_data_not_code(self, sandbox, discover,
                                                 payload):
        # the recording ssh stub behaves like a real sshd: it hands
        # the received command string to a REAL shell with the
        # received stdin attached, so a name spliced into the command
        # string would execute here
        probe, name = payload
        ini = make_ini(sandbox / "injection.ini")
        ini.write_text(ini.read_text().replace(
            "guest_name=selftest-libvirt-guest", f"guest_name={name}"))
        proc = discover(ini, "libvirt",
                        env={"FAKE_SSH_MODE": "record",
                             "FAKE_SSH_RECORD_DIR": str(probe)})
        assert proc.returncode == 0, proc.stderr
        assert not (probe / "INJECTED").exists(), \
            "a quoted guest_name executed commands on the remote side " \
            "(injection)"
        stdin = (probe / "stdin").read_text()
        cmd = (probe / "cmd").read_text()
        assert name in stdin, \
            "the guest_name did not reach the remote side as stdin data"
        assert name not in cmd, \
            "the guest_name was spliced into the remote command string"
        # the discovery still works end-to-end for the odd-but-valid
        # name: the IP is written back and the name survives as data
        assert_ini_value(ini, "libvirt", "guest_ip", "192.0.2.50")
        assert_ini_value(ini, "libvirt", "guest_name", name)

    def test_hyperv_guest_name_is_data_not_code(self, sandbox, discover,
                                                payload):
        probe, name = payload
        ini = make_ini(sandbox / "injection-hyperv.ini")
        ini.write_text(ini.read_text().replace(
            "guest_name=selftest-hyperv-guest", f"guest_name={name}"))
        proc = discover(ini, "hyperv",
                        env={"FAKE_SSH_MODE": "record",
                             "FAKE_SSH_RECORD_DIR": str(probe)})
        assert proc.returncode == 0, proc.stderr
        assert not (probe / "INJECTED").exists(), \
            "a quoted guest_name executed commands on the hyperv side " \
            "(injection)"
        cmd = (probe / "cmd").read_text()
        stdin = (probe / "stdin").read_text()
        assert name not in cmd, \
            "the guest_name was spliced into the PowerShell command string"
        assert name in stdin, \
            "the guest_name did not reach the hyperv side as stdin data"
        # the PowerShell query post-filters the adapter list by the
        # EXACT name: -VMName alone treats wildcard characters as
        # patterns, so a name containing * or ? must not be able to
        # match a different VM
        assert "Where-Object Name -eq $n" in cmd, \
            "the PowerShell query does not post-filter by the exact VM name"

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


# --- the shared ssh transport baseline ------------------------------------

class TestSharedSshBaseline:
    """lib.sh's SSH_BASE_OPTS/ssh_exec: the one transport baseline
    every shell-side ssh invocation in systemtest/ builds on. Three
    of the five historical sites carried no ConnectTimeout at all --
    an unbounded ssh connect hangs its phase until the farm timeout
    kills the job, the same LESSON-02 class as an unbounded curl.
    The behavioral pin below exercises both invocation shapes the
    discovery uses (the key path through ssh_exec, the password path
    through the array spliced into a `sshpass -e ssh` line -- sshpass
    execvp's the ssh binary itself, so the wrapper cannot be used
    there); the source-level pins cover lib.sh's single definition
    and the non-hermetic sites that splice it."""

    def test_discovery_ssh_calls_carry_the_baseline(self, sandbox,
                                                    discover):
        # the recording ssh stub sees the full argv of every ssh the
        # REAL script made; each family here exercises one transport
        # shape (libvirt: the ssh_exec key path; hyperv: the sshpass
        # splice)
        record = sandbox / "ssh-record"
        record.mkdir()
        for family in ("libvirt", "hyperv"):
            ini = make_ini(sandbox / f"baseline-{family}.ini")
            proc = discover(ini, family,
                            env={"FAKE_SSH_MODE": "record",
                                 "FAKE_SSH_RECORD_DIR": str(record)})
            assert proc.returncode == 0, proc.stderr
            argv = (record / "argv").read_text()
            assert "-o StrictHostKeyChecking=no" in argv, \
                f"the {family} ssh call lost StrictHostKeyChecking=no"
            assert "-o ConnectTimeout=10" in argv, \
                f"the {family} ssh call lost its bounded connect"
            assert "-o LogLevel=ERROR" in argv, \
                f"the {family} ssh call lost the quiet log level"

    def test_the_baseline_is_single_sourced_in_lib_sh(self):
        # the baseline is defined exactly once, in lib.sh, and
        # ssh_exec prepends it; a ConnectTimeout drop anywhere is one
        # edit, caught here and by the behavioral pin above
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
