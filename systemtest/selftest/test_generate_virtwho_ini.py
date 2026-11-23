"""Pytest self-test for generate-virtwho-ini.sh and the tmpfs/symlink/
ssh_config/cleanup/prepare plumbing (the pytest conversion of the
former test-generate-virtwho-ini.sh checkpoint script).

All values used here are dummy (non-secret, non-real):
example.invalid / example.com names, TEST-NET-1/2/3 addresses,
all-zero digests, FAKE-* Vault payloads. The REAL scripts under
systemtest/scripts/ run inside throwaway /dev/shm sandboxes; a
loopback fake Vault stands in for the secret store. No network
egress, no real credentials.

Covers, behavior-first:
  * env-only fallback generation (VIRTWHO_INI_URL unset): sections,
    options, values, 0600 mode, newline-value rejection;
  * base-download + env-overlay mode: env secrets win, base values
    survive, pass-through sections, the SHA256 pin, and the loud
    failures (bad download, malformed/empty base, planted plaintext
    credentials, sentinels in never-resolved sections);
  * @vault: sentinel resolution against the fake Vault: SELECTIVE
    (active sections only, proven in the output ini AND in the
    server's request log), AppRole and static-token paths, env-over-
    resolved precedence, one read per path (successes and failures),
    multi_hypervisors (env and base forms, normalized write-back),
    and the clean failures (unresolved active sentinel, redirects,
    plaintext http, malformed payloads, missing credentials, the
    strict knob);
  * the legacy KUBEVIRT_TOKEN alias, misspelled-variable warnings,
    the [job] plan-level aliases, the ESX/VCENTER clash;
  * the destination knob (CCT-3155, test_destination_knob.py): the
    container default, the [rhsm] overlay's immunity to stale
    VIRTWHO_RHSM_* stage secrets, the no-Vault-needed container pass
    vs the stage contrast, the clean invalid-knob failure, and the
    checked-in overlay file's own contract; the prefix-awareness of
    the three former /subscription hardcode sites
    (test_destination_prefix.py); the prepare/teardown behaviors of
    prepare-candlepin.sh and the pod-teardown half of
    cleanup-secrets.sh (test_prepare_candlepin.py);
  * single materialization: symlinks survive cp -a, configparser and
    the generator itself write THROUGH them;
  * the ssh_config approach (ssh -G resolves the tmpfs IdentityFile)
    and the REAL cleanup-secrets.sh against a sandboxed tree with
    the same layout as a CI guest;
  * the REAL prepare-kubevirt.sh write-side kubeconfig confinement;
  * the wrapper-script credential contracts (env-or-random password
    flow, env-var squid image, POLARION_URL, the real run-tests.sh
    ini-merge heredoc).

Run: python -m pytest systemtest/selftest/ -v
"""

import configparser
import importlib.util
import os
import re
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from _utils import (
    REPO_ROOT,
    SCRIPTS_DIR,
    assert_ini_value,
    assert_mode,
    ini_value,
    read_ini,
    rmtree,
    run,
    shm_workdir,
    write_executable,
)

GENERATOR = SCRIPTS_DIR / "generate-virtwho-ini.sh"

# --- Fixtures -----------------------------------------------------------

@pytest.fixture
def generate():
    """Run the REAL generator; a successful run is asserted here so a
    broken generator fails every dependent test with its stderr."""
    def _generate(output, *, env=None, unset=(), expect_success=True):
        proc = run(["bash", GENERATOR, output], env=env, unset=unset)
        if expect_success:
            assert proc.returncode == 0, (
                "generate-virtwho-ini.sh failed "
                f"(exit {proc.returncode}):\n{proc.stderr}")
        return proc
    return _generate


@pytest.fixture(scope="module")
def env_only_ini():
    """One env-only generation shared by the parse tests (the inputs
    are constants, so the output is deterministic)."""
    work = shm_workdir()
    try:
        out = work / "env-only.ini"
        proc = run(["bash", GENERATOR, out],
                   env=ENV_ONLY_ENV, unset=("VIRTWHO_INI_URL",))
        assert proc.returncode == 0, proc.stderr
        yield out
    finally:
        rmtree(work)


@pytest.fixture(scope="module")
def base_ini():
    """The dummy sanitized base ini (non-secret values only)."""
    work = shm_workdir()
    try:
        path = work / "base.ini"
        path.write_text(BASE_INI_TEXT)
        yield path
    finally:
        rmtree(work)


@pytest.fixture(scope="module")
def overlay_ini(base_ini):
    """One base+overlay generation shared by the overlay tests."""
    out = base_ini.parent / "overlay.ini"
    # stage tier: the [rhsm] base values this fixture asserts must
    # survive the env overlay -- the container default would replace
    # the section with the synthetic values instead
    proc = run(["bash", GENERATOR, out], env={
        "HYPERVISOR": "libvirt",
        "REGISTER": "rhsm",
        "RHEL_COMPOSE": "RHEL-10.0-DUMMY",
        "VIRTWHO_DESTINATION": "stage",
        "VIRTWHO_ESX_PASSWORD": "env-esx-pass",
        "VIRTWHO_ESX_GUEST_IP": "192.0.2.51",
        "VIRTWHO_RHEVM_SERVER": "dummy-rhevm.example.com",
        "VIRTWHO_INI_URL": f"file://{base_ini}",
    })
    assert proc.returncode == 0, proc.stderr
    return out


def write_base(sandbox, name, text):
    path = sandbox / name
    path.write_text(text)
    return path


@pytest.fixture
def sentinel_base(sandbox):
    """A sentinel-bearing base (fake values only; ahv keys missing in
    the fake Vault on purpose for the unresolved-sentinel case)."""
    return write_base(sandbox, "sentinel-base.ini", SENTINEL_BASE_TEXT)


@pytest.fixture
def broken_base(sandbox):
    """A base whose [hyperv] sentinels point at the always-500 path."""
    return write_base(sandbox, "broken-base.ini", BROKEN_BASE_TEXT)


@pytest.fixture
def badsent_base(sandbox):
    """A base with malformed sentinel targets (space in path, string
    payload, wrong-shape envelopes, newline value)."""
    return write_base(sandbox, "badsent-base.ini", BADSENT_BASE_TEXT)


@pytest.fixture
def multi_base(sandbox):
    return write_base(sandbox, "multi-base.ini", MULTI_BASE_TEXT)


@pytest.fixture
def sentinel_elsewhere(sandbox):
    """A base whose ONLY sentinels sit in the non-active [libvirt]."""
    return write_base(sandbox, "sentinel-elsewhere.ini",
                      SENTINEL_ELSEWHERE_TEXT)


def plan_env(hypervisor, register="rhsm", compose=""):
    return {"HYPERVISOR": hypervisor, "REGISTER": register,
            "RHEL_COMPOSE": compose}


def vault_env(fake_vault, **extra):
    """The standard fake-Vault environment (loopback plain http is
    explicitly opted into, like every fake-Vault case in the former
    bash suite)."""
    env = {"VAULT_ALLOW_HTTP": "1", "VAULT_ADDR": fake_vault.addr,
           "VAULT_TOKEN": "FAKE-static-token"}
    env.update(extra)
    return env


NO_VAULT_CREDS = ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_ROLE_ID",
                  "VAULT_SECRET_ID", "VIRTWHO_VAULT_REQUIRED")

# --- 1) Env-only fallback generation (VIRTWHO_INI_URL unset) -----------

# Stage tier pinned: these env-only expectations assert the
# VIRTWHO_RHSM_* overlay of [rhsm], which the container default no
# longer applies (the container tier fills [rhsm] with the synthetic
# values -- covered by test_destination_knob.py).
ENV_ONLY_ENV = {
    "HYPERVISOR": "libvirt",
    "REGISTER": "rhsm",
    "RHEL_COMPOSE": "RHEL-10.0-DUMMY",
    "VIRTWHO_DESTINATION": "stage",
    "VIRTWHO_VCENTER_SERVER": "dummy-vcenter.example.com",
    "VIRTWHO_VCENTER_USERNAME": "dummy-vcenter-user",
    "VIRTWHO_VCENTER_PASSWORD": "dummy-vcenter-pass",
    "VIRTWHO_ESX_GUEST_IP": "192.0.2.50",
    "VIRTWHO_ESX_GUEST_USERNAME": "dummy-guest-user",
    "VIRTWHO_ESX_GUEST_PASSWORD": "dummy-guest-pass",
    "VIRTWHO_RHEVM_SERVER": "dummy-rhevm.example.com",
    "VIRTWHO_RHEVM_USERNAME": "dummy-rhevm-user",
    "VIRTWHO_RHEVM_PASSWORD": "dummy-rhevm-pass",
    "VIRTWHO_LIBVIRT_SERVER": "dummy-libvirt.example.com",
    "VIRTWHO_LIBVIRT_USERNAME": "dummy-libvirt-user",
    "VIRTWHO_LIBVIRT_PASSWORD": "dummy-libvirt-pass",
    "VIRTWHO_KUBEVIRT_TOKEN": "dummy-kubevirt-token",
    "VIRTWHO_KUBEVIRT_ENDPOINT": "https://dummy-kubevirt.example.com",
    "VIRTWHO_RHSM_SERVER": "stage.example.com",
    "VIRTWHO_RHSM_USERNAME": "dummy-rhsm-user",
    "VIRTWHO_RHSM_PASSWORD": "dummy-rhsm-pass",
    "VIRTWHO_RHSM_DEFAULT_ORG": "dummy-org",
    "VIRTWHO_SATELLITE_SERVER": "dummy-satellite.example.com",
    "VIRTWHO_SATELLITE_USERNAME": "dummy-sat-user",
    "VIRTWHO_SATELLITE_PASSWORD": "dummy-sat-pass",
}

ENV_ONLY_EXPECTED = [
    ("job", "hypervisor", "libvirt"),
    ("job", "register", "rhsm"),
    ("job", "rhel_compose", "RHEL-10.0-DUMMY"),
    ("esx", "server", "dummy-vcenter.example.com"),
    ("esx", "username", "dummy-vcenter-user"),
    ("esx", "password", "dummy-vcenter-pass"),
    ("esx", "guest_ip", "192.0.2.50"),
    ("esx", "guest_username", "dummy-guest-user"),
    ("esx", "guest_password", "dummy-guest-pass"),
    ("rhevm", "server", "dummy-rhevm.example.com"),
    ("rhevm", "username", "dummy-rhevm-user"),
    ("rhevm", "password", "dummy-rhevm-pass"),
    ("libvirt", "server", "dummy-libvirt.example.com"),
    ("libvirt", "username", "dummy-libvirt-user"),
    ("libvirt", "password", "dummy-libvirt-pass"),
    ("kubevirt", "token", "dummy-kubevirt-token"),
    ("kubevirt", "endpoint", "https://dummy-kubevirt.example.com"),
    ("kubevirt", "config_file", "/root/kubeconfig"),
    ("kubevirt", "config_file_no_cert", "/root/kubeconfig-no-cert"),
    ("rhsm", "server", "stage.example.com"),
    ("rhsm", "username", "dummy-rhsm-user"),
    ("rhsm", "password", "dummy-rhsm-pass"),
    ("rhsm", "default_org", "dummy-org"),
    ("satellite", "server", "dummy-satellite.example.com"),
    ("satellite", "username", "dummy-sat-user"),
    ("satellite", "password", "dummy-sat-pass"),
]

# every option the suite accesses must exist (empty is fine, missing
# is not)
REQUIRED_OPTIONS = {
    "job": ("hypervisor", "register", "rhel_compose", "rhel_compose_path",
            "multi_hypervisors"),
    "virtwho": ("server", "username", "password", "port", "package",
                "proxy_server", "proxy_port"),
    "rhsm": ("server", "username", "password", "prefix", "port",
             "default_org", "activation_key"),
    "satellite": ("server", "username", "password", "ssh_username",
                  "ssh_password", "default_org", "secondary_org",
                  "activation_key"),
    "esx": ("server", "username", "password", "ssh_username", "ssh_password",
            "ssh_ip", "esx_ip", "esx_username", "esx_password"),
}


class TestEnvOnlyGeneration:
    def test_file_mode_is_0600(self, env_only_ini):
        assert_mode(env_only_ini, "600")

    @pytest.mark.parametrize("section",
                             ["job", "virtwho", "rhsm", "satellite", "esx"])
    def test_core_sections_always_emitted(self, env_only_ini, section):
        assert read_ini(env_only_ini).has_section(section)

    @pytest.mark.parametrize("section", ["libvirt", "rhevm", "kubevirt"])
    def test_active_and_env_backed_sections_emitted(self, env_only_ini,
                                                    section):
        # libvirt: the active hypervisor; rhevm/kubevirt: env vars set
        assert read_ini(env_only_ini).has_section(section)

    @pytest.mark.parametrize("section", ["hyperv", "ahv", "xen", "local"])
    def test_sections_without_env_vars_omitted(self, env_only_ini, section):
        assert not read_ini(env_only_ini).has_section(section)

    @pytest.mark.parametrize("section,option,expected", ENV_ONLY_EXPECTED)
    def test_env_values_land_in_sections(self, env_only_ini, section,
                                         option, expected):
        assert_ini_value(env_only_ini, section, option, expected)

    @pytest.mark.parametrize(
        "section,option",
        [(section, option)
         for section, options in REQUIRED_OPTIONS.items()
         for option in options])
    def test_required_options_exist(self, env_only_ini, section, option):
        assert read_ini(env_only_ini).has_option(section, option), \
            f"missing required option [{section}] {option}"

    def test_newline_containing_value_rejected(self, sandbox, generate):
        # a newline inside a value would be written as a literal new
        # line and silently corrupt the ini; the generator must fail
        # loudly instead
        out = sandbox / "env-only.ini"
        proc = generate(out, expect_success=False,
                        env={**plan_env("libvirt"),
                             "VIRTWHO_RHEVM_PASSWORD": "line1\nline2"},
                        unset=("VIRTWHO_INI_URL",))
        assert proc.returncode != 0, \
            "generator accepted a value containing a newline"
        assert not out.exists(), \
            "generator wrote output despite rejecting the value"


# --- 2) Base-download + env-overlay mode (dummy file:// base) -----------

BASE_INI_TEXT = """\
; dummy sanitized base ini -- non-secret values only, all fake.
; Credential-shaped options (username/password/token/...) are
; deliberately absent: they come from the VIRTWHO_* env secrets and a
; base carrying them is rejected (see the forbidden-key case below).
[job]
hypervisor=esx
register=rhsm
rhel_compose=RHEL-9.9-DUMMY

[virtwho]
server=base-virtwho.example.com
port=22
repo=http://base-mirror.example.com/virt-who.repo
brew=http://base-brew.example.com/koji
proxy_server=base-proxy.example.com
proxy_port=3128

[rhsm]
server=base-rhsm.example.com
default_org=base-org

[esx]
server=base-esx.example.com
ssh_ip=192.0.2.10
esx_cluster=base-cluster
guest_name=base-guest.example.invalid

; a section outside the generator table: must be passed through
[beaker]
server=base-beaker.example.com
"""

OVERLAY_BASE_SURVIVES = [
    ("esx", "server", "base-esx.example.com"),
    ("esx", "esx_cluster", "base-cluster"),
    ("virtwho", "server", "base-virtwho.example.com"),
    ("virtwho", "brew", "http://base-brew.example.com/koji"),
    ("rhsm", "server", "base-rhsm.example.com"),
    ("rhsm", "default_org", "base-org"),
    # non-table section of the base is passed through unchanged
    ("beaker", "server", "base-beaker.example.com"),
]


class TestBaseOverlay:
    def test_file_mode_is_0600(self, overlay_ini):
        assert_mode(overlay_ini, "600")

    def test_env_secret_wins_over_base(self, overlay_ini):
        assert_ini_value(overlay_ini, "esx", "password", "env-esx-pass")

    @pytest.mark.parametrize("section,option,expected", OVERLAY_BASE_SURVIVES)
    def test_base_values_survive_when_env_silent(self, overlay_ini, section,
                                                 option, expected):
        assert_ini_value(overlay_ini, section, option, expected)

    def test_env_only_option_added_on_top_of_base(self, overlay_ini):
        assert_ini_value(overlay_ini, "esx", "guest_ip", "192.0.2.51")

    def test_env_emitted_section_value(self, overlay_ini):
        # section emitted because an env var is set, value from env
        assert_ini_value(overlay_ini, "rhevm", "server",
                         "dummy-rhevm.example.com")

    @pytest.mark.parametrize("option,value",
                             [("hypervisor", "libvirt"),
                              ("rhel_compose", "RHEL-10.0-DUMMY")])
    def test_plan_level_preseed_wins_over_base(self, overlay_ini, option,
                                               value):
        assert_ini_value(overlay_ini, "job", option, value)

    def test_failing_base_download_fails_the_generator(self, sandbox,
                                                       generate):
        out = sandbox / "nope.ini"
        proc = generate(out, expect_success=False,
                        env={"VIRTWHO_INI_URL":
                              "file:///nonexistent-virtwho-base.ini"})
        assert proc.returncode != 0, \
            "generator survived a failing base download"
        assert not out.exists(), \
            "generator wrote output despite failed download"

    def test_sha256_pin_mismatch_aborts(self, sandbox, generate, base_ini):
        # the base selects where resolved credentials are sent, so a
        # pinned digest must abort a tampered/incorrect base
        out = sandbox / "sha256-bad.ini"
        proc = generate(out, expect_success=False, env={
            "HYPERVISOR": "esx", "REGISTER": "rhsm", "RHEL_COMPOSE": "",
            "VIRTWHO_INI_URL": f"file://{base_ini}",
            "VIRTWHO_INI_SHA256": "0" * 64})
        assert proc.returncode != 0, \
            "generator accepted a base ini that does not match " \
            "VIRTWHO_INI_SHA256"
        assert not out.exists(), \
            "generator wrote output despite a VIRTWHO_INI_SHA256 mismatch"
        assert "ERROR: the downloaded base ini does not match " \
            "VIRTWHO_INI_SHA256" in proc.stderr

    def test_sha256_pin_match_passes(self, sandbox, generate, base_ini):
        import hashlib
        digest = hashlib.sha256(base_ini.read_bytes()).hexdigest()
        out = sandbox / "sha256-good.ini"
        proc = generate(out, env={
            "HYPERVISOR": "esx", "REGISTER": "rhsm", "RHEL_COMPOSE": "",
            "VIRTWHO_INI_URL": f"file://{base_ini}",
            "VIRTWHO_INI_SHA256": digest})
        assert_ini_value(out, "esx", "server", "base-esx.example.com")
        assert "Base ini matches the VIRTWHO_INI_SHA256 pin" in proc.stdout

    def test_malformed_base_fails_with_clean_error(self, sandbox, generate):
        garbage = sandbox / "garbage.ini"
        garbage.write_text("this is not an ini file\nno section header here\n")
        out = sandbox / "garbage-out.ini"
        proc = generate(out, expect_success=False,
                        env={"VIRTWHO_INI_URL": f"file://{garbage}"})
        assert proc.returncode != 0, "generator survived a malformed base ini"
        assert "ERROR: could not parse the downloaded base ini" in proc.stderr
        assert "Traceback" not in proc.stderr, \
            "malformed base produced a raw Python traceback"
        assert not out.exists()

    def test_empty_base_body_fails_loudly(self, sandbox, generate):
        # an empty body is a download failure, not a license for the
        # silent env-only fallback (that fallback is only for an
        # unset URL)
        empty = sandbox / "empty.ini"
        empty.write_text("")
        out = sandbox / "empty-out.ini"
        proc = generate(out, expect_success=False,
                        env={"VIRTWHO_INI_URL": f"file://{empty}"})
        assert proc.returncode != 0, \
            "generator silently fell back to env-only on an empty base"
        assert "ERROR: the downloaded base ini is empty" in proc.stderr
        assert not out.exists()

    def test_planted_forbidden_keys_abort(self, sandbox, generate):
        bad = sandbox / "bad-base.ini"
        bad.write_text("[job]\nhypervisor=esx\n\n"
                       "[esx]\nserver=base-esx.example.com\n"
                       "password=PLANTED-base-password\n\n"
                       "[kubevirt]\ntoken=PLANTED-base-token\n")
        out = sandbox / "forbidden.ini"
        proc = generate(out, expect_success=False,
                        env={"VIRTWHO_INI_URL": f"file://{bad}"})
        assert proc.returncode != 0, \
            "generator accepted a base ini with planted forbidden keys"
        assert not out.exists()
        assert "forbidden credential option: [esx] password" in proc.stderr
        assert "forbidden credential option: [kubevirt] token" in proc.stderr
        assert "PLANTED" not in proc.stderr, \
            "forbidden-key error leaked the planted value"

    def test_empty_credential_option_aborts(self, sandbox, generate):
        # an empty credential-shaped option is not a sentinel either
        empty_cred = sandbox / "empty-cred-base.ini"
        empty_cred.write_text("[job]\nhypervisor=esx\n\n"
                              "[rhsm]\nserver=base-rhsm.example.com\n"
                              "password=\n")
        out = sandbox / "empty-cred.ini"
        proc = generate(out, expect_success=False,
                        env={"VIRTWHO_INI_URL": f"file://{empty_cred}"})
        assert proc.returncode != 0
        assert "forbidden credential option: [rhsm] password" in proc.stderr

    def test_unsupported_section_sentinels_abort(self, sandbox, generate):
        # [virtwho] and the pass-through sections take their values
        # from the VIRTWHO_* env; a literal @vault: string there
        # would silently become the credential (the run-tests.sh
        # merge-back only fills EMPTY options)
        unsup = sandbox / "unsupported-base.ini"
        unsup.write_text(UNSUPPORTED_BASE_TEXT)
        out = sandbox / "unsupported.ini"
        proc = generate(out, expect_success=False, env={
            "HYPERVISOR": "esx", "REGISTER": "rhsm", "RHEL_COMPOSE": "",
            "VIRTWHO_INI_URL": f"file://{unsup}"}, unset=NO_VAULT_CREDS)
        assert proc.returncode != 0, \
            "a sentinel in a never-resolved section was accepted"
        assert not out.exists()
        assert "sentinel in the unsupported section [virtwho] " \
            "(option username)" in proc.stderr
        assert "sentinel in the unsupported section [nfs] " \
            "(option password)" in proc.stderr
        assert "values for this section must come from the VIRTWHO_* " \
            "environment" in proc.stderr
        assert "Traceback" not in proc.stderr


UNSUPPORTED_BASE_TEXT = """\
[job]
hypervisor=
register=

[virtwho]
server=base-virtwho.example.com
username=@vault:apps/cct-ci/satellite-lab:ssh_username

[esx]
server=base-esx.example.com

[nfs]
server=base-nfs.example.com
password=@vault:apps/cct-ci/satellite-lab:satellite_password
"""


# --- 2d) Vault sentinel resolution against the fake Vault --------------

SENTINEL_BASE_TEXT = """\
; dummy sentinel-bearing base ini -- fake values only. Credential-
; shaped options carry @vault: sentinels (the only allowed form).
[job]
hypervisor=
register=

[esx]
server=base-esx.example.com

[hyperv]
server=base-hyperv.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_username
password=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_password
guest_username=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_guest_username
guest_password=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_guest_password

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username
password=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_password

[ahv]
server=base-ahv.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:ahv_username
password=@vault:apps/cct-ci/virtwho-hypervisors:ahv_password

[kubevirt]
endpoint=https://base-kubevirt.example.com
guest_username=@vault:apps/cct-ci/virtwho-hypervisors:kubevirt_guest_username
guest_password=@vault:apps/cct-ci/virtwho-hypervisors:kubevirt_guest_password

[rhsm]
server=base-rhsm.example.com
username=@vault:apps/cct-ci/candlepin/stage:username
password=@vault:apps/cct-ci/candlepin/stage:password
default_org=base-rhsm-org

[satellite]
server=base-satellite.example.com
username=@vault:apps/cct-ci/satellite-lab:satellite_username
password=@vault:apps/cct-ci/satellite-lab:satellite_password
ssh_username=@vault:apps/cct-ci/satellite-lab:ssh_username
ssh_password=@vault:apps/cct-ci/satellite-lab:ssh_password
activation_key=@vault:apps/cct-ci/satellite-lab:activation_key
default_org=base-satellite-org
"""

BROKEN_BASE_TEXT = """\
[job]
hypervisor=
register=

[hyperv]
server=base-hyperv.example.com
username=@vault:apps/cct-ci/broken:hyperv_username
password=@vault:apps/cct-ci/broken:hyperv_password

[rhsm]
server=base-rhsm.example.com
username=@vault:apps/cct-ci/candlepin/stage:username
password=@vault:apps/cct-ci/candlepin/stage:password
"""

BADSENT_BASE_TEXT = """\
[job]
hypervisor=
register=

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/bad path:username

[ahv]
server=base-ahv.example.com
username=@vault:apps/cct-ci/stringy:username

[kubevirt]
endpoint=https://base-kubevirt.example.com
guest_username=@vault:apps/cct-ci/multiline:multiline_password

[local]
server=base-local.example.com
username=@vault:apps/cct-ci/badshape:key

[xen]
server=base-xen.example.com
username=@vault:apps/cct-ci/listshape:key

[rhsm]
server=base-rhsm.example.com
"""

SENTINEL_ELSEWHERE_TEXT = """\
[job]
hypervisor=
register=

[esx]
server=base-esx.example.com

[rhsm]
server=base-rhsm.example.com
default_org=base-rhsm-org

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username
password=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_password
"""

MULTI_BASE_TEXT = """\
[job]
hypervisor=
register=
multi_hypervisors=[libvirt]

[esx]
server=base-esx.example.com

[hyperv]
server=base-hyperv.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_username
password=@vault:apps/cct-ci/virtwho-hypervisors:hyperv_password

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username
password=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_password
"""

MULTI_NORM_BASE_TEXT = """\
[job]
hypervisor=
register=
multi_hypervisors=[ Libvirt , Hyperv ]

[esx]
server=base-esx.example.com

[libvirt]
server=base-libvirt.example.com
username=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username
password=@vault:apps/cct-ci/virtwho-hypervisors:libvirt_password
"""


class TestVaultResolution:
    @pytest.fixture(autouse=True)
    def _reset_request_log(self, fake_vault):
        # Structural, not conventional: the fake Vault's request log
        # is cleared before EVERY test in this class, so the per-test
        # selectivity/caching counts can never be skewed by whatever
        # an earlier test requested (the vault itself is session-
        # scoped; only the log is per-test).
        fake_vault.reset()

    def test_vault_resolve_sentinel_helpers(self):
        # the vault_resolve module API: sentinel shape helpers (a
        # single-segment path is a grammar error, not a missing
        # secret -- and no request is issued for it)
        spec = importlib.util.spec_from_file_location(
            "vault_resolve", SCRIPTS_DIR / "vault_resolve.py")
        vault_resolve = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vault_resolve)

        assert vault_resolve.is_sentinel("@vault:p:k")
        assert not vault_resolve.is_sentinel("plain")
        assert not vault_resolve.is_sentinel("")
        assert vault_resolve.parse_sentinel("@vault:apps/x:key") == \
            ("apps/x", "key")
        with pytest.raises(vault_resolve.VaultError):
            vault_resolve.parse_sentinel("@vault:nokeys")

        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string("[a]\nx = @vault:p:k\ny = plain\n[b]\nz = @vault:p:j\n")
        assert vault_resolve.sections_with_sentinels(cfg) == {"a", "b"}

        resolver = vault_resolve.VaultResolver(environ={
            "VAULT_ADDR": "https://vault.example.invalid",
            "VAULT_TOKEN": "FAKE-token"})
        with pytest.raises(vault_resolve.VaultError) as excinfo:
            resolver.resolve("@vault:apps:key")
        assert "invalid Vault path" in str(excinfo.value)

    def test_selective_resolution_approle(self, sandbox, generate,
                                          sentinel_base, fake_vault):
        # active sections resolved (env secret wins over the resolved
        # value), non-active keep their sentinels as literals, ONE
        # read per secret path (the four hyperv sentinels share one
        # path) and ONE login, and the resolution log names the
        # sections -- proven in the ini AND in the request log
        out = sandbox / "sentinel.ini"
        proc = generate(out, env={
            **plan_env("hyperv"),
            # stage tier: this test asserts [rhsm] sentinel resolution
            "VIRTWHO_DESTINATION": "stage",
            "VIRTWHO_INI_URL": f"file://{sentinel_base}",
            "VAULT_ROLE_ID": "FAKE-role-id",
            "VAULT_SECRET_ID": "FAKE-secret-id",
            "VIRTWHO_HYPERV_USERNAME": "env-overrides-vault",
            "VAULT_ALLOW_HTTP": "1",
            "VAULT_ADDR": fake_vault.addr})
        assert_mode(out, "600")
        assert_ini_value(out, "hyperv", "username", "env-overrides-vault")
        assert_ini_value(out, "hyperv", "password",
                         "FAKE-vault-hyperv-password")
        assert_ini_value(out, "hyperv", "guest_username",
                         "FAKE-vault-hyperv-guest-username")
        assert_ini_value(out, "hyperv", "guest_password",
                         "FAKE-vault-hyperv-guest-password")
        assert_ini_value(out, "rhsm", "username", "FAKE-vault-rhsm-username")
        assert_ini_value(out, "rhsm", "password", "FAKE-vault-rhsm-password")
        # plaintext of the active sections survives
        assert_ini_value(out, "hyperv", "server", "base-hyperv.example.com")
        assert_ini_value(out, "rhsm", "default_org", "base-rhsm-org")
        # NON-active sections keep their sentinels as literals
        # (per-cell exposure: the other families' credentials are
        # never materialized)
        assert_ini_value(out, "libvirt", "username",
                         "@vault:apps/cct-ci/virtwho-hypervisors:"
                         "libvirt_username")
        assert_ini_value(out, "ahv", "username",
                         "@vault:apps/cct-ci/virtwho-hypervisors:"
                         "ahv_username")
        assert_ini_value(out, "kubevirt", "guest_username",
                         "@vault:apps/cct-ci/virtwho-hypervisors:"
                         "kubevirt_guest_username")
        assert_ini_value(out, "satellite", "username",
                         "@vault:apps/cct-ci/satellite-lab:"
                         "satellite_username")
        # network-level proof of selectivity
        assert fake_vault.count("POST /v1/auth/approle/login") == 1, \
            "expected exactly 1 AppRole login"
        assert fake_vault.count(
            "GET /v1/apps/data/cct-ci/virtwho-hypervisors") == 1, \
            "per-path caching broken (expected 1 GET for the shared path)"
        assert fake_vault.count("GET /v1/apps/data/cct-ci/candlepin/stage") \
            == 1, "the active register path was not requested"
        assert not fake_vault.requested("satellite-lab"), \
            "the non-active satellite path was requested " \
            "(resolution not selective)"
        # the env-covered sentinel (username) is never resolved: 5 of 6
        assert "Resolved 5 Vault sentinel(s) in the active section(s): " \
            "hyperv, rhsm" in proc.stdout

    def test_satellite_register_static_token(self, sandbox, generate,
                                             sentinel_base, fake_vault):
        # register=satellite + static VAULT_TOKEN (no AppRole login)
        out = sandbox / "satellite.ini"
        generate(out, env={
            **plan_env("libvirt", register="satellite"),
            "VIRTWHO_INI_URL": f"file://{sentinel_base}",
            **vault_env(fake_vault)})
        assert_ini_value(out, "libvirt", "username",
                         "FAKE-vault-libvirt-username")
        assert_ini_value(out, "libvirt", "password",
                         "FAKE-vault-libvirt-password")
        assert_ini_value(out, "satellite", "username",
                         "FAKE-vault-satellite-username")
        assert_ini_value(out, "satellite", "password",
                         "FAKE-vault-satellite-password")
        assert_ini_value(out, "satellite", "ssh_username",
                         "FAKE-vault-satellite-ssh-username")
        assert_ini_value(out, "satellite", "ssh_password",
                         "FAKE-vault-satellite-ssh-password")
        assert_ini_value(out, "satellite", "activation_key",
                         "FAKE-vault-satellite-activation-key")
        # the rhsm register path is never requested in a satellite
        # cell, and no AppRole login happens with a static token set
        assert not fake_vault.requested("candlepin/stage")
        assert not fake_vault.requested("approle/login")
        assert fake_vault.count("GET /v1/apps/data/cct-ci/satellite-lab") \
            == 1

    def test_unresolved_active_sentinel_hard_fails(self, sandbox, generate,
                                                   sentinel_base,
                                                   fake_vault):
        out = sandbox / "unresolved.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("ahv"),
            "VIRTWHO_INI_URL": f"file://{sentinel_base}",
            "VAULT_ROLE_ID": "FAKE-role-id",
            "VAULT_SECRET_ID": "FAKE-secret-id",
            "VAULT_ALLOW_HTTP": "1",
            "VAULT_ADDR": fake_vault.addr})
        assert proc.returncode != 0, \
            "generator survived an unresolved sentinel in the active section"
        assert not out.exists()
        assert "cannot resolve the sentinel of [ahv] username" in proc.stderr
        assert "'ahv_username' not found at Vault path " \
            "'apps/cct-ci/virtwho-hypervisors'" in proc.stderr
        assert "Traceback" not in proc.stderr
        assert "FAKE-vault" not in proc.stderr, \
            "unresolved-sentinel error leaked a resolved value"

    def test_redirects_refused(self, sandbox, generate, sentinel_base,
                               fake_vault, redirect_vault):
        # the token must never be re-sent to the address a redirect
        # response names
        out = sandbox / "redirect.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("hyperv"),
            "VIRTWHO_INI_URL": f"file://{sentinel_base}",
            "VAULT_ALLOW_HTTP": "1",
            "VAULT_ADDR": redirect_vault,
            "VAULT_TOKEN": "FAKE-static-token"})
        assert proc.returncode != 0, \
            "generator followed a Vault redirect instead of refusing it"
        assert not out.exists()
        assert "refusing to follow" in proc.stderr
        assert f"{redirect_vault}/v1/apps/data" in proc.stderr, \
            "the redirect refusal does not name the configured address"
        assert "Traceback" not in proc.stderr
        assert "FAKE-static-token" not in proc.stderr, \
            "the redirect refusal leaked the token"

    def test_env_supplied_credentials_survive_vault_failure(
            self, sandbox, generate, broken_base, fake_vault):
        # [hyperv] credentials point at the always-500 path, but the
        # environment covers both: the run must succeed (env values
        # are final and never resolved), the healthy register path
        # must still resolve, and the broken path must never be
        # requested
        out = sandbox / "env-wins.ini"
        generate(out, env={
            **plan_env("hyperv"),
            # stage tier: asserts the healthy [rhsm] register path
            # still resolves
            "VIRTWHO_DESTINATION": "stage",
            "VIRTWHO_INI_URL": f"file://{broken_base}",
            "VIRTWHO_HYPERV_USERNAME": "env-hyperv-user",
            "VIRTWHO_HYPERV_PASSWORD": "env-hyperv-pass",
            **vault_env(fake_vault)})
        assert_ini_value(out, "hyperv", "username", "env-hyperv-user")
        assert_ini_value(out, "hyperv", "password", "env-hyperv-pass")
        assert_ini_value(out, "rhsm", "username", "FAKE-vault-rhsm-username")
        assert_ini_value(out, "rhsm", "password", "FAKE-vault-rhsm-password")
        assert not fake_vault.requested("cct-ci/broken"), \
            "an env-covered sentinel was resolved (the broken path " \
            "was requested)"

    def test_fully_env_covered_cell_needs_no_vault(self, sandbox, generate,
                                                   sentinel_base):
        # the no-credentials gate only fires for sentinels the
        # environment does NOT override
        out = sandbox / "env-covered.ini"
        generate(out, env={
            **plan_env("hyperv"),
            # stage tier: the env-covered [rhsm] sentinels are the
            # point of this test
            "VIRTWHO_DESTINATION": "stage",
            "VIRTWHO_INI_URL": f"file://{sentinel_base}",
            "VIRTWHO_HYPERV_USERNAME": "env-hyperv-user",
            "VIRTWHO_HYPERV_PASSWORD": "env-hyperv-pass",
            "VIRTWHO_HYPERV_GUEST_USERNAME": "env-hyperv-guest-user",
            "VIRTWHO_HYPERV_GUEST_PASSWORD": "env-hyperv-guest-pass",
            "VIRTWHO_RHSM_USERNAME": "env-rhsm-user",
            "VIRTWHO_RHSM_PASSWORD": "env-rhsm-pass"},
            unset=NO_VAULT_CREDS)
        assert_ini_value(out, "hyperv", "username", "env-hyperv-user")
        assert_ini_value(out, "rhsm", "password", "env-rhsm-pass")
        assert_ini_value(out, "libvirt", "username",
                         "@vault:apps/cct-ci/virtwho-hypervisors:"
                         "libvirt_username")

    def test_multi_hypervisors_env_form_resolves_listed_families(
            self, sandbox, generate, sentinel_base, fake_vault):
        # via the env variable (which wins), with spaces and mixed
        # case that the suite's own parser would keep (' rhevm')
        out = sandbox / "multi-env.ini"
        generate(out, env={
            **plan_env("esx"),
            # stage tier: asserts [rhsm] sentinel resolution alongside
            # the multi-hypervisor families
            "VIRTWHO_DESTINATION": "stage",
            "VIRTWHO_JOB_MULTI_HYPERVISORS": "[ Libvirt , Hyperv ]",
            "VIRTWHO_INI_URL": f"file://{sentinel_base}",
            **vault_env(fake_vault)})
        assert_ini_value(out, "libvirt", "username",
                         "FAKE-vault-libvirt-username")
        assert_ini_value(out, "libvirt", "password",
                         "FAKE-vault-libvirt-password")
        assert_ini_value(out, "hyperv", "username",
                         "FAKE-vault-hyperv-username")
        assert_ini_value(out, "rhsm", "username", "FAKE-vault-rhsm-username")
        # families outside the list keep their literals
        assert_ini_value(out, "ahv", "username",
                         "@vault:apps/cct-ci/virtwho-hypervisors:"
                         "ahv_username")
        assert_ini_value(out, "kubevirt", "guest_username",
                         "@vault:apps/cct-ci/virtwho-hypervisors:"
                         "kubevirt_guest_username")

    def test_multi_hypervisors_base_form_resolves_listed_family(
            self, sandbox, generate, multi_base, fake_vault):
        # via the base file's [job] multi_hypervisors (no env var)
        out = sandbox / "multi-base-out.ini"
        generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_INI_URL": f"file://{multi_base}",
            **vault_env(fake_vault)},
            unset=("VIRTWHO_JOB_MULTI_HYPERVISORS",))
        assert_ini_value(out, "libvirt", "username",
                         "FAKE-vault-libvirt-username")
        assert_ini_value(out, "hyperv", "username",
                         "@vault:apps/cct-ci/virtwho-hypervisors:"
                         "hyperv_username")

    @pytest.mark.parametrize("value", [
        pytest.param("[libvirt] ", id="trailing-space"),
        pytest.param(" [libvirt] ", id="leading-space"),
    ])
    def test_multi_hypervisors_outer_whitespace_still_resolves(
            self, sandbox, generate, multi_base, fake_vault, value):
        # str.strip("[") strips a character set from both ends, so
        # ' [libvirt] ' used to keep a bracket, match no section and
        # skip resolution with exit 0
        out = sandbox / "multi-ws.ini"
        generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_JOB_MULTI_HYPERVISORS": value,
            "VIRTWHO_INI_URL": f"file://{multi_base}",
            **vault_env(fake_vault)})
        assert_ini_value(out, "libvirt", "username",
                         "FAKE-vault-libvirt-username")

    @pytest.mark.parametrize("raw,expected", [
        ("[ Libvirt , Hyperv ]", "[libvirt,hyperv]"),
        (" [libvirt] ", "[libvirt]"),
        ("[esx,rhevm]", "[esx,rhevm]"),
    ])
    def test_multi_hypervisors_written_back_normalized(self, sandbox,
                                                       generate, raw,
                                                       expected):
        # the suite re-parses [job] multi_hypervisors with its own,
        # UNNORMALIZED expression (virtwho/base.py
        # hypervisors_list()) and get_hypervisor_handler() compares
        # each entry RAW against the mode list, falling back to the
        # [esx] handler for anything else: the generator must write
        # the normalized list back into the ini so both ends agree
        out = sandbox / "multi-normalized.ini"
        generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_JOB_MULTI_HYPERVISORS": raw},
            unset=("VIRTWHO_INI_URL",))
        value = ini_value(out, "job", "multi_hypervisors")
        assert value == expected, \
            f"[job] multi_hypervisors from {raw!r}: " \
            f"expected {expected!r}, got {value!r}"
        # the suite's own parser, VERBATIM from virtwho/base.py
        # hypervisors_list() -- it does NOT normalize the entries
        parsed = value.strip("[").strip("]").split(",")
        assert parsed == expected.strip("[]").split(","), \
            f"suite parser disagrees with the generated ini: " \
            f"{parsed!r} vs {value!r}"
        # get_hypervisor_handler()'s recognized modes (esx is its
        # fallback section, so it counts as recognized)
        modes = {"hyperv", "rhevm", "libvirt", "kubevirt", "ahv", "local",
                 "esx"}
        for entry in parsed:
            assert entry in modes, \
                f"suite would not recognize mode {entry!r} " \
                f"(parsed from {value!r})"

    def test_multi_hypervisors_base_form_written_back_normalized(
            self, sandbox, generate, fake_vault):
        # the base-file form gets the same write-back: the overlay
        # copies the RAW base value, so '[ Libvirt , Hyperv ]' in the
        # base must land in the ini normalized too -- and the listed
        # family still resolves
        base = write_base(sandbox, "multi-norm-base.ini",
                          MULTI_NORM_BASE_TEXT)
        out = sandbox / "multi-norm-base-out.ini"
        generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_INI_URL": f"file://{base}",
            **vault_env(fake_vault)},
            unset=("VIRTWHO_JOB_MULTI_HYPERVISORS",))
        assert_ini_value(out, "libvirt", "username",
                         "FAKE-vault-libvirt-username")
        value = ini_value(out, "job", "multi_hypervisors")
        assert value == "[libvirt,hyperv]", \
            f"[job] multi_hypervisors (base-file form): " \
            f"expected '[libvirt,hyperv]', got {value!r}"
        parsed = value.strip("[").strip("]").split(",")
        assert parsed == ["libvirt", "hyperv"]
        modes = {"hyperv", "rhevm", "libvirt", "kubevirt", "ahv", "local",
                 "esx"}
        for entry in parsed:
            assert entry in modes

    def test_plaintext_http_vault_addr_refused(self, sandbox, generate,
                                               sentinel_base, fake_vault):
        # the AppRole secret_id and the client token must never
        # travel in cleartext
        out = sandbox / "https.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("hyperv"),
            "VIRTWHO_INI_URL": f"file://{sentinel_base}",
            "VAULT_ADDR": fake_vault.addr,
            "VAULT_TOKEN": "FAKE-static-token"},
            unset=("VAULT_ALLOW_HTTP",))
        assert proc.returncode != 0, \
            "a plaintext http:// VAULT_ADDR was accepted"
        assert "VAULT_ADDR must use https " \
            "(set VAULT_ALLOW_HTTP=1 to allow plaintext)" in proc.stderr
        assert not fake_vault.requests, \
            "a request was made despite the https refusal"
        assert "Traceback" not in proc.stderr

    def test_sentinel_path_with_space_fails_clean(self, sandbox, generate,
                                                  badsent_base,
                                                  fake_vault):
        # InvalidURL derives from HTTPException, not
        # ValueError/OSError: without it in the caught tuple the
        # error escapes as a raw traceback
        out = sandbox / "badurl.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("libvirt"),
            "VIRTWHO_INI_URL": f"file://{badsent_base}",
            **vault_env(fake_vault)})
        assert proc.returncode != 0, "a sentinel path with a space was accepted"
        assert "Vault request failed: InvalidURL" in proc.stderr
        assert "Traceback" not in proc.stderr

    def test_nondict_payload_is_malformed_response(self, sandbox, generate,
                                                   badsent_base,
                                                   fake_vault):
        # a non-dict payload is a malformed response, not a missing key
        out = sandbox / "badpayload.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("ahv"),
            "VIRTWHO_INI_URL": f"file://{badsent_base}",
            **vault_env(fake_vault)})
        assert proc.returncode != 0, "a non-dict Vault payload was accepted"
        assert "malformed Vault response for path 'apps/cct-ci/stringy'" \
            in proc.stderr
        assert "not found" not in proc.stderr, \
            "a malformed response was misreported as a missing key"

    @pytest.mark.parametrize("hypervisor,path", [
        ("local", "badshape"),
        ("xen", "listshape"),
    ])
    def test_wrong_shape_envelopes_fail_clean(self, sandbox, generate,
                                              badsent_base, fake_vault,
                                              hypervisor, path):
        # a 200 whose TOP-LEVEL envelope is not the kv2 shape
        # ({"data": "..."} or a bare JSON list) must be a clean
        # malformed error -- blind subscripting raised a raw TypeError
        out = sandbox / f"badshape-{path}.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env(hypervisor),
            "VIRTWHO_INI_URL": f"file://{badsent_base}",
            **vault_env(fake_vault)})
        assert proc.returncode != 0
        assert f"malformed Vault response for path 'apps/cct-ci/{path}'" \
            in proc.stderr
        assert "Traceback" not in proc.stderr

    def test_newline_resolved_value_rejected(self, sandbox, generate,
                                             badsent_base, fake_vault):
        # a resolved value containing a newline would corrupt the ini
        out = sandbox / "badnl.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("kubevirt"),
            "VIRTWHO_INI_URL": f"file://{badsent_base}",
            **vault_env(fake_vault)})
        assert proc.returncode != 0, \
            "a newline-containing resolved value was accepted"
        assert "contains a newline: ini values must be single-line" \
            in proc.stderr
        assert "FAKE-line" not in proc.stderr, \
            "the newline rejection leaked the value"

    def test_failing_path_read_once(self, sandbox, generate, broken_base,
                                     fake_vault):
        # two sentinels share the broken path and the generator aborts
        # on the first failing sentinel (fail-fast), so exactly ONE
        # request reaches the server. NOTE: this shape alone cannot
        # falsify the failure cache -- fail-fast yields one GET with
        # the cache disabled too; the direct pin is
        # test_failure_cache_pinned_directly below.
        out = sandbox / "broken.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("hyperv"),
            "VIRTWHO_INI_URL": f"file://{broken_base}",
            **vault_env(fake_vault)},
            unset=("VIRTWHO_HYPERV_USERNAME", "VIRTWHO_HYPERV_PASSWORD"))
        assert proc.returncode != 0, "an always-500 Vault path was accepted"
        assert "Vault request failed: HTTP 500" in proc.stderr
        assert fake_vault.count("GET /v1/apps/data/cct-ci/broken") == 1, \
            "the generator repeated the request for a shared failing path"

    def test_failure_cache_pinned_directly(self, fake_vault):
        # the failure cache, falsifiably: drive the REAL resolver
        # against the fake Vault and resolve failing sentinels on the
        # always-500 path more than once. With the failure cache
        # disabled each resolve re-fetches and the counts below grow,
        # so this test fails under that mutation (verified).
        spec = importlib.util.spec_from_file_location(
            "vault_resolve_failure_cache", SCRIPTS_DIR / "vault_resolve.py")
        vault_resolve = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vault_resolve)
        resolver = vault_resolve.VaultResolver(environ={
            "VAULT_ADDR": fake_vault.addr,
            "VAULT_TOKEN": "FAKE-static-token",
            "VAULT_ALLOW_HTTP": "1"})
        for attempt in (1, 2):
            with pytest.raises(vault_resolve.VaultError) as excinfo:
                resolver.resolve("@vault:apps/cct-ci/broken:hyperv_username")
            assert "HTTP 500" in str(excinfo.value), \
                f"resolve attempt {attempt} did not fail against " \
                "the always-500 path"
        assert fake_vault.count("GET /v1/apps/data/cct-ci/broken") == 1, \
            "the second resolve of the same failing sentinel " \
            "re-fetched (per-(path, key) failure caching broken)"
        # a SECOND key on the same failing path: the path-level
        # failure cache must answer without another request -- the
        # documented invariant is "each secret path is read at most
        # once per resolver instance, failures included"
        fake_vault.reset()
        with pytest.raises(vault_resolve.VaultError):
            resolver.resolve("@vault:apps/cct-ci/broken:hyperv_password")
        assert fake_vault.count("GET /v1/apps/data/cct-ci/broken") == 0, \
            "a second key on the same failing path re-fetched " \
            "(per-path failure caching broken)"

    def test_credentials_without_vault_addr_fail(self, sandbox, generate,
                                                 sentinel_base):
        # no default address: sending the credentials to a host the
        # caller never configured must never happen
        out = sandbox / "noaddr.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("hyperv"),
            "VIRTWHO_INI_URL": f"file://{sentinel_base}",
            "VAULT_TOKEN": "FAKE-static-token"},
            unset=("VAULT_ADDR",))
        assert proc.returncode != 0, \
            "credentials without VAULT_ADDR were accepted"
        assert "Vault credentials are set but VAULT_ADDR is not" \
            in proc.stderr
        assert "Traceback" not in proc.stderr

    def test_active_sentinels_without_credentials_hard_fail(
            self, sandbox, generate, sentinel_base):
        # a credentialed cell must not silently run credless; the
        # error names the env-only escape hatch
        out = sandbox / "nocreds.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("hyperv"),
            "VIRTWHO_INI_URL": f"file://{sentinel_base}"},
            unset=NO_VAULT_CREDS)
        assert proc.returncode != 0, \
            "generator ran a credentialed cell without Vault credentials"
        assert not out.exists()
        assert "no Vault credentials are set" in proc.stderr
        assert "unset VIRTWHO_INI_URL" in proc.stderr, \
            "missing-credentials error does not name the env-only " \
            "escape hatch"
        assert "Traceback" not in proc.stderr

    def test_non_active_sentinels_without_credentials_stay_literal(
            self, sandbox, generate, sentinel_elsewhere):
        # knob unset: the run succeeds, the non-active sentinels stay
        # literal (per-cell exposure)
        out = sandbox / "strict-off.ini"
        generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_INI_URL": f"file://{sentinel_elsewhere}"},
            unset=NO_VAULT_CREDS)
        assert_ini_value(out, "esx", "server", "base-esx.example.com")
        assert_ini_value(out, "libvirt", "username",
                         "@vault:apps/cct-ci/virtwho-hypervisors:"
                         "libvirt_username")

    def test_strict_knob_requires_credentials(self, sandbox, generate,
                                              sentinel_elsewhere):
        out = sandbox / "strict-on.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("esx"),
            "VIRTWHO_INI_URL": f"file://{sentinel_elsewhere}",
            "VIRTWHO_VAULT_REQUIRED": "1"},
            unset=NO_VAULT_CREDS)
        assert proc.returncode != 0, \
            "VIRTWHO_VAULT_REQUIRED did not require credentials"
        assert "VIRTWHO_VAULT_REQUIRED is set and the base ini carries " \
            "@vault: sentinels" in proc.stderr
        assert not out.exists()

    def test_strict_knob_does_not_widen_scope(self, sandbox, generate,
                                              sentinel_elsewhere,
                                              fake_vault):
        # with the knob AND credentials the non-active section is
        # still not resolved (the knob never widens the per-cell
        # exposure)
        out = sandbox / "strict-creds.ini"
        generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_INI_URL": f"file://{sentinel_elsewhere}",
            "VIRTWHO_VAULT_REQUIRED": "1",
            **vault_env(fake_vault)})
        assert_ini_value(out, "libvirt", "username",
                         "@vault:apps/cct-ci/virtwho-hypervisors:"
                         "libvirt_username")

    def test_strict_mode_requires_usable_credentials(self, sandbox,
                                                     generate,
                                                     sentinel_elsewhere):
        # a token without VAULT_ADDR used to satisfy the strict gate
        # (exit 0, literal sentinels written); the gate now runs the
        # resolver's own pre-flight checks
        out = sandbox / "strict-addr.ini"
        proc = generate(out, expect_success=False, env={
            **plan_env("esx"),
            "VIRTWHO_INI_URL": f"file://{sentinel_elsewhere}",
            "VIRTWHO_VAULT_REQUIRED": "1",
            "VAULT_TOKEN": "FAKE-static-token"},
            unset=("VAULT_ADDR",))
        assert proc.returncode != 0, \
            "strict mode was satisfied by credentials without VAULT_ADDR"
        assert "VIRTWHO_VAULT_REQUIRED is set but the Vault credentials " \
            "are unusable" in proc.stderr
        assert "Vault credentials are set but VAULT_ADDR is not" \
            in proc.stderr
        assert not out.exists()

    def test_sentinel_free_base_inert_with_credentials(self, sandbox,
                                                       generate, base_ini,
                                                       fake_vault):
        # credentials + strict set, plain base: identical output, no
        # Vault request at all (the resolver stays inert)
        out = sandbox / "plain-with-creds.ini"
        generate(out, env={
            "HYPERVISOR": "libvirt", "REGISTER": "rhsm",
            "RHEL_COMPOSE": "RHEL-10.0-DUMMY",
            "VIRTWHO_ESX_PASSWORD": "env-esx-pass",
            "VIRTWHO_INI_URL": f"file://{base_ini}",
            "VIRTWHO_VAULT_REQUIRED": "1",
            **vault_env(fake_vault)})
        assert_ini_value(out, "esx", "password", "env-esx-pass")
        assert_ini_value(out, "esx", "server", "base-esx.example.com")
        assert_ini_value(out, "virtwho", "server", "base-virtwho.example.com")
        assert_ini_value(out, "beaker", "server", "base-beaker.example.com")
        assert not fake_vault.requests, \
            "Vault requests were made for a sentinel-free base"
        assert_mode(out, "600")

    def test_no_staging_leftovers(self, sandbox, generate):
        # the generator's mktemp staging (output.tmp.* / output.base.*)
        # must never survive a run, successful or not
        out1 = sandbox / "env-only.ini"
        generate(out1, env=plan_env("esx"), unset=("VIRTWHO_INI_URL",))
        base = write_base(sandbox, "base.ini", BASE_INI_TEXT)
        out2 = sandbox / "overlay.ini"
        generate(out2, env={
            **plan_env("esx"),
            "VIRTWHO_INI_URL": f"file://{base}"})
        leftovers = [p.name for p in sandbox.iterdir()
                     if ".tmp." in p.name or ".base." in p.name]
        assert not leftovers, f"staging leftovers left behind: {leftovers}"

    def test_no_staging_leftovers_on_failed_run(self, sandbox, generate):
        # the failed-run variant: a bad download URL plus a pin
        # mismatch in one sandbox must not leave the mktemp staging
        # (output.tmp.* / output.base.*) behind either
        out = sandbox / "failed.ini"
        proc = generate(out, expect_success=False, env={
            "HYPERVISOR": "esx", "REGISTER": "rhsm", "RHEL_COMPOSE": "",
            "VIRTWHO_INI_URL": "file:///nonexistent-virtwho-base.ini",
            "VIRTWHO_INI_SHA256": "0" * 64})
        assert proc.returncode != 0, \
            "generator survived a bad download URL and a pin mismatch"
        assert not out.exists()
        leftovers = [p.name for p in sandbox.iterdir()
                     if ".tmp." in p.name or ".base." in p.name]
        assert not leftovers, f"failed run left staging behind: {leftovers}"


# --- 2g) Bounded connection-level retry of the Vault resolver ------------

class TestVaultRetry:
    """The resolver's bounded retry for CONNECTION-LEVEL failures
    (Jenkins virt-who/compose #175: one transient Vault/network blip
    -- URLError from three independent guests over 8 minutes, minutes
    after a fully successful resolution -- aborted three whole cells).
    Connection-level failures are retried up to 5 total attempts with
    an exponential backoff (raised from 3 after #177/#180 observed
    3-consecutive-drop windows exhausting the old budget on two cells
    of one run); anything the server ANSWERED (HTTP 403:
    auth/permission) fails immediately, loudly, and unretried."""

    @pytest.fixture(autouse=True)
    def _reset_request_log(self, fake_vault):
        # structural, like TestVaultResolution: the request log and
        # the connection-failure simulation state are per-test
        fake_vault.reset()
        fake_vault.flaky_reset_counts = {}
        fake_vault.always_reset_paths = set()
        fake_vault.forbidden_paths = set()

    @staticmethod
    def _load_vault_resolve():
        # the REAL module, loaded fresh (like the failure-cache pin);
        # the backoff constants are shrunk to keep the suite fast --
        # they are production constants, the retry COUNT and the
        # retry SELECTIVITY are what these tests pin
        spec = importlib.util.spec_from_file_location(
            "vault_resolve_retry", SCRIPTS_DIR / "vault_resolve.py")
        vault_resolve = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vault_resolve)
        vault_resolve.RETRY_BACKOFF_SECONDS = (0.01, 0.01, 0.01, 0.01)
        return vault_resolve

    def test_connection_resets_then_success(self, fake_vault, capsys):
        # four connection resets (the observed #180 burst class: a
        # dense flake window dropping 3+ consecutive attempts), then
        # the server recovers: the resolution SUCCEEDS on the 5th
        # attempt and exactly 5 requests are observed in the server's
        # request log
        fake_vault.flaky_reset_counts = {"cct-ci/virtwho-hypervisors": 4}
        vault_resolve = self._load_vault_resolve()
        resolver = vault_resolve.VaultResolver(environ={
            "VAULT_ADDR": fake_vault.addr,
            "VAULT_TOKEN": "FAKE-static-token",
            "VAULT_ALLOW_HTTP": "1"})
        secret = resolver.resolve(
            "@vault:apps/cct-ci/virtwho-hypervisors:libvirt_username")
        assert secret == "FAKE-vault-libvirt-username", \
            "the resolver did not survive four connection resets"
        assert fake_vault.count(
            "GET /v1/apps/data/cct-ci/virtwho-hypervisors") == 5, \
            "expected exactly 5 attempts (4 reset + 1 success)"
        err = capsys.readouterr().err
        assert "Vault request attempt 1 of 5 failed with" in err, \
            "the first retry was not logged"
        assert "Vault request attempt 2 of 5 failed with" in err, \
            "the second retry was not logged"
        assert "Vault request attempt 4 of 5 failed with" in err, \
            "the fourth retry was not logged"
        assert "attempt 5 of 5" not in err, \
            "a successful final attempt was logged as a failure"
        assert fake_vault.addr not in err, \
            "the retry warning leaked the Vault server address"
        assert "retrying" in err

    def test_immediate_403_is_not_retried(self, fake_vault, capsys):
        # an auth/permission failure: the server ANSWERED, retrying
        # is pointless and would only delay the loud failure --
        # exactly 1 attempt, hard fail
        fake_vault.forbidden_paths = {"cct-ci/forbidden"}
        vault_resolve = self._load_vault_resolve()
        resolver = vault_resolve.VaultResolver(environ={
            "VAULT_ADDR": fake_vault.addr,
            "VAULT_TOKEN": "FAKE-static-token",
            "VAULT_ALLOW_HTTP": "1"})
        with pytest.raises(vault_resolve.VaultError) as excinfo:
            resolver.resolve("@vault:apps/cct-ci/forbidden:key")
        assert "Vault request failed: HTTP 403" in str(excinfo.value)
        assert fake_vault.count("GET /v1/apps/data/cct-ci/forbidden") == 1, \
            "an HTTP 403 was retried (it must fail immediately)"
        assert "retrying" not in capsys.readouterr().err

    def test_all_attempts_fail_loudly(self, fake_vault, capsys):
        # the connection never recovers: a hard fail after exactly 5
        # attempts, with the loud error and the retry log
        fake_vault.always_reset_paths = {"cct-ci/always-down"}
        vault_resolve = self._load_vault_resolve()
        resolver = vault_resolve.VaultResolver(environ={
            "VAULT_ADDR": fake_vault.addr,
            "VAULT_TOKEN": "FAKE-static-token",
            "VAULT_ALLOW_HTTP": "1"})
        with pytest.raises(vault_resolve.VaultError) as excinfo:
            resolver.resolve("@vault:apps/cct-ci/always-down:key")
        assert "Vault request failed: RemoteDisconnected" \
            in str(excinfo.value), \
            "the exhausted-retries error is not the loud connection error"
        assert fake_vault.count("GET /v1/apps/data/cct-ci/always-down") == 5, \
            "expected exactly 5 attempts before the hard fail"
        err = capsys.readouterr().err
        assert "Vault request attempt 1 of 5 failed with" in err
        assert "Vault request attempt 2 of 5 failed with" in err
        assert "Vault request attempt 4 of 5 failed with" in err
        assert "attempt 5 of 5 failed with" not in err, \
            "the final failed attempt must raise, not log-and-retry"
        assert fake_vault.addr not in err, \
            "the retry warning leaked the Vault server address"


# --- 2b/2c/2e/2f) aliases, warnings, clashes ----------------------------

class TestAliasesAndWarnings:
    def test_legacy_kubevirt_token_survives_regeneration(self, sandbox,
                                                         generate):
        # run-tests.sh regenerates the ini at test time and only
        # knows the new name; the mapping here keeps the legacy
        # variable working end to end
        out = sandbox / "legacy-token.ini"
        generate(out, env={
            "HYPERVISOR": "kubevirt", "REGISTER": "rhsm", "RHEL_COMPOSE": "",
            "KUBEVIRT_TOKEN": "legacy-kubevirt-token"},
            unset=("VIRTWHO_KUBEVIRT_TOKEN", "VIRTWHO_INI_URL"))
        assert_ini_value(out, "kubevirt", "token", "legacy-kubevirt-token")

    def test_new_kubevirt_token_name_wins(self, sandbox, generate):
        out = sandbox / "both-tokens.ini"
        generate(out, env={
            "HYPERVISOR": "kubevirt", "REGISTER": "rhsm", "RHEL_COMPOSE": "",
            "KUBEVIRT_TOKEN": "legacy-kubevirt-token",
            "VIRTWHO_KUBEVIRT_TOKEN": "new-kubevirt-token"},
            unset=("VIRTWHO_INI_URL",))
        assert_ini_value(out, "kubevirt", "token", "new-kubevirt-token")

    def test_misspelled_option_warns(self, sandbox, generate):
        # a typo like VIRTWHO_ESX_GUEST_IPS would otherwise be
        # silently dropped and leave an empty ini option
        out = sandbox / "typo.ini"
        proc = generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_ESX_GUEST_IPS": "192.0.2.99"},
            unset=("VIRTWHO_INI_URL",))
        assert "WARNING: ignoring VIRTWHO_* variable(s) matching no " \
            "known ini option" in proc.stderr
        assert "VIRTWHO_ESX_GUEST_IPS" in proc.stderr, \
            "warning does not name the misspelled variable"
        assert not re.search(r"^guest_ips=", out.read_text(), re.MULTILINE), \
            "misspelled option leaked into the ini"

    def test_clean_run_stays_warning_free(self, sandbox, generate):
        out = sandbox / "clean.ini"
        proc = generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_ESX_GUEST_IP": "192.0.2.50"},
            unset=("VIRTWHO_INI_URL",))
        assert "WARNING: ignoring VIRTWHO" not in proc.stderr, \
            "clean run produced a spurious unknown-variable warning"

    def test_job_hypervisor_alias_wins_when_plan_level_unset(self, sandbox,
                                                             generate):
        # the preseed would otherwise clobber it with the esx default
        out = sandbox / "job-alias.ini"
        generate(out, env={
            "REGISTER": "rhsm", "RHEL_COMPOSE": "",
            "VIRTWHO_JOB_HYPERVISOR": "libvirt"},
            unset=("VIRTWHO_INI_URL", "HYPERVISOR"))
        assert_ini_value(out, "job", "hypervisor", "libvirt")

    def test_job_hypervisor_alias_feeds_section_creation(self, sandbox,
                                                         generate):
        # without the promotion, [job] hypervisor=libvirt with no
        # [libvirt] section fails the whole suite at conftest import
        out = sandbox / "job-alias.ini"
        generate(out, env={
            "REGISTER": "rhsm", "RHEL_COMPOSE": "",
            "VIRTWHO_JOB_HYPERVISOR": "libvirt"},
            unset=("VIRTWHO_INI_URL", "HYPERVISOR"))
        assert re.search(r"^\[libvirt\]", out.read_text(), re.MULTILINE), \
            "VIRTWHO_JOB_HYPERVISOR=libvirt produced no [libvirt] " \
            "section (the suite reads it at import time)"

    def test_job_hypervisor_alias_lowercased(self, sandbox, generate):
        # get_hypervisor_handler only matches the lower-case mode
        # list; an upper-case alias must not silently select the ESX
        # handler
        out = sandbox / "job-alias-upper.ini"
        proc = generate(out, env={
            "REGISTER": "rhsm", "RHEL_COMPOSE": "",
            "VIRTWHO_JOB_HYPERVISOR": "LIBVIRT"},
            unset=("VIRTWHO_INI_URL", "HYPERVISOR"))
        assert_ini_value(out, "job", "hypervisor", "libvirt")
        assert re.search(r"^\[libvirt\]", out.read_text(), re.MULTILINE)
        assert "shadowed" not in proc.stderr, \
            "the promoted (lower-cased) alias was reported as shadowed " \
            "by itself"

    def test_job_register_alias_wins_over_rhsm_default(self, sandbox,
                                                       generate):
        # the invocation used to hard-code REGISTER=rhsm, making the
        # alias unwinnable
        out = sandbox / "job-alias-register.ini"
        proc = generate(out, env={
            "HYPERVISOR": "esx", "RHEL_COMPOSE": "",
            "VIRTWHO_JOB_REGISTER": "satellite"},
            unset=("VIRTWHO_INI_URL", "REGISTER"))
        assert_ini_value(out, "job", "register", "satellite")
        assert "VIRTWHO_JOB_REGISTER is shadowed" not in proc.stderr, \
            "VIRTWHO_JOB_REGISTER was shadowed although the plan-level " \
            "REGISTER was never set"

    def test_job_rhel_compose_alias_wins(self, sandbox, generate):
        # setup-virtwho-test.sh resolves RESOLVED_COMPOSE from the
        # same variable
        out = sandbox / "job-alias-compose.ini"
        generate(out, env={
            "HYPERVISOR": "esx", "REGISTER": "rhsm",
            "VIRTWHO_JOB_RHEL_COMPOSE": "RHEL-10.0-DUMMY"},
            unset=("VIRTWHO_INI_URL", "RHEL_COMPOSE"))
        assert_ini_value(out, "job", "rhel_compose", "RHEL-10.0-DUMMY")

    def test_plan_level_hypervisor_shadows_alias(self, sandbox, generate):
        # a set plan-level variable wins and the warning names the
        # winner (never the values)
        out = sandbox / "job-shadow.ini"
        proc = generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_JOB_HYPERVISOR": "libvirt"},
            unset=("VIRTWHO_INI_URL",))
        assert_ini_value(out, "job", "hypervisor", "esx")
        assert "VIRTWHO_JOB_HYPERVISOR is shadowed by the plan-level " \
            "HYPERVISOR variable" in proc.stderr
        assert "libvirt" not in proc.stderr, \
            "plan-level shadowing warning leaked a value"

    def test_esx_vcenter_clash_warns_esx_wins(self, sandbox, generate):
        out = sandbox / "dual-prefix.ini"
        proc = generate(out, env={
            **plan_env("esx"),
            "VIRTWHO_VCENTER_SERVER": "198.51.100.10",
            "VIRTWHO_ESX_SERVER": "198.51.100.20"},
            unset=("VIRTWHO_INI_URL",))
        assert_ini_value(out, "esx", "server", "198.51.100.20")
        assert "VIRTWHO_ESX_* wins" in proc.stderr, \
            "ESX/VCENTER clash produced no warning naming the winner"
        assert "server" in proc.stderr, \
            "ESX/VCENTER clash warning does not name the option"
        assert not re.search(r"198\.51\.100\.(10|20)", proc.stderr), \
            "ESX/VCENTER clash warning leaked a value"


# --- 3) Single materialization: symlink survives cp -a, writes go through

class TestSingleMaterialization:
    @pytest.fixture
    def linked_ini(self, sandbox, generate):
        """A generated tmpfs ini plus a tree dir holding a symlink to it."""
        target = sandbox / "materialized.ini"
        generate(target, env={
            "HYPERVISOR": "esx",
            "VIRTWHO_VCENTER_SERVER": "dummy-vcenter.example.com"},
            unset=("VIRTWHO_INI_URL",))
        tree = sandbox / "tree"
        tree.mkdir()
        link = tree / "virtwho.ini"
        link.symlink_to(target)
        return target, tree, link

    def test_cp_a_preserves_symlink(self, sandbox, linked_ini):
        # the bootc writable-copy path in run-tests.sh
        _target, tree, _link = linked_ini
        copy = sandbox / "tree-copy"
        shutil.copytree(tree, copy, symlinks=True)
        assert (copy / "virtwho.ini").is_symlink(), \
            "cp -a did not preserve the virtwho.ini symlink"

    def test_configparser_writes_through_symlink(self, sandbox, linked_ini):
        # Configure.save() semantics: configparser opens the path
        # with "w", which follows the symlink to the tmpfs target
        target, tree, link = linked_ini
        copy = sandbox / "tree-copy"
        shutil.copytree(tree, copy, symlinks=True)
        path = copy / "virtwho.ini"
        assert path.is_symlink()
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(path)
        assert cfg.get("esx", "server") == "dummy-vcenter.example.com"
        cfg.set("esx", "server", "written-through-symlink.example.com")
        with open(path, "w") as f:
            cfg.write(f, space_around_delimiters=False)
        assert "written-through-symlink.example.com" in target.read_text(), \
            "write through the symlink did not reach the tmpfs target"
        assert path.is_symlink(), "symlink was replaced by a file"
        assert link.is_symlink(), "original symlink was replaced by a file"

    def test_generator_writes_through_symlinked_output(self, sandbox,
                                                       generate,
                                                       linked_ini):
        # re-running the generator with the tree's symlink as OUTPUT
        # must not replace the link with a regular file
        target, _tree, link = linked_ini
        generate(link, env={
            "VIRTWHO_VCENTER_SERVER":
                "written-via-symlink-output.example.com"},
            unset=("VIRTWHO_INI_URL",))
        assert link.is_symlink(), \
            "generator replaced the symlinked OUTPUT with a regular file"
        assert "written-via-symlink-output.example.com" \
            in target.read_text(), \
            "generator did not write through the symlink to the tmpfs " \
            "target"


# --- 4) ssh_config approach + the REAL cleanup-secrets.sh ----------------

@pytest.fixture
def ssh_setup(sandbox):
    """A tmpfs SSH key plus exactly the ssh_config block run-tests.sh
    writes (base block + tmpfs key entry)."""
    key = sandbox / "virtwho-ssh-key"
    proc = run(["ssh-keygen", "-t", "rsa", "-N", "", "-f", key,
                "-C", "selftest", "-q"])
    assert proc.returncode == 0, proc.stderr
    os.chmod(key, 0o600)
    pub = Path(str(key) + ".pub")
    proc = run(["ssh-keygen", "-y", "-f", key])
    assert proc.returncode == 0, proc.stderr
    pub.write_text(proc.stdout)
    config = sandbox / "ssh-config"
    config.write_text(
        f"Host *\n"
        f"  StrictHostKeyChecking no\n"
        f"  UserKnownHostsFile {sandbox}/known_hosts\n\n"
        f"  # virtwho-test tmpfs key\n"
        f"  IdentityFile {key}\n")
    os.chmod(config, 0o600)
    ns = SimpleNamespace()
    ns.key, ns.pub, ns.config = key, pub, config
    return ns


class TestSshConfig:
    def test_public_key_derived_next_to_tmpfs_key(self, ssh_setup):
        assert ssh_setup.pub.read_text().startswith("ssh-rsa "), \
            "could not derive the public key"

    def test_ssh_g_resolves_tmpfs_identity_file(self, ssh_setup):
        # ssh -G resolves the config WITHOUT connecting: the
        # IdentityFile entry must point ssh (and through it the
        # virt-who daemon's qemu+ssh URIs) at the tmpfs key
        proc = run(["ssh", "-G", "-F", ssh_setup.config,
                    "dummy-hypervisor.example.invalid"])
        assert proc.returncode == 0, proc.stderr
        assert f"identityfile {ssh_setup.key}" in proc.stdout.splitlines(), \
            "ssh -G did not resolve the tmpfs IdentityFile entry"


@pytest.fixture
def cleaned_sandbox(sandbox, ssh_setup):
    """A sandbox with the same layout as a CI guest, already swept by
    the REAL cleanup-secrets.sh (locations overridden via the
    VIRTWHO_CLEANUP_* knobs; VIRTWHO_CLEANUP_KUBECONFIGS deliberately
    UNSET so the finish step must read the kubeconfig paths from the
    ini)."""
    ini = sandbox / "virtwho.ini"
    ini.write_text(
        "[esx]\npassword=dummy-selftest-secret\n[kubevirt]\n"
        f"config_file={sandbox}/root/kc-custom\n"
        f"config_file_no_cert={sandbox}/outside/important\n")
    os.chmod(ini, 0o600)
    staging = sandbox / "virtwho.ini.tmp.ABCDEF"
    staging.write_text("partial\n")
    root = sandbox / "root"
    outside = sandbox / "outside"
    root.mkdir()
    outside.mkdir()
    kc_custom = root / "kc-custom"
    kc_custom.write_text("token: dummy-selftest-sa-token\n")
    os.chmod(kc_custom, 0o644)
    (outside / "important").write_text("definitely not a kubeconfig\n")
    os.chmod(outside / "important", 0o644)
    # the /etc/virt-who.d uploads (per-mode config + Hyper-V keytab),
    # the SUFFIXED and HIDDEN variants the suite's tests leave there,
    # a non-matching file, an UPPERCASE variant and a DANGLING symlink
    etc_d = sandbox / "etc-virt-who.d"
    etc_d.mkdir()
    cred_text = ("username=dummy-selftest-register-user\n"
                 "password=dummy-selftest-register-password\n")
    for name in ("esx.conf", "esx.conf.txt", ".test.conf.swp",
                 "ESX.CONF.TXT"):
        (etc_d / name).write_text(cred_text)
    (etc_d / "hyperv-kerberos.keytab").write_text("dummy-keytab-bytes\n")
    (etc_d / "notes.txt").write_text("not a credential file\n")
    (etc_d / "dangling.conf.old").symlink_to(sandbox / "no-such-target")
    # the suite's test-side copy under the kubeconfig root
    # (tests/function/test_cli.py)
    (root / "test_cli_config.conf").write_text(cred_text)
    # the tree dirs: ini symlinks, bookkeeping files, temp/ artifacts,
    # and one REGULAR legacy ini
    tree_dirs = []
    for tree in ("tree-opt", "tree-usr", "tree-var"):
        tree_dir = sandbox / tree
        tree_dirs.append(tree_dir)
        (tree_dir / "temp").mkdir(parents=True)
        (tree_dir / "virtwho.ini").symlink_to(ini)
        (tree_dir / ".virtwho-ini-generated").touch()
        (tree_dir / ".virtwho-computed.ini").touch()
        (tree_dir / "temp" / "esx.conf").write_text(
            "password=dummy-selftest-hypervisor-password\n")
        (tree_dir / "temp" / "hyperv-kerberos.keytab").write_text(
            "dummy-keytab-bytes\n")
    legacy = sandbox / "tree-legacy"
    tree_dirs.append(legacy)
    legacy.mkdir()
    (legacy / "virtwho.ini").write_text(
        "[esx]\npassword=dummy-selftest-legacy-ini-password\n")
    # a sibling IdentityFile entry (e.g. a .bak) must survive the
    # anchored delete
    with ssh_setup.config.open("a") as f:
        f.write(f"  IdentityFile {ssh_setup.key}.bak\n")
    # the upgrade tests' /tmp copies (plus the non-credential
    # sysconfig copy that must survive)
    tmp_dir = sandbox / "tmp-upgrade"
    tmp_dir.mkdir()
    for name in ("esx.conf.pre", "esx.conf.post"):
        (tmp_dir / name).write_text(cred_text)
    (tmp_dir / "virt-who.conf.pre").write_text("[global]\n")
    (tmp_dir / "virt-who.conf.post").write_text("[global]\n")
    (tmp_dir / "virt-who.pre").write_text("VIRTWHO_INTERVAL=3600\n")

    proc = run(["bash", SCRIPTS_DIR / "cleanup-secrets.sh"], env={
        "VIRTWHO_CLEANUP_SHM_DIR": str(sandbox),
        "VIRTWHO_CLEANUP_SSH_CONFIG": str(ssh_setup.config),
        "VIRTWHO_CLEANUP_TREE_DIRS":
            " ".join(str(d) for d in tree_dirs),
        "VIRTWHO_KUBECONFIG_ROOT": str(root),
        "VIRTWHO_CLEANUP_VIRTWHO_D_DIR": str(etc_d),
        "VIRTWHO_CLEANUP_TMP_DIR": str(tmp_dir),
    })
    assert proc.returncode == 0, proc.stderr

    ns = SimpleNamespace()
    ns.ini = ini
    ns.key = ssh_setup.key
    ns.pub = ssh_setup.pub
    ns.staging = staging
    ns.root = root
    ns.outside = outside
    ns.etc_d = etc_d
    ns.tmp_dir = tmp_dir
    ns.tree_dirs = tree_dirs
    ns.config = ssh_setup.config
    ns.proc = proc
    return ns


class TestCleanupSecrets:
    def test_tmpfs_originals_and_staging_shredded(self, cleaned_sandbox):
        cs = cleaned_sandbox
        for f in (cs.ini, cs.key, cs.pub, cs.staging):
            assert not f.exists(), f"cleanup left {f} behind"

    def test_ini_kubeconfig_confined_shredded_outside_refused(
            self, cleaned_sandbox):
        # the ini-configured kubeconfig path UNDER the kubeconfig
        # root is shredded; the path OUTSIDE it is refused with a
        # warning naming it and survives untouched
        cs = cleaned_sandbox
        assert not (cs.root / "kc-custom").exists(), \
            f"cleanup left the ini-configured kubeconfig " \
            f"{cs.root}/kc-custom behind"
        assert (cs.outside / "important").exists(), \
            "cleanup shredded an ini-supplied path outside the " \
            "kubeconfig root"
        assert f"WARNING: refusing to shred {cs.outside}/important " \
            "(not a kubeconfig path)" in cs.proc.stdout, \
            "the refused kubeconfig path produced no warning naming it"

    def test_tree_dirs_swept(self, cleaned_sandbox):
        # ini symlinks, bookkeeping files, the suite's temp/
        # artifacts and the regular legacy ini are removed/shredded
        # from every tree dir
        cs = cleaned_sandbox
        for tree_dir in cs.tree_dirs:
            for name in ("virtwho.ini", ".virtwho-ini-generated",
                         ".virtwho-computed.ini", "temp/esx.conf",
                         "temp/hyperv-kerberos.keytab"):
                assert not (tree_dir / name).exists(), \
                    f"cleanup left {tree_dir}/{name} behind"

    def test_etc_virtwho_d_uploads_shredded(self, cleaned_sandbox):
        # the per-mode config, the suffixed/hidden test variants and
        # the keytab twin carry the same credentials as the temp/
        # artifacts; a non-matching file survives
        cs = cleaned_sandbox
        for name in ("esx.conf", "esx.conf.txt", ".test.conf.swp",
                     "hyperv-kerberos.keytab", "ESX.CONF.TXT"):
            assert not (cs.etc_d / name).exists(), \
                f"cleanup left the virt-who.d upload {name} behind"
        assert (cs.etc_d / "notes.txt").exists(), \
            "cleanup shredded a non-matching file in /etc/virt-who.d " \
            "(glob over-matches)"

    def test_sweep_case_insensitive_and_dangling_links(self,
                                                       cleaned_sandbox):
        # an uppercase variant of a suite-written name and a broken
        # link matched by the globs must not survive
        cs = cleaned_sandbox
        assert not (cs.etc_d / "ESX.CONF.TXT").exists()
        assert not (cs.etc_d / "dangling.conf.old").is_symlink(), \
            "cleanup left a dangling virt-who.d symlink behind"

    def test_root_test_cli_copy_shredded(self, cleaned_sandbox):
        # tests/function/test_cli.py copies the per-mode config to a
        # fixed /root path to exercise `virt-who -c`
        cs = cleaned_sandbox
        assert not (cs.root / "test_cli_config.conf").exists(), \
            "cleanup left the suite's /root/test_cli_config.conf " \
            "copy behind"

    def test_tmp_upgrade_copies_shredded(self, cleaned_sandbox):
        # tests/upgrade/test_upgrade.py pulls the per-mode configs
        # and /etc/virt-who.conf onto /tmp; the non-credential
        # sysconfig copy (no .conf component) does not match
        cs = cleaned_sandbox
        for name in ("esx.conf.pre", "esx.conf.post",
                     "virt-who.conf.pre", "virt-who.conf.post"):
            assert not (cs.tmp_dir / name).exists(), \
                f"cleanup left the upgrade-test /tmp copy {name} behind"
        assert (cs.tmp_dir / "virt-who.pre").exists(), \
            "cleanup shredded a non-credential /tmp file " \
            "(glob over-reach)"

    def test_ssh_config_entry_removed_anchored(self, cleaned_sandbox):
        # the tmpfs IdentityFile entry is dropped with an EXACT
        # match; a sibling .bak entry and the rest of the config
        # survive
        cs = cleaned_sandbox
        lines = cs.config.read_text().splitlines()
        assert f"  IdentityFile {cs.key}" not in lines, \
            "cleanup did not remove the exact IdentityFile entry"
        assert f"  IdentityFile {cs.key}.bak" in lines, \
            "cleanup removed the sibling .bak IdentityFile entry " \
            "(delete not anchored)"
        assert "virtwho-test tmpfs key" not in lines, \
            "cleanup left the tmpfs-key marker comment behind"
        assert any("StrictHostKeyChecking no" in line for line in lines), \
            "cleanup clobbered the rest of the ssh config"


# --- 4b) prepare-kubevirt.sh: write-side kubeconfig confinement ----------

def run_prepare(sandbox, ini_text, kv_root, env_extra=None):
    """Run the REAL prepare-kubevirt.sh against the sandbox install
    dir (VIRTWHO_PREPARE_INSTALL_DIR) with the given ini content."""
    prep_dir = sandbox / "prep-install"
    prep_dir.mkdir(exist_ok=True)
    (prep_dir / "virtwho.ini").write_text(ini_text)
    env = {
        "VIRTWHO_PREPARE_INSTALL_DIR": str(prep_dir),
        "VIRTWHO_KUBECONFIG_ROOT": kv_root,
    }
    if env_extra:
        env.update(env_extra)
    return run(["bash", SCRIPTS_DIR / "prepare-kubevirt.sh"], env=env,
               unset=("KUBEVIRT_TOKEN", "VIRTWHO_KUBEVIRT_TOKEN"))


def run_cleanup(sandbox, kv_root, shm_dir=None):
    """Run the REAL cleanup-secrets.sh; the kubeconfig paths come from
    the virtwho.ini inside shm_dir when one is given (mirroring the
    CI-guest layout), else the shm dir is an empty sandbox."""
    if shm_dir is None:
        shm_dir = sandbox / "cleanup-shm"
        shm_dir.mkdir()
    for name in ("cleanup-tree", "cleanup-etc", "cleanup-tmp"):
        (sandbox / name).mkdir(exist_ok=True)
    return run(["bash", SCRIPTS_DIR / "cleanup-secrets.sh"], env={
        "VIRTWHO_KUBECONFIG_ROOT": kv_root,
        "VIRTWHO_CLEANUP_SHM_DIR": str(shm_dir),
        "VIRTWHO_CLEANUP_SSH_CONFIG": str(sandbox / "no-such-ssh-config"),
        "VIRTWHO_CLEANUP_TREE_DIRS": str(sandbox / "cleanup-tree"),
        "VIRTWHO_CLEANUP_VIRTWHO_D_DIR": str(sandbox / "cleanup-etc"),
        "VIRTWHO_CLEANUP_TMP_DIR": str(sandbox / "cleanup-tmp"),
    })


class TestPrepareKubevirt:
    def test_confined_write_and_no_cert_refusal(self, sandbox):
        # config_file confined (written 0600), config_file_no_cert
        # outside the root (refused with a warning)
        root = sandbox / "prep-root"
        outside = sandbox / "prep-outside"
        root.mkdir()
        outside.mkdir()
        proc = run_prepare(sandbox,
                           "[kubevirt]\n"
                           "endpoint=http://127.0.0.1:9\n"
                           "token=dummy-selftest-sa-token\n"
                           f"config_file={root}/kc-in-ini\n"
                           f"config_file_no_cert={outside}/kc-no-cert\n",
                           str(root))
        assert proc.returncode == 0, proc.stderr
        kc = root / "kc-in-ini"
        assert kc.exists(), \
            "prepare-kubevirt.sh did not write the confined kubeconfig"
        assert_mode(kc, "600")
        assert "kind: Config" in kc.read_text(), \
            "the written kubeconfig is not a YAML Config"
        assert not (outside / "kc-no-cert").exists(), \
            "prepare-kubevirt.sh wrote the no-cert kubeconfig outside " \
            "the kubeconfig root"
        assert f"WARNING: refusing to write the no-cert kubeconfig copy " \
            f"to {outside}/kc-no-cert" in proc.stdout, \
            "the refused no-cert path produced no warning naming it"

    def test_spaced_ini_still_writes_kubeconfig(self, sandbox):
        # `key = value` spacing is configparser-valid; the ini read is
        # configparser-based (never awk), so a spaced ini must not
        # silently skip the kubeconfig generation -- and through it
        # the write-side confinement
        root = sandbox / "prep-root"
        root.mkdir()
        proc = run_prepare(sandbox,
                           "[kubevirt]\n"
                           "endpoint = http://127.0.0.1:9\n"
                           "token = dummy-selftest-sa-token\n"
                           f"config_file = {root}/kc-spaced\n",
                           str(root))
        assert proc.returncode == 0, proc.stderr
        kc = root / "kc-spaced"
        assert kc.exists(), \
            "a spaced `key = value` ini disabled the kubeconfig generation"
        assert_mode(kc, "600")
        assert "kind: Config" in kc.read_text(), \
            "the written kubeconfig is not a YAML Config"

    def test_main_config_outside_root_refused(self, sandbox):
        outside = sandbox / "prep-outside"
        root = sandbox / "prep-root"
        outside.mkdir()
        root.mkdir()
        proc = run_prepare(sandbox,
                           "[kubevirt]\n"
                           "endpoint=http://127.0.0.1:9\n"
                           "token=dummy-selftest-sa-token\n"
                           f"config_file={outside}/kc-main\n",
                           str(root))
        assert proc.returncode == 0, proc.stderr
        assert not (outside / "kc-main").exists(), \
            "prepare-kubevirt.sh wrote a kubeconfig outside the " \
            "kubeconfig root"
        assert f"WARNING: refusing to write the kubeconfig to " \
            f"{outside}/kc-main" in proc.stdout, \
            "the refused main kubeconfig path produced no warning " \
            "naming it"

    @pytest.mark.parametrize("password", [
        pytest.param("", id="empty"),
        pytest.param("@vault:apps/cct-ci/dummy:key", id="sentinel"),
    ])
    def test_guest_password_has_no_default(self, sandbox, password):
        # an empty value and an unresolved @vault: sentinel (what the
        # raw base ini carries before resolution) both warn and skip
        # the guest proxy setup -- a published default would be a
        # working password for every guest this suite builds
        root = sandbox / "prep-root"
        root.mkdir()
        proc = run_prepare(sandbox,
                           "[kubevirt]\n"
                           "guest_ip=192.0.2.50\n"
                           "guest_port=32046\n"
                           "guest_username=guestuser\n"
                           f"guest_password={password}\n",
                           str(root),
                           env_extra=None)
        assert proc.returncode == 0, proc.stderr
        assert "WARNING: [kubevirt] guest_password is not set" in proc.stdout
        assert "skipping guest VM proxy configuration" in proc.stdout

    def test_write_and_shred_share_one_knob(self, sandbox):
        # the write side (prepare-kubevirt.sh) and the shred side
        # (cleanup-secrets.sh) must honor the SAME
        # VIRTWHO_KUBECONFIG_ROOT -- two independently-settable knobs
        # for one confinement rule could drift apart, and the token
        # would be written somewhere the finish step refuses to shred
        shared_root = sandbox / "shared-root"
        shared_outside = sandbox / "shared-outside"
        shared_root.mkdir()
        shared_outside.mkdir()
        proc = run_prepare(sandbox,
                           "[kubevirt]\n"
                           "endpoint=http://127.0.0.1:9\n"
                           "token=dummy-selftest-sa-token\n"
                           f"config_file={shared_root}/kc-shared\n"
                           f"config_file_no_cert={shared_outside}/"
                           f"kc-shared-no-cert\n",
                           str(shared_root))
        assert proc.returncode == 0, proc.stderr
        assert (shared_root / "kc-shared").exists(), \
            "prepare-kubevirt.sh did not write the kubeconfig under " \
            "the shared VIRTWHO_KUBECONFIG_ROOT"
        assert not (shared_outside / "kc-shared-no-cert").exists(), \
            "prepare-kubevirt.sh wrote the no-cert copy outside the " \
            "shared VIRTWHO_KUBECONFIG_ROOT"
        shm = sandbox / "shared-shm"
        shm.mkdir()
        (shm / "virtwho.ini").write_text(
            "[kubevirt]\n"
            f"config_file={shared_root}/kc-shared\n"
            f"config_file_no_cert={shared_outside}/kc-shared-no-cert\n")
        proc = run_cleanup(sandbox, str(shared_root), shm_dir=shm)
        assert proc.returncode == 0, proc.stderr
        assert not (shared_root / "kc-shared").exists(), \
            "cleanup-secrets.sh left the kubeconfig under the shared " \
            "VIRTWHO_KUBECONFIG_ROOT behind"
        assert not (shared_outside / "kc-shared-no-cert").exists(), \
            "cleanup-secrets.sh shredded a path outside the shared " \
            "VIRTWHO_KUBECONFIG_ROOT"
        assert f"WARNING: refusing to shred {shared_outside}/" \
            "kc-shared-no-cert (not a kubeconfig path)" in proc.stdout, \
            "the out-of-root kubeconfig path produced no refusal warning"
        # the old, split knob name must be gone from both sides of
        # the gate
        for script in ("cleanup-secrets.sh", "prepare-kubevirt.sh"):
            assert "VIRTWHO_CLEANUP_KUBECONFIG_ROOT" \
                not in (SCRIPTS_DIR / script).read_text(), \
                f"{script} still carries its own kubeconfig-root knob"

    def test_trailing_slash_on_knob_canonicalized(self, sandbox):
        # the knob is canonicalized once on both sides, so
        # VIRTWHO_KUBECONFIG_ROOT=<root>/ behaves exactly like <root>
        ts_root = sandbox / "ts-root"
        ts_root.mkdir()
        proc = run_prepare(sandbox,
                           "[kubevirt]\n"
                           "endpoint=http://127.0.0.1:9\n"
                           "token=dummy-selftest-sa-token\n"
                           f"config_file={ts_root}/kc-ts\n",
                           f"{ts_root}/")
        assert proc.returncode == 0, proc.stderr
        assert (ts_root / "kc-ts").exists(), \
            "a trailing slash on VIRTWHO_KUBECONFIG_ROOT disabled " \
            "the kubeconfig write"
        ts_shm = sandbox / "ts-shm"
        ts_shm.mkdir()
        (ts_shm / "virtwho.ini").write_text(
            f"[kubevirt]\nconfig_file={ts_root}/kc-ts\n")
        proc = run_cleanup(sandbox, f"{ts_root}/", shm_dir=ts_shm)
        assert proc.returncode == 0, proc.stderr
        assert not (ts_root / "kc-ts").exists(), \
            "a trailing slash on VIRTWHO_KUBECONFIG_ROOT disabled " \
            "the kubeconfig shred"

    def test_dotdot_path_not_confined(self, sandbox):
        # canonicalization rules out a /root/../ escape: the RAW path
        # textually matches the "$KV_ROOT"/* pattern, but the RESOLVED
        # path lands outside the root and must be refused (with the
        # warning naming the raw path) -- the per-path realpath inside
        # kv_path_is_confined is what catches it
        root = sandbox / "dd-root"
        outside = sandbox / "dd-outside"
        root.mkdir()
        outside.mkdir()
        raw_path = f"{root}/../{outside.name}/kc-dd"
        proc = run_prepare(sandbox,
                           "[kubevirt]\n"
                           "endpoint=http://127.0.0.1:9\n"
                           "token=dummy-selftest-sa-token\n"
                           f"config_file={raw_path}\n",
                           str(root))
        assert proc.returncode == 0, proc.stderr
        assert not (outside / "kc-dd").exists(), \
            "a /root/../ path was treated as confined " \
            "(per-path canonicalization missing)"
        assert f"WARNING: refusing to write the kubeconfig to {raw_path}" \
            in proc.stdout, \
            "the escaped kubeconfig path produced no warning naming it"


# --- 5) Wrapper-script credential contracts ------------------------------

class TestWrapperContracts:
    def test_no_password_or_image_defaults(self):
        # run-tests.sh cannot run hermetically (it restarts sshd and
        # runs pytest), so its password flow is pinned with
        # source-level checks: env-or-random per-run guest root
        # password, passwd fed via stdin, the ini merge via the
        # environment -- and the squid image read from
        # VIRTWHO_SQUID_IMAGE at every site, never a literal
        run_tests = (SCRIPTS_DIR / "run-tests.sh").read_text()
        assert "VIRTWHO_VIRTWHO_PASSWORD" in run_tests, \
            "run-tests.sh no longer reads VIRTWHO_VIRTWHO_PASSWORD"
        assert "secrets.token_hex" in run_tests, \
            "run-tests.sh no longer generates a random per-run guest " \
            "root password"
        assert "printf '%s\\n' \"$GUEST_ROOT_PASS\" | passwd --stdin root" \
            in run_tests, \
            "run-tests.sh no longer feeds passwd from the per-run " \
            "password variable"
        assert ('fallback("virtwho", "password", '
                'os.environ.get("GUEST_ROOT_PASS"))') in run_tests, \
            "run-tests.sh no longer fills [virtwho] password from the " \
            "per-run environment"
        assert not re.search(r'echo "[^$"]+" \| passwd --stdin', run_tests), \
            "run-tests.sh feeds passwd a quoted literal"
        prepare = (SCRIPTS_DIR / "prepare-kubevirt.sh").read_text()
        assert not re.search(
            r'SSHPASS="\$\{[A-Z_]+:-[^}"$]+\}"', prepare), \
            "prepare-kubevirt.sh still carries a default inside a " \
            "SSHPASS expansion"
        for site in (SCRIPTS_DIR / "install-deps.sh",
                     SCRIPTS_DIR / "run-tests.sh",
                     REPO_ROOT / "tests" / "conftest.py"):
            assert "VIRTWHO_SQUID_IMAGE" in site.read_text(), \
                f"{site} no longer reads VIRTWHO_SQUID_IMAGE"

    def test_install_deps_squid_pre_pull(self, sandbox):
        # the squid skip branch, exercised behaviorally in a stubbed
        # sandbox (dnf/systemctl/podman stubs on PATH, systemd
        # "running"): with VIRTWHO_SQUID_IMAGE unset the pre-pull is
        # a visible no-op; with it set the image IS pre-pulled
        deps_bin = sandbox / "deps-bin"
        deps_bin.mkdir()
        write_executable(deps_bin / "dnf",
                         "#!/bin/bash\n"
                         "# Fake dnf: accept every install.\n"
                         "exit 0\n")
        write_executable(deps_bin / "systemctl",
                         "#!/bin/bash\n"
                         "# Fake systemctl: report a running system.\n"
                         '[ "$1" = "is-system-running" ] && exit 0\n'
                         "exit 1\n")
        write_executable(
            deps_bin / "podman",
            "#!/bin/bash\n"
            "# Fake podman: record every invocation.\n"
            'printf \'%s\\n\' "$*" > "${FAKE_PODMAN_ARGS_FILE}"\n'
            "exit 0\n")
        podman_args = sandbox / "podman-args"
        env = {"PATH": f"{deps_bin}:{os.environ['PATH']}",
               "FAKE_PODMAN_ARGS_FILE": str(podman_args)}
        proc = run(["bash", SCRIPTS_DIR / "install-deps.sh"],
                   env=env, unset=("VIRTWHO_SQUID_IMAGE", "TEST_RPMS"))
        assert proc.returncode == 0, proc.stderr
        assert "VIRTWHO_SQUID_IMAGE not set; skipping the bad-proxy " \
            "container image pre-pull" in proc.stdout
        assert not podman_args.exists(), \
            "install-deps.sh invoked podman although VIRTWHO_SQUID_IMAGE " \
            "is unset"
        proc = run(["bash", SCRIPTS_DIR / "install-deps.sh"], env={
            **env,
            "VIRTWHO_SQUID_IMAGE": "dummy-squid.example.invalid/squid:1"},
            unset=("TEST_RPMS",))
        assert proc.returncode == 0, proc.stderr
        assert "pull dummy-squid.example.invalid/squid:1" \
            in podman_args.read_text(), \
            "install-deps.sh did not pre-pull the VIRTWHO_SQUID_IMAGE image"

    def test_polarion_url_env_delivered(self):
        # the Polarion URL is equally env-delivered at every site of
        # the legacy import tooling, and no internal Polarion host
        # remains anywhere in the tree (the fragmented pattern keeps
        # this check from matching its own source)
        for site in ("import_polarion_testcases.sh",
                     "utils/polarion_testcase_upload.py",
                     "utils/polarion_testrun_import.py"):
            text = (REPO_ROOT / site).read_text()
            assert "POLARION_URL" in text, \
                f"{site} no longer reads POLARION_URL"
        internal_host = ("polarion" + "[.]engineering" + "[.]redhat"
                         + "[.]com")
        for path in sorted(REPO_ROOT.rglob("*")):
            if ".git" in path.parts or not path.is_file():
                continue
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            assert not re.search(internal_host, text), \
                f"an internal Polarion host survived in {path}"

    def test_run_tests_ini_merge_password_flow(self, sandbox):
        # behavioral half of the password-flow check: extract the
        # REAL ini-merge heredoc from run-tests.sh and run it against
        # dummy files -- the [virtwho] password must land from the
        # per-run environment variable (and stay empty without it),
        # never from a literal
        lines = (SCRIPTS_DIR / "run-tests.sh").read_text().splitlines()
        marker = ('GUEST_ROOT_PASS="$GUEST_ROOT_PASS" python3 - '
                  '/dev/shm/virtwho.ini .virtwho-computed.ini '
                  "<<'PYEOF'")
        starts = [i for i, line in enumerate(lines) if marker in line]
        assert len(starts) == 1, \
            "could not extract the ini-merge heredoc from run-tests.sh"
        end = next(i for i in range(starts[0] + 1, len(lines))
                   if lines[i] == "PYEOF")
        merge_py = sandbox / "merge.py"
        merge_py.write_text("\n".join(lines[starts[0] + 1:end]) + "\n")
        assert merge_py.stat().st_size > 0

        new = sandbox / "new.ini"
        new.write_text("[virtwho]\nserver=192.0.2.10\n\n"
                       "[kubevirt]\nguest_ip=\n")
        computed = sandbox / "computed.ini"
        computed.write_text(
            "[virtwho]\npackage=virt-who-1.31.28-1.el9.noarch\n\n"
            "[job]\nrhel_compose=RHEL-10.0-DUMMY\n")
        proc = run(["python3", merge_py, new, computed],
                   env={"GUEST_ROOT_PASS": "dummy-selftest-per-run-pass"})
        assert proc.returncode == 0, proc.stderr
        assert_ini_value(new, "virtwho", "username", "root")
        assert_ini_value(new, "virtwho", "password",
                         "dummy-selftest-per-run-pass")
        assert_ini_value(new, "virtwho", "package",
                         "virt-who-1.31.28-1.el9.noarch")
        assert_ini_value(new, "job", "rhel_compose", "RHEL-10.0-DUMMY")

        # without the per-run password the option stays EMPTY: no default
        new2 = sandbox / "new2.ini"
        new2.write_text("[virtwho]\nserver=192.0.2.10\n")
        proc = run(["python3", merge_py, new2, computed],
                   unset=("GUEST_ROOT_PASS",))
        assert proc.returncode == 0, proc.stderr
        assert not re.search(r"^password=.", new2.read_text(), re.MULTILINE), \
            "the ini merge filled [virtwho] password with a default"
