"""Destination-knob self-tests (CCT-3155): the containerized
Candlepin tier of generate-virtwho-ini.sh.

VIRTWHO_DESTINATION selects the [rhsm] contract:

  * container (the DEFAULT -- what fixes the Jenkins runs without any
    pipeline change): [rhsm] is forced to the SYNTHETIC values of the
    checked-in systemtest/config/virtwho-container.ini. The base's
    [rhsm] sentinels are neither resolved nor kept, VIRTWHO_RHSM_* env
    secrets do NOT overlay the section (stale stage secrets from an
    old pipeline are ignored with a warning), and no Vault wiring is
    needed at all.
  * stage: today's sentinel flow, unchanged (env wins, sentinels
    resolve).

Also covered: the knob's clean failure on an invalid value, the
[job] destination record the suite reads back, and the contract of
the checked-in overlay file itself (it must stay parseable, complete
and free of @vault: sentinels -- it is synthetic public test data,
not credentials).

Run: python -m pytest systemtest/selftest/ -v
"""

import re

import pytest
from _utils import (
    REPO_ROOT,
    SCRIPTS_DIR,
    assert_ini_value,
    ini_value,
    run,
)

GENERATOR = SCRIPTS_DIR / "generate-virtwho-ini.sh"
CONTAINER_INI = REPO_ROOT / "systemtest" / "config" / "virtwho-container.ini"

# The synthetic container values (public-by-design test data baked
# into the ghcr.io/candlepin images -- every value asserted here is
# deliberately publishable, NOT a real credential). baseurl points
# at the deliberately-unbound localhost:8080 (review H1 + the run-#7
# follow-up): the pod has no repo container, so the value keeps
# content access LOCAL (no CDN fallback, no external egress) while
# content operations fail bounded -- the tier must never inherit a
# stage CDN baseurl, and must never fall back to one either.
CONTAINER_RHSM = {
    "server": "candlepin",
    "username": "testuser1",
    "password": "password",
    "prefix": "/candlepin",
    "port": "8443",
    "baseurl": "http://localhost:8080",
    "default_org": "snowwhite",
    "activation_key": "",
    "proxy_hostname": "",
    "proxy_port": "",
}

# A base whose ONLY sentinels sit in [rhsm]: in container mode they
# are dead values (the overlay rewrites the section), so the run
# needs NO Vault credentials; in stage mode the same base must abort
# (an active unresolved sentinel). No plaintext credentials anywhere
# (the generator's filter would rightly reject them).
RHSM_SENTINEL_BASE = """\
; dummy base: only [rhsm] carries sentinels
[job]
hypervisor=libvirt
register=rhsm

[libvirt]
server=base-libvirt.example.com

[rhsm]
server=base-rhsm.example.com
username=@vault:apps/cct-ci/candlepin/stage:username
password=@vault:apps/cct-ci/candlepin/stage:password
default_org=base-rhsm-org
proxy_hostname=base-proxy.example.com
proxy_port=3128
"""


@pytest.fixture
def generate():
    """Run the REAL generator; assert success so a broken generator
    fails every dependent test with its stderr."""
    def _generate(output, *, env=None, unset=(), expect_success=True):
        proc = run(["bash", GENERATOR, output], env=env, unset=unset)
        if expect_success:
            assert proc.returncode == 0, (
                "generate-virtwho-ini.sh failed "
                f"(exit {proc.returncode}):\n{proc.stderr}")
        return proc
    return _generate


@pytest.fixture
def rhsm_sentinel_base(sandbox):
    path = sandbox / "rhsm-sentinel-base.ini"
    path.write_text(RHSM_SENTINEL_BASE)
    return path


PLAN_ENV = {"HYPERVISOR": "libvirt", "REGISTER": "rhsm",
            "RHEL_COMPOSE": "RHEL-10.0-DUMMY"}
NO_DESTINATION = ("VIRTWHO_INI_URL", "VIRTWHO_DESTINATION")


class TestContainerDefault:
    def test_env_only_generation_carries_container_values(self, sandbox,
                                                           generate):
        # the DEFAULT (no VIRTWHO_DESTINATION anywhere): even a bare
        # env-only run gets a working hermetic destination
        out = sandbox / "container-default.ini"
        proc = generate(out, env=dict(PLAN_ENV),
                        unset=NO_DESTINATION + NO_VAULT())
        for option, value in CONTAINER_RHSM.items():
            assert ini_value(out, "rhsm", option) == value, \
                f"[rhsm] {option} is not the container value"
        # the tier is recorded for the suite (conftest reads it)
        assert_ini_value(out, "job", "destination", "container")
        assert "destination: container" in proc.stdout

    def test_env_secrets_do_not_override_rhsm(self, sandbox, generate):
        # a stale stage secret delivered by an old pipeline must not
        # break the hermetic run: [rhsm] keeps the container values
        # and the ignored variables are announced (names only)
        out = sandbox / "container-envsecret.ini"
        proc = generate(out, env={
            **PLAN_ENV,
            "VIRTWHO_RHSM_SERVER": "stage.example.com",
            "VIRTWHO_RHSM_USERNAME": "dummy-stage-user",
            "VIRTWHO_RHSM_PASSWORD": "dummy-stage-pass",
            "VIRTWHO_RHSM_PROXY_HOSTNAME": "proxy.example.com"},
            unset=NO_DESTINATION + NO_VAULT())
        for option, value in CONTAINER_RHSM.items():
            assert ini_value(out, "rhsm", option) == value, \
                f"a VIRTWHO_RHSM_* secret overrode [rhsm] {option}"
        assert "ignoring 4 VIRTWHO_RHSM_* environment variable(s)" \
            in proc.stderr
        assert "VIRTWHO_RHSM_SERVER" in proc.stderr
        # never the values
        assert "stage.example.com" not in proc.stderr
        assert "dummy-stage-pass" not in proc.stderr

    def test_env_secrets_do_not_overlay_extra_rhsm_options(self, sandbox,
                                                             generate):
        # the skip covers the WHOLE [rhsm] section, not just the
        # overlay's table options: a base may carry extra [rhsm]
        # options (e.g. a stage repo_ca_cert) and a stale env secret
        # must not land on those either (the overlay itself only
        # rewrites the table options, so THIS is the skip's own
        # observable effect -- mutation-pinned)
        base = sandbox / "extra-option-base.ini"
        base.write_text(
            "[job]\nhypervisor=libvirt\nregister=rhsm\n\n"
            "[libvirt]\nserver=base-libvirt.example.com\n\n"
            "[rhsm]\nserver=base-rhsm.example.com\n"
            "repo_ca_cert=base-ca.example.com\n")
        out = sandbox / "container-extra-option.ini"
        generate(out, env={
            **PLAN_ENV,
            "VIRTWHO_INI_URL": f"file://{base}",
            "VIRTWHO_RHSM_REPO_CA_CERT": "stage-ca.example.com"},
            unset=("VIRTWHO_DESTINATION",) + NO_VAULT())
        assert ini_value(out, "rhsm", "repo_ca_cert") == \
            "base-ca.example.com", \
            "a VIRTWHO_RHSM_* secret overrode an extra [rhsm] option"
        for option, value in CONTAINER_RHSM.items():
            assert ini_value(out, "rhsm", option) == value, \
                f"[rhsm] {option} is not the container value"

    def test_stage_cdn_baseurl_leftover_does_not_survive(self, sandbox,
                                                          generate):
        # review H1: baseurl is now a TABLE option of [rhsm], so the
        # container overlay rewrites it -- a stage CDN leftover in
        # the base (or a stale VIRTWHO_RHSM_BASEURL secret) must not
        # survive into the hermetic tier: content ops would 403
        # against stage and the tier would not be hermetic on
        # content. The container value is the deliberately-unbound
        # local port (no repo container -- the run-#7 follow-up).
        base = sandbox / "stage-cdn-base.ini"
        base.write_text(
            "[job]\nhypervisor=libvirt\nregister=rhsm\n\n"
            "[libvirt]\nserver=base-libvirt.example.com\n\n"
            "[rhsm]\nserver=base-rhsm.example.com\n"
            "baseurl=base-cdn.example.com\n")
        out = sandbox / "container-baseurl.ini"
        generate(out, env={
            **PLAN_ENV,
            "VIRTWHO_INI_URL": f"file://{base}",
            "VIRTWHO_RHSM_BASEURL": "stage-cdn.example.com"},
            unset=("VIRTWHO_DESTINATION",) + NO_VAULT())
        assert ini_value(out, "rhsm", "baseurl") == \
            "http://localhost:8080", \
            "a stage CDN baseurl survived into the container tier"

    def test_stage_baseurl_is_env_deliverable(self, sandbox, generate):
        # the TABLE addition cuts both ways: stage mode can deliver
        # baseurl through the environment (VIRTWHO_RHSM_BASEURL),
        # like every other [rhsm] option
        out = sandbox / "stage-baseurl.ini"
        generate(out, env={
            **PLAN_ENV,
            "VIRTWHO_DESTINATION": "stage",
            "VIRTWHO_RHSM_BASEURL": "stage-cdn.example.com"},
            unset=("VIRTWHO_INI_URL",) + NO_VAULT())
        assert_ini_value(out, "rhsm", "baseurl", "stage-cdn.example.com")

    def test_baseurl_option_always_emitted(self, sandbox, generate):
        # the AttributeError class (review H1): SubscriptionManager
        # reads register.baseurl; the generator must ALWAYS emit the
        # option, never leave it missing (empty in stage env-only
        # mode, the container value in container mode)
        out = sandbox / "bare.ini"
        generate(out, env=dict(PLAN_ENV),
                 unset=NO_DESTINATION + NO_VAULT())
        assert ini_value(out, "rhsm", "baseurl") == \
            "http://localhost:8080"
        out_stage = sandbox / "bare-stage.ini"
        generate(out_stage, env={
            **PLAN_ENV, "VIRTWHO_DESTINATION": "stage"},
            unset=("VIRTWHO_INI_URL",) + NO_VAULT())
        assert_ini_value(out_stage, "rhsm", "baseurl", "")

    def test_base_rhsm_sentinels_need_no_vault(self, sandbox, generate,
                                               rhsm_sentinel_base):
        # the base's [rhsm] sentinels are dead values in container
        # mode: not resolved, not kept, no Vault credentials required
        out = sandbox / "container-sentinels.ini"
        generate(out, env={
            **PLAN_ENV,
            "VIRTWHO_INI_URL": f"file://{rhsm_sentinel_base}"},
            unset=("VIRTWHO_DESTINATION",) + NO_VAULT())
        for option, value in CONTAINER_RHSM.items():
            assert ini_value(out, "rhsm", option) == value, \
                f"a base [rhsm] value survived into {option}"
        # the non-[rhsm] base values are untouched by the knob
        assert_ini_value(out, "libvirt", "server",
                         "base-libvirt.example.com")

    def test_base_rhsm_sentinels_stage_contrast(self, sandbox, generate,
                                                rhsm_sentinel_base):
        # the SAME base in stage mode: the active [rhsm] sentinels
        # must abort without credentials (a credentialed cell must
        # not silently run credless) -- proving the container pass
        # above is the knob's doing, not a sentinel-resolution bug
        out = sandbox / "stage-sentinels.ini"
        proc = generate(out, env={
            **PLAN_ENV,
            "VIRTWHO_DESTINATION": "stage",
            "VIRTWHO_INI_URL": f"file://{rhsm_sentinel_base}"},
            unset=NO_VAULT(), expect_success=False)
        assert proc.returncode != 0
        assert "no Vault credentials are set" in proc.stderr


class TestStageMode:
    def test_stage_restores_env_overlay(self, sandbox, generate):
        out = sandbox / "stage-env.ini"
        generate(out, env={
            **PLAN_ENV,
            "VIRTWHO_DESTINATION": "stage",
            "VIRTWHO_RHSM_SERVER": "stage.example.com",
            "VIRTWHO_RHSM_USERNAME": "dummy-stage-user",
            "VIRTWHO_RHSM_PASSWORD": "dummy-stage-pass"},
            unset=("VIRTWHO_INI_URL",) + NO_VAULT())
        assert_ini_value(out, "rhsm", "server", "stage.example.com")
        assert_ini_value(out, "rhsm", "username", "dummy-stage-user")
        assert_ini_value(out, "rhsm", "password", "dummy-stage-pass")
        assert_ini_value(out, "job", "destination", "stage")

    def test_invalid_destination_fails_cleanly(self, sandbox, generate):
        out = sandbox / "bogus.ini"
        proc = generate(out, env={**PLAN_ENV,
                                  "VIRTWHO_DESTINATION": "bogus"},
                        unset=("VIRTWHO_INI_URL",), expect_success=False)
        assert proc.returncode != 0
        assert "VIRTWHO_DESTINATION must be 'container' or 'stage'" \
            in proc.stderr
        assert not out.exists() or not out.read_text().strip()


class TestContainerOverlayFile:
    # the checked-in overlay is the tier's contract: it must parse,
    # carry exactly the [rhsm] section with every table option, hold
    # no @vault: sentinel (it is synthetic public test data) and be
    # labeled as such
    def test_parses_with_expected_values(self):
        text = CONTAINER_INI.read_text()
        assert "[rhsm]" in text
        for option, value in CONTAINER_RHSM.items():
            assert re.search(rf"^{option}={re.escape(value)}$", text,
                             re.MULTILINE), \
                f"the container overlay lost its {option} value"

    def test_no_sentinels_and_labeled_synthetic(self):
        text = CONTAINER_INI.read_text()
        assert "@vault:" not in text, \
            "the container overlay must never carry Vault sentinels"
        assert "SYNTHETIC" in text, \
            "the overlay must label its values as synthetic test data"


def NO_VAULT():
    """The vault-credential variables to unset (hermetic runs)."""
    return ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_ROLE_ID",
            "VAULT_SECRET_ID", "VIRTWHO_VAULT_REQUIRED")
