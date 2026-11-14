"""Test cases Global fields

:casecomponent: virt-who
:testtype: nonfunctional
:subtype1: installability
:caseautomation: Automated
:subsystemteam: rhel-sst-csi-client-tools
:caselevel: Component
"""

import re

import pytest

from virtwho import RHEL_COMPOSE, TEST_RPMS, VIRTWHO_PKG
from virtwho.base import (
    package_check,
    package_install,
    package_uninstall,
    random_string,
    virtwho_download_under_test,
    virtwho_install_under_test,
)

pytestmark = pytest.mark.notImageMode


class TestInstallUninstall:
    @pytest.mark.tier1
    def test_install_uninstall_by_dnf(self, ssh_host):
        """Test virt-who install/uninstall by dnf

        :title: virt-who: package: install/uninstall by dnf
        :id: 7b32612a-11eb-437e-92c9-b7d501d2e8a0
        :caseimportance: High
        :tags: package,tier1
        :customerscenario: false
        :steps:
            1. uninstall virt-who by #dnf remove virt-who
            2. install the version under test by #dnf install
            3. check the /etc/virt-who.d/template.conf
        :expectedresults:
            1. virt-who can be removed and the version under test
               reinstalled successfully (TEST_RPMS when set, else the
               compose-provided package -- never the destination's
               content repo, which does not serve virt-who in the
               container tier).
            2.
        """
        try:
            # Keep virt-who's dependencies installed through the
            # remove: dnf5 (RHEL-10) cleans automatically-installed
            # dependencies together with the package
            # (clean_requirements_on_remove), and the repo-less
            # reinstall of the version under test below could no
            # longer resolve a removed python3-cryptography.
            package_uninstall(ssh_host, "virt-who", keep_deps=True)
            assert package_check(ssh_host, "virt-who") is False
            # reinstall the VERSION UNDER TEST
            # (TEST_RPMS has precedence, else the compose-provided
            # RPM cached at prepare time), never whatever the
            # currently-enabled content repos serve -- the container
            # tier's registered host gets its content from the pod's
            # repo, which does not carry virt-who.
            virtwho_install_under_test(ssh_host)
            if TEST_RPMS:
                assert package_check(ssh_host, "virt-who") is not False
            else:
                assert package_check(ssh_host, "virt-who") == VIRTWHO_PKG

            options = [
                "#[config name]",
                "#type=",
                "#server=",
                "#username=",
                "#password=",
                "#encrypted_password=",
                "#owner=",
                "#hypervisor_id=",
                "#rhsm_hostname=",
                "#rhsm_port=",
                "#rhsm_username=",
                "#rhsm_password=",
                "#rhsm_encrypted_password=",
                "#rhsm_prefix=/rhsm",
                "#kubeconfig=",
                "#kubeversion=",
                "#insecure=",
            ]
            line_num = 44
            if "RHEL-8" in RHEL_COMPOSE:
                line_num = 43
                options.remove("#insecure=")
            _, output = ssh_host.runcmd("cat /etc/virt-who.d/template.conf")
            for option in options:
                assert len(re.findall(option, output)) > 0
            lines = output.strip().split("\n")
            assert len(lines) == line_num
        finally:
            # Cascade guard: the version under test is reinstalled
            # unconditionally, whatever happened in the body above --
            # a virt-who-less suite cascades into every later test.
            # In gating mode (TEST_RPMS) this restores the gating
            # build even when some other version is present; in
            # compose mode the helper is a no-op success when the
            # version under test is already installed. It raises
            # loudly on a failed install -- never a silent continue.
            virtwho_install_under_test(ssh_host)

    @pytest.mark.tier1
    def test_install_uninstall_by_rpm(self, ssh_host):
        """Test virt-who install/uninstall by rpm

        :title: virt-who: package: install/uninstall by rpm
        :id: 14152159-22a7-4550-9281-1109c4440f34
        :caseimportance: High
        :tags: package,tier1
        :customerscenario: false
        :steps:
            1. uninstall virt-who by #rpm -e
            2. fetch the version-under-test RPM (the undertest
               cache; dnf download only as the hand-run local
               fallback when no cache exists)
            3. install virt-who by #rpm -ivh
        :expectedresults:
            1. virt-who can be removed and reinstalled successfully.
        """
        file_path = None
        try:
            file_path = "/tmp/packageInstallUninstall-" + random_string()
            # Source the rpm from the undertest cache -- the version
            # under test, never the enabled repos: after registration
            # the destination's content repo is the only enabled one
            # and is dead by design in the container tier. The
            # precedence mirrors virtwho_install_under_test(): cache
            # first, enabled repos only as the hand-run local
            # fallback.
            rpm_path = virtwho_download_under_test(ssh_host, file_path)

            package_uninstall(ssh_host, "virt-who", rpm=VIRTWHO_PKG)
            assert package_check(ssh_host, "virt-who") is False

            package_install(ssh_host, "virt-who", rpm=rpm_path)
            if TEST_RPMS:
                assert package_check(ssh_host, "virt-who") is not False
            else:
                assert package_check(ssh_host, "virt-who") == VIRTWHO_PKG
        finally:
            # the same cascade guard as by_dnf: the version under
            # test is reinstalled unconditionally through the
            # precedence helper, loudly raising on failure; the temp
            # dir is cleaned.
            virtwho_install_under_test(ssh_host)
            if file_path:
                ssh_host.runcmd(f"rm -rf {file_path}")
