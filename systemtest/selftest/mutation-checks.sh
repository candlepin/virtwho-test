#!/bin/bash
# mutation-checks.sh -- Maintainers' tool: prove the selftest suite
# actually CATCHES the standing battery of security-regression
# mutations (the executable counterpart of PARITY.md).
#
# For each mutation in the battery below, this script copies the
# repository to a throwaway tree under /dev/shm (tmpfs; the copy
# carries no real credentials -- every value the suite touches is an
# RFC 2606/5737 dummy), applies the ONE mutation to the copy, runs
# the full pytest selftest suite AGAINST THE COPY and asserts the run
# FAILS (at least one test). A mutation whose anchor text no longer
# matches (the code drifted) is a loud error, never a silently green
# run; a mutation the suite survives is a MISS and fails this script.
#
# Not wired into the Lint workflow on purpose: 39 full suite runs
# (~30 minutes locally, ~45 s per run). Run it manually before
# touching systemtest/scripts/:
#
#     bash systemtest/selftest/mutation-checks.sh
#
# Prerequisites: the selftest requirements installed
# (systemtest/selftest/requirements.txt) -- the same environment the
# manual `python -m pytest systemtest/selftest/ -v` run needs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORK=$(mktemp -d /dev/shm/virtwho-mutations.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

echo "Copying the repository to a throwaway tree under /dev/shm..."
TREE="$WORK/tree"
mkdir -p "$TREE"
tar -C "$REPO_ROOT" --exclude=.git --exclude=__pycache__ \
    --exclude=.pytest_cache -cf - . | tar -C "$TREE" -xf -

python3 - "$TREE" <<'PYEOF'
"""Apply the standing mutation battery and assert each is caught.

Every entry is (id, description, repo-relative path, old, new,
replace_all): `old` must occur exactly once in the target file unless
replace_all is set (then every occurrence is replaced). The mutated
file is restored after its suite run, so mutations are independent.
"""
import os
import re
import subprocess
import sys

tree = sys.argv[1]

# --- the standing battery -------------------------------------------------
# Every mutation here re-introduces a REAL regression this PR (or the
# #297/#298 hardening before it) fixed; the suite must fail on each.
# NOTE on the hb conversion (CCT-3162): the libvirt/hyperv query
# mutations (inject-libvirt, inject-hyperv, exact-name) RETIRED with
# the shell queries they mutated -- those behaviors moved into
# hypervisor-builder, whose own test suite (tests/test_guest_ip.py)
# now pins the stdin transport and the exact-name filter. The
# vt-side behaviors that stayed (the empty-password guard, the URI
# normalization, the hb dispatch itself) keep their entries below,
# re-anchored on the new code.
BATTERY = [
    # 1) injection splice: the ini-sourced guest_name is
    # DOWNLOADED, untrusted input; splicing it into the Prism URL
    # is remote code execution on the hypervisor. (The
    # libvirt/hyperv twins of this class retired with the shell
    # queries -- see the note above.)
    ("inject-ahv",
     "raw guest_name spliced into the Prism query URL (percent-"
     "encoding removed)",
     "systemtest/scripts/discover-guest-ips.sh",
     "\"https://${HYP_SERVER}:9440/api/nutanix/v2.0/vms/?name=${GUEST_NAME_ENC}&include_vm_nic_config=true\"",
     "\"https://${HYP_SERVER}:9440/api/nutanix/v2.0/vms/?name=${GUEST_NAME}&include_vm_nic_config=true\"",
     False),
    # confinement disables x2: the write side and the shred side
    # of the kubeconfig confinement, disabled independently (the rule
    # itself is single-sourced in lib.sh's kv_path_is_confined).
    ("confine-disable-write",
     "write-side kubeconfig confinement disabled (every config_file "
     "path accepted)",
     "systemtest/scripts/prepare-kubevirt.sh",
     "kv_path_is_confined",
     "true",
     True),
    ("confine-disable-shred",
     "shred-side kubeconfig confinement disabled (every kubeconfig "
     "path shredded)",
     "systemtest/scripts/cleanup-secrets.sh",
     "kv_path_is_confined \"$f\"",
     "true",
     False),
    # 2) glob revert: suffixed/hidden credential variants survive.
    ("glob-revert",
     "/etc/virt-who.d sweep glob narrowed from *.conf* to *.conf "
     "(suffixed/hidden variants survive)",
     "systemtest/scripts/cleanup-secrets.sh",
     "\"${VIRTWHO_D_DIR}\"/*.conf* \"${VIRTWHO_D_DIR}\"/.*.conf*",
     "\"${VIRTWHO_D_DIR}\"/*.conf \"${VIRTWHO_D_DIR}\"/.*.conf",
     False),
    # 3) split-knob revert: two independently-settable knobs for one
    # invariant could drift apart.
    ("split-knob",
     "shred side back on its own VIRTWHO_CLEANUP_KUBECONFIG_ROOT knob "
     "(the split the one-knob rule removed)",
     "systemtest/scripts/cleanup-secrets.sh",
     "KV_ROOT=$(kv_root)",
     "KV_ROOT=${VIRTWHO_CLEANUP_KUBECONFIG_ROOT:-/root}",
     False),
    # 4) /tmp shred revert: the upgrade tests' credential copies
    # survive on disk.
    ("tmp-shred-revert",
     "the upgrade tests' /tmp *.conf.pre/.post copies no longer "
     "shredded",
     "systemtest/scripts/cleanup-secrets.sh",
     "for f in \"${TMP_DIR}\"/*.conf.pre \"${TMP_DIR}\"/*.conf.post; do\n"
     "    [ -e \"$f\" ] || [ -L \"$f\" ] || continue\n"
     "    shred_file \"$f\"\n"
     "done",
     ":",
     False),
    # 5) ahv-argv: credentials on curl's command line (/proc visibility).
    ("ahv-argv",
     "ahv credentials on curl's command line (-u) instead of the "
     "stdin config stream (-K -)",
     "systemtest/scripts/discover-guest-ips.sh",
     "    if ! body=$(printf 'user = \"%s:%s\"\\n' \"$AHV_USER_ESC\" \"$AHV_PASS_ESC\" \\\n"
     "        | curl -skf --connect-timeout 10 --max-time 60 \\\n"
     "            --retry 2 --retry-delay 5 -K - \\",
     "    if ! body=$(curl -skf --connect-timeout 10 --max-time 60 \\\n"
     "            --retry 2 --retry-delay 5 -u \"${HYP_USER}:${HYP_PASS}\" \\",
     False),
    # canonicalization x2: the knob root and the checked path.
    # kv_root()/kv_path_is_confined() are single-sourced in lib.sh,
    # so each canonicalization is one mutation covering BOTH sides.
    ("canon-root",
     "VIRTWHO_KUBECONFIG_ROOT no longer canonicalized (a trailing "
     "slash fails closed on both sides)",
     "systemtest/scripts/lib.sh",
     "realpath -m -- \"$root\"",
     "printf '%s' \"$root\"",
     False),
    ("canon-path",
     "the checked kubeconfig path no longer canonicalized (a "
     "/root/../ escape matches the raw pattern)",
     "systemtest/scripts/lib.sh",
     "resolved=$(realpath -m -- \"$1\" 2>/dev/null) || return 1",
     "resolved=$1",
     False),
    # 6) nocaseglob removal: uppercase variants survive the sweep.
    ("nocaseglob",
     "nocaseglob removed from the virt-who.d sweep (an uppercase "
     "variant of a suite-written name survives)",
     "systemtest/scripts/cleanup-secrets.sh",
     "shopt -s nocaseglob",
     ":",
     False),
    # 7) skip-knob removal: the discovery opt-out disappears.
    ("skip-knob",
     "VIRTWHO_SKIP_IP_DISCOVERY gate removed from the discovery",
     "systemtest/scripts/discover-guest-ips.sh",
     "if [ \"${VIRTWHO_SKIP_IP_DISCOVERY:-}\" = \"1\" ]; then\n"
     "    echo \"SKIP: VIRTWHO_SKIP_IP_DISCOVERY is set; keeping the ini's existing guest_ip\"\n"
     "    exit 0\n"
     "fi",
     ":",
     False),
    # 8) empty-pass guard removal: empty-password query attempt.
    # (Re-anchored on the python helper by the hb conversion: the
    # guard now keeps the CLI from being constructed at all, since
    # hb's transport would fall back to an ssh-agent attempt
    # instead of the ini credential.)
    ("empty-pass",
     "hyperv empty-password guard removed (hb's transport falls "
     "back to an ssh-agent attempt instead of the ini credential)",
     "systemtest/scripts/discover_guest_ips.py",
     "    if family == \"hyperv\" and not password:\n"
     "        return None\n",
     "",
     False),
    # 9) overwrite-warning removal: a wrong-IP success is silent.
    ("overwrite-warning",
     "the differing-guest_ip overwrite WARNING removed (a wrong-IP "
     "success is silent)",
     "systemtest/scripts/discover-guest-ips.sh",
     "    if [ -n \"$GUEST_IP_OLD\" ] && [ \"$IP\" != \"$GUEST_IP_OLD\" ]; then\n"
     "        echo \"WARNING: discovered ${HYP} guest_ip ${IP} differs from the ini value ${GUEST_IP_OLD}; overwriting the ini (set VIRTWHO_SKIP_IP_DISCOVERY=1 to keep a known-good static value)\" >&2\n"
     "    fi\n",
     "",
     False),
    # 10) hb-dispatch bypass: the bash discovery stops calling the
    # hb query helper -- every libvirt/hyperv run silently degrades
    # to the fallback warning (the conversion's own seam).
    ("hb-dispatch-bypassed",
     "the bash discovery stops calling the hb query helper (an "
     "empty answer on every libvirt/hyperv run)",
     "systemtest/scripts/discover-guest-ips.sh",
     "    python3 \"${SCRIPT_DIR}/discover_guest_ips.py\" \"$INI\" \"$HYP\"",
     "    true",
     False),
    # 11) uri-normalize disable: hb's LibvirtCLI is handed the full
    # qemu+ssh://user@host/system URI as the connection target.
    ("uri-normalize",
     "the qemu+ssh:// URI normalization disabled (hb's LibvirtCLI "
     "is handed the full URI as the connection target)",
     "systemtest/scripts/discover_guest_ips.py",
     "    if \"://\" in server:\n"
     "        server = server.split(\"://\", 1)[1]\n",
     "    if False:\n"
     "        server = server.split(\"://\", 1)[1]\n",
     False),
    # 12) install-deps message: the skip becomes invisible.
    ("install-deps-message",
     "the VIRTWHO_SQUID_IMAGE skip message replaced with a vague one "
     "(the env-contract regression the message pins)",
     "systemtest/scripts/install-deps.sh",
     "echo \"VIRTWHO_SQUID_IMAGE not set; skipping the bad-proxy container image pre-pull\"",
     "echo \"no image configured\"",
     False),
    # 13) failure-cache disable: failing Vault paths re-fetched.
    ("failure-cache",
     "per-path Vault failure cache disabled (every resolution of a "
     "failing path re-fetches)",
     "systemtest/scripts/vault_resolve.py",
     "if path not in self._path_cache:",
     "if True:",
     False),
    # 14) destination default flip: every run without an explicit
    # knob would silently build the stage-tier ini (the Jenkins runs
    # this PR exists to fix).
    ("destination-default-flip",
     "VIRTWHO_DESTINATION default flipped from container to stage "
     "(the hermetic tier is no longer the default)",
     "systemtest/scripts/generate-virtwho-ini.sh",
     "DESTINATION=${VIRTWHO_DESTINATION:-container}",
     "DESTINATION=${VIRTWHO_DESTINATION:-stage}",
     False),
    # 15) prefix regression: the configured prefix ignored, every
    # destination spoken to as /subscription (send-counts read zero
    # against the container tier).
    ("prefix-regression",
     "normalize_prefix returns the hardcoded /subscription, ignoring "
     "the configured prefix",
     "virtwho/destination.py",
     "        return \"/\" + stripped\n",
     "        return \"/subscription\"\n",
     False),
    # 16) overlay-skip removal: a stale VIRTWHO_RHSM_* stage secret
    # from an old pipeline would override the hermetic destination.
    ("overlay-skip-removal",
     "the container-mode [rhsm] env-overlay skip removed (stale stage "
     "secrets override the container values)",
     "systemtest/scripts/generate-virtwho-ini.sh",
     "    if destination == \"container\" and name == \"rhsm\":\n"
     "        continue\n",
     "",
     False),
    # 17) readiness-503 regression: readiness accepts any HTTP
    # answer again.
    ("readiness-503-passes",
     "readiness accepts any HTTP status again (a 503 during app "
     "warmup passes readiness)",
     "systemtest/scripts/prepare-candlepin.sh",
     "    if [ \"$http_code\" = \"200\" ]; then",
     "    if [ \"$http_code\" != \"000\" ]; then",
     False),
    # 18) marker-absent-green regression: the
    # vacuous-green guard stops failing the run.
    ("marker-absent-green",
     "the vacuous-green guard exits 0 on a missing marker (a broken "
     "container tier reports green with skips again)",
     "systemtest/scripts/assert-candlepin-tier.sh",
     "    exit 1",
     "    exit 0",
     False),
    # 19) plan-ordering revert: the candlepin deploy back BEFORE
    # the clone. A successful deploy
    # creates INSTALL_DIR + the marker, and the subsequent git clone
    # into the non-empty dir exits 128 -- tmt prepare fails on every
    # standard container-tier cell exactly when the destination
    # works.
    ("plan-order-revert",
     "regression.fmf prepare order reverted: prepare-candlepin.sh "
      "runs BEFORE setup-virtwho-test.sh (the clone into the "
      "marker-bearing dir fails prepare on every standard cell)",
     "systemtest/plans/regression.fmf",
     "    - name: Setup virtwho-test\n"
     "      how: shell\n"
     "      script: ./systemtest/scripts/setup-virtwho-test.sh\n"
     "\n"
     "    - name: Deploy containerized Candlepin destination\n"
     "      how: shell\n"
     "      script: ./systemtest/scripts/prepare-candlepin.sh",
     "    - name: Deploy containerized Candlepin destination\n"
     "      how: shell\n"
     "      script: ./systemtest/scripts/prepare-candlepin.sh\n"
     "\n"
     "    - name: Setup virtwho-test\n"
     "      how: shell\n"
     "      script: ./systemtest/scripts/setup-virtwho-test.sh",
     False),
    # 20) baseurl removal: the container overlay loses
    # its repo-container baseurl -- the tier would silently inherit
    # a stage CDN leftover from the base ini (content ops 403 against
    # stage) and stop being hermetic on content.
    ("baseurl-removal",
     "the container overlay's baseurl blanked (the tier inherits the "
      "base ini's stage CDN baseurl and is no longer hermetic on "
      "content)",
     "systemtest/config/virtwho-container.ini",
     "baseurl=http://localhost:8080\n",
     "baseurl=\n",
     False),
    # 21) noproxy removal: the readiness
    # probe's proxy bypass removed -- the pipeline env's HTTPS_PROXY
    # routes the pod-facing probe through a proxy that can never
    # reach the guest's own ports (connection-level 000 while the
    # pod is fully healthy).
    ("noproxy-removal",
     "the readiness probe's --noproxy bypass removed (the pipeline "
     "env's HTTPS_PROXY routes the pod-facing probe through a proxy "
     "that can never reach the guest's own ports -- connection-level "
     "000 while the pod is fully healthy)",
     "systemtest/scripts/prepare-candlepin.sh",
     "curl -sk -o /dev/null -w '%{http_code}' --noproxy '*' \\\n"
     "        --connect-timeout 5 --max-time 10 \\\n"
     "        https://localhost:8443/candlepin/status",
     "curl -sk -o /dev/null -w '%{http_code}' \\\n"
     "        --connect-timeout 5 --max-time 10 \\\n"
     "        https://localhost:8443/candlepin/status",
     False),
    # 22) SCA strictness revert: the strict ACTIVE-mode
    # re-verification weakened to a parse-only check -- an
    # entitlement-active org passes again (RHEL-10's
    # subscription-manager gates username/password registration
    # on the org's ACTIVE contentAccessMode, while the contract
    # probe only proves the LIST).
    ("sca-strictness-revert",
     "the SCA activation's strict ACTIVE-mode check weakened to a "
     "parse-only check (an entitlement-active org passes again -- "
     "the probe-vs-register asymmetry re-introduced)",
     "systemtest/scripts/prepare-candlepin.sh",
     "    if active != \"org_environment\":\n"
     "        drift.append(f\"the org '{org}' active content access mode is \"\n"
     "                     f\"{active!r}, not 'org_environment' (username/\"\n"
     "                     \"password registration requires the ACTIVE mode)\")\n",
     "    if active is None:\n"
     "        drift.append(f\"the org '{org}' active content access mode is \"\n"
     "                     f\"{active!r}, not 'org_environment' (username/\"\n"
     "                     \"password registration requires the ACTIVE mode)\")\n",
     False),
    # 23) undertest precedence flip : the version-under-test cache
    # ignores TEST_RPMS -- the compose download runs even in gating
    # mode, caching the compose's virt-who while a gated build is
    # under test.
    ("undertest-precedence-flip",
     "the version-under-test cache ignores TEST_RPMS (the compose "
      "download runs even in gating mode )",
     "systemtest/scripts/setup-virtwho-test.sh",
     "UNDERTTEST_CACHE=\"${INSTALL_DIR}/virt-who-under-test.rpm\"\n"
     "if [ -n \"${TEST_RPMS:-}\" ]; then",
     "UNDERTTEST_CACHE=\"${INSTALL_DIR}/virt-who-under-test.rpm\"\n"
     "if false; then",
     False),
    # 24) sidecar-override revert : the computed virt-who NEVRA is
    # silently discarded again whenever the statically published
    # base ini carries a (stale) value -- every version expectation
    # in the suite goes stale.
    ("sidecar-override-revert",
     "the [virtwho] package merge reverted from override to the "
      "empty-only fallback (a stale base-ini NEVRA silently beats "
      "the computed sidecar value again )",
     "systemtest/scripts/run-tests.sh",
     "override(\"virtwho\", \"package\")",
     "fallback(\"virtwho\", \"package\", None)",
     False),
    # 25) by-rpm repo-download revert : the by-rpm test downloads
    # its rpm from the enabled repos again -- the registered
    # container-tier host's only enabled repo is the pod's dead
    # content repo.
    ("by-rpm-repo-download-revert",
     "test_install_uninstall_by_rpm downloads its rpm from the "
      "enabled repos again instead of the undertest cache (the "
      "dead destination repo fails the test on the container tier)",
     "tests/package/test_install_uninstall.py",
     "rpm_path = virtwho_download_under_test(ssh_host, file_path)",
     "rpm_path = dnf_download_pkg(ssh_host, \"virt-who\", file_path)",
     False),
    # 26) dep-safe uninstall revert : dnf5 cleans virt-who's
    # automatically-installed dependencies with the package again,
    # starving the repo-less reinstall of the version under test.
    ("depsafe-uninstall-revert",
     "the by-dnf uninstall drops keep_deps (dnf5 removes "
      "python3-cryptography together with virt-who again -- the "
      "repo-less reinstall of the version under test starves)",
     "tests/package/test_install_uninstall.py",
     "package_uninstall(ssh_host, \"virt-who\", keep_deps=True)",
     "package_uninstall(ssh_host, \"virt-who\")",
     False),
    # 27) reinstall-guard revert (the cascade guard): the by-dnf
    # teardown reinstalls conditionally again -- a failed body
    # leaves the suite without virt-who for every later test.
    ("reinstall-guard-revert",
     "the by-dnf finally reinstalls the version under test "
      "conditionally again (a failed body leaves the suite without "
      "virt-who -- the cascade guard)",
     "tests/package/test_install_uninstall.py",
     "            # loudly on a failed install -- never a silent continue.\n"
     "            virtwho_install_under_test(ssh_host)",
     "            # loudly on a failed install -- never a silent continue.\n"
     "            if TEST_RPMS or package_check(ssh_host, \"virt-who\") is False:\n"
     "                virtwho_install_under_test(ssh_host)",
     False),
    # 28) arch stderr revert: the cached-rpm arch query captures
    # stderr again -- the compose-signed rpm's GPG NOKEY warning
    # becomes the parsed arch value.
    ("arch-stderr-revert",
     "the cached-rpm arch query stops discarding stderr (a GPG "
      "NOKEY warning becomes the parsed arch value again)",
     "tests/package/test_info.py",
     "f\"rpm -qp --qf '%{{arch}}' {VIRTWHO_UNDERTEST_RPM} 2>/dev/null\"",
     "f\"rpm -qp --qf '%{{arch}}' {VIRTWHO_UNDERTEST_RPM}\"",
     False),
    # 29) download TEST_RPMS rung removal: the by-rpm test's
    # downloader loses its TEST_RPMS branch again -- a gating run
    # with a failed prepare-phase cache falls through to the
    # enabled repos (the dead pod repo on the container tier).
    ("download-test-rpms-rung-removal",
     "virtwho_download_under_test ignores TEST_RPMS again (a gating "
      "run with a cache miss falls through to the enabled repos -- "
      "the dead destination repo on the container tier)",
     "virtwho/base.py",
      "    if TEST_RPMS:\n"
      "        # the virt-who rpm of the URL list (the same selection the\n",
      "    if False:\n"
      "        # the virt-who rpm of the URL list (the same selection the\n",
      False),
    # 30) override-clear revert: the version-under-test trio's merge
    # goes back to the non-empty-only rule -- an empty computed
    # test_rpms cannot CLEAR a stale published base-ini value.
    ("override-clear-revert",
     "the sidecar merge reverted from presence-based to the "
      "non-empty-only rule (an empty computed test_rpms cannot clear "
      "a stale base-ini value again)",
     "systemtest/scripts/run-tests.sh",
      "    if computed.has_option(section, option):\n",
      "    if computed.has_option(section, option) and computed.get(section, option):\n",
      False),
    # 31) placeholder-guard removal: the sidecar records a bare
    # virt-who placeholder again when no real NEVRA resolves --
    # it clobbers a correct base-ini value through the override.
    ("placeholder-guard-removal",
     "the sidecar records a placeholder NEVRA again when no real one "
      "resolves (it clobbers a correct base-ini value through the "
      "merge override)",
     "systemtest/scripts/setup-virtwho-test.sh",
      "if nevra:\n"
      "    cfg.set(\"virtwho\", \"package\", nevra)",
      "cfg.set(\"virtwho\", \"package\", nevra or \"virt-who\")",
      False),
    # 32) uninstall-guard revert: the failure guard goes back to the
    # dead `is True` form -- a failed uninstall passes silently.
    ("uninstall-guard-revert",
     "package_uninstall's failure guard reverts to the dead `is True` "
      "form (a failed uninstall never raises again)",
     "virtwho/base.py",
      "    if package_check(ssh, pkg_name) is not False:\n",
      "    if package_check(ssh, pkg_name) is True:\n",
      False),
    # 33) contract-curl insecure-flag revert: the post-CA
    # data-contract status probe carries -k again (a
    # credential-bearing curl with TLS verification disabled after
    # trust was proven).
    ("contract-curl-k-revert",
     "the post-CA data-contract status probe carries -k again (a "
      "credential-bearing curl with TLS verification disabled after "
      "trust was established)",
     "systemtest/scripts/prepare-candlepin.sh",
      "status_code=$(curl -s -o \"$CONTRACT_STATUS_TMP\" -w '%{http_code}' \\\n",
      "status_code=$(curl -sk -o \"$CONTRACT_STATUS_TMP\" -w '%{http_code}' \\\n",
      False),
    # 34) proxy-alias promotion removal: configure-proxy.sh stops
    # promoting the [job] aliases -- a satellite cell configured via
    # VIRTWHO_JOB_REGISTER gets a stray rhsm.conf proxy.
    ("proxy-alias-promotion-removal",
     "configure-proxy.sh stops promoting the [job] aliases (a "
      "satellite cell configured via the VIRTWHO_JOB_REGISTER alias "
      "gets a stray rhsm.conf proxy)",
     "systemtest/scripts/configure-proxy.sh",
      "promote_job_aliases",
      ":",
      False),
    # 35) ssh-baseline unbounding: the shared ConnectTimeout drops
    # out of lib.sh's ssh transport baseline -- every shell-side ssh
    # site re-opens the unbounded-connect class (three of the five
    # sites carried no ConnectTimeout before the baseline existed).
    ("ssh-baseline-connect-timeout",
     "ConnectTimeout removed from the shared ssh baseline (every "
      "shell ssh site re-opens the unbounded-connect class)",
      "systemtest/scripts/lib.sh",
      "SSH_BASE_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=ERROR)",
      "SSH_BASE_OPTS=(-o StrictHostKeyChecking=no -o LogLevel=ERROR)",
      False),
]


def run_suite():
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "systemtest/selftest/", "-q"],
        cwd=tree, capture_output=True, text=True, timeout=900,
        # a mutated script can leave a stub reading stdin that no
        # producer feeds anymore; EOF (not an interactive hang) is
        # the right input for every run
        stdin=subprocess.DEVNULL)
    summary = ""
    for match in re.finditer(r"^([0-9]+ (?:failed|passed|error).*)$",
                             proc.stdout, re.MULTILINE):
        summary = match.group(1)
    return proc.returncode, summary or "(no pytest summary line)"


misses = []
drifts = []
for mid, desc, rel, old, new, replace_all in BATTERY:
    path = os.path.join(tree, rel)
    with open(path) as f:
        original = f.read()
    count = original.count(old)
    if count == 0 or (not replace_all and count != 1):
        print(f"DRIFT  {mid}: anchor not found uniquely in {rel} "
              f"({count} match(es)) -- update the battery")
        drifts.append(mid)
        continue
    with open(path, "w") as f:
        f.write(original.replace(old, new) if replace_all
                else original.replace(old, new, 1))
    try:
        code, summary = run_suite()
    finally:
        with open(path, "w") as f:
            f.write(original)
    if code == 0:
        print(f"MISS   {mid}: {desc}\n       the suite STAYED GREEN -- "
              "the regression is no longer caught!")
        misses.append(mid)
    else:
        print(f"CAUGHT {mid}: {desc}\n       {summary}")

print()
total = len(BATTERY)
caught = total - len(misses) - len(drifts)
print(f"mutation battery: {caught}/{total} caught "
      f"({len(misses)} missed, {len(drifts)} drifted)")
if misses or drifts:
    sys.exit(1)
print("every mutation in the battery is caught by the suite")
PYEOF
