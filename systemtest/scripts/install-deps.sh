#!/bin/bash
# install-deps.sh -- Install system and Python dependencies for virt-who testing.
#
# Runs in the TMT prepare phase. On bootc image-mode composes, TMT
# executes this inside a Containerfile RUN layer (no systemd, no
# network services). All commands must work in that context.
set -euo pipefail

dnf -y install python3-pip git gcc python3-devel openssh-clients \
    libvirt-client python3-libvirt openssh-server expect sshpass podman

# TEST_RPMS is set by the cct-gate pipeline after parsing Brew UMB
# messages (a space-separated RPM URL list, delivered as a plain
# request-time Testing Farm variable; the dist-git OSCI gating plan
# uses the same flow). This is the PREPARE-PHASE INSTALL of the
# version under test (the run-#7 ruling): TEST_RPMS always has
# precedence (manual overrides, PR-build testing, gated release
# builds); when it is empty the RHEL compose's own virt-who is
# installed from the compose repos. Either way the version under
# test is on the guest BEFORE any test (and before any registration
# can switch the host's content sources). It must NEVER come from
# the destination's content repo: the container tier's pod repo
# does not serve virt-who packages. setup-virtwho-test.sh
# additionally caches the same RPM as a file for the suite's
# reinstall/arch tests (see its version-under-test cache step).
if [[ -n "${TEST_RPMS:-}" ]]; then
    echo "Gating mode: installing RPMs from TEST_RPMS"
    # shellcheck disable=SC2086
    dnf -y install --allowerasing ${TEST_RPMS} \
        || { echo "ERROR: failed to install gated RPMs: ${TEST_RPMS}"; exit 2; }
else
    dnf -y install virt-who
fi

# On image-mode container builds, systemd is not running so
# systemctl will fail. The podman pull is deferred to run-tests.sh
# which executes after the guest boots with systemd available.
if systemctl is-system-running &>/dev/null; then
    # The bad-proxy container image comes from the environment; there
    # is no default (an internal registry literal does not belong in a
    # public repo). The pre-pull is best-effort.
    if [ -n "${VIRTWHO_SQUID_IMAGE:-}" ]; then
        podman pull "$VIRTWHO_SQUID_IMAGE" 2>/dev/null || true
    else
        echo "VIRTWHO_SQUID_IMAGE not set; skipping the bad-proxy container image pre-pull"
    fi
else
    echo "No systemd (container build context); deferring podman pull to execute phase"
fi
