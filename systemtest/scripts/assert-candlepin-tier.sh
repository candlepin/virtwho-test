#!/bin/bash
# assert-candlepin-tier.sh -- Vacuous-green guard for the containerized
# Candlepin destination (CCT-3155).
#
# Every failure mode of prepare-candlepin.sh is a loud SKIP by design
# (bootc container-build contexts need that), and tests/conftest.py
# turns the missing readiness marker into per-test skips. This guard
# makes a silently-absent tier a RED run instead of a green one full
# of skips.
#
# Contract, read from the generated ini (the single source of the
# tier record, the same values tests/conftest.py gates on):
#   * [job] destination != container (the stage tier, or a
#     hand-written ini without the option) -> exit 0, no check
#   * [job] register != rhsm (satellite cells never deploy the pod)
#     -> exit 0, no check
#   * destination=container + register=rhsm: the readiness marker
#     prepare-candlepin.sh writes on success MUST exist -> exit 1
#     with a pointed ERROR when it does not. The conftest per-test
#     skip stays as defense-in-depth for contexts the caller chose
#     not to guard (bootc container-build runs keep the skip:
#     prepare legitimately executes there without a runtime podman).
#
# Usage: assert-candlepin-tier.sh <virtwho.ini> <test-tree-dir>
# Both arguments are plain paths; the ini values read here are the
# tier record, not credentials.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

INI_FILE=${1:?usage: assert-candlepin-tier.sh <virtwho.ini> <test-tree-dir>}
TREE_DIR=${2:?usage: assert-candlepin-tier.sh <virtwho.ini> <test-tree-dir>}

# The shared read-only ini access (lib.sh's ini_read): the tier
# record, lower-cased here (a mixed-case value must not silently
# skip the guard).
mapfile -d '' -t TIER < <(ini_read "$INI_FILE" job destination register)
DESTINATION=$(printf '%s' "${TIER[0]:-}" | tr '[:upper:]' '[:lower:]')
REGISTER=$(printf '%s' "${TIER[1]:-}" | tr '[:upper:]' '[:lower:]')

if [ "$DESTINATION" != "container" ] || [ "$REGISTER" != "rhsm" ]; then
    # Not the container tier (or an old-contract ini): the conftest
    # skip logic owns this case; nothing to assert here.
    exit 0
fi

MARKER="${TREE_DIR}/.virtwho-candlepin-ready"
if [ ! -f "$MARKER" ]; then
    echo "ERROR: [job] destination=container but the readiness marker ${MARKER} is absent -- the containerized Candlepin tier was NOT deployed. Find the WARNING in the prepare-phase logs (no podman, an unreachable registry, a readiness timeout or a test-data contract drift are the usual causes). A silently-absent destination tier must FAIL the run, not report green with skips (rhsm-qe LESSON-04)." >&2
    exit 1
fi
echo "Container destination tier deployed (marker: ${MARKER})"
