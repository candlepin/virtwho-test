#!/bin/bash
# assert-candlepin-tier.sh -- Vacuous-green guard for the containerized
# Candlepin destination (rhsm-qe LESSON-04, CCT-3155).
#
# Every failure mode of prepare-candlepin.sh is a loud SKIP by design
# (bootc container-build contexts need that), and tests/conftest.py
# turns the missing readiness marker into per-test skips. But nothing
# at plan level distinguished "tier deployed" from "tier silently
# absent": a run where podman was missing or ghcr was unreachable was
# GREEN with ~38 skips. rhsm-qe's lesson is fail-fast -- a broken
# tier is a red run, never a green one.
#
# Contract, read from the generated ini (the single source of the
# tier record, the same values tests/conftest.py gates on):
#   * [job] destination != container (the stage tier, or a
#     hand-written ini without the option -- the old contract)
#     -> exit 0, no check
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

INI_FILE=${1:?usage: assert-candlepin-tier.sh <virtwho.ini> <test-tree-dir>}
TREE_DIR=${2:?usage: assert-candlepin-tier.sh <virtwho.ini> <test-tree-dir>}

# configparser, never sed/awk (the repo-wide rule): values containing
# '=' or spaces survive, and a missing option is a clean "".
mapfile -t TIER < <(python3 - "$INI_FILE" <<'PYEOF'
import configparser
import sys

cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
cfg.read(sys.argv[1])
for option in ("destination", "register"):
    print(cfg.get("job", option, fallback="").strip().lower())
PYEOF
)
DESTINATION=${TIER[0]:-}
REGISTER=${TIER[1]:-}

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
