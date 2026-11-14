#!/bin/bash
# configure-proxy.sh -- Configure subscription-manager proxy for Stage access.
# TF guests cannot reach stage directly; a proxy is needed to reach Stage.
# This runs BEFORE rhsm.conf backup so tests that restore rhsm.conf retain proxy.
#
# Proxy settings are derived from the HTTPS_PROXY / HTTP_PROXY environment
# variables (set in regression.fmf or by TF). Falls back to a sensible
# default if unset.
#
# On bootc image-mode composes, TMT runs this inside a Containerfile RUN
# layer. subscription-manager may not be fully functional in that context
# (no dbus, no systemd), so errors are handled gracefully. The proxy
# configuration is written to disk and takes effect when the guest boots.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# Parse host and port from the environment proxy URL (set by the TMT plan
# environment block in regression.fmf or by CI).  Accepts formats:
# http://host:port, host:port, host.  There is no default: without
# HTTPS_PROXY/HTTP_PROXY the proxy configuration is skipped with a
# warning -- set the variables for environments that need a proxy to
# reach the subscription server.
_proxy_url="${HTTPS_PROXY:-${HTTP_PROXY:-}}"
PROXY_HOST=""
PROXY_PORT=""
if [ -z "$_proxy_url" ]; then
    echo "WARNING: HTTPS_PROXY/HTTP_PROXY not set; skipping subscription-manager proxy configuration"
else
    # the shared parser (lib.sh): strip protocol prefix and trailing
    # slash, split host:port, default the port to 3128
    parse_proxy_url "$_proxy_url"
fi

# Destination tier (CCT-3155, the build-#179 defect class): in
# container mode the subscription destination is the per-run
# Candlepin pod on THIS guest -- subscription-manager must reach it
# directly. rhsm.conf is subscription-manager's only proxy source
# (its commands run through ssh and do not inherit this process's
# environment, so a no_proxy export cannot save them), and a proxy
# can never resolve or route the guest's own pod ports: configuring
# it here would deterministically break every registration in the
# container tier. The proxy below exists for the stage tier (the
# preprod lockdown traversal); the default mirrors the generator's
# destination knob: container.
DESTINATION=${VIRTWHO_DESTINATION:-container}

if [ "$DESTINATION" = "container" ]; then
    echo "SKIP: VIRTWHO_DESTINATION=container; the destination is the per-run Candlepin pod on this guest -- subscription-manager reaches it directly, no rhsm.conf proxy is configured (a proxy could never route the guest's own pod ports)"
elif [ "${REGISTER:-rhsm}" = "rhsm" ] && [ -n "${PROXY_HOST:-}" ]; then
    if command -v subscription-manager &>/dev/null; then
        subscription-manager config \
            --server.proxy_hostname="$PROXY_HOST" \
            --server.proxy_port="$PROXY_PORT" \
            2>/dev/null \
            || echo "WARNING: subscription-manager config failed (container build?); will retry at boot"
        echo "Configured rhsm.conf proxy: ${PROXY_HOST}:${PROXY_PORT}"
    else
        echo "WARNING: subscription-manager not found; proxy will be configured at boot"
    fi
fi

mkdir -p /backup && cp /etc/rhsm/rhsm.conf /backup/ 2>/dev/null || true
subscription-manager unregister 2>/dev/null || true
subscription-manager clean 2>/dev/null || true
