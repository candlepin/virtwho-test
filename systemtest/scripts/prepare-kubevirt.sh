#!/bin/bash
# prepare-kubevirt.sh -- KubeVirt-specific preparation for virt-who testing.
# Handles SA token injection, kubeconfig generation, and guest VM proxy setup.
#
# NOTE: virt-who's kubevirt backend currently requires cluster-scoped API
# access (list nodes, list VMIs cluster-wide) which is not available in
# namespace-restricted environments like ITUP.Scale.  See CCT-2379.
# Until that bug is fixed upstream, most tests that start the virt-who
# daemon will fail with ApiException(403).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# Mirror the path detection in setup-virtwho-test.sh: use /usr/share on bootc
# (ostree-safe), /opt otherwise. VIRTWHO_PREPARE_INSTALL_DIR overrides both
# for the self-test sandbox.
if [ -n "${VIRTWHO_PREPARE_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$VIRTWHO_PREPARE_INSTALL_DIR"
elif command -v bootc &>/dev/null || [ -f /run/ostree-booted ] || [ -L /ostree ]; then
    INSTALL_DIR=/usr/share/virtwho-test
else
    INSTALL_DIR=/opt/virtwho-test
fi
cd "$INSTALL_DIR"

# configparser, never awk (the convention discover-guest-ips.sh
# codifies): `key = value` spacing is configparser-valid but an awk
# ^key= match silently skips it, which here would silently skip the
# kubeconfig generation AND its write-side confinement; an
# `=`-containing value would be truncated at the first `=`. ONE
# python invocation reads all the [kubevirt] options this script
# needs; the values are returned to the caller only, never printed.
# The stream is NUL-delimited (not newline-delimited): an ini value
# may itself contain a newline (configparser joins indented
# continuation lines in a hand-edited ini), which a newline-delimited
# stream would silently shift into the next slot. strict=False so a
# duplicate option degrades to the skip paths instead of dying here.
mapfile -d '' -t KV_VALUES < <(python3 - <<'PYEOF'
import configparser
import sys

cfg = configparser.ConfigParser(interpolation=None, strict=False)
cfg.optionxform = str
try:
    cfg.read("virtwho.ini")
except configparser.Error:
    pass
for option in ("endpoint", "token", "config_file", "config_file_no_cert",
               "guest_ip", "guest_port", "guest_username", "guest_password"):
    value = (cfg.get("kubevirt", option, fallback="")
             if cfg.has_section("kubevirt") else "")
    sys.stdout.write(value + "\0")
PYEOF
)
KV_ENDPOINT=${KV_VALUES[0]:-}
KV_TOKEN=${KV_VALUES[1]:-}
KV_CONFIG_FILE=${KV_VALUES[2]:-}
KV_CONFIG_NO_CERT=${KV_VALUES[3]:-}
KV_GUEST_IP=${KV_VALUES[4]:-}
KV_GUEST_PORT=${KV_VALUES[5]:-}
KV_GUEST_USER=${KV_VALUES[6]:-}
KV_GUEST_PASS=${KV_VALUES[7]:-}

# Inject the real SA token (passed via the VIRTWHO_KUBEVIRT_TOKEN secret
# or the legacy KUBEVIRT_TOKEN env var).
# Uses configparser to safely write the token value without corrupting subsequent lines.
# The token is passed via the environment (not argv) so it does not appear
# in /proc/<pid>/cmdline. Discovered (non-secret) guest coordinates are
# also recorded in the .virtwho-computed.ini sidecar for the run-tests.sh
# merge: run-tests.sh regenerates the ini on tmpfs at test time, and on
# bootc the prepare-phase tmpfs content does not survive the container
# build. The token itself is never written to the sidecar.
KUBEVIRT_TOKEN=${KUBEVIRT_TOKEN:-${VIRTWHO_KUBEVIRT_TOKEN:-}}
if [ -n "${KUBEVIRT_TOKEN:-}" ]; then
    KUBEVIRT_TOKEN="$KUBEVIRT_TOKEN" python3 -c "
import configparser, json, os, re, socket, ssl, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
token = os.environ['KUBEVIRT_TOKEN']
cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
cfg.read('virtwho.ini')
sc = configparser.ConfigParser(interpolation=None)
sc.optionxform = str
sc.read('.virtwho-computed.ini')
if not sc.has_section('kubevirt'):
    sc.add_section('kubevirt')
if 'kubevirt' in cfg:
    cfg['kubevirt']['token'] = token
    endpoint = cfg['kubevirt'].get('endpoint')
    namespace = cfg['kubevirt'].get('namespace')
    guest_name = cfg['kubevirt'].get('guest_name', 'rhel10-virtwho-guest')

    if endpoint and token and namespace:
        http = urllib3.PoolManager(cert_reqs=ssl.CERT_NONE)
        headers = {'Authorization': f'Bearer {token}'}

        # Discover guest VM node IP
        try:
            r = http.request(
                'GET',
                f'{endpoint}/apis/kubevirt.io/v1/namespaces/{namespace}/virtualmachineinstances/{guest_name}',
                headers=headers,
                timeout=10,
            )
            if 200 <= r.status < 300:
                vmi = json.loads(r.data.decode('utf-8'))
                node_name = vmi.get('status', {}).get('nodeName', '')
                discovered_ip = None

                # Strategy 1: AWS EC2 node name encodes the IP (ip-A-B-C-D.region...)
                m = re.match(r'^ip-(\d+)-(\d+)-(\d+)-(\d+)[.-]', node_name)
                if m:
                    discovered_ip = '.'.join(m.groups())

                # Strategy 2: query Node object for InternalIP (may 403 in namespace-restricted envs)
                if not discovered_ip:
                    try:
                        nr = http.request('GET', f'{endpoint}/api/v1/nodes/{node_name}', headers=headers, timeout=10)
                        if 200 <= nr.status < 300:
                            node_obj = json.loads(nr.data.decode('utf-8'))
                            for addr in node_obj.get('status', {}).get('addresses', []):
                                if addr.get('type') == 'InternalIP':
                                    discovered_ip = addr['address']
                                    break
                    except Exception:
                        pass

                # Strategy 3: node_name is already a bare IP address
                if not discovered_ip:
                    try:
                        socket.inet_aton(node_name)
                        discovered_ip = node_name
                    except OSError:
                        pass

                # Strategy 4: DNS resolution as a last resort
                if not discovered_ip and node_name:
                    try:
                        discovered_ip = socket.gethostbyname(node_name)
                    except OSError:
                        pass

                if discovered_ip:
                    cfg['kubevirt']['guest_ip'] = discovered_ip
                    sc['kubevirt']['guest_ip'] = discovered_ip
                    print(f'Discovered guest_ip: {discovered_ip} (node: {node_name})')
                else:
                    print(f'Warning: could not determine guest_ip from node: {node_name}')
        except Exception as e:
            print(f'Warning: guest_ip discovery failed: {e}')

        # Discover guest SSH NodePort service
        try:
            r = http.request(
                'GET',
                f'{endpoint}/api/v1/namespaces/{namespace}/services/virtwho-guest-ssh',
                headers=headers,
                timeout=10,
            )
            if 200 <= r.status < 300:
                svc = json.loads(r.data.decode('utf-8'))
                node_port = svc.get('spec', {}).get('ports', [{}])[0].get('nodePort')
                if node_port:
                    cfg['kubevirt']['guest_port'] = str(node_port)
                    sc['kubevirt']['guest_port'] = str(node_port)
                    print(f'Discovered guest_port: {node_port}')
        except Exception as e:
            print(f'Warning: guest_port discovery failed: {e}')

    with open('virtwho.ini', 'w') as f:
        cfg.write(f, space_around_delimiters=False)
    with open('.virtwho-computed.ini', 'w') as f:
        sc.write(f, space_around_delimiters=False)
else:
    print('Warning: [kubevirt] section not found in virtwho.ini; skipping token injection')
"
    echo "Injected KUBEVIRT_TOKEN and updated dynamic coordinates in virtwho.ini"
fi

# Generate kubeconfig YAML from SA token (token passed via the
# environment, not argv, to keep it out of /proc/<pid>/cmdline). The
# kubeconfig contains the token, so it is created 0600 from the start
# and shredded by cleanup-secrets.sh in the tmt finish step.
# On kubevirt image-mode (bootc) runs the prepare phase may run
# without a writable /root: gate the write on an explicit writability
# test of the target directory and skip with a clear message when it
# fails -- the kubevirt tests then cannot run with a kubeconfig
# (review PR297-04; this implements the README claim).
# Write-side kubeconfig confinement: the kubeconfig paths come from
# the DOWNLOADED base ini (untrusted input), so the token-bearing
# files may only be written to an absolute path canonicalized under
# the kubeconfig root (/root -- where the generator's defaults and
# the daemon's fixed paths live; kv_root() reads the SAME
# VIRTWHO_KUBECONFIG_ROOT knob the shred side confines to in
# cleanup-secrets.sh -- one gate for both sides, single-sourced in
# lib.sh's kv_path_is_confined). Anything else is refused with a
# warning: no token may ever be created where the finish step would
# not shred it.
KV_ROOT=$(kv_root)
if [ -n "$KV_ENDPOINT" ] && [ -n "$KV_TOKEN" ] && [ -n "$KV_CONFIG_FILE" ]; then
    if ! kv_path_is_confined "$KV_CONFIG_FILE"; then
        echo "WARNING: refusing to write the kubeconfig to ${KV_CONFIG_FILE} (not an absolute path under ${KV_ROOT}); skipping kubeconfig generation -- cleanup-secrets.sh would not shred it there"
    else
        KV_CONFIG_DIR=$(dirname -- "$KV_CONFIG_FILE")
        if [ ! -w "$KV_CONFIG_DIR" ]; then
            echo "WARNING: ${KV_CONFIG_DIR} is not writable (kubevirt image-mode/bootc runs prepare without a writable /root); skipping kubeconfig generation at ${KV_CONFIG_FILE} -- the kubevirt tests cannot run with a kubeconfig"
        else
            echo "Generating kubeconfig at $KV_CONFIG_FILE for $KV_ENDPOINT"
            KUBEVIRT_TOKEN="$KV_TOKEN" python3 -c "
import os, sys, yaml
kc = {
    'apiVersion': 'v1', 'kind': 'Config',
    'clusters': [{'cluster': {'server': sys.argv[1], 'insecure-skip-tls-verify': True}, 'name': 'kubevirt'}],
    'contexts': [{'context': {'cluster': 'kubevirt', 'user': 'ci-runner'}, 'name': 'kubevirt'}],
    'current-context': 'kubevirt',
    'users': [{'name': 'ci-runner', 'user': {'token': os.environ['KUBEVIRT_TOKEN']}}],
}
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
# os.open's mode only applies when O_CREAT creates the file; force
# 0600 regardless of any pre-existing file's mode (review PR297-11).
os.fchmod(fd, 0o600)
with os.fdopen(fd, 'w') as f:
    yaml.safe_dump(kc, f, default_flow_style=False)
" "$KV_ENDPOINT" "$KV_CONFIG_FILE"
            echo "Kubeconfig written ($(wc -c < "$KV_CONFIG_FILE") bytes, mode 0600)"

            if [ -n "$KV_CONFIG_NO_CERT" ]; then
                if ! kv_path_is_confined "$KV_CONFIG_NO_CERT"; then
                    echo "WARNING: refusing to write the no-cert kubeconfig copy to ${KV_CONFIG_NO_CERT} (not an absolute path under ${KV_ROOT}); skipping the copy -- cleanup-secrets.sh would not shred it there"
                else
                    KV_NOCERT_DIR=$(dirname -- "$KV_CONFIG_NO_CERT")
                    if [ -w "$KV_NOCERT_DIR" ]; then
                        install -m 600 "$KV_CONFIG_FILE" "$KV_CONFIG_NO_CERT"
                        echo "No-cert kubeconfig written to $KV_CONFIG_NO_CERT (mode 0600)"
                    else
                        echo "WARNING: ${KV_NOCERT_DIR} is not writable; skipping the no-cert kubeconfig copy"
                    fi
                fi
            fi
        fi
    fi
fi

# Configure proxy on the KubeVirt guest VM so subscription-manager
# can reach the subscription server. The guest is inside the cluster
# network and has no direct route out. The proxy comes from the
# HTTPS_PROXY / HTTP_PROXY environment variables (the same contract as
# configure-proxy.sh); there is no default -- without the variables the
# configuration is skipped.
if [ -n "$KV_GUEST_IP" ] && [ -n "$KV_GUEST_PORT" ]; then
    # The guest password comes from the ini (the @vault: sentinel of
    # the base ini, resolved for the active section, or an env
    # secret): there is NO default -- a published default would be a
    # working password for every guest this suite builds. An empty
    # value or an unresolved @vault: sentinel means the credential
    # was not delivered: warn and skip (the kubevirt tests that need
    # the proxy then fail loudly on their own).
    case "$KV_GUEST_PASS" in
        "" | @vault:*)
            echo "WARNING: [kubevirt] guest_password is not set (or is an unresolved @vault: sentinel); there is no default -- skipping guest VM proxy configuration"
            ;;
        *)
            # Destination tier (CCT-3155, the build-#179 class): in
            # container mode the kubevirt guest registers against the
            # per-run Candlepin pod on the TEST HOST, not an external
            # subscription server -- a proxy configured here could
            # never route the guest to the pod host's published port.
            # The guest either reaches the pod host directly (its
            # registrations work) or the suite's guest-reachability
            # probe skips the guest-coupled tests loudly (LESSON-01);
            # a proxy would break the first case without enabling the
            # second. The default mirrors the generator's knob.
            if [ "${VIRTWHO_DESTINATION:-container}" = "container" ]; then
                echo "SKIP: VIRTWHO_DESTINATION=container; the destination is the per-run Candlepin pod on the test host -- no guest VM proxy is configured (the guest must reach the pod host directly; a proxy could never route it there)"
            else
                _proxy_url="${HTTPS_PROXY:-${HTTP_PROXY:-}}"
                if [ -z "$_proxy_url" ]; then
                    echo "WARNING: HTTPS_PROXY/HTTP_PROXY not set; skipping guest VM proxy configuration"
                else
                    parse_proxy_url "$_proxy_url"
                    echo "Configuring proxy on KubeVirt guest VM at ${KV_GUEST_IP}:${KV_GUEST_PORT}"
                    # sshpass -e with SSHPASS set only for this command keeps the
                    # password off the process list (/proc/*/cmdline).
                    SSHPASS="$KV_GUEST_PASS" sshpass -e \
                        ssh -o StrictHostKeyChecking=no -p "$KV_GUEST_PORT" \
                        "${KV_GUEST_USER:-root}@${KV_GUEST_IP}" \
                        "subscription-manager config --server.proxy_hostname=${PROXY_HOST} --server.proxy_port=${PROXY_PORT}" \
                        && echo "Guest VM proxy configured" \
                        || echo "WARNING: Failed to configure guest VM proxy"
                fi
            fi
            ;;
    esac
fi
