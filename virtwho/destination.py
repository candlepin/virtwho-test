"""Destination URL helpers shared by the suite's Candlepin/RHSM code.

The destination tier (stage RHSM vs the containerized Candlepin of
systemtest/config/) differs only in the [rhsm] VALUES (server, port,
prefix); the URL shape is identical. Three call sites previously
hardcoded the "/subscription" prefix (and omitted the port), which
silently broke against any Candlepin whose prefix is "/candlepin"
(the containerized destination emits request log lines like
``request="POST /candlepin/hypervisors/..."`` -- the hardcoded
prefix then counts zero sends).

This module is a deliberate LEAF: it imports nothing from the virtwho
package, so the host-side selftests can load it directly by file
path (importing the full package would read/write the guest-side
virtwho.ini at a fixed path -- see virtwho/settings.py).

All functions accept the raw ini values (possibly empty strings, the
generator always emits the options but not always the values) and
fall back to the historical defaults: /subscription and port 443 for
the RHSM tier, /rhsm for satellite.
"""

import shlex
import urllib.parse

# The fallback prefixes per register type. register_type may be a
# plain "rhsm"/"satellite" or the suffixed forms ("rhsm_sw",
# "rhsm_product"): substring matching preserves the historical
# behavior of virtwho/runner.py send_number().
DEFAULT_PORT = "443"


def normalize_prefix(prefix, register_type="rhsm"):
    """The configured prefix, or the tier default when empty.

    A non-empty prefix is canonicalized to exactly one leading slash
    (review DEV-05): the ini is downloaded, hand-editable input, and
    ``candlepin``, ``candlepin/`` and ``/candlepin/`` must all build
    the same URL -- a bare ``candlepin`` would otherwise fuse onto
    the port (``https://host:8443candlepin``) and a trailing slash
    would double up (``/candlepin//status``).

    >>> normalize_prefix("", "rhsm")
    '/subscription'
    >>> normalize_prefix("", "satellite")
    '/rhsm'
    >>> normalize_prefix("/candlepin")
    '/candlepin'
    >>> normalize_prefix("candlepin")
    '/candlepin'
    >>> normalize_prefix("candlepin/")
    '/candlepin'
    >>> normalize_prefix("/candlepin/")
    '/candlepin'
    """
    stripped = str(prefix or "").strip().strip("/")
    if stripped:
        return "/" + stripped
    if "satellite" in register_type:
        return "/rhsm"
    return "/subscription"


def normalize_port(port):
    """The configured port as a string, or 443 when empty.

    >>> normalize_port("")
    '443'
    >>> normalize_port(8443)
    '8443'
    """
    if port is None:
        return DEFAULT_PORT
    text = str(port).strip()
    return text or DEFAULT_PORT


def api_base(server, port, prefix, register_type="rhsm"):
    """The API base URL for a register section's values.

    >>> api_base("candlepin", "8443", "/candlepin")
    'https://candlepin:8443/candlepin'
    >>> api_base("subscription.example.com", "", "")
    'https://subscription.example.com:443/subscription'
    """
    return (f"https://{server}:{normalize_port(port)}"
            f"{normalize_prefix(prefix, register_type)}")


def status_url(server, port, prefix, register_type="rhsm"):
    """The readiness/status endpoint URL for a register section's
    values (the endpoint every readiness and reachability probe of
    the destination uses).

    >>> status_url("candlepin", "8443", "/candlepin")
    'https://candlepin:8443/candlepin/status'
    """
    return f"{api_base(server, port, prefix, register_type)}/status"


def guest_probe_command(url, connect_timeout=5, max_time=10,
                        insecure=False, bypass_proxy=False):
    """A curl command that probes *url* from a REMOTE GUEST context.

    Both ends are bounded (--connect-timeout bounds the TCP connect,
    --max-time the whole transfer): a pod port that stays bound while
    its server is slow must skip the probe, not hang a test session
    for hours (the rhsm-qe CCT-2222 class).

    The probe is TWO-STAGE (review DEV-03): the default command runs
    WITHOUT ``-k`` (full TLS verification, the exact connection shape
    subscription-manager uses); the caller retries with
    ``insecure=True`` only when the verified probe fails, and an
    ``-k`` success then means "reachable but its CA is not trusted on
    the guest" -- a distinct skip reason from "not reachable" (trust
    distribution is the documented follow-up).

    *url* is shlex-quoted (review DEV-04): it is assembled from ini
    values (downloaded, untrusted input) into a command string that
    runs on the guest, so a crafted value must stay one argument.

    ``bypass_proxy=True`` (the build-#179 class, guest-side) adds
    ``--noproxy <host>`` for the URL's host ONLY: the guest's
    environment may carry the pipeline's HTTPS_PROXY, and a probe of
    the per-run Candlepin pod must not traverse a proxy that can
    never route back to the pod host. The bypass is deliberately
    scoped to the one host -- the guest keeps the proxy for every
    other egress -- and off by default, so a probe of an external
    destination (the stage tier, which REQUIRES the proxy) is never
    silently bypassed.

    >>> guest_probe_command("https://candlepin:8443/candlepin/status")
    "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 https://candlepin:8443/candlepin/status"
    >>> guest_probe_command("https://candlepin:8443/candlepin/status",
    ...                     insecure=True)
    "curl -s -o /dev/null -w '%{http_code}' -k --connect-timeout 5 --max-time 10 https://candlepin:8443/candlepin/status"
    >>> guest_probe_command("https://candlepin:8443/candlepin/status",
    ...                     bypass_proxy=True)
    "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 --noproxy candlepin https://candlepin:8443/candlepin/status"
    >>> guest_probe_command("https://h/x;rm -rf /")
    "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 'https://h/x;rm -rf /'"
    """
    for name, value in (("connect_timeout", connect_timeout),
                        ("max_time", max_time)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(
                f"{name} must be an int (got {type(value).__name__})")
    command = ("curl -s -o /dev/null -w '%{http_code}'"
               + (" -k" if insecure else "")
               + f" --connect-timeout {connect_timeout}"
               + f" --max-time {max_time}")
    if bypass_proxy:
        host = urllib.parse.urlsplit(str(url)).hostname
        if not host:
            raise ValueError(
                f"bypass_proxy needs a URL with a host (got {url!r})")
        command += f" --noproxy {shlex.quote(host)}"
    command += f" {shlex.quote(str(url))}"
    return command


def probe_reachable(ret, output):
    """Whether a probe result means the destination was reached.

    *ret*/*output* are the (exit code, stdout) of a
    guest_probe_command() run: reachable means curl exited 0 AND the
    status endpoint answered HTTP 200 (an answering-but-wrong server,
    a 503 during warmup or a name-resolution failure all count as
    unreachable).

    >>> probe_reachable(0, "200")
    True
    >>> probe_reachable(0, "503")
    False
    >>> probe_reachable(6, "000")
    False
    """
    return ret == 0 and str(output).strip() == "200"


# The two-stage probe outcome (review DEV-03): the verified probe
# (no -k) runs first; only its failure triggers the insecure retry,
# and the pair classifies the guest's view of the destination.
PROBE_TRUSTED = "trusted"
PROBE_UNTRUSTED_CA = "untrusted-ca"
PROBE_UNREACHABLE = "unreachable"


def probe_outcome(verified, insecure):
    """Classify a two-stage guest probe as one of the PROBE_* states.

    *verified* and *insecure* are the (exit code, stdout) pairs of a
    guest_probe_command() run without and with ``-k`` respectively:
    a verified HTTP 200 means fully usable; an insecure-only 200
    means the destination is reachable but its CA is not trusted on
    the guest (a DISTINCT skip reason -- trust distribution is the
    documented follow-up); anything else is unreachable.

    >>> probe_outcome((0, "200"), (0, "200"))
    'trusted'
    >>> probe_outcome((60, "000"), (0, "200"))
    'untrusted-ca'
    >>> probe_outcome((6, "000"), (6, "000"))
    'unreachable'
    """
    if probe_reachable(*verified):
        return PROBE_TRUSTED
    if probe_reachable(*insecure):
        return PROBE_UNTRUSTED_CA
    return PROBE_UNREACHABLE
