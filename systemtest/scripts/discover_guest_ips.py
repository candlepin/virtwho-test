"""Query the libvirt/hyperv guest IP through hypervisor-builder (hb).

This is the query half of the guest-IP discovery run by
discover-guest-ips.sh just before pytest: the guests inside these
hypervisors receive DHCP addresses that change whenever the guest is
rebuilt or rebooted, so a static guest_ip in the sanitized base ini
goes stale and the suite cannot reach the guest. The bash entry
point keeps the vt-side contract (the VIRTWHO_SKIP_IP_DISCOVERY
opt-out, the warning+fallback on a failed discovery, the
differing-guest_ip overwrite warning, the configparser ini access
and the guest_ip write-back); what lives HERE is asking the
hypervisor's management plane for the current address for libvirt
and hyperv -- through hb's LibvirtCLI/HypervCLI ``guest_ip()``, the
hardened forms this suite's shell code used to implement inline
(the guest name rides the ssh session's stdin into a fixed remote
command string, the PowerShell adapter list is post-filtered by the
exact VM name, the libvirt agent source falls back to the ARP
table, every query is bounded by a timeout). The knowledge of HOW
to ask each hypervisor belongs to hb -- one implementation shared
by every consumer -- not re-derived per test suite.

The ahv family stays in the bash script: hb's AHVApi cannot express
vt's query semantics without hb-side changes (its get_vm_by_name
splices the guest name into the Prism URL unencoded, and its
guest_search takes the last NIC address instead of the first
non-loopback IPv4) -- converting ahv is a hypervisor-builder
follow-up (C5), and the shell path's current hardening is not
weakened in the meantime.

The ini is DOWNLOADED, untrusted input, so its values are data,
never code: they reach hb as python arguments (server/username/
password into the CLI constructor, the guest name into
``guest_ip()``); nothing from the ini is ever interpolated into a
command string or a URL by this module, and only the ini path and
the family name ride its own command line. A discovery that fails
-- hb raising, ``guest_ip()`` returning None, the ini section not
carrying server/username/guest_name -- prints nothing and exits 1:
the bash side turns that into the warning + fallback, never a run
failure.

Usage: discover_guest_ips.py <ini-path> <family>

Prints the discovered guest_ip on stdout and exits 0, or prints
nothing and exits 1 (a usage error exits 2). Runs on the booted
test guest in the execute phase; hypervisor-builder is
pip-installed in the prepare phase (requirements.txt). Never
prints credential values: an exception text can embed connection
details, so failures stay silent here and the bash side emits the
named fallback warning.
"""

import configparser
import sys

FAMILIES = ("libvirt", "hyperv")


def read_section(path, section):
    """One ini section as a plain dict (configparser, never awk).

    Lenient exactly like the bash side's ini_read (strict=False): a
    duplicate option in a hand-edited ini degrades to the callers'
    warning/skip paths instead of failing the read, a missing
    section reads as no values, and the caller treats all of that
    as a failed discovery.
    """
    cfg = configparser.ConfigParser(interpolation=None, strict=False)
    cfg.optionxform = str
    try:
        cfg.read(path)
    except configparser.Error:
        return {}
    if not cfg.has_section(section):
        return {}
    return {opt: cfg.get(section, opt) for opt in cfg.options(section)}


def normalize_libvirt_server(server):
    """Accept a qemu+ssh://user@host/system URI, return the bare host.

    hb's LibvirtCLI connects to the server by ssh; the URI forms
    some base inis publish would be a nonsense ssh destination. The
    same reduction the former shell path applied: drop the scheme,
    the userinfo and the path.
    """
    if "://" in server:
        server = server.split("://", 1)[1]
    if "@" in server:
        server = server.split("@", 1)[1]
    return server.split("/", 1)[0]


def discover(path, family):
    """The guest_ip hb reports for the family, or None.

    Any failure is a failed discovery, never an exception past this
    point: hb raising, hb answering None, or the ini section not
    carrying the needed values all return None, so the bash side
    can warn and keep the ini value.
    """
    # The import is family-lazy: the CLI class comes from the
    # pip-installed hypervisor-builder (requirements.txt).
    if family == "libvirt":
        from hypervisor.virt.libvirt.libvirtcli import LibvirtCLI
        cli_cls = LibvirtCLI
    else:
        from hypervisor.virt.hyperv.hypervcli import HypervCLI
        cli_cls = HypervCLI

    values = read_section(path, family)
    server = values.get("server", "")
    username = values.get("username", "")
    password = values.get("password", "")
    guest_name = values.get("guest_name", "")

    if family == "libvirt":
        server = normalize_libvirt_server(server)

    # hyperv: never attempt the query with an empty password. hb's
    # transport would fall back to an ssh-agent attempt instead of
    # the ini credential -- an empty-password login attempt this
    # suite's hardening rules out; a failed discovery keeps the ini
    # value (the bash side emits the fallback warning).
    if family == "hyperv" and not password:
        return None

    if not server or not username or not guest_name:
        # the bash side already warned about the missing values
        return None

    try:
        cli = cli_cls(server, username, password)
        return cli.guest_ip(guest_name)
    except Exception:  # noqa: BLE001  # deliberately blind: ANY hb
        # failure is a failed discovery, not a run abort (a timed-out
        # or unreachable hypervisor is a lab problem, and the ini
        # value is the fallback); the exception text is not printed
        # either -- it can embed connection details.
        return None


def main(argv):
    if len(argv) != 3 or argv[2].lower() not in FAMILIES:
        print("usage: discover_guest_ips.py <ini-path> <libvirt|hyperv>",
              file=sys.stderr)
        return 2
    ini_path, family = argv[1], argv[2].lower()
    ip = discover(ini_path, family)
    if not ip:
        return 1
    print(ip)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
