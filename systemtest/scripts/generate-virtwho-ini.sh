#!/bin/bash
# generate-virtwho-ini.sh -- Generate a virtwho.ini on tmpfs.
#
# Primary mode (VIRTWHO_INI_URL set): download the sanitized base ini
# from VIRTWHO_INI_URL and overlay the VIRTWHO_* environment secrets on
# top -- the environment always wins. VIRTWHO_INI_URL is a PLAIN
# (non-secret) Testing Farm variable pointing at a sanitized base ini
# provided by CI, which contains ONLY non-secret values (server
# hostnames/IPs, ports, domains/clusters, guest names, stable UUIDs,
# org IDs, repo/brew/proxy hosts, manifest/dogfood URLs). It must NEVER
# point at a file containing credentials: usernames, passwords, tokens,
# keytabs and SSH keys come exclusively from the VIRTWHO_* environment
# secrets (delivered as CI secrets). This contract is ENFORCED, not
# assumed: after download, any credential-shaped option found in the
# base (username/password/token/keytab/secret or key-material shapes)
# aborts the run -- the served file is secret-free, so a violation
# means VIRTWHO_INI_URL points at the wrong file.
#
# Fallback mode (VIRTWHO_INI_URL unset): generate the complete ini from
# the VIRTWHO_* environment variables alone.
#
# The environment variables map onto the sections/options of
# virtwho.ini.sample (option names are lower-cased into the ini):
#
#   VIRTWHO_JOB_<OPTION>        -> [job]        (rhel_compose_path,
#                                                multi_hypervisors, ...)
#   VIRTWHO_VIRTWHO_<OPTION>    -> [virtwho]    (virt-who test host:
#                                                server/username/password/...)
#   VIRTWHO_RHSM_<OPTION>       -> [rhsm]
#   VIRTWHO_SATELLITE_<OPTION>  -> [satellite]
#   VIRTWHO_VCENTER_<OPTION>    -> [esx]        (alias for the esx section)
#   VIRTWHO_ESX_<OPTION>        -> [esx]        (guest/esx_*/ssh_* options;
#                                                when both prefixes supply
#                                                the same option with
#                                                different values,
#                                                VIRTWHO_ESX_* wins and the
#                                                generator warns on the
#                                                clash)
#   VIRTWHO_RHEVM_<OPTION>      -> [rhevm]
#   VIRTWHO_HYPERV_<OPTION>     -> [hyperv]
#   VIRTWHO_AHV_<OPTION>        -> [ahv]
#   VIRTWHO_KUBEVIRT_<OPTION>   -> [kubevirt]
#   VIRTWHO_LIBVIRT_<OPTION>    -> [libvirt]
#   VIRTWHO_LOCAL_<OPTION>      -> [local]
#   VIRTWHO_XEN_<OPTION>        -> [xen]
#
# The legacy KUBEVIRT_TOKEN variable is an alias for
# VIRTWHO_KUBEVIRT_TOKEN (the new name wins when both are set), so the
# token survives the execute-phase regeneration performed by
# run-tests.sh.
#
# Example: VIRTWHO_VCENTER_SERVER/USERNAME/PASSWORD populate
# server/username/password of [esx]; VIRTWHO_ESX_GUEST_IP populates
# guest_ip of [esx]. In primary mode the same variables override the
# matching option of the downloaded base ini. A VIRTWHO_* variable
# under a known section prefix that matches no known option (e.g. a
# typo like VIRTWHO_ESX_GUEST_IPS) triggers a stderr warning: it would
# otherwise be silently dropped and leave an empty ini option.
#
# Values must be single-line: values containing newlines are rejected
# with an error (an embedded newline would be written as a new line and
# silently corrupt the ini). Multiline secrets must be base64-encoded by
# the caller (e.g. VIRTWHO_HYPERV_KERBEROS_KEYTAB_B64).
#
# [job] is preseeded from the plan-level HYPERVISOR/REGISTER/RHEL_COMPOSE
# variables (the same ones the shell scripts use); the preseed wins over
# the base file so the ini always agrees with what the scripts execute.
# The prefixed VIRTWHO_JOB_HYPERVISOR/_REGISTER/_RHEL_COMPOSE forms are
# accepted aliases: when the plan-level variable is unset, the alias is
# promoted into it BEFORE any ${VAR:-default} evaluation (here and in
# the wrapper scripts, which run this generator as a child), so the
# alias feeds the hypervisor-section creation and everything downstream
# (test-file pruning, compose resolution, SSH trust) executes with it;
# VIRTWHO_JOB_HYPERVISOR is lower-cased to match the handler list. A
# set plan-level variable is never overridden and wins over a
# disagreeing prefixed value (with a warning naming the winner).
#
# Core sections ([job], [virtwho], [rhsm], [satellite], [esx]) and the
# active hypervisor's section are ALWAYS emitted (with empty values when
# unset) because the pytest suite accesses them at import time. Other
# sections are emitted only when at least one of their variables is set
# (or when the base ini provides them). Sections of the base ini that
# are not part of the table above (e.g. [beaker], [gating]) are passed
# through unchanged.
#
# The file is written 0600 and MUST be destroyed after the test run; see
# cleanup-secrets.sh (wired into the tmt finish step).
#
# Usage: generate-virtwho-ini.sh [output-path]
#        (default: /dev/shm/virtwho.ini; a symlinked output path is
#        resolved and written through, never replaced with a regular
#        file)
#
# This script never prints credential values.
set -euo pipefail

OUTPUT=${1:-/dev/shm/virtwho.ini}
# Single materialization (review PR297-10): when OUTPUT is a symlink
# (the test tree's view of the tmpfs ini), resolve it and write
# THROUGH to the target -- the atomic mv below would otherwise
# replace the link with a regular file and silently strand the tmpfs
# original.
if [ -L "$OUTPUT" ]; then
    OUTPUT=$(readlink -f "$OUTPUT")
fi

# [job] plan-level aliases (review PR297-09): when the plan-level
# variable is unset, promote the prefixed VIRTWHO_JOB_* value into it
# BEFORE any ${VAR:-default} evaluation -- here (HYP below, the
# python invocation) and in the wrapper scripts, which run this
# generator as a child and evaluate the same variables themselves
# (test-file pruning, compose resolution, SSH trust). Promoting here
# is what makes the alias feed hyp: VIRTWHO_JOB_HYPERVISOR=libvirt
# must yield a [libvirt] section, not just [job] hypervisor=libvirt
# (the suite reads the section at import time and fails at conftest
# otherwise). VIRTWHO_JOB_HYPERVISOR is lower-cased because
# get_hypervisor_handler only matches the lower-case mode list -- an
# upper-case alias must not silently select the ESX handler. A set
# plan-level variable is never overridden here; the python side warns
# when it disagrees with the alias.
if [ -z "${HYPERVISOR:-}" ] && [ -n "${VIRTWHO_JOB_HYPERVISOR:-}" ]; then
    HYPERVISOR=$(printf '%s' "$VIRTWHO_JOB_HYPERVISOR" | tr '[:upper:]' '[:lower:]')
    export HYPERVISOR
fi
if [ -z "${REGISTER:-}" ] && [ -n "${VIRTWHO_JOB_REGISTER:-}" ]; then
    REGISTER="$VIRTWHO_JOB_REGISTER"
    export REGISTER
fi
if [ -z "${RHEL_COMPOSE:-}" ] && [ -n "${VIRTWHO_JOB_RHEL_COMPOSE:-}" ]; then
    RHEL_COMPOSE="$VIRTWHO_JOB_RHEL_COMPOSE"
    export RHEL_COMPOSE
fi
HYP=$(printf '%s' "${HYPERVISOR:-esx}" | tr '[:upper:]' '[:lower:]')

# Legacy alias: KUBEVIRT_TOKEN maps onto VIRTWHO_KUBEVIRT_TOKEN (the
# new name wins when both are set). run-tests.sh regenerates the ini
# from the environment at test time and only knows the new name, so
# the mapping here is what keeps the legacy variable working end to
# end. Done before the newline check so the mapped value is checked
# too.
if [ -z "${VIRTWHO_KUBEVIRT_TOKEN:-}" ] && [ -n "${KUBEVIRT_TOKEN:-}" ]; then
    VIRTWHO_KUBEVIRT_TOKEN="$KUBEVIRT_TOKEN"
    export VIRTWHO_KUBEVIRT_TOKEN
fi

# Reject newline-containing values up front: an embedded newline would
# be written as a literal new line and silently corrupt the ini
# (configparser would parse it as an option or a section header).
# Multiline secrets must be base64-encoded by the caller.
for envname in ${!VIRTWHO@} HYPERVISOR REGISTER RHEL_COMPOSE; do
    case ${!envname:-} in
        *$'\n'*)
            echo "ERROR: ${envname} value contains a newline; ini values must be single-line (base64-encode multiline secrets)" >&2
            exit 1
            ;;
    esac
done

# mktemp gives an unpredictable name next to the output; the file is
# atomically moved into place and never appears at the final path with
# default permissions.
TMP_OUTPUT=$(mktemp "${OUTPUT}.tmp.XXXXXX")
BASE_FILE=""
cleanup() {
    rm -f "$TMP_OUTPUT"
    if [ -n "$BASE_FILE" ]; then
        rm -f "$BASE_FILE"
    fi
}
trap cleanup EXIT

# --- Primary mode: fetch the sanitized base ini (non-secret only) ---
if [ -n "${VIRTWHO_INI_URL:-}" ]; then
    BASE_FILE=$(mktemp "${OUTPUT}.base.XXXXXX")
    # Hard fail on download errors: a silently missing base would
    # produce an ini without its non-secret values and confusing test
    # failures. The env-only fallback only applies when the variable
    # is unset altogether.
    if ! curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 10 \
        -o "$BASE_FILE" "$VIRTWHO_INI_URL"; then
        echo "ERROR: failed to download the sanitized base ini from VIRTWHO_INI_URL" >&2
        exit 1
    fi
    echo "Downloaded sanitized base ini from VIRTWHO_INI_URL"
fi

umask 077
HYP=$HYP REGISTER=${REGISTER:-rhsm} RHEL_COMPOSE=${RHEL_COMPOSE:-} \
    python3 - "$TMP_OUTPUT" "$BASE_FILE" <<'PYEOF'
import configparser
import os
import sys

out_path = sys.argv[1]
base_path = sys.argv[2]
hyp = os.environ["HYP"]
register = os.environ["REGISTER"]
compose = os.environ["RHEL_COMPOSE"]

# Section table: name -> (env prefixes, options). Mirrors
# virtwho.ini.sample plus the options the pytest suite accesses.
TABLE = {
    "job": (
        ["JOB"],
        # hypervisor/register/rhel_compose are the plan-level options;
        # their VIRTWHO_JOB_* forms are accepted aliases (see the
        # preseed below, review PR297-09).
        ["hypervisor", "register", "rhel_compose", "rhel_compose_path",
         "multi_hypervisors"],
    ),
    "virtwho": (
        ["VIRTWHO"],
        ["server", "username", "password", "port", "repo", "package",
         "brew", "test_rpms", "proxy_server", "proxy_port"],
    ),
    "rhsm": (
        ["RHSM"],
        ["server", "username", "password", "prefix", "port",
         "default_org", "activation_key", "proxy_hostname", "proxy_port"],
    ),
    "satellite": (
        ["SATELLITE"],
        ["server", "username", "password", "prefix", "port",
         "ssh_username", "ssh_password", "default_org", "secondary_org",
         "activation_key", "manifest", "manifest_second"],
    ),
    "esx": (
        ["ESX", "VCENTER"],
        ["server", "username", "password", "ssh_username",
         "ssh_password", "ssh_ip", "esx_ip", "esx_username",
         "esx_password", "esx_uuid", "esx_hwuuid", "esx_hostname",
         "esx_version", "esx_cpu", "esx_cluster", "guest_name",
         "guest_ip", "guest_username", "guest_password", "guest_uuid",
         "guest_state"],
    ),
    "rhevm": (
        ["RHEVM"],
        ["server", "username", "password", "vdsm_uuid", "vdsm_hwuuid",
         "vdsm_hostname", "vdsm_version", "vdsm_cpu", "vdsm_cluster",
         "guest_name", "guest_ip", "guest_username", "guest_password",
         "guest_uuid", "guest_state"],
    ),
    "hyperv": (
        ["HYPERV"],
        ["server", "username", "password", "kerberos_principal",
         "kerberos_keytab_b64", "uuid", "hostname", "version", "cpu",
         "guest_name", "guest_ip", "guest_username", "guest_password",
         "guest_uuid", "guest_state"],
    ),
    "ahv": (
        ["AHV"],
        ["server", "username", "password", "uuid", "hostname",
         "version", "cpu", "cluster", "guest_name", "guest_ip",
         "guest_username", "guest_password", "guest_uuid",
         "guest_state"],
    ),
    "kubevirt": (
        ["KUBEVIRT"],
        ["endpoint", "token", "config_file", "config_file_no_cert",
         "config_url", "config_url_no_cert", "namespace", "uuid",
         "hostname", "version", "cpu", "guest_name", "guest_ip",
         "guest_port", "guest_username", "guest_password",
         "guest_uuid", "guest_state"],
    ),
    "libvirt": (
        ["LIBVIRT"],
        ["server", "username", "password", "uuid", "hostname",
         "version", "cpu", "guest_name", "guest_ip", "guest_username",
         "guest_password", "guest_uuid", "guest_state"],
    ),
    "local": (
        ["LOCAL"],
        ["server", "username", "password", "port", "guest_name",
         "guest_ip", "guest_username", "guest_password", "guest_uuid",
         "guest_state", "guest_image_path", "guest_image_url",
         "guest_xml_path", "guest_xml_url"],
    ),
    "xen": (
        ["XEN"],
        ["server", "username", "password", "uuid", "hostname",
         "version", "cpu", "guest_name", "guest_ip", "guest_username",
         "guest_password", "guest_uuid", "guest_state"],
    ),
}
# The pytest suite reads these at import time, so they are always
# emitted (with empty values when unset).
ALWAYS = ("job", "virtwho", "rhsm", "satellite", "esx")


def env_value(prefixes, option):
    """First non-empty VIRTWHO_<PREFIX>_<OPTION> value (never printed)."""
    for prefix in prefixes:
        name = "VIRTWHO_%s_%s" % (prefix, option.upper().replace("-", "_"))
        value = os.environ.get(name, "")
        if value:
            return value
    return ""


cfg = configparser.ConfigParser(interpolation=None)
cfg.optionxform = str
if base_path:
    # A malformed base must die with the clean one-line error, not a
    # raw traceback; an empty body means the download silently went
    # wrong, which is a failure -- not a license to fall back to
    # env-only mode (that fallback is only for an unset URL).
    try:
        cfg.read(base_path)
    except configparser.Error:
        print("ERROR: could not parse the downloaded base ini", file=sys.stderr)
        sys.exit(1)
    if not cfg.sections():
        print("ERROR: the downloaded base ini is empty (failed download?)",
              file=sys.stderr)
        sys.exit(1)

    # The base is contractually secret-free. Any credential-shaped
    # option means VIRTWHO_INI_URL points at the wrong file (e.g. the
    # old pre-split ini) -- abort loudly instead of passing the value
    # through, even if an env secret would have overridden it.
    def forbidden_option(opt):
        o = opt.lower().replace("-", "_")
        if any(s in o for s in ("username", "password", "token", "keytab",
                                "secret")):
            return True
        # key-material shapes: key, ssh_key, api_key, private_key, ...
        return o == "key" or o.endswith("_key")

    offenders = ["[%s] %s" % (sec, opt)
                 for sec in cfg.sections() for opt in cfg.options(sec)
                 if forbidden_option(opt)]
    if offenders:
        for off in offenders:
            print("ERROR: the downloaded base ini contains a forbidden "
                  "credential option: %s" % off, file=sys.stderr)
        print("ERROR: the base ini must be secret-free; credentials come "
              "from the VIRTWHO_* environment secrets", file=sys.stderr)
        sys.exit(1)

# Warn about VIRTWHO_* variables that map to no known option: a typo
# like VIRTWHO_ESX_GUEST_IPS would otherwise be silently dropped and
# leave an empty ini option. Warning only (never a failure) so that
# variables for future options stay forward-compatible; a variable
# that overlays an extra option the base provides for a table section
# is legitimate and not warned about.
known = {}
for _name, (_prefixes, _options) in TABLE.items():
    for _p in _prefixes:
        known[_p] = (_name, set(_options))
unknown = []
for _env in os.environ:
    if not _env.startswith("VIRTWHO_"):
        continue
    _prefix, _sep, _opt = _env[len("VIRTWHO_"):].partition("_")
    if not _sep or not _opt:
        continue  # not VIRTWHO_<SECTION>_<OPTION> shaped
    _entry = known.get(_prefix.upper())
    if _entry is None:
        continue  # unknown section prefix: not ours to flag
    _section, _options = _entry
    if _opt.lower() in _options or cfg.has_option(_section, _opt.lower()):
        continue
    unknown.append(_env)
if unknown:
    print("WARNING: ignoring VIRTWHO_* variable(s) matching no known ini "
          "option (possible typo): %s" % ", ".join(sorted(unknown)),
          file=sys.stderr)

# Create missing sections: the always-on core sections, the active
# hypervisor's section (the suite reads it at import time via
# get_hypervisor_handler), and any section with at least one env
# variable set. Sections already provided by the base ini are kept.
for name, (prefixes, options) in TABLE.items():
    if name in cfg:
        continue
    needed = name in ALWAYS or name == hyp
    if not needed:
        needed = any(env_value(prefixes, opt) for opt in options)
    if needed:
        cfg.add_section(name)

# Ensure every table option of an emitted section exists (an empty
# value is fine for the suite, a missing option is not).
for name, (prefixes, options) in TABLE.items():
    if name not in cfg:
        continue
    for opt in options:
        if not cfg.has_option(name, opt):
            cfg.set(name, opt, "")

# Env-secret overlay: the environment (CI secrets) always wins, both
# for table options and for options that only exist in the base ini
# (e.g. extra options of the sanitized file).
for name in cfg.sections():
    if name in TABLE:
        prefixes = TABLE[name][0]
    else:
        prefixes = [name.upper().replace("-", "_")]
    for opt in cfg.options(name):
        value = env_value(prefixes, opt)
        if value:
            cfg.set(name, opt, value)

# [esx] accepts two prefixes (ESX and VCENTER). When both supply the
# same option with different values, ESX wins (it is first in the
# prefix list) -- announce the clash instead of dropping the VCENTER
# value silently (review PR297-13). Option names only, never values.
if cfg.has_section("esx"):
    _esx_opts = set(TABLE["esx"][1]) | set(cfg.options("esx"))
    _clashes = []
    for _opt in sorted(_esx_opts):
        _suffix = _opt.upper().replace("-", "_")
        _esx_val = os.environ.get("VIRTWHO_ESX_" + _suffix, "")
        _vcenter_val = os.environ.get("VIRTWHO_VCENTER_" + _suffix, "")
        if _esx_val and _vcenter_val and _esx_val != _vcenter_val:
            _clashes.append(_opt)
    if _clashes:
        print("WARNING: both VIRTWHO_ESX_* and VIRTWHO_VCENTER_* supply "
              "%s of [esx] with different values; VIRTWHO_ESX_* wins "
              "(checked first), the VIRTWHO_VCENTER_* value is ignored"
              % ", ".join(_clashes), file=sys.stderr)

# kubevirt: kubeconfig paths are not secrets; prepare-kubevirt.sh
# generates the files, so provide working defaults when unset.
if cfg.has_section("kubevirt"):
    for opt, default in (("config_file", "/root/kubeconfig"),
                         ("config_file_no_cert", "/root/kubeconfig-no-cert")):
        if not cfg.get("kubevirt", opt, fallback=""):
            cfg.set("kubevirt", opt, default)

# [job] preseed from the plan-level variables: they win over the base
# file so the ini always agrees with what the shell scripts execute.
if not cfg.has_section("job"):
    cfg.add_section("job")
# The prefixed VIRTWHO_JOB_HYPERVISOR/_REGISTER/_RHEL_COMPOSE forms
# are accepted aliases for the same three plan-level options (review
# PR297-09). The shell side has already promoted an alias into the
# plan-level variable when the plan-level variable was unset (feeding
# hyp and the wrapper scripts' ${VAR:-default} evaluations), so by the
# time python runs, a winning alias IS the plan-level value and the
# preseed below simply writes it. What remains here: a genuinely SET
# plan-level variable wins over a disagreeing prefixed value --
# announced with a warning naming the winner (never the values),
# because the shell scripts execute with the plan-level variables and
# the ini must agree with them. The hypervisor comparison is
# case-insensitive: a promoted VIRTWHO_JOB_HYPERVISOR arrives here
# lower-cased, and that must not read as a disagreement.
PLAN_LEVEL = {"hypervisor": hyp, "register": register,
              "rhel_compose": compose}
for option, default in PLAN_LEVEL.items():
    prefixed = env_value(["JOB"], option)
    plan_set = os.environ.get(option.upper(), "")
    if prefixed and not plan_set:
        continue  # the env overlay already applied the prefixed value
    if (prefixed and plan_set and prefixed != plan_set
            and prefixed.lower() != plan_set.lower()):
        print("WARNING: VIRTWHO_JOB_%s is shadowed by the plan-level "
              "%s variable; %s wins (the scripts execute with it)"
              % (option.upper(), option.upper(), option.upper()),
              file=sys.stderr)
    cfg.set("job", option, default)

with open(out_path, "w") as f:
    cfg.write(f, space_around_delimiters=False)
PYEOF

mv -f "$TMP_OUTPUT" "$OUTPUT"
rm -f "$BASE_FILE"
BASE_FILE=""
trap - EXIT
chmod 600 "$OUTPUT"

# Only section names are logged -- never values.
echo "Generated ${OUTPUT} (mode 0600, mode: $([ -n "${VIRTWHO_INI_URL:-}" ] && echo base+env-overlay || echo env-only)) with sections: $(grep '^\[' "$OUTPUT" | tr -d '[]' | tr '\n' ' ')"
