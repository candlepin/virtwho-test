#!/bin/bash
# generate-virtwho-ini.sh -- Generate a virtwho.ini on tmpfs.
#
# Primary mode (VIRTWHO_INI_URL set): download the base ini
# from VIRTWHO_INI_URL and overlay the VIRTWHO_* environment secrets on
# top -- the environment always wins. VIRTWHO_INI_URL is a PLAIN
# (non-secret) Testing Farm variable pointing at a base ini provided
# by CI, which contains ONLY non-secret values (server hostnames/IPs,
# ports, domains/clusters, guest names, stable UUIDs, org IDs,
# repo/brew/proxy hosts, manifest/dogfood URLs) plus, optionally,
# "@vault:<mount>/<path>:<key>" sentinel values in the credential-shaped
# option slots (username/password/token/keytab/secret, key, *_key) --
# <mount> is the Vault kv2 mount name, part of the sentinel grammar.
# It must NEVER point at a file containing PLAINTEXT credentials: any
# credential-shaped option whose value is not an @vault: sentinel
# aborts the run -- the served file is plaintext-credential-free, so a
# violation means VIRTWHO_INI_URL points at the wrong file.
#
# Sentinels are resolved GUEST-SIDE, after the download and before the
# env overlay, from a Vault kv2 server (systemtest/scripts/
# vault_resolve.py), for the ACTIVE sections only -- the active
# hypervisor's section, the register section, and every entry of the
# effective multi_hypervisors list (multi-hypervisor cells consume
# every family in the list; the normalized list is written back into
# [job] multi_hypervisors, because the suite re-parses that value
# without normalizing it) -- so the credentials of the other
# hypervisor families are never materialized on a guest that does not
# need them. A sentinel in any OTHER section ([virtwho], [job], the
# pass-through sections) aborts the run: those values must come from
# the VIRTWHO_* environment, never from Vault. Vault credentials come from the environment: VAULT_ADDR
# (https) plus VAULT_TOKEN, or VAULT_ROLE_ID and VAULT_SECRET_ID (an
# AppRole) -- all delivered as Testing Farm secrets (the environment
# is how Testing Farm hands decrypted blob values to the guest).
# Env-supplied credentials are final and never resolved, so a Vault
# outage cannot block a cell whose active credentials are all
# env-supplied; a sentinel that still needs resolution without Vault
# credentials aborts the run (a credentialed cell must not silently
# run credless; unset VIRTWHO_INI_URL for a local/dev, env-only run);
# VIRTWHO_VAULT_REQUIRED=1 additionally requires the credentials
# whenever the base carries any sentinel at all. Env secrets still WIN
# over resolved values, preserving the CI override.
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
# REGISTER is normalised like HYP: a mixed-case value would otherwise
# match no ini section and silently skip the register section's
# sentinel resolution.
REGISTER=$(printf '%s' "${REGISTER:-rhsm}" | tr '[:upper:]' '[:lower:]')

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
    # Optional integrity pin (review PR298-23): when VIRTWHO_INI_SHA256
    # is set (a plain, non-secret hex digest), verify the downloaded
    # base against it and abort on a mismatch -- the base selects
    # where resolved credentials are sent, so tampering must not pass
    # silently. Unset means unpinned; the accepted-risk posture of the
    # plain-http supply (and the stronger future options) is stated in
    # README.rst.
    if [ -n "${VIRTWHO_INI_SHA256:-}" ]; then
        ACTUAL_SHA256=$(sha256sum "$BASE_FILE" | awk '{print $1}')
        if [ "$ACTUAL_SHA256" != "$VIRTWHO_INI_SHA256" ]; then
            echo "ERROR: the downloaded base ini does not match VIRTWHO_INI_SHA256 (got ${ACTUAL_SHA256}, expected ${VIRTWHO_INI_SHA256})" >&2
            exit 1
        fi
        echo "Base ini matches the VIRTWHO_INI_SHA256 pin"
    fi
fi

umask 077
HYP=$HYP REGISTER=${REGISTER:-rhsm} RHEL_COMPOSE=${RHEL_COMPOSE:-} \
    PYTHONPATH="${SCRIPT_DIR}" \
    python3 - "$TMP_OUTPUT" "$BASE_FILE" <<'PYEOF'
import configparser
import os
import sys

import vault_resolve

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

    # The base must be free of PLAINTEXT credentials. Credential-shaped
    # option names (username/password/token/keytab/secret, key and
    # *_key -- this catches activation_key) are allowed ONLY with
    # @vault: sentinel values, resolved guest-side from Vault for the
    # active sections (see below). A plaintext value in a
    # credential-shaped option means VIRTWHO_INI_URL points at the
    # wrong file (e.g. the old pre-split ini) -- abort loudly instead
    # of passing the value through, even if an env secret would have
    # overridden it.
    def credential_option(opt):
        o = opt.lower().replace("-", "_")
        if any(s in o for s in ("username", "password", "token", "keytab",
                                "secret")):
            return True
        # key-material shapes: key, ssh_key, api_key, private_key, ...
        return o == "key" or o.endswith("_key")

    offenders = ["[%s] %s" % (sec, opt)
                 for sec in cfg.sections() for opt in cfg.options(sec)
                 if credential_option(opt)
                 and not vault_resolve.is_sentinel(cfg.get(sec, opt))]
    if offenders:
        for off in offenders:
            print("ERROR: the downloaded base ini contains a forbidden "
                  "credential option: %s" % off, file=sys.stderr)
        print("ERROR: credential-shaped options in the base ini are only "
              "allowed with @vault: sentinel values; plaintext credentials "
              "must never be served -- they come from the VIRTWHO_* "
              "environment secrets or from Vault", file=sys.stderr)
        sys.exit(1)

    # --- Sentinel resolution (guest-side credential pull) ---
    # Resolve the sentinels of the ACTIVE sections only: the active
    # hypervisor's section, the register section and the entries of
    # the effective multi_hypervisors list. The base ini carries the
    # credential slots of every family, but a guest must only ever
    # materialize the credentials of its own cell -- the sentinels of
    # the non-active sections are left as literal @vault: values (they
    # name Vault paths, not secrets).
    # multi_hypervisors cells consume every family in the list, so
    # those sections are active too. VIRTWHO_JOB_MULTI_HYPERVISORS
    # wins (the env overlay would overwrite the base value anyway);
    # parsed like the suite's hypervisors_list() -- bracketed,
    # comma-separated -- but also strip()ped and lower()cased, because
    # the section names are lowercase and the suite's parser keeps
    # the spaces ('esx, rhevm' yields ' rhevm'). The normalized list
    # is written back into [job] after the overlay (see below), so
    # the suite's unnormalized re-parse sees the same entries.
    multi_raw = os.environ.get("VIRTWHO_JOB_MULTI_HYPERVISORS", "")
    if not multi_raw.strip() and cfg.has_option("job", "multi_hypervisors"):
        multi_raw = cfg.get("job", "multi_hypervisors")
    # strip the OUTER whitespace before the brackets: str.strip("[")
    # strips a character set from both ends, so ' [libvirt] ' would
    # otherwise keep a bracket, match no section and silently drop the
    # family
    multi_raw = multi_raw.strip()
    if multi_raw.startswith("[") and multi_raw.endswith("]"):
        multi_raw = multi_raw[1:-1]
    active_sections = []
    for name in (hyp, register) + tuple(
            entry.strip().lower()
            for entry in multi_raw.split(",")):
        if name and name not in active_sections:
            active_sections.append(name)

    # Env-supplied credentials are final: an option whose sentinel the
    # environment already overrides is never resolved, so a Vault
    # outage cannot block a cell whose active credentials are all
    # env-supplied (the env overlay applies them after this anyway).
    # The prefixes follow the overlay's own rule below.
    def overlay_prefixes(section):
        if section in TABLE:
            return TABLE[section][0]
        return [section.upper().replace("-", "_")]

    targets = []
    for section in active_sections:
        if not cfg.has_section(section):
            continue
        for option in cfg.options(section):
            value = cfg.get(section, option)
            if not vault_resolve.is_sentinel(value):
                continue
            if env_value(overlay_prefixes(section), option):
                continue  # the env overlay will win; never resolve it
            targets.append((section, option))
    target_sections = sorted({section for section, _ in targets})

    resolver = vault_resolve.VaultResolver()
    sentinel_sections = vault_resolve.sections_with_sentinels(cfg)

    # A sentinel in a section that is never resolved is a base-authoring
    # error: [virtwho], [job] and the pass-through sections take their
    # values from the VIRTWHO_* environment variables, and a literal
    # @vault: string would silently become the credential (the
    # run-tests.sh merge-back only fills EMPTY options, so nothing
    # catches it later). The hypervisor families and the two register
    # sections are the per-cell credential slots: their sentinels stay
    # literal when the cell does not use them, by design.
    resolvable_sections = set(
        name for name in TABLE if name not in ("job", "virtwho"))
    unsupported = [
        (section, option)
        for section in sorted(sentinel_sections - resolvable_sections)
        for option in cfg.options(section)
        if vault_resolve.is_sentinel(cfg.get(section, option))
    ]
    for section, option in unsupported:
        print("ERROR: the base ini carries a sentinel in the unsupported"
              " section [%s] (option %s): values for this section must"
              " come from the VIRTWHO_* environment variables, never"
              " from Vault" % (section, option), file=sys.stderr)
    if unsupported:
        sys.exit(1)

    if targets or (resolver.strict and sentinel_sections):
        if not resolver.configured:
            if targets:
                print("ERROR: the base ini carries @vault: sentinels in "
                      "the active section(s) %s that the environment does "
                      "not override, but no Vault credentials are set "
                      "(VAULT_TOKEN, or VAULT_ROLE_ID and VAULT_SECRET_ID): "
                      "a credentialed cell must not silently run credless. "
                      "For a local/dev run without Vault, unset "
                      "VIRTWHO_INI_URL to generate the ini from the "
                      "VIRTWHO_* environment alone"
                      % ", ".join("[%s]" % s for s in target_sections),
                      file=sys.stderr)
            else:
                print("ERROR: VIRTWHO_VAULT_REQUIRED is set and the base "
                      "ini carries @vault: sentinels, but no Vault "
                      "credentials are set (VAULT_TOKEN, or VAULT_ROLE_ID "
                      "and VAULT_SECRET_ID)", file=sys.stderr)
            sys.exit(1)
        if targets:
            try:
                count = vault_resolve.resolve_options(cfg, targets, resolver)
            except vault_resolve.VaultError as error:
                print("ERROR: %s" % error, file=sys.stderr)
                sys.exit(1)
            print("Resolved %d Vault sentinel(s) in the active section(s): %s"
                  % (count, ", ".join(target_sections)))
        else:
            # strict mode with no target: verify the credentials are
            # actually usable (present, addressed, https), not merely
            # present -- "requires credentials" must not be satisfied
            # by a token that cannot reach any server
            try:
                resolver.check_usable()
            except vault_resolve.VaultError as error:
                print("ERROR: VIRTWHO_VAULT_REQUIRED is set but the Vault"
                      " credentials are unusable: %s" % error, file=sys.stderr)
                sys.exit(1)
            print("VIRTWHO_VAULT_REQUIRED set: Vault credentials present"
                  " and usable (address checked -- no Vault request is"
                  " made until an active-section sentinel needs"
                  " resolution)")

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
# (e.g. extra options of the sanitized file) -- and over the values
# resolved from @vault: sentinels above, which preserves the CI-side
# override of any credential during the transition.
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

# The suite re-parses [job] multi_hypervisors with its own,
# unnormalized expression (virtwho/base.py hypervisors_list():
# strip("[").strip("]").split(",")), and get_hypervisor_handler()
# compares each entry RAW against the mode list, falling back to the
# [esx] handler for anything else: a spaced or mixed-case value would
# resolve the right credentials above but drive the WRONG handler in
# the suite. Write the NORMALIZED list back into the ini after the
# overlay (env value or base value -- the same parse as the
# active-sections computation above), so both ends agree.
if cfg.has_option("job", "multi_hypervisors"):
    multi_norm = cfg.get("job", "multi_hypervisors").strip()
    if multi_norm:
        if multi_norm.startswith("[") and multi_norm.endswith("]"):
            multi_norm = multi_norm[1:-1]
        entries = [entry.strip().lower() for entry in multi_norm.split(",")]
        cfg.set("job", "multi_hypervisors",
                "[%s]" % ",".join(entry for entry in entries if entry))


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
