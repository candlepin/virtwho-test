"""Resolve ``@vault:`` sentinels in the base virtwho.ini (guest-side).

A sentinel is a placeholder for a value stored in a Vault kv2 secret
store, with the form::

    @vault:<mount>/<path>:<key>

where ``<mount>`` is the kv2 mount name (``apps`` in the CI Vault),
``<path>`` is the rest of the logical path of the secret (for example
``cct-ci/virtwho-hypervisors``) and ``<key>`` is the name of the value
within that secret. Note the mount: it is part of the sentinel and the
read URL inserts ``/data/`` right after it, so
``@vault:cct-ci/virtwho-hypervisors:key`` (mount omitted) is a grammar
error, not a missing secret. In the served base ini, credential-shaped
options (username/password/token/keytab/secret, ``key`` and ``*_key``)
are allowed ONLY with sentinel values: plaintext credentials abort the
generator, and sentinels are resolved here into the tmpfs ini.

Resolution is SELECTIVE: the caller names the options to resolve (the
generator passes the active cell's sections -- see
:func:`resolve_sections` and :func:`resolve_options`), so the
credentials of the other hypervisor families never land on a guest
that does not need them. Sentinels the environment already overrides
are not resolved at all: the env value is final, so a Vault outage
must not block a cell whose credentials are all env-supplied.

The credentials for the Vault server come from the environment, never
from the command line:

- ``VAULT_TOKEN``: a static token;
- ``VAULT_ROLE_ID`` and ``VAULT_SECRET_ID``: an AppRole, exchanged for
  a client token with a login request;
- ``VAULT_ADDR``: the address of the Vault server, required whenever
  credentials are set: there is no default address, and credentials
  without an address are a configuration error. The address must use
  ``https`` -- the AppRole secret_id and the client token must never
  travel in cleartext -- unless ``VAULT_ALLOW_HTTP`` explicitly opts
  out (loopback/fake servers in the self-test);
- ``VAULT_SKIP_VERIFY``: skip the TLS certificate validation of the
  Vault server (needed with self-signed certificates; insecure);
- ``VIRTWHO_VAULT_REQUIRED``: strict mode -- a base carrying any
  sentinel at all then requires Vault credentials, even when the
  active sections hold none.

Each secret path is read at most once per resolver instance (the
decoded payload is cached by path, failures included), and each
(path, key) outcome is cached on top of that.

This module is stdlib-only (urllib.request) so it works in any phase
(prepare or execute), with any python3 and no pip installs. Secret
values are never logged: the error messages name paths and keys only,
and the address of the Vault server never appears in an error either
(the messages of urllib exceptions can embed request URLs) -- with one
deliberate exception: the refusal of an HTTP redirect names the
address the caller configured, because a redirect means that address
is wrong and must be located; the token never appears anywhere.
"""

import http.client
import json
import os
import ssl
import urllib.error
import urllib.request

# prefix that marks an ini value as a Vault sentinel
SENTINEL_PREFIX = "@vault:"

# environment variable that requires Vault credentials whenever the
# base ini carries any sentinel, even outside the active sections
STRICT_ENV_VAR = "VIRTWHO_VAULT_REQUIRED"

# environment variable that allows a plaintext http:// VAULT_ADDR
# (self-test fake servers only; the secret_id and client token would
# otherwise travel in cleartext)
ALLOW_HTTP_ENV_VAR = "VAULT_ALLOW_HTTP"

# seconds to wait for each Vault request
REQUEST_TIMEOUT = 10

_TRUTHY_VALUES = ("1", "true", "yes", "on")


class VaultError(Exception):
    """A sentinel could not be resolved.

    The message names the Vault path and the key involved, never their
    value and never the address of the Vault server.
    """


def is_sentinel(value):
    """Whether a value is a Vault sentinel."""
    return isinstance(value, str) and value.startswith(SENTINEL_PREFIX)


def parse_sentinel(value):
    """Split a sentinel into its ``(path, key)`` pair.

    :raises VaultError: if the sentinel is malformed.
    """
    _, _, target = value.partition(SENTINEL_PREFIX)
    path, separator, key = target.rpartition(":")
    if not (separator and path and key):
        # the sentinel itself names a path, not a secret: naming it in
        # the error is safe and needed to locate the broken option
        raise VaultError(
            f"malformed Vault sentinel {value!r}: expected the form"
            " '@vault:<mount>/<path>:<key>'"
        )
    return path, key


def sections_with_sentinels(cfg):
    """Names of the ini sections holding at least one sentinel."""
    return {
        section
        for section in cfg.sections()
        if any(is_sentinel(cfg.get(section, opt)) for opt in cfg.options(section))
    }


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse HTTP redirects instead of following them.

    urllib would follow a redirect and re-send the request headers --
    including the Vault auth token -- to whatever address the response
    names, possibly on another host: a compromised or misaddressed
    Vault endpoint must never be able to bounce the token elsewhere.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # the URL names the address the caller configured, so the
        # misconfiguration can be located; the token never appears
        raise VaultError(
            f"Vault returned a redirect (HTTP {code}) for"
            f" {req.full_url}: refusing to follow it -- the auth token"
            " must never be re-sent to another address; check"
            " VAULT_ADDR"
        )


class VaultResolver:
    """Resolves Vault sentinels into the values of a kv2 secret store.

    An instance holds the client token (taken directly from
    ``VAULT_TOKEN``, or obtained once with an AppRole login), a cache
    of the outcomes per secret path and per (path, key), so that
    resolving the sentinels of a path never issues further requests --
    failures included.
    """

    def __init__(self, environ=None):
        self._environ = os.environ if environ is None else environ
        self._token = None
        self._cache = {}
        self._path_cache = {}

    @property
    def configured(self):
        """Whether Vault credentials are available (token/AppRole)."""
        if self._environ.get("VAULT_TOKEN", "").strip():
            return True
        return bool(
            self._environ.get("VAULT_ROLE_ID", "").strip()
            and self._environ.get("VAULT_SECRET_ID", "").strip()
        )

    @property
    def strict(self):
        """Whether any sentinel in the base requires Vault credentials."""
        value = self._environ.get(STRICT_ENV_VAR, "").strip().lower()
        return value in _TRUTHY_VALUES

    @property
    def address(self):
        """The address of the Vault server (no default, PVL-02)."""
        return self._environ.get("VAULT_ADDR", "").strip()

    @property
    def _allow_http(self):
        """Whether a plaintext http:// address is explicitly allowed."""
        value = self._environ.get(ALLOW_HTTP_ENV_VAR, "").strip().lower()
        return value in _TRUTHY_VALUES

    @property
    def _ssl_context(self):
        if self._environ.get("VAULT_SKIP_VERIFY", "").strip().lower() in _TRUTHY_VALUES:
            return ssl._create_unverified_context()
        return None

    def check_usable(self):
        """The pre-flight checks of :meth:`resolve`, without a request.

        :raises VaultError: credentials absent, the address missing, or
            a plaintext address without the explicit opt-out.
        """
        if not self.configured:
            raise VaultError(
                "no Vault credentials: set VAULT_TOKEN, or VAULT_ROLE_ID and"
                " VAULT_SECRET_ID"
            )
        if not self.address:
            # no default address: sending the credentials to a host the
            # caller never configured must never happen
            raise VaultError(
                "Vault credentials are set but VAULT_ADDR is not: set it to"
                " the address of the Vault server"
            )
        if not self.address.lower().startswith("https://") and not self._allow_http:
            # the AppRole secret_id and the client token must never
            # travel in cleartext
            raise VaultError(
                "VAULT_ADDR must use https (set VAULT_ALLOW_HTTP=1 to allow"
                " plaintext)"
            )

    def resolve(self, value):
        """Resolve a sentinel into the value it refers to.

        :raises VaultError: if the value cannot be resolved.
        """
        self.check_usable()
        path, key = parse_sentinel(value)
        if (path, key) not in self._cache:
            try:
                self._cache[(path, key)] = ("ok", self._fetch(path, key))
            except VaultError as error:
                # cache the failure too, so that resolving the same
                # sentinel again does not repeat the request
                self._cache[(path, key)] = ("error", error)
        status, resolved = self._cache[(path, key)]
        if status == "error":
            raise resolved
        return resolved

    def _request(self, url, payload=None):
        """One HTTP request to the Vault server; JSON body or VaultError.

        Never lets a urllib error message through: those can embed the
        request URL, which would leak the address of the Vault server.
        """
        body = None
        headers = {}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        else:
            headers["X-Vault-Token"] = self._get_token()
        request = urllib.request.Request(url, data=body, headers=headers)
        # redirects are never followed (see _RefuseRedirects), so an
        # opener with the refusal handler replaces the default one
        handlers = [_RefuseRedirects()]
        if self._ssl_context is not None:
            handlers.append(
                urllib.request.HTTPSHandler(context=self._ssl_context)
            )
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise VaultError(
                f"Vault request failed: HTTP {error.code}"
            )
        except (
            urllib.error.URLError,
            OSError,
            ValueError,
            http.client.HTTPException,
        ) as error:
            # InvalidURL (a space or control character in the address
            # or in a sentinel path) derives from HTTPException, not
            # from ValueError/OSError: without it in the tuple the
            # error escapes as a raw traceback that echoes the URL
            raise VaultError(
                f"Vault request failed: {type(error).__name__}"
            )

    def _read_path(self, path):
        """The decoded kv2 payload of a path, read at most once.

        The outcome -- the payload, or the failure -- is cached per
        path: N sentinels on one path cost one request, and a
        transient 5xx aborts the run on the first sentinel only.
        """
        if path not in self._path_cache:
            mount, _, rest = path.partition("/")
            if not rest:
                self._path_cache[path] = (
                    "error",
                    VaultError(
                        "invalid Vault path (expected '<mount>/<path>'):"
                        f" {path!r}"
                    ),
                )
            else:
                # the path of the sentinel is the logical path of the
                # kv2 secret: the data API inserts '/data/' right
                # after the mount prefix
                url = f"{self.address.rstrip('/')}/v1/{mount}/data/{rest}"
                try:
                    # validate every level before indexing it: a 200 in
                    # the wrong shape (a proxy answer, a JSON error
                    # page, a bare list) must be a clean VaultError, not
                    # a raw TypeError from blind subscripting
                    payload = self._request(url)
                    data = None
                    if isinstance(payload, dict):
                        inner = payload.get("data")
                        if isinstance(inner, dict):
                            data = inner.get("data")
                    if not isinstance(data, dict):
                        # a non-dict payload is malformed, not a
                        # missing key: say so instead of a misleading
                        # 'key not found'
                        raise VaultError(
                            f"malformed Vault response for path {path!r}"
                        )
                    self._path_cache[path] = ("ok", data)
                except VaultError as error:
                    self._path_cache[path] = ("error", error)
        status, data = self._path_cache[path]
        if status == "error":
            raise data
        return data

    def _fetch(self, path, key):
        data = self._read_path(path)
        if key not in data:
            raise VaultError(f"key {key!r} not found at Vault path {path!r}")
        if not isinstance(data[key], str):
            raise VaultError(
                f"the value of key {key!r} at Vault path {path!r} is not a"
                " string"
            )
        return data[key]

    def _get_token(self):
        if self._token is None:
            token = self._environ.get("VAULT_TOKEN", "").strip()
            if not token:
                token = self._login()
            self._token = token
        return self._token

    def _login(self):
        """Exchange the AppRole for a client token."""
        role_id = self._environ.get("VAULT_ROLE_ID", "").strip()
        secret_id = self._environ.get("VAULT_SECRET_ID", "").strip()
        url = f"{self.address.rstrip('/')}/v1/auth/approle/login"
        try:
            token = self._request(url, {"role_id": role_id, "secret_id": secret_id})[
                "auth"
            ]["client_token"]
        except (KeyError, TypeError):
            raise VaultError("Vault AppRole login response has no client token")
        if not token:
            raise VaultError("Vault AppRole login returned an empty client token")
        return token


def resolve_options(cfg, targets, resolver=None):
    """Resolve the given ``(section, option)`` sentinel slots, in place.

    The caller names exactly which options to resolve -- the generator
    passes the active cell's sentinels that the environment does not
    already override, so the credentials of the other families are
    never materialized on a guest that does not need them, and an
    env-supplied credential is never resolved (the env overlay applies
    it afterwards anyway, so a Vault outage cannot block it).

    An unresolved sentinel among the targets is a hard error: the run
    is credentialed by construction, and a missing value would
    silently produce an empty credential.

    :param cfg: the parsed ini (configparser.ConfigParser).
    :param targets: iterable of ``(section, option)`` pairs.
    :param resolver: an optional pre-built :class:`VaultResolver`.
    :return: the number of sentinels resolved (never their values).
    :raises VaultError: if a target cannot be resolved, or the
        resolved value is not single-line.
    """
    resolver = resolver if resolver is not None else VaultResolver()
    resolved = 0
    for section, option in targets:
        value = cfg.get(section, option)
        if not is_sentinel(value):
            continue
        # name section.option, path and key in the errors, never the
        # resolved value
        try:
            path, key = parse_sentinel(value)
            secret = resolver.resolve(value)
        except VaultError as error:
            raise VaultError(
                f"cannot resolve the sentinel of [{section}] {option} (value"
                f" {value!r}): {error}"
            )
        if "\n" in secret or "\r" in secret:
            # an embedded newline would be written as a literal new
            # line and silently corrupt the ini
            raise VaultError(
                f"the value of key {key!r} at Vault path {path!r} contains a"
                " newline: ini values must be single-line (base64-encode"
                " multiline secrets in Vault)"
            )
        cfg.set(section, option, secret)
        resolved += 1
    return resolved


def resolve_sections(cfg, sections, resolver=None):
    """Resolve every sentinel of the REQUESTED sections, in place.

    Section-level wrapper over :func:`resolve_options`: every
    sentinel of the named sections is a target. The generator uses
    :func:`resolve_options` directly (it excludes env-overridden
    slots); this wrapper keeps the simple all-sentinels-of-a-section
    contract for other callers.
    """
    targets = [
        (section, option)
        for section in sections
        if cfg.has_section(section)
        for option in cfg.options(section)
        if is_sentinel(cfg.get(section, option))
    ]
    return resolve_options(cfg, targets, resolver)
