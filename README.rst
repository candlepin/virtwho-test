virtwho-test
=========

`virtwho-test`_ is focused on virt-who package testing based on the rhel lifecycle

* Team Members: `Eko`_, `Coulson`_, `Yuefen`_
* Supproted Hypervisors: libvirt, esx, rhevm, hyperv, xen, kubevirt and fake
* Supported Subscription Servers: rhsm, satellite, sam(deprecated)

`virtwho.ini.sample`_ is provided as a sample to define attributes

* Change the file name to virtwho.ini
* Update the necessary datas based on test requirements
* `hypervisor-builder`_ can help to get part of the information

CI secrets (Testing Farm)
-------------------------

In CI, virtwho.ini is **not** fetched over HTTP and never contains
credentials at rest: it is generated at test time on tmpfs
(``/dev/shm/virtwho.ini``, mode 0600) by
``systemtest/scripts/generate-virtwho-ini.sh`` and destroyed by
``systemtest/scripts/cleanup-secrets.sh`` in the tmt finish step.
That contract is enforced, not assumed: a downloaded base containing
a **plaintext or empty** credential-shaped option (any
``*username*``/``*password*``/``*token*``/``*keytab*``/``*secret*`` or
key-material option) aborts the generator -- the one allowed value
form for those options is a ``@vault:`` sentinel, resolved guest-side
from Vault (below) -- and a ``VIRTWHO_*`` variable under a known
section prefix that matches no known option (e.g. a typo like
``VIRTWHO_ESX_GUEST_IPS``) prints a stderr warning instead of being
silently dropped.

How the ini is assembled:

1. **Base download (primary mode)**: when ``VIRTWHO_INI_URL`` is set,
   the generator downloads the base ini it points at. The variable is
   a *plain* (non-secret) Testing Farm variable and the file contains
   ONLY non-secret values (server hostnames/IPs, ports,
   domains/clusters, guest names, stable UUIDs, org IDs,
   repo/brew/proxy hosts, manifest/dogfood URLs) plus, optionally,
   ``@vault:<mount>/<path>:<key>`` sentinel values in the
   credential-shaped option slots. ``<mount>`` is the Vault kv2 mount
   name (part of the grammar: ``@vault:cct-ci/...:key`` without the
   mount is a grammar error). It must never point at a file containing
   *plaintext* credentials -- that aborts the generator.
2. **Sentinel resolution (guest-side, selective)**: the sentinels of
   the ACTIVE sections only -- the active hypervisor's section, the
   register section, and every entry of the effective
   ``multi_hypervisors`` list -- are resolved from the Vault kv2
   server into the tmpfs ini, so the credentials of the other
   hypervisor families are never materialized on a guest that does
   not need them (their sentinels stay as literal path values).
   Vault access comes from the environment: ``VAULT_ADDR`` (must be
   ``https``; ``VAULT_ALLOW_HTTP=1`` is a loopback/self-test opt-out)
   plus either ``VAULT_TOKEN`` or the AppRole pair
   ``VAULT_ROLE_ID``/``VAULT_SECRET_ID``; ``VAULT_SKIP_VERIFY``
   skips TLS validation (insecure, self-signed labs). An env-supplied
   credential is final and never resolved, so a Vault outage cannot
   block a cell whose active credentials are all env-supplied. A
   sentinel that still needs resolution and fails (missing key, Vault
   error) aborts the run naming the path and key; the same holds when
   no Vault credentials are set at all. ``VIRTWHO_VAULT_REQUIRED=1``
   additionally requires Vault credentials whenever the base carries
   any sentinel, even outside the active sections. A sentinel in
   ``[virtwho]``, ``[job]`` or a pass-through section aborts; those
   values come only from the ``VIRTWHO_*`` environment.
3. **Env-secret overlay (env wins)**: the ``VIRTWHO_*`` environment
   variables, delivered as CI secrets, are
   overlaid on top of the resolved base (or, when ``VIRTWHO_INI_URL``
   is unset, they build the complete ini alone -- the
   backward-compatible fallback). Usernames, passwords, tokens,
   keytabs and SSH keys come only from these variables or from Vault
   via sentinels -- never as plaintext in any downloaded or committed
   file.
4. **Computed values**: values computed during the run (the resolved
   compose, the virt-who NEVRA, gating ``test_rpms``, the kubevirt
   guest coordinates) are recorded in the non-secret sidecar
   ``.virtwho-computed.ini`` and merged back by ``run-tests.sh`` when
   it regenerates the ini at test time.

CI supply (outside this repository): ``VIRTWHO_INI_URL`` is delivered
as a *plain* request-time variable by the rhsm-jobs virt-who
pipelines -- live on rhsm-jobs main since the **!557** merge
(2026-11-16). Their default points at the staged sanitized base
(``http://<auto-services>/automation-properties/virtwho.vault.ini``,
live since 2026-11-16 -- structure: 22 ``@vault:`` sentinel slots,
zero plaintext secrets). The ``VAULT_*`` AppRole secrets that resolve
those sentinels arrive with the stacked PR #298. **Cutover gate 1:
merge #297 and #298 together.** The pipelines already default
``VIRTWHO_INI_URL`` to the sentinel-bearing base, so merging #297
alone makes the next pipeline-submitted run abort (loudly, by
design): the strict credential-name filter above makes the generator
refuse the sentinel-bearing default base (a hard failure) rather
than run credless -- a deliberate, *loud* cutover, not a silent mode
change. Once both are in, the virt-who default runs work end to end.
``HTTPS_PROXY``/``VIRTWHO_REPO`` are delivered the same way by the
follow-up MR **!560** (rhsm-jobs, merged 2026-11-19; see below).

Accepted supply risk, stated plainly (review PR298-23): the served
base is fetched over plain ``http://`` with no transport check --
an asymmetry, since the credential resolver itself refuses a
non-``https`` ``VAULT_ADDR`` (unless ``VAULT_ALLOW_HTTP=1``). The
base selects where resolved credentials are *sent*, so the fetch is
part of the trust path. The accepted bound: the served location is
an internal-only host (not reachable from outside the corp network),
the base is structure-validated on arrival (the credential-name
filter aborts any plaintext credential, and sentinels are only ever
resolved for the active sections), and the credentials themselves
travel Vault → guest over TLS -- only non-secret structure rides the
plain-http leg. Stronger options are future hardening, not current
behavior: enforcing ``https`` for ``VIRTWHO_INI_URL`` (it would break
the live supply, which serves plain http by design) and the optional
``VIRTWHO_INI_SHA256`` digest pin -- already implemented: when set
(a plain, non-secret hex digest), the generator verifies the
downloaded base against it and aborts on a mismatch.

Single materialization point: the ini exists ONLY on tmpfs. The test
tree (``/opt/virtwho-test`` / ``/usr/share/virtwho-test``, and the
writable bootc copy) holds a *symlink* to ``/dev/shm/virtwho.ini``
instead of a copy; the suite reads and writes through it
(``Configure.save()`` opens the path with ``w``, which follows
symlinks) and the bootc copy step uses ``cp -a``, which preserves it.
The invariant is enforced, not just documented: the generator
resolves a symlinked output path and writes through to the target
(never replacing the link with a regular file), and the finish step
shreds a regular legacy ``virtwho.ini`` found in a tree before
unlinking it. Three disk exceptions exist and are destroyed by the
finish step: the kubevirt kubeconfigs (below), the suite's own
artifacts under the tree's ``temp/`` directory --
``VirtwhoHypervisorConfig`` writes ``temp/<mode>.conf`` (it carries
the hypervisor password) and the Hyper-V path decodes
``temp/hyperv-kerberos.keytab`` there; on bootc that tree is the
writable copy under ``$TMT_PLAN_DATA``, which survives the run -- and
the per-mode configs uploaded to ``/etc/virt-who.d/``:
``Configure.save()`` uploads ``temp/<mode>.conf`` there as
``/etc/virt-who.d/<mode>.conf`` (``run-tests.sh`` rewrites
``[virtwho] server`` to the guest's own address, so the upload lands
on the same machine the finish step runs on) carrying the same
hypervisor and register passwords, and the Hyper-V keytab twin is
uploaded to the same directory; all are shredded by the finish step.

The SSH key for the libvirt hypervisor is injected as
``CCT_SSH_KEY_B64`` (base64); it is decoded to
``/dev/shm/virtwho-ssh-key`` (0600) and reached through an
``IdentityFile /dev/shm/virtwho-ssh-key`` entry in ``/root/.ssh/config``
-- both the ssh CLI and the virt-who daemon (its ``qemu+ssh://`` URIs
resolve through root's ssh_config; the systemd daemon cannot use an
ssh-agent) pick it up from there. The key is never installed into
``/root/.ssh``. The legacy ``CCT_SSH_KEY_URL`` fetch is still honored
during the transition and lands on tmpfs the same way.
``VIRTWHO_<HYPERVISOR>_PASSWORD`` is only consumed by the libvirt
SSH-trust path (``ssh-copy-id`` when no SSH key is injected).

The kubevirt service-account token is the one credential that touches
real disk: the virt-who daemon reads its kubeconfig from fixed paths,
so ``prepare-kubevirt.sh`` writes ``/root/kubeconfig`` and
``/root/kubeconfig-no-cert`` mode 0600, and ``cleanup-secrets.sh``
shreds both files in the tmt finish step. The shred path follows the
ini: the finish step reads ``[kubevirt]`` ``config_file`` /
``config_file_no_cert`` from the ini while it is still readable
(falling back per-option to the two literals, which are also the
generator's defaults), so an overridden kubeconfig path under
``/root`` is shredded too. A path read from the downloaded base ini
that is not an absolute path under ``/root`` is *refused* with a
warning instead of shredded -- the ini is downloaded input and must
not aim the finish step at arbitrary files. The ini and the SSH key,
by contrast, are tmpfs-only.

Environment variable contract (all optional; option names are
lower-cased into the ini, e.g. ``VIRTWHO_ESX_GUEST_IP`` -> ``guest_ip``
of ``[esx]``):

===================================  ===========================
Environment variable prefix          ini section
===================================  ===========================
``VIRTWHO_JOB_*``                    ``[job]``
``VIRTWHO_VIRTWHO_*``                ``[virtwho]``
``VIRTWHO_RHSM_*``                   ``[rhsm]``
``VIRTWHO_SATELLITE_*``              ``[satellite]``
``VIRTWHO_VCENTER_*`` (alias)        ``[esx]``
``VIRTWHO_ESX_*``                    ``[esx]``
``VIRTWHO_RHEVM_*``                  ``[rhevm]``
``VIRTWHO_HYPERV_*``                 ``[hyperv]``
``VIRTWHO_AHV_*``                    ``[ahv]``
``VIRTWHO_KUBEVIRT_*``               ``[kubevirt]``
``VIRTWHO_LIBVIRT_*``                ``[libvirt]``
``VIRTWHO_LOCAL_*``                  ``[local]``
``VIRTWHO_XEN_*``                    ``[xen]``
===================================  ===========================

Notes:

* ``[job]`` is preseeded from the plan-level ``HYPERVISOR``,
  ``REGISTER`` and ``RHEL_COMPOSE`` variables. The prefixed forms
  ``VIRTWHO_JOB_HYPERVISOR`` / ``VIRTWHO_JOB_REGISTER`` /
  ``VIRTWHO_JOB_RHEL_COMPOSE`` are accepted aliases: the prefixed
  value wins when the plan-level variable is unset -- it is promoted
  into the plan-level variable *before* the wrapper scripts evaluate
  their ``${HYPERVISOR:-esx}``-style defaults, so the alias also
  selects the hypervisor section (``VIRTWHO_JOB_HYPERVISOR`` is
  lower-cased to match the handler list) and drives the test-file
  pruning and compose resolution -- and a set plan-level variable
  wins over a disagreeing prefixed value (the generator warns and
  names the winner -- the scripts execute with the plan-level
  variables).
* ``VIRTWHO_ESX_*`` and ``VIRTWHO_VCENTER_*`` are two prefixes for
  the same ``[esx]`` section. When both supply the same option with
  different values, ``VIRTWHO_ESX_*`` wins (prefix order) and the
  generator warns about the clash; keep only one prefix set when
  migrating between them.
* Sanitizing a base derived from ``virtwho.ini.sample``: **delete**
  the credential-shaped lines (``username``/``password``/``token``/
  ``keytab``/``secret``, ``key``, ``*_key``). Blanking the value is
  not enough -- the generator's filter matches the option *name*
  regardless of value, so a blanked line still aborts the run.
* The core sections (``[job]``, ``[virtwho]``, ``[rhsm]``,
  ``[satellite]``, ``[esx]``) and the active hypervisor's section are
  always emitted (with empty values when unset) because the pytest
  suite reads them at import time. Other sections are emitted only when
  at least one of their variables is set or the base ini provides them
  (sections of the base ini that are outside the table, e.g.
  ``[beaker]`` or ``[gating]``, are passed through unchanged).
* Typical per-hypervisor credentials:
  ``VIRTWHO_VCENTER_SERVER/USERNAME/PASSWORD`` (esx),
  ``VIRTWHO_RHEVM_SERVER/USERNAME/PASSWORD``,
  ``VIRTWHO_HYPERV_SERVER/USERNAME/PASSWORD``,
  ``VIRTWHO_AHV_SERVER/USERNAME/PASSWORD``,
  ``VIRTWHO_KUBEVIRT_TOKEN``.
* Values must be single-line: the generator rejects values containing
  newlines. Base64-encode multiline secrets (e.g. kerberos keytabs).
* ``VIRTWHO_REPO`` (optional) enables nightly compose alias resolution
  in ``setup-virtwho-test.sh``; there is no default. ``HTTPS_PROXY`` /
  ``HTTP_PROXY`` configure the subscription-manager proxy
  (``configure-proxy.sh`` and the kubevirt guest); there is no default
  either. Both are delivered as plain request-time variables by the
  rhsm-jobs virt-who pipelines (follow-up MR !560, merged 2026-11-19);
  the in-repo internal defaults stay removed.
* Known limitations: on kubevirt image-mode (bootc) runs the
  kubeconfig write is skipped when the target directory is not
  writable (``prepare-kubevirt.sh`` tests writability explicitly and
  says so -- the prepare phase runs without a writable ``/root``);
  the kubevirt tests then cannot run with a kubeconfig. The
  ``[beaker]`` and ``[gating]`` ini sections are not covered by the
  ``VIRTWHO_*`` generator in env-only fallback mode (the sanitized base
  file can provide them). The ``rhsm_sw`` register path
  (``[rhsm_sw]``/``[rhsm_product]``) has no credential delivery yet:
  the sections are outside the generator's table and the staged base
  carries neither them nor the ``*_sw`` guest accounts, so
  ``tests/others/test_hypervisors_sw.py`` is skipped until a follow-up
  wires the sections into the generator table and the environment
  contract.

Vault delivery (for the ``@vault:`` sentinels of the base ini; all
optional, all delivered as Testing Farm secrets except where noted):

===================================  =============================
Environment variable                 Purpose
===================================  =============================
``VAULT_ADDR``                       Vault server address (must be
                                     ``https``; set
                                     ``VAULT_ALLOW_HTTP=1`` only for
                                     loopback/self-test servers)
``VAULT_TOKEN``                      static token, or:
``VAULT_ROLE_ID`` +                  AppRole login (the CI form)
``VAULT_SECRET_ID``
``VAULT_SKIP_VERIFY``                skip TLS validation (insecure)
``VIRTWHO_VAULT_REQUIRED``           strict mode: require
                                     **usable** Vault credentials
                                     (address present; ``https``
                                     unless ``VAULT_ALLOW_HTTP=1``)
                                     for any sentinel in the base,
                                     active or not
===================================  =============================

``VIRTWHO_INI_URL`` itself is a *plain* (non-secret) Testing Farm
variable.

Self-test for the generator and the tmpfs/symlink/ssh_config plumbing
(no real credentials involved; runs on every push and pull request in
the ``Lint`` workflow's ``selftest`` job, and can be run manually)::

    bash systemtest/scripts/test-generate-virtwho-ini.sh

.. _virtwho-test: https://github.com/candlepin/virtwho-test
.. _Eko: https://github.com/eko999
.. _Coulson: https://github.com/hkx303
.. _Yuefen: https://github.com/Junefen
.. _virtwho.ini.sample:
    https://github.com/candlepin/virtwho-test/blob/master/virtwho.ini.sample
.. _hypervisor-builder: https://github.com/candlepin/hypervisor-builder