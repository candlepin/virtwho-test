# Self-test conversion checkpoint parity (bash → pytest)

The former bash checkpoint scripts — `test-generate-virtwho-ini.sh`
(71 checkpoint lines) and `test-discover-guest-ips.sh` (19) at
pre-conversion commit `1fe2e3c` — were replaced by the pytest suite
under `systemtest/selftest/` (PR #299). Checkpoint parity was the
contract of that conversion: **every old checkpoint maps to at least
one named pytest test**, usually with equal or stronger assertions
(parametrized expansion of the section/option matrices, real failure
messages instead of `ok()/fail()` counting, network-level selectivity
proofs via the fake Vault's request log).

Counting rule (stated so the numbers stay checkable): a checkpoint
is one `OK:` line **emitted by an executed run** of a script at
`1fe2e3c` (reproduced 2026-11-20 on the pre-conversion checkout:
`bash systemtest/scripts/test-generate-virtwho-ini.sh` emits 71,
`bash systemtest/scripts/test-discover-guest-ips.sh` emits 19 — 90
executed checkpoints total). An earlier draft of this header said
65 for the generate script: that counted only the literal
`echo "OK:"` **source lines** (65 of them), missing the python-side
`print("OK: ...")` checkpoints (the env-only configparser parse, the
`vault_resolve` helper pin) and the loop-expanded multi_hypervisors
normalized write-back lines (one print per variant, 4 lines). The
table below numbers the 65 echo checkpoints 1–65 and carries the
python-side checkpoints as rows 66–67; the write-back variants fold
into rows 20–21 (their one print statement, loop-expanded).

This table is the in-tree record of that audit (EM-06). Test node IDs
are relative to `systemtest/selftest/`; run any of them with
`python -m pytest systemtest/selftest/ -k <name>`.

## test-generate-virtwho-ini.sh → test_generate_virtwho_ini.py

| # | Old bash checkpoint (`OK:` line) | New pytest test(s) |
|---|---|---|
| 1 | env-only mode, file mode is 0600 | `TestEnvOnlyGeneration::test_file_mode_is_0600` |
| 2 | newline-containing values are rejected | `TestEnvOnlyGeneration::test_newline_containing_value_rejected` |
| 3 | base+overlay mode, file mode is 0600 | `TestBaseOverlay::test_file_mode_is_0600` |
| 4 | base+overlay assertions (env wins, base survives, pass-through) | `TestBaseOverlay::test_env_secret_wins_over_base`, `::test_base_values_survive_when_env_silent` (parametrized), `::test_env_only_option_added_on_top_of_base`, `::test_env_emitted_section_value`, `::test_plan_level_preseed_wins_over_base` |
| 5 | failing base download fails the generator | `TestBaseOverlay::test_failing_base_download_fails_the_generator` |
| 6 | a VIRTWHO_INI_SHA256 mismatch aborts the generator | `TestBaseOverlay::test_sha256_pin_mismatch_aborts` |
| 7 | a matching VIRTWHO_INI_SHA256 pin passes (and says so) | `TestBaseOverlay::test_sha256_pin_match_passes` |
| 8 | malformed base ini fails with the clean error (no traceback) | `TestBaseOverlay::test_malformed_base_fails_with_clean_error` |
| 9 | empty base body fails loudly (no silent env-only fallback) | `TestBaseOverlay::test_empty_base_body_fails_loudly` |
| 10 | base with planted forbidden keys aborts, naming section.option | `TestBaseOverlay::test_planted_forbidden_keys_abort` |
| 11 | empty credential-shaped option aborts (only @vault: values allowed) | `TestBaseOverlay::test_empty_credential_option_aborts` |
| 12 | sentinels in never-resolved sections ([virtwho], pass-throughs) abort loudly | `TestBaseOverlay::test_unsupported_section_sentinels_abort` |
| 13 | fake Vault server running (harness bootstrap) | the session-scoped `fake_vault` fixture (`conftest.py::FakeVault`) |
| 14 | selective resolution (active only), AppRole login, env wins over resolved, one read per path | `TestVaultResolution::test_selective_resolution_approle` (ini assertions AND the server request log) |
| 15 | register-section selection (satellite) + static token path | `TestVaultResolution::test_satellite_register_static_token` |
| 16 | unresolved active sentinel hard-fails, naming path+key (no traceback) | `TestVaultResolution::test_unresolved_active_sentinel_hard_fails` |
| 17 | Vault redirects are refused (token never re-sent to the redirect target) | `TestVaultResolution::test_redirects_refused` (via the `redirect_vault` fixture) |
| 18 | env-supplied credentials survive a Vault failure (never resolved) | `TestVaultResolution::test_env_supplied_credentials_survive_vault_failure` |
| 19 | a fully env-covered cell needs no Vault credentials | `TestVaultResolution::test_fully_env_covered_cell_needs_no_vault` |
| 20 | multi_hypervisors (env form, spaced/mixed-case) resolves every listed family | `TestVaultResolution::test_multi_hypervisors_env_form_resolves_listed_families` |
| 21 | multi_hypervisors (base-file form) resolves the listed family only | `TestVaultResolution::test_multi_hypervisors_base_form_resolves_listed_family` |
| 20a | (python-side checkpoint, loop-expanded: one `OK:` per shape) multi_hypervisors of every shape written back NORMALIZED and the suite's own verbatim parser agrees | `TestVaultResolution::test_multi_hypervisors_written_back_normalized` (env form) and `::test_multi_hypervisors_base_form_written_back_normalized` (base-file form) — refiled here from "Beyond parity": these ARE old checkpoints |
| 22 | multi_hypervisors with whitespace outside the brackets still resolves | `TestVaultResolution::test_multi_hypervisors_outer_whitespace_still_resolves` (explicit ids: trailing-space / leading-space) |
| 23 | plaintext http:// VAULT_ADDR refused unless VAULT_ALLOW_HTTP is set | `TestVaultResolution::test_plaintext_http_vault_addr_refused` |
| 24 | a space in a sentinel path fails cleanly (InvalidURL caught, no traceback) | `TestVaultResolution::test_sentinel_path_with_space_fails_clean` |
| 25 | a non-dict Vault payload fails as a malformed response | `TestVaultResolution::test_nondict_payload_is_malformed_response` |
| 26 | wrong-shape 200 envelopes (string data / bare list) fail cleanly | `TestVaultResolution::test_wrong_shape_envelopes_fail_clean` (parametrized: badshape / listshape) |
| 27 | a newline-containing resolved value is rejected (value never leaked) | `TestVaultResolution::test_newline_resolved_value_rejected` |
| 28 | a failing path is read once (per-path failure caching) | `TestVaultResolution::test_failing_path_read_once` + `::test_failure_cache_pinned_directly` (the falsifiable pin; it was briefly misfiled under "Beyond parity" — it strengthens this row's checkpoint) |
| 29 | credentials without VAULT_ADDR fail loudly (no default address) | `TestVaultResolution::test_credentials_without_vault_addr_fail` |
| 30 | active sentinels without credentials hard-fail (escape hatch named) | `TestVaultResolution::test_active_sentinels_without_credentials_hard_fail` |
| 31 | non-active sentinels without credentials stay literal (knob unset) | `TestVaultResolution::test_non_active_sentinels_without_credentials_stay_literal` |
| 32 | strict knob requires credentials for any sentinel | `TestVaultResolution::test_strict_knob_requires_credentials` |
| 33 | strict knob does not widen the resolution scope | `TestVaultResolution::test_strict_knob_does_not_widen_scope` |
| 34 | strict mode requires usable credentials (address present) | `TestVaultResolution::test_strict_mode_requires_usable_credentials` |
| 35 | sentinel-free base identical with credentials + strict set (resolver inert) | `TestVaultResolution::test_sentinel_free_base_inert_with_credentials` |
| 36 | no base/tmp staging leftovers in the selftest workdir | `TestVaultResolution::test_no_staging_leftovers` + `::test_no_staging_leftovers_on_failed_run` (failed-run variant) |
| 37 | legacy KUBEVIRT_TOKEN survives regeneration | `TestAliasesAndWarnings::test_legacy_kubevirt_token_survives_regeneration` |
| 38 | VIRTWHO_KUBEVIRT_TOKEN wins over the legacy alias | `TestAliasesAndWarnings::test_new_kubevirt_token_name_wins` |
| 39 | misspelled VIRTWHO_* option warns on stderr; clean run stays silent | `TestAliasesAndWarnings::test_misspelled_option_warns` + `::test_clean_run_stays_warning_free` |
| 40 | VIRTWHO_JOB_HYPERVISOR wins when the plan-level HYPERVISOR is unset | `TestAliasesAndWarnings::test_job_hypervisor_alias_wins_when_plan_level_unset` |
| 41 | the promoted VIRTWHO_JOB_HYPERVISOR feeds the hypervisor section ([libvirt] emitted) | `TestAliasesAndWarnings::test_job_hypervisor_alias_feeds_section_creation` |
| 42 | VIRTWHO_JOB_HYPERVISOR is lower-cased (no spurious shadow warning) | `TestAliasesAndWarnings::test_job_hypervisor_alias_lowercased` |
| 43 | VIRTWHO_JOB_REGISTER wins over the rhsm default | `TestAliasesAndWarnings::test_job_register_alias_wins_over_rhsm_default` |
| 44 | VIRTWHO_JOB_RHEL_COMPOSE wins when the plan-level RHEL_COMPOSE is unset | `TestAliasesAndWarnings::test_job_rhel_compose_alias_wins` |
| 45 | a set plan-level HYPERVISOR wins over VIRTWHO_JOB_HYPERVISOR; the warning names the winner | `TestAliasesAndWarnings::test_plan_level_hypervisor_shadows_alias` |
| 46 | an ESX/VCENTER clash warns on stderr and VIRTWHO_ESX_* wins | `TestAliasesAndWarnings::test_esx_vcenter_clash_warns_esx_wins` |
| 47 | cp -a preserves the symlink (bootc copy path) | `TestSingleMaterialization::test_cp_a_preserves_symlink` |
| 48 | configparser writes through the symlink to the tmpfs target | `TestSingleMaterialization::test_configparser_writes_through_symlink` |
| 49 | generator writes through a symlinked OUTPUT (link preserved) | `TestSingleMaterialization::test_generator_writes_through_symlinked_output` |
| 50 | public key derived next to the tmpfs key | `TestSshConfig::test_public_key_derived_next_to_tmpfs_key` |
| 51 | ssh -G resolves the tmpfs IdentityFile entry | `TestSshConfig::test_ssh_g_resolves_tmpfs_identity_file` |
| 52 | ini-configured kubeconfig path under /root is shredded; a path outside it is refused with a warning | `TestCleanupSecrets::test_ini_kubeconfig_confined_shredded_outside_refused` |
| 53 | cleanup shreds the /etc/virt-who.d uploads (suffixed/hidden variants + keytab) and the /root/test_cli_config.conf copy; a non-matching file survives | `TestCleanupSecrets::test_etc_virtwho_d_uploads_shredded` + `::test_root_test_cli_copy_shredded` |
| 54 | cleanup shreds the upgrade tests' /tmp config copies (sysconfig copy survives) | `TestCleanupSecrets::test_tmp_upgrade_copies_shredded` |
| 55 | the virt-who.d sweep is case-insensitive and unlinks dangling symlinks | `TestCleanupSecrets::test_sweep_case_insensitive_and_dangling_links` |
| 56 | real cleanup-secrets.sh full sweep (tmpfs + kubeconfigs + temp/ + legacy ini + ssh_config entry) | `TestCleanupSecrets::test_tmpfs_originals_and_staging_shredded` + `::test_tree_dirs_swept` + `::test_ssh_config_entry_removed_anchored` |
| 57 | prepare-kubevirt.sh writes the confined kubeconfig 0600 and refuses an out-of-root no-cert copy | `TestPrepareKubevirt::test_confined_write_and_no_cert_refusal` |
| 58 | prepare-kubevirt.sh refuses an out-of-root kubeconfig path | `TestPrepareKubevirt::test_main_config_outside_root_refused` |
| 59 | prepare-kubevirt.sh warns and skips the guest proxy when the password is unset or an unresolved sentinel | `TestPrepareKubevirt::test_guest_password_has_no_default` (ids: empty / sentinel) |
| 60 | write side and shred side honor the SAME VIRTWHO_KUBECONFIG_ROOT knob | `TestPrepareKubevirt::test_write_and_shred_share_one_knob` |
| 61 | a trailing slash on VIRTWHO_KUBECONFIG_ROOT is canonicalized on both sides | `TestPrepareKubevirt::test_trailing_slash_on_knob_canonicalized` |
| 62 | wrapper scripts carry no password/image defaults (env-or-random flow, env-var squid image) | `TestWrapperContracts::test_no_password_or_image_defaults` |
| 63 | install-deps.sh skips the squid pre-pull with a message when VIRTWHO_SQUID_IMAGE is unset (and pulls when set) | `TestWrapperContracts::test_install_deps_squid_pre_pull` |
| 64 | the Polarion URL comes from POLARION_URL at all three sites (no internal host in the tree) | `TestWrapperContracts::test_polarion_url_env_delivered` |
| 65 | the real run-tests.sh ini merge fills [virtwho] password from the per-run environment only | `TestWrapperContracts::test_run_tests_ini_merge_password_flow` (the REAL heredoc extracted and executed) |
| 66 | (python-side checkpoint) env-only configparser parse and section/option assertions passed | `TestEnvOnlyGeneration::test_core_sections_always_emitted`, `::test_active_and_env_backed_sections_emitted`, `::test_sections_without_env_vars_omitted`, `::test_env_values_land_in_sections`, `::test_required_options_exist` (all parametrized) |
| 67 | (python-side checkpoint) vault_resolve sentinel helpers behave | `TestVaultResolution::test_vault_resolve_sentinel_helpers` — refiled here from "Beyond parity": an old checkpoint |

## test-discover-guest-ips.sh → test_discover_guest_ips.py

| # | Old bash checkpoint (`OK:` line) | New pytest test(s) |
|---|---|---|
| 1 | libvirt guest_ip discovered via the sshpass fallback (loopback excluded) | `TestDiscoveryParsing::test_libvirt_sshpass_fallback_loopback_excluded` |
| 2 | libvirt guest_ip discovered via key-based ssh | `TestDiscoveryParsing::test_libvirt_key_based_ssh` |
| 3 | arp fallback used when the guest agent reports nothing | `TestDiscoveryParsing::test_libvirt_arp_fallback` |
| 4 | hyperv guest_ip discovered (IPv4 preferred over IPv6) | `TestDiscoveryParsing::test_hyperv_powershell_ipv4_preferred` |
| 5 | ahv guest_ip discovered from the Prism response | `TestDiscoveryParsing::test_ahv_prism_json_exact_match_empty_skipped` |
| 6 | failed discovery keeps the ini value, exits 0 and warns on stderr | `TestDiscoveryGates::test_failed_discovery_keeps_ini_and_warns` (ids: curl-fail / ssh-down) |
| 7 | unsupported hypervisor is a no-op | `TestDiscoveryGates::test_unsupported_hypervisor_is_noop` |
| 8 | missing ini file fails loudly | `TestDiscoveryGates::test_missing_ini_fails_loudly` |
| 9 | update written through a symlink, mode 0600 preserved | `TestWriteBack::test_write_through_symlink_mode_preserved` |
| 10 | a quoted guest_name is remote DATA, never remote code (no execution; stdin) | `TestInjectionChecks::test_libvirt_guest_name_is_data_not_code` |
| 11 | the hyperv PowerShell query receives the guest name as stdin data (fixed command, exact-name post-filter) | `TestInjectionChecks::test_hyperv_guest_name_is_data_not_code` |
| 12 | the ahv query percent-encodes the guest_name (no raw splicing) | `TestInjectionChecks::test_ahv_guest_name_percent_encoded` |
| 13 | ahv credentials travel on curl's stdin config stream, never the command line | `TestInjectionChecks::test_ahv_credentials_on_stdin_config_stream` |
| 14 | configparser-valid 'key = value' spacing is parsed (inner-space value survives) | `TestWriteBack::test_configparser_spacing_parsed` |
| 15 | hyperv discovery never attempts ssh with an empty password | `TestDiscoveryGates::test_hyperv_empty_password_skips_ssh` |
| 16 | VIRTWHO_SKIP_IP_DISCOVERY=1 keeps the ini guest_ip and logs the skip | `TestDiscoveryGates::test_skip_knob_keeps_ini_value` |
| 17 | overwriting a differing non-empty ini guest_ip emits a WARNING naming both values | `TestDiscoveryGates::test_overwrite_warning_names_both_values` |
| 18 | a malformed ini makes the write-back a clean warning (ini kept, exit 0) | `TestWriteBack::test_malformed_ini_writeback_is_warning` |
| 19 | run-tests.sh turns a failed discovery into a warning (ini fallback) | `TestRunTestsGuard::test_discovery_invocation_is_guarded` |

## Beyond parity (new-in-pytest cases, no old checkpoint)

The conversion also added cases the bash suite never had — each one
closes a gap found during the conversion reviews. (Rows 20a, 28, 36
and 66–67 above were originally misfiled here; they map to old
checkpoints and have been refiled into their proper rows. The
remaining entries below are genuinely new.)

- `TestVaultResolution::test_no_staging_leftovers_on_failed_run` —
  the failed-run twin of row 36's staging-hygiene checkpoint
  (strengthening only: the bash suite checked a shared workdir after
  successes).
- `TestDiscoveryParsing::test_qemu_ssh_uri_normalized_to_bare_host` —
  the qemu+ssh:// URI normalization.
- `TestDiscoveryGates::test_same_value_discovery_no_overwrite_warning`
  — an agreeing discovery emits no spurious warning.
- `TestDiscoveryGates::test_ahv_newline_credential_named_warning` —
  the newline-in-ahv-credential named rejection (value never leaked).
- `TestPrepareKubevirt::test_spaced_ini_still_writes_kubeconfig` —
  `key = value` spacing flows through the configparser read.
- `TestPrepareKubevirt::test_dotdot_path_not_confined` — a
  `/root/../` path is ruled out by the per-path canonicalization.
- `TestVaultRetry` — the resolver's bounded connection-level retry
  (4 resets then success = 5 attempts, the #180 burst class; an HTTP
  403 is never retried; exhausted retries fail loudly after exactly
  5 attempts).
- `TestProxyBypass` / `TestReadinessUnderHostileProxy`
  (test_prepare_candlepin.py) and `TestGuestProbeCommand::
  test_bypass_proxy_*` (test_guest_reachability.py) — the build-#179
  proxy-bypass contract: every curl in prepare-candlepin.sh carries
  the per-command `--noproxy` (source- and stub-log-pinned), the
  script never touches the proxy environment (external egress keeps
  it), and the REAL readiness segment still passes against a real
  local TLS stand-in with HTTPS_PROXY pointed at an unreachable
  proxy — the exact #179 failure shape, hermetically.
- `TestScaActivation` (test_prepare_candlepin.py) — the run-#6
  register gap: prepare-candlepin.sh ACTIVATES Simple Content Access
  on the baked org (a PUT /owners/{org} with the tier's register
  credentials riding curl's stdin config, rhsm-qe's
  setContentAccesModeBeforeSuite shape) and STRICTLY re-verifies the
  org's ACTIVE mode with a fresh read before the marker; the curl
  stub models the org as stateful (baked entitlement-active, flipped
  by a successful PUT) like a real server. Pins the PUT shape
  (never on argv, exact org_environment payload, fired only after
  the contract probe passed) and every failure path (PUT refused,
  re-read failure, and the ACTIVE mode still entitlement after a
  200 — the contains-vs-active asymmetry itself) as loud skips with
  no marker and a torn-down pod.
- `test_proxy_bypass.py` — the suite-side wiring of the same
  contract: run-tests.sh's container-mode `no_proxy` export (before
  pytest, exactly the pod hosts), configure-proxy.sh's container
  -tier skip of the rhsm.conf proxy (exercised against the real
  script with a stubbed subscription-manager; stage mode still
  configures it), the kubevirt guest-proxy tier gate and the
  test_default.py guestids-curl bypass (source-level pins).

The mutation battery (`mutation-checks.sh`, next to this file) is
the executable counterpart of this table: it proves the suite
actually catches regressions in the behaviors the checkpoints
encode.
