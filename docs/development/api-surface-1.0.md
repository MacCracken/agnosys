# Agnosys 1.0 API Surface

> Frozen at **1.0.0** (2026-04-17). The 1.0 baseline (556 fns) is the stable contract: removal or signature change of any 1.0-era fn requires a 2.0 bump. Post-1.0 additions (V1.1.x → V1.2.x) are listed inline below; all are additive.
>
> **Auto-generated** from `docs/development/api-surface-1.0.snapshot` + source-comment extraction by `scripts/gen-api-surface-prose.sh`. To regenerate: `scripts/gen-api-surface-prose.sh`. The audit gate (`stage 2/11 "API surface"`) verifies the snapshot stays in sync with the source.


## Summary

- Total public functions: **730**
- Modules: **23**
- 1.0 baseline (frozen): 556 fns
- Post-1.0 additions (V1.1 + V1.2 cycles): 174 fns
- Outliers (fns lacking module prefix): 0


## By module


### `audit` (src/audit.cyr)

- `audit_add_rule(arg1, arg2)` → (no behavioral docs)
- `audit_agnos_log(arg1, arg2, arg3)` → (no behavioral docs)
- `audit_build_nlmsg(arg1, arg2, arg3)` → (no behavioral docs)
- `audit_close(arg)` → (no behavioral docs)
- `audit_config_new()` → (no behavioral docs)
- `audit_config_proc_path(arg)` → (no behavioral docs)
- `audit_config_set_netlink(arg1, arg2)` → 1.0 API preservation — asymmetric setter names delegate to derive.
- `audit_config_set_proc(arg1, arg2)` → (no behavioral docs)
- `audit_config_set_proc_path(arg1, arg2)` → (no behavioral docs)
- `audit_config_set_use_netlink(arg1, arg2)` → (no behavioral docs)
- `audit_config_set_use_proc(arg1, arg2)` → (no behavioral docs)
- `audit_config_use_netlink(arg)` → (no behavioral docs)
- `audit_config_use_proc(arg)` → (no behavioral docs)
- `audit_delete_rule(arg1, arg2)` → (no behavioral docs)
- `audit_get_status(arg)` → (no behavioral docs)
- `audit_handle_config(arg)` → (no behavioral docs)
- `audit_handle_fd(arg)` → (no behavioral docs)
- `audit_handle_new(arg1, arg2)` → (no behavioral docs)
- `audit_handle_set_config(arg1, arg2)` → (no behavioral docs)
- `audit_handle_set_fd(arg1, arg2)` → (no behavioral docs)
- `audit_nlmsg_len(arg)` → Get total length of a built nlmsg (read from the header)
- `audit_open(arg)` → (no behavioral docs)
- `audit_read_proc_events(arg)` → (no behavioral docs)
- `audit_recv_raw(arg1, arg2, arg3)` → (no behavioral docs)
- `audit_rule_file_watch(arg1, arg2)` → Create a file watch rule
- `audit_rule_key(arg)` → (no behavioral docs)
- `audit_rule_new(arg1, arg2, arg3, arg4)` → (no behavioral docs)
- `audit_rule_path(arg)` → (no behavioral docs)
- `audit_rule_set_key(arg1, arg2)` → (no behavioral docs)
- `audit_rule_set_path(arg1, arg2)` → (no behavioral docs)
- `audit_rule_set_syscall_nr(arg1, arg2)` → (no behavioral docs)
- `audit_rule_set_type(arg1, arg2)` → (no behavioral docs)
- `audit_rule_syscall(arg)` → 1.0 API preservation — `syscall` getter delegates to `syscall_nr`.
- `audit_rule_syscall_nr(arg)` → (no behavioral docs)
- `audit_rule_syscall_watch(arg1, arg2)` → Create a syscall watch rule
- `audit_rule_type(arg)` → (no behavioral docs)
- `audit_rule_validate(arg)` → (no behavioral docs)
- `audit_send_event(arg1, arg2, arg3)` → (no behavioral docs)
- `audit_send_raw(arg1, arg2, arg3)` → (no behavioral docs)
- `audit_send_rule_msg(arg1, arg2, arg3)` → (no behavioral docs)
- `audit_set_enabled(arg1, arg2)` → (no behavioral docs)
- `audit_sockaddr_nl(arg)` → (no behavioral docs)
- `audit_status_backlog(arg)` → (no behavioral docs)
- `audit_status_backlog_limit(arg)` → (no behavioral docs)
- `audit_status_enabled(arg)` → (no behavioral docs)
- `audit_status_failure_action(arg)` → (no behavioral docs)
- `audit_status_from_json(arg)` → (no behavioral docs)
- `audit_status_lost(arg)` → (no behavioral docs)
- `audit_status_new()` → (no behavioral docs)
- `audit_status_pid(arg)` → (no behavioral docs)
- `audit_status_set_backlog(arg1, arg2)` → (no behavioral docs)
- `audit_status_set_backlog_limit(arg1, arg2)` → (no behavioral docs)
- `audit_status_set_enabled(arg1, arg2)` → (no behavioral docs)
- `audit_status_set_failure_action(arg1, arg2)` → (no behavioral docs)
- `audit_status_set_lost(arg1, arg2)` → (no behavioral docs)
- `audit_status_set_pid(arg1, arg2)` → (no behavioral docs)
- `audit_status_to_json(arg)` → (no behavioral docs)

### `bootloader` (src/bootloader.cyr)

- `bootloader_config_default_id(arg)` → (no behavioral docs)
- `bootloader_config_entries(arg)` → 1.0 API preservation — `entries` getter + 3-arg `set_entries` delegate through the derive-generat...
- `bootloader_config_entries_arr(arg)` → (no behavioral docs)
- `bootloader_config_entry_count(arg)` → (no behavioral docs)
- `bootloader_config_new()` → (no behavioral docs)
- `bootloader_config_set_default_id(arg1, arg2)` → (no behavioral docs)
- `bootloader_config_set_entries(arg1, arg2, arg3)` → (no behavioral docs)
- `bootloader_config_set_entries_arr(arg1, arg2)` → (no behavioral docs)
- `bootloader_config_set_entry_count(arg1, arg2)` → (no behavioral docs)
- `bootloader_config_set_timeout(arg1, arg2)` → (no behavioral docs)
- `bootloader_config_set_type(arg1, arg2)` → (no behavioral docs)
- `bootloader_config_timeout(arg)` → (no behavioral docs)
- `bootloader_config_type(arg)` → (no behavioral docs)
- `bootloader_danger_reset()` → (no behavioral docs)
- `bootloader_detect()` → Detect the installed bootloader by probing well-known paths. Returns Result: Ok(BootloaderType co...
- `bootloader_entry_id(arg)` → (no behavioral docs)
- `bootloader_entry_initrd(arg)` → (no behavioral docs)
- `bootloader_entry_is_default(arg)` → (no behavioral docs)
- `bootloader_entry_linux(arg)` → (no behavioral docs)
- `bootloader_entry_new()` → (no behavioral docs)
- `bootloader_entry_options(arg)` → (no behavioral docs)
- `bootloader_entry_set_id(arg1, arg2)` → (no behavioral docs)
- `bootloader_entry_set_initrd(arg1, arg2)` → (no behavioral docs)
- `bootloader_entry_set_is_default(arg1, arg2)` → (no behavioral docs)
- `bootloader_entry_set_linux(arg1, arg2)` → (no behavioral docs)
- `bootloader_entry_set_options(arg1, arg2)` → (no behavioral docs)
- `bootloader_entry_set_title(arg1, arg2)` → (no behavioral docs)
- `bootloader_entry_set_version(arg1, arg2)` → (no behavioral docs)
- `bootloader_entry_title(arg)` → (no behavioral docs)
- `bootloader_entry_version(arg)` → (no behavioral docs)
- `bootloader_extract_value(arg1, arg2, arg3)` → Extract the value after a key in a line (trim whitespace). Returns heap string pointer.
- `bootloader_is_dangerous_token(arg1, arg2, arg3)` → (no behavioral docs)
- `bootloader_line_starts_with(arg1, arg2, arg3)` → Helper: check if line starts with prefix (skipping leading whitespace)
- `bootloader_list_boot_entries(arg1, arg2)` → List boot entries using bootctl or by reading loader entries. result_arr: pre-allocated array of ...
- `bootloader_parse_bootctl_list(arg1, arg2, arg3)` → Parse bootctl list output (simplified). Each entry block starts with a line containing "title:" o...
- `bootloader_parse_loader_conf(arg)` → Parse loader.conf file contents. Returns { timeout, default_id } as a 16-byte struct.
- `bootloader_type_str(arg)` → Bootloader type to string.
- `bootloader_validate_kernel_cmdline(arg)` → Validate kernel command-line parameters. Returns Result: Ok(0) if valid, Err if dangerous or malf...

### `certpin` (src/certpin.cyr)

- `certpin_check_pin_expiry(arg1, arg2)` → Check pin expiry against current time. Returns 1 if expired, 0 if not expired or no expiry set.
- `certpin_compute_spki_pin(arg)` → Compute the SPKI SHA-256 pin for a PEM certificate file on disk. cert_path: path to a PEM-encoded...
- `certpin_ct_streq(arg1, arg2)` → Constant-time cstring comparison to prevent timing side-channels. Returns 1 if equal, 0 otherwise...
- `certpin_entry_backup_count(arg)` → (no behavioral docs)
- `certpin_entry_backups(arg)` → (no behavioral docs)
- `certpin_entry_backups_arr(arg)` → (no behavioral docs)
- `certpin_entry_expires(arg)` → (no behavioral docs)
- `certpin_entry_host(arg)` → (no behavioral docs)
- `certpin_entry_new(arg1, arg2)` → (no behavioral docs)
- `certpin_entry_pin_count(arg)` → (no behavioral docs)
- `certpin_entry_pins(arg)` → 1.0 API preservation — `pins`/`backups` getters + 3-arg `set_pins`/`set_backups` setters delegate...
- `certpin_entry_pins_arr(arg)` → (no behavioral docs)
- `certpin_entry_set_backup_count(arg1, arg2)` → (no behavioral docs)
- `certpin_entry_set_backups(arg1, arg2, arg3)` → (no behavioral docs)
- `certpin_entry_set_backups_arr(arg1, arg2)` → (no behavioral docs)
- `certpin_entry_set_expires(arg1, arg2)` → (no behavioral docs)
- `certpin_entry_set_host(arg1, arg2)` → (no behavioral docs)
- `certpin_entry_set_pin_count(arg1, arg2)` → (no behavioral docs)
- `certpin_entry_set_pins(arg1, arg2, arg3)` → (no behavioral docs)
- `certpin_entry_set_pins_arr(arg1, arg2)` → (no behavioral docs)
- `certpin_find_entry(arg1, arg2)` → Find the pin entry for a given host in the pin set. Returns entry pointer or 0 if not found.
- `certpin_info_issuer(arg)` → (no behavioral docs)
- `certpin_info_new()` → (no behavioral docs)
- `certpin_info_not_after(arg)` → (no behavioral docs)
- `certpin_info_not_before(arg)` → (no behavioral docs)
- `certpin_info_serial(arg)` → (no behavioral docs)
- `certpin_info_set_issuer(arg1, arg2)` → (no behavioral docs)
- `certpin_info_set_not_after(arg1, arg2)` → (no behavioral docs)
- `certpin_info_set_not_before(arg1, arg2)` → (no behavioral docs)
- `certpin_info_set_serial(arg1, arg2)` → (no behavioral docs)
- `certpin_info_set_sha256_fp(arg1, arg2)` → (no behavioral docs)
- `certpin_info_set_spki_sha256(arg1, arg2)` → (no behavioral docs)
- `certpin_info_set_subject(arg1, arg2)` → (no behavioral docs)
- `certpin_info_sha256_fp(arg)` → (no behavioral docs)
- `certpin_info_spki_sha256(arg)` → (no behavioral docs)
- `certpin_info_subject(arg)` → (no behavioral docs)
- `certpin_info_to_json(arg1, arg2)` → Hand-rolled JSON serializer (cstring-pointer fields not yet supported by cyrius #derive(Serialize)).
- `certpin_set_count(arg)` → (no behavioral docs)
- `certpin_set_enforce(arg)` → (no behavioral docs)
- `certpin_set_entries(arg)` → 1.0 API preservation
- `certpin_set_entries_arr(arg)` → (no behavioral docs)
- `certpin_set_new(arg)` → (no behavioral docs)
- `certpin_set_set_count(arg1, arg2)` → (no behavioral docs)
- `certpin_set_set_enforce(arg1, arg2)` → (no behavioral docs)
- `certpin_set_set_entries(arg1, arg2, arg3)` → (no behavioral docs)
- `certpin_set_set_entries_arr(arg1, arg2)` → (no behavioral docs)
- `certpin_validate_pin_format(arg)` → Validate a base64-encoded SHA-256 pin string. A valid pin is 44 characters of base64 (32 bytes ->...
- `certpin_verify_pin(arg1, arg2, arg3, arg4)` → Verify a certificate pin against a pin set. actual_pin: the base64-encoded SPKI SHA-256 hash from...

### `dmverity` (src/dmverity.cyr)

- `dmverity_close(arg)` → Close (deactivate) a dm-verity volume. name: volume mapping name. Returns Ok(0) or Err.
- `dmverity_config_alloc()` → (no behavioral docs)
- `dmverity_config_data_block_size(arg)` → (no behavioral docs)
- `dmverity_config_data_device(arg)` → (no behavioral docs)
- `dmverity_config_hash_algorithm(arg)` → (no behavioral docs)
- `dmverity_config_hash_block_size(arg)` → (no behavioral docs)
- `dmverity_config_hash_device(arg)` → (no behavioral docs)
- `dmverity_config_name(arg)` → (no behavioral docs)
- `dmverity_config_root_hash(arg)` → (no behavioral docs)
- `dmverity_config_salt(arg)` → (no behavioral docs)
- `dmverity_config_set_data_block_size(arg1, arg2)` → (no behavioral docs)
- `dmverity_config_set_data_device(arg1, arg2)` → (no behavioral docs)
- `dmverity_config_set_devices(arg1, arg2, arg3, arg4)` → (no behavioral docs)
- `dmverity_config_set_hash_algorithm(arg1, arg2)` → (no behavioral docs)
- `dmverity_config_set_hash_block_size(arg1, arg2)` → (no behavioral docs)
- `dmverity_config_set_hash_device(arg1, arg2)` → (no behavioral docs)
- `dmverity_config_set_name(arg1, arg2)` → (no behavioral docs)
- `dmverity_config_set_params(arg1, arg2, arg3, arg4, arg5, arg6)` → (no behavioral docs)
- `dmverity_config_set_root_hash(arg1, arg2)` → (no behavioral docs)
- `dmverity_config_set_salt(arg1, arg2)` → (no behavioral docs)
- `dmverity_config_validate(arg)` → Validate a VerityConfig. Returns Ok(0) or Err.
- `dmverity_format(arg1, arg2, arg3, arg4)` → Format a data device for dm-verity, generating the hash tree. Returns Ok(root_hash_ptr) — the com...
- `dmverity_hash_algo_str(arg)` → (no behavioral docs)
- `dmverity_hash_hex_len(arg)` → (no behavioral docs)
- `dmverity_is_hex_char(arg)` → Check if a byte is a valid hex character
- `dmverity_is_name_char(arg)` → Check if a byte is valid for a dm name (alphanum, dash, underscore)
- `dmverity_open(arg)` → Open (activate) a dm-verity volume. Creates a read-only device mapping at /dev/mapper/{name}. Ret...
- `dmverity_run_capture(arg1, arg2, arg3)` → (no behavioral docs)
- `dmverity_run_checked(arg)` → (no behavioral docs)
- `dmverity_status(arg)` → Query the status of a dm-verity volume. Returns Ok(verity_status_ptr) or Err.
- `dmverity_status_corruption_detected(arg)` → (no behavioral docs)
- `dmverity_status_is_active(arg)` → (no behavioral docs)
- `dmverity_status_is_verified(arg)` → (no behavioral docs)
- `dmverity_status_name(arg)` → (no behavioral docs)
- `dmverity_status_new(arg1, arg2, arg3, arg4, arg5)` → (no behavioral docs)
- `dmverity_status_root_hash(arg)` → (no behavioral docs)
- `dmverity_status_set_corruption_detected(arg1, arg2)` → (no behavioral docs)
- `dmverity_status_set_is_active(arg1, arg2)` → (no behavioral docs)
- `dmverity_status_set_is_verified(arg1, arg2)` → (no behavioral docs)
- `dmverity_status_set_name(arg1, arg2)` → (no behavioral docs)
- `dmverity_status_set_root_hash(arg1, arg2)` → (no behavioral docs)
- `dmverity_status_to_json(arg1, arg2)` → Hand-rolled JSON serializer (mirrors #derive(Serialize) shape; replace when cyrius cstring-pointe...
- `dmverity_supported()` → Check if dm-verity is supported on this system. Returns 1 if supported, 0 if not.
- `dmverity_validate_hex(arg1, arg2)` → Validate a hex string. Returns Ok(0) or Err.
- `dmverity_validate_root_hash(arg1, arg2)` → Validate a root hash: correct length for algorithm, all hex. Returns Ok(0) or Err.
- `dmverity_verify(arg1, arg2, arg3)` → Verify a dm-verity volume without activating it. Returns Ok(1) if valid, Ok(0) if failed.

### `drm` (src/drm.cyr)

- `drm_close(arg)` → Close a DRM device fd.
- `drm_get_capability(arg1, arg2)` → Query a DRM capability value for an open device fd. cap: one of the DRM_CAP_* constants. Returns ...
- `drm_get_driver_version(arg)` → Get the DRM driver version for an open device fd. Returns Result: Ok(drm_verinfo_ptr) or Err.
- `drm_list_devices(arg1, arg2)` → List DRM card device paths under /dev/dri/. result_arr: pre-allocated array of string pointers. m...
- `drm_open(arg)` → Open a DRM device by path. Returns Result: Ok(fd) or Err.
- `drm_supports_dumb_buffer(arg)` → Check if device supports dumb buffers. Returns Result: Ok(1) or Ok(0).
- `drm_verinfo_date(arg)` → (no behavioral docs)
- `drm_verinfo_desc(arg)` → (no behavioral docs)
- `drm_verinfo_major(arg)` → (no behavioral docs)
- `drm_verinfo_minor(arg)` → (no behavioral docs)
- `drm_verinfo_name(arg)` → (no behavioral docs)
- `drm_verinfo_new(arg1, arg2, arg3, arg4, arg5, arg6)` → (no behavioral docs)
- `drm_verinfo_patch(arg)` → (no behavioral docs)
- `drm_verinfo_set_date(arg1, arg2)` → (no behavioral docs)
- `drm_verinfo_set_desc(arg1, arg2)` → (no behavioral docs)
- `drm_verinfo_set_major(arg1, arg2)` → (no behavioral docs)
- `drm_verinfo_set_minor(arg1, arg2)` → (no behavioral docs)
- `drm_verinfo_set_name(arg1, arg2)` → (no behavioral docs)
- `drm_verinfo_set_patch(arg1, arg2)` → (no behavioral docs)
- `drm_verinfo_to_json(arg1, arg2)` → Hand-rolled JSON serializer (cstring-pointer fields not yet supported by cyrius #derive(Serialize)).

### `error` (src/error.cyr)

- `err_from_errno(arg)` → (no behavioral docs)
- `err_from_syscall_ret(arg)` → (no behavioral docs)
- `err_invalid_argument(arg)` → (no behavioral docs)
- `err_invalid_argument_nr()` → (no behavioral docs)
- `err_io(arg1, arg2)` → (no behavioral docs)
- `err_module_not_loaded(arg)` → (no behavioral docs)
- `err_not_supported(arg)` → (no behavioral docs)
- `err_not_supported_nr()` → (no behavioral docs)
- `err_permission_denied(arg)` → (no behavioral docs)
- `err_permission_denied_nr(arg)` → (no behavioral docs)
- `err_syscall_failed(arg1, arg2)` → (no behavioral docs)
- `err_syscall_failed_nr(arg)` → (no behavioral docs)
- `err_unknown(arg)` → (no behavioral docs)
- `err_would_block()` → (no behavioral docs)
- `is_syscall_err(arg)` → Check if a syscall return value indicates error (negative = errno)
- `result_print_err(arg)` → Print error from a Result if it's Err, then return the error code. Returns 0 if the Result is Ok.
- `syserr_errno(arg)` → Get errno value (works for both packed and heap errors)
- `syserr_kind(arg)` → Get error kind (works for both packed and heap errors)
- `syserr_message(arg)` → Get error message pointer (0 for packed errors)
- `syserr_new(arg1, arg2, arg3)` → Create a new error with message (heap-allocated, cold path)
- `syserr_pack(arg1, arg2)` → Pack kind + errno into a single integer (zero allocation)
- `syserr_print(arg)` → (no behavioral docs)
- `wrap_syscall(arg)` → Wrap a raw syscall return: Ok(ret) if >= 0, Err(from_errno) if < 0

### `fuse` (src/fuse.cyr)

- `fuse_extract_field(arg1, arg2, arg3)` → Extract a whitespace-delimited field from a line. field_idx: 0-based field index. Returns heap-al...
- `fuse_get_status(arg)` → Get the status of a FUSE mount at the given mountpoint. Returns Result: Ok(FuseStatus) or Err.
- `fuse_is_available()` → Check whether FUSE is available on this system (/dev/fuse exists). Returns 1 if available, 0 othe...
- `fuse_list_mounts()` → List all currently mounted FUSE filesystems. Returns Result: Ok(vec_of_mounts) or Err.
- `fuse_mount(arg1, arg2, arg3, arg4)` → Mount a FUSE filesystem. device: the FUSE filesystem source (e.g., sshfs#user@host:path). mountpo...
- `fuse_mount_device(arg)` → (no behavioral docs)
- `fuse_mount_fstype(arg)` → (no behavioral docs)
- `fuse_mount_mountpoint(arg)` → (no behavioral docs)
- `fuse_mount_new(arg1, arg2, arg3, arg4)` → (no behavioral docs)
- `fuse_mount_options(arg)` → (no behavioral docs)
- `fuse_mount_set_device(arg1, arg2)` → (no behavioral docs)
- `fuse_mount_set_fstype(arg1, arg2)` → (no behavioral docs)
- `fuse_mount_set_mountpoint(arg1, arg2)` → (no behavioral docs)
- `fuse_mount_set_options(arg1, arg2)` → (no behavioral docs)
- `fuse_parse_proc_mounts(arg1, arg2, arg3)` → Parse /proc/mounts and return FUSE mounts. result_arr: pre-allocated array of FuseMount pointers....
- `fuse_starts_with(arg1, arg2)` → Check if a string starts with a prefix.
- `fuse_unmount(arg)` → Unmount a FUSE filesystem at the given mountpoint. Returns Result: Ok(0) or Err.
- `fuse_unmount_lazy(arg)` → Lazy unmount via fusermount -uz (for busy mounts).
- `fuse_validate_mountpoint(arg)` → Validate that a path is suitable as a FUSE mountpoint. Checks: not null, not root, exists, is a d...

### `ima` (src/ima.cyr)

- `ima_action_str(arg)` → (no behavioral docs)
- `ima_get_status()` → (no behavioral docs)
- `ima_is_hex_char(arg)` → (no behavioral docs)
- `ima_measurement_filedata_hash(arg)` → (no behavioral docs)
- `ima_measurement_filename(arg)` → (no behavioral docs)
- `ima_measurement_new(arg1, arg2, arg3, arg4, arg5)` → (no behavioral docs)
- `ima_measurement_pcr(arg)` → (no behavioral docs)
- `ima_measurement_set_filedata_hash(arg1, arg2)` → (no behavioral docs)
- `ima_measurement_set_filename(arg1, arg2)` → (no behavioral docs)
- `ima_measurement_set_pcr(arg1, arg2)` → (no behavioral docs)
- `ima_measurement_set_template_hash(arg1, arg2)` → (no behavioral docs)
- `ima_measurement_set_template_name(arg1, arg2)` → (no behavioral docs)
- `ima_measurement_template_hash(arg)` → (no behavioral docs)
- `ima_measurement_template_name(arg)` → (no behavioral docs)
- `ima_parse_measurements(arg)` → (no behavioral docs)
- `ima_read_measurements()` → (no behavioral docs)
- `ima_rule_action(arg)` → (no behavioral docs)
- `ima_rule_fowner(arg)` → (no behavioral docs)
- `ima_rule_fsuuid(arg)` → (no behavioral docs)
- `ima_rule_mask(arg)` → (no behavioral docs)
- `ima_rule_new(arg1, arg2)` → (no behavioral docs)
- `ima_rule_obj_type(arg)` → (no behavioral docs)
- `ima_rule_set_action(arg1, arg2)` → (no behavioral docs)
- `ima_rule_set_fowner(arg1, arg2)` → (no behavioral docs)
- `ima_rule_set_fsuuid(arg1, arg2)` → (no behavioral docs)
- `ima_rule_set_mask(arg1, arg2)` → (no behavioral docs)
- `ima_rule_set_obj_type(arg1, arg2)` → (no behavioral docs)
- `ima_rule_set_target(arg1, arg2)` → (no behavioral docs)
- `ima_rule_set_uid(arg1, arg2)` → (no behavioral docs)
- `ima_rule_target(arg)` → (no behavioral docs)
- `ima_rule_to_policy_line(arg)` → (no behavioral docs)
- `ima_rule_uid(arg)` → (no behavioral docs)
- `ima_rule_validate(arg)` → Validate a single rule. Returns Ok(0) or Err.
- `ima_status_active(arg)` → (no behavioral docs)
- `ima_status_from_json(arg)` → (no behavioral docs)
- `ima_status_measurement_count(arg)` → (no behavioral docs)
- `ima_status_new(arg1, arg2, arg3)` → (no behavioral docs)
- `ima_status_policy_loaded(arg)` → (no behavioral docs)
- `ima_status_set_active(arg1, arg2)` → (no behavioral docs)
- `ima_status_set_measurement_count(arg1, arg2)` → (no behavioral docs)
- `ima_status_set_policy_loaded(arg1, arg2)` → (no behavioral docs)
- `ima_status_to_json(arg)` → (no behavioral docs)
- `ima_target_str(arg)` → (no behavioral docs)
- `ima_verify_file_integrity(arg)` → (no behavioral docs)
- `ima_write_policy(arg)` → (no behavioral docs)

### `journald` (src/journald.cyr)

- `journald_debug(arg)` → Send a debug-level message to the journal.
- `journald_entry_add_field(arg1, arg2, arg3)` → Add an extra field (key-value pair) to a journal entry
- `journald_entry_field_keys(arg)` → (no behavioral docs)
- `journald_entry_field_vals(arg)` → (no behavioral docs)
- `journald_entry_message(arg)` → (no behavioral docs)
- `journald_entry_new(arg1, arg2, arg3, arg4, arg5)` → (no behavioral docs)
- `journald_entry_pid(arg)` → (no behavioral docs)
- `journald_entry_priority(arg)` → (no behavioral docs)
- `journald_entry_set_field_keys(arg1, arg2)` → (no behavioral docs)
- `journald_entry_set_field_vals(arg1, arg2)` → (no behavioral docs)
- `journald_entry_set_message(arg1, arg2)` → (no behavioral docs)
- `journald_entry_set_pid(arg1, arg2)` → (no behavioral docs)
- `journald_entry_set_priority(arg1, arg2)` → (no behavioral docs)
- `journald_entry_set_timestamp(arg1, arg2)` → (no behavioral docs)
- `journald_entry_set_unit(arg1, arg2)` → (no behavioral docs)
- `journald_entry_timestamp(arg)` → (no behavioral docs)
- `journald_entry_unit(arg)` → (no behavioral docs)
- `journald_error(arg)` → Send an error-level message to the journal.
- `journald_filter_boot(arg)` → (no behavioral docs)
- `journald_filter_grep(arg)` → (no behavioral docs)
- `journald_filter_lines(arg)` → (no behavioral docs)
- `journald_filter_new()` → (no behavioral docs)
- `journald_filter_priority(arg)` → (no behavioral docs)
- `journald_filter_set_boot(arg1, arg2)` → (no behavioral docs)
- `journald_filter_set_grep(arg1, arg2)` → (no behavioral docs)
- `journald_filter_set_lines(arg1, arg2)` → (no behavioral docs)
- `journald_filter_set_priority(arg1, arg2)` → (no behavioral docs)
- `journald_filter_set_since(arg1, arg2)` → (no behavioral docs)
- `journald_filter_set_unit(arg1, arg2)` → (no behavioral docs)
- `journald_filter_set_until(arg1, arg2)` → (no behavioral docs)
- `journald_filter_since(arg)` → (no behavioral docs)
- `journald_filter_unit(arg)` → (no behavioral docs)
- `journald_filter_until(arg)` → (no behavioral docs)
- `journald_get_unit_logs(arg1, arg2)` → Get the last `lines` journal entries for a specific systemd unit. unit_name: C string (e.g. "sshd...
- `journald_info(arg)` → Send an info-level message to the journal. message: C string. Returns Result: Ok(0) or Err.
- `journald_json_get_str(arg1, arg2)` → Minimal JSON field extraction: find a key in a JSON object string and extract the string value. R...
- `journald_make_sockaddr()` → Build a sockaddr_un pointing to /run/systemd/journal/socket. Returns pointer to the struct (110 b...
- `journald_parse_json(arg)` → Parse a single JSON line from journalctl output into a JournalEntry. Returns Result: Ok(entry_ptr...
- `journald_query(arg)` → Query the systemd journal using journalctl and parse JSON output. filter: JournalFilter pointer (...
- `journald_send(arg1, arg2, arg3)` → Send a structured log message to the journald socket. message: C string — the log message text. p...
- `journald_send_fields(arg1, arg2, arg3, arg4, arg5)` → Send a structured log with extra key-value fields. fields_keys: vec of C string pointers (field n...
- `journald_warning(arg)` → Send a warning-level message to the journal.

### `logging` (src/logging.cyr)

- `log_debug(arg)` → (no behavioral docs)
- `log_error(arg)` → (no behavioral docs)
- `log_get_level()` → (no behavioral docs)
- `log_info(arg)` → (no behavioral docs)
- `log_init_from_env()` → (no behavioral docs)
- `log_level_prefix(arg)` → (no behavioral docs)
- `log_msg(arg1, arg2)` → Log a message at the given level to stderr (fd 2). Does nothing if the current level is above the...
- `log_msg_kv(arg1, arg2, arg3, arg4)` → Log a message with a key=value context pair. Outputs: [LEVEL] message key=value
- `log_set_level(arg)` → (no behavioral docs)
- `log_trace(arg)` → (no behavioral docs)
- `log_warn(arg)` → (no behavioral docs)

### `luks` (src/luks.cyr)

- `luks_cipher_str(arg)` → (no behavioral docs)
- `luks_close(arg)` → Close (lock) a LUKS volume. Closes the dm-crypt mapping. name: volume name (string pointer). Retu...
- `luks_config_alloc()` → (no behavioral docs)
- `luks_config_backing_path(arg)` → (no behavioral docs)
- `luks_config_cipher_algo(arg)` → (no behavioral docs)
- `luks_config_cipher_mode(arg)` → (no behavioral docs)
- `luks_config_default(arg1, arg2, arg3)` → Create a default config with sensible defaults (AES-XTS, 512-bit, Argon2id)
- `luks_config_filesystem(arg)` → (no behavioral docs)
- `luks_config_key_size_bits(arg)` → (no behavioral docs)
- `luks_config_mount_point(arg)` → (no behavioral docs)
- `luks_config_name(arg)` → (no behavioral docs)
- `luks_config_pbkdf(arg)` → (no behavioral docs)
- `luks_config_set_backing_path(arg1, arg2)` → (no behavioral docs)
- `luks_config_set_cipher_algo(arg1, arg2)` → (no behavioral docs)
- `luks_config_set_cipher_mode(arg1, arg2)` → (no behavioral docs)
- `luks_config_set_core(arg1, arg2, arg3, arg4, arg5, arg6)` → (no behavioral docs)
- `luks_config_set_crypto(arg1, arg2, arg3, arg4, arg5)` → (no behavioral docs)
- `luks_config_set_filesystem(arg1, arg2)` → (no behavioral docs)
- `luks_config_set_key_size_bits(arg1, arg2)` → (no behavioral docs)
- `luks_config_set_mount_point(arg1, arg2)` → (no behavioral docs)
- `luks_config_set_name(arg1, arg2)` → (no behavioral docs)
- `luks_config_set_pbkdf(arg1, arg2)` → (no behavioral docs)
- `luks_config_set_size_mb(arg1, arg2)` → (no behavioral docs)
- `luks_config_size_mb(arg)` → (no behavioral docs)
- `luks_config_validate(arg)` → Validate a LuksConfig. Returns Ok(0) or Err.
- `luks_format(arg1, arg2, arg3)` → Format a LUKS2 encrypted volume. Steps: 1) fallocate backing file 2) losetup 3) cryptsetup luksFo...
- `luks_fs_as_str(arg)` → (no behavioral docs)
- `luks_fs_mkfs_cmd(arg)` → (no behavioral docs)
- `luks_generate_key(arg)` → Generate a random key of `size` bytes. Returns Ok(ptr) or Err. The returned pointer points to `si...
- `luks_is_name_char(arg)` → Check if a byte is alphanumeric, dash, or underscore
- `luks_keyfile_path()` → Build a per-PID keyfile path with 8 random bytes appended. Audit F-3 (2026-04-26): PID alone is e...
- `luks_mkfs(arg1, arg2)` → Create a filesystem on a device. device: path to device (e.g., /dev/mapper/name) filesystem: LUKS...
- `luks_mount(arg1, arg2, arg3)` → Mount a device at a mount point. device: path to block device mount_point: path to mount director...
- `luks_open(arg1, arg2, arg3)` → Open (unlock) a LUKS volume. Maps to /dev/mapper/{name}. key_ptr/key_len: key material. Returns O...
- `luks_pbkdf_as_str(arg)` → (no behavioral docs)
- `luks_run_capture(arg1, arg2, arg3)` → Helper: build argv vec and run with exec_capture, return Ok(bytes_read) or Err
- `luks_run_checked(arg)` → Helper: build argv vec and run, return Ok(exit_code) or Err
- `luks_unmount(arg)` → Unmount a mount point. Returns Ok(0) or Err.
- `luks_validate_cipher(arg1, arg2)` → Validate that (algo, mode) names a safe cipher pairing. Rejects: empty strings, anything containi...
- `luks_write_keyfile(arg1, arg2)` → Write key material to a unique per-PID-plus-random keyfile. Audit F-3: O_EXCL refuses to open if ...
- `luks_zeroize_key(arg1, arg2)` → Zeroize key material in memory

### `mac` (src/mac.cyr)

- `mac_apparmor_change_profile(arg)` → (no behavioral docs)
- `mac_apply_agent_profile(arg1, arg2, arg3)` → (no behavioral docs)
- `mac_default_profile(arg)` → (no behavioral docs)
- `mac_detect_system()` → (no behavioral docs)
- `mac_file_exists(arg)` → (no behavioral docs)
- `mac_get_apparmor_mode()` → (no behavioral docs)
- `mac_get_selinux_context()` → (no behavioral docs)
- `mac_get_selinux_mode()` → (no behavioral docs)
- `mac_profile_agent_type(arg)` → (no behavioral docs)
- `mac_profile_apparmor_name(arg)` → (no behavioral docs)
- `mac_profile_new(arg)` → (no behavioral docs)
- `mac_profile_selinux_ctx(arg)` → (no behavioral docs)
- `mac_profile_set_agent_type(arg1, arg2)` → (no behavioral docs)
- `mac_profile_set_apparmor_name(arg1, arg2)` → (no behavioral docs)
- `mac_profile_set_selinux_ctx(arg1, arg2)` → (no behavioral docs)
- `mac_profile_to_json(arg1, arg2)` → Hand-rolled JSON serializer (cyrius v5.10.15 #derive(Serialize) doesn't support cstring-pointer f...
- `mac_profile_validate(arg1, arg2)` → (no behavioral docs)
- `mac_read_file(arg)` → (no behavioral docs)
- `mac_set_selinux_context(arg1, arg2)` → (no behavioral docs)
- `mac_set_selinux_mode(arg)` → (no behavioral docs)
- `mac_write_file(arg1, arg2, arg3)` → (no behavioral docs)

### `main` (src/main.cyr)

- `main()` → (no behavioral docs)

### `netns` (src/netns.cyr)

- `netns_apply_nftables_ruleset(arg1, arg2)` → Apply a pre-rendered nftables ruleset inside the namespace. ruleset: null-terminated nftables scr...
- `netns_concat2(arg1, arg2)` → (no behavioral docs)
- `netns_concat3(arg1, arg2, arg3)` → (no behavioral docs)
- `netns_config_agent_ip(arg)` → (no behavioral docs)
- `netns_config_dns_arr(arg)` → (no behavioral docs)
- `netns_config_dns_count(arg)` → (no behavioral docs)
- `netns_config_enable_nat(arg)` → (no behavioral docs)
- `netns_config_for_agent(arg)` → (no behavioral docs)
- `netns_config_host_ip(arg)` → (no behavioral docs)
- `netns_config_name(arg)` → (no behavioral docs)
- `netns_config_new(arg1, arg2, arg3, arg4, arg5)` → (no behavioral docs)
- `netns_config_prefix_len(arg)` → (no behavioral docs)
- `netns_config_set_agent_ip(arg1, arg2)` → (no behavioral docs)
- `netns_config_set_dns(arg1, arg2, arg3)` → (no behavioral docs)
- `netns_config_set_dns_arr(arg1, arg2)` → (no behavioral docs)
- `netns_config_set_dns_count(arg1, arg2)` → (no behavioral docs)
- `netns_config_set_enable_nat(arg1, arg2)` → (no behavioral docs)
- `netns_config_set_host_ip(arg1, arg2)` → (no behavioral docs)
- `netns_config_set_name(arg1, arg2)` → (no behavioral docs)
- `netns_config_set_prefix_len(arg1, arg2)` → (no behavioral docs)
- `netns_create_agent_netns(arg)` → Create a network namespace for an agent with veth pair and IP configuration. Returns Result: Ok(h...
- `netns_destroy_agent_netns(arg)` → (no behavioral docs)
- `netns_fw_policy_default_in(arg)` → (no behavioral docs)
- `netns_fw_policy_default_out(arg)` → (no behavioral docs)
- `netns_fw_policy_new(arg1, arg2)` → (no behavioral docs)
- `netns_fw_policy_rule_count(arg)` → (no behavioral docs)
- `netns_fw_policy_rules(arg)` → 1.0 API preservation
- `netns_fw_policy_rules_arr(arg)` → (no behavioral docs)
- `netns_fw_policy_set_default_in(arg1, arg2)` → (no behavioral docs)
- `netns_fw_policy_set_default_out(arg1, arg2)` → (no behavioral docs)
- `netns_fw_policy_set_rule_count(arg1, arg2)` → (no behavioral docs)
- `netns_fw_policy_set_rules(arg1, arg2, arg3)` → (no behavioral docs)
- `netns_fw_policy_set_rules_arr(arg1, arg2)` → (no behavioral docs)
- `netns_fw_rule_action(arg)` → (no behavioral docs)
- `netns_fw_rule_comment(arg)` → (no behavioral docs)
- `netns_fw_rule_direction(arg)` → (no behavioral docs)
- `netns_fw_rule_new(arg1, arg2, arg3, arg4, arg5, arg6)` → (no behavioral docs)
- `netns_fw_rule_port(arg)` → (no behavioral docs)
- `netns_fw_rule_protocol(arg)` → (no behavioral docs)
- `netns_fw_rule_remote_addr(arg)` → (no behavioral docs)
- `netns_fw_rule_set_action(arg1, arg2)` → (no behavioral docs)
- `netns_fw_rule_set_comment(arg1, arg2)` → (no behavioral docs)
- `netns_fw_rule_set_direction(arg1, arg2)` → (no behavioral docs)
- `netns_fw_rule_set_port(arg1, arg2)` → (no behavioral docs)
- `netns_fw_rule_set_protocol(arg1, arg2)` → (no behavioral docs)
- `netns_fw_rule_set_remote_addr(arg1, arg2)` → (no behavioral docs)
- `netns_generate_agent_ips(arg)` → Generate agent IPs. Returns a struct { host_ip, agent_ip }.
- `netns_handle_name(arg)` → (no behavioral docs)
- `netns_handle_netns_path(arg)` → (no behavioral docs)
- `netns_handle_new(arg1, arg2, arg3, arg4)` → (no behavioral docs)
- `netns_handle_set_name(arg1, arg2)` → (no behavioral docs)
- `netns_handle_set_netns_path(arg1, arg2)` → (no behavioral docs)
- `netns_handle_set_veth_agent(arg1, arg2)` → (no behavioral docs)
- `netns_handle_set_veth_host(arg1, arg2)` → (no behavioral docs)
- `netns_handle_veth_agent(arg)` → (no behavioral docs)
- `netns_handle_veth_host(arg)` → (no behavioral docs)
- `netns_hash_name(arg)` → Simple hash function for agent name -> 10.100.x.{1,2}/30
- `netns_nft_action_str(arg)` → (no behavioral docs)
- `netns_nft_append(arg1, arg2, arg3)` → Helper to append a string to a buffer, return new position. Checks bounds against buf_size; if ex...
- `netns_nft_proto_str(arg)` → (no behavioral docs)
- `netns_render_nftables_ruleset(arg)` → Render a FirewallPolicy into an nftables ruleset string. Returns a heap-allocated null-terminated...
- `netns_run_ip(arg)` → (no behavioral docs)
- `netns_truncate_veth(arg)` → (no behavioral docs)
- `netns_validate_config(arg)` → (no behavioral docs)

### `pam` (src/pam.cyr)

- `pam_control_name(arg)` → (no behavioral docs)
- `pam_get_user_info(arg)` → Lookup a user in /etc/passwd by name. Returns Result: Ok(user_info_ptr) or Err.
- `pam_list_services()` → Returns Result: Ok(vec_of_Str) — filenames in /etc/pam.d/.
- `pam_list_sessions()` → Run `who` and parse output into vec of SessionInfo. Returns Result: Ok(vec) or Err.
- `pam_list_users()` → Read /etc/passwd and return vec of UserInfo pointers. Returns Result: Ok(vec) or Err.
- `pam_parse_config(arg)` → Parse PAM config text into a vec of PamRule pointers. Each non-blank, non-comment line: type cont...
- `pam_parse_control(arg)` → Parse control flag from Str. Returns control id or -1 on error.
- `pam_parse_passwd_line(arg)` → Format: username:x:uid:gid:gecos:home:shell Returns Result: Ok(user_info_ptr) or Err.
- `pam_parse_rule_type(arg)` → Parse rule type from Str. Returns type id or -1 on error.
- `pam_parse_who_output(arg)` → Typical who output lines:   alice    pts/0        2026-03-06 10:30 (192.168.1.5)   bob      tty1 ...
- `pam_read_service_config(arg)` → Read /etc/pam.d/<service_name> and parse it. service_name: C string (e.g. "sshd", "sudo"). Return...
- `pam_render_config(arg)` → Render a full PAM config from a vec of PamRule pointers. Returns Str.
- `pam_render_rule(arg)` → Render a single PamRule to a config-file line (Str).
- `pam_rule_args(arg)` → (no behavioral docs)
- `pam_rule_control(arg)` → (no behavioral docs)
- `pam_rule_module(arg)` → (no behavioral docs)
- `pam_rule_new(arg1, arg2, arg3, arg4)` → (no behavioral docs)
- `pam_rule_set_args(arg1, arg2)` → (no behavioral docs)
- `pam_rule_set_control(arg1, arg2)` → (no behavioral docs)
- `pam_rule_set_module(arg1, arg2)` → (no behavioral docs)
- `pam_rule_set_type(arg1, arg2)` → (no behavioral docs)
- `pam_rule_type(arg)` → (no behavioral docs)
- `pam_rule_type_name(arg)` → (no behavioral docs)
- `pam_service_name(arg)` → Get the config filename for a PAM service ID. Returns a C string pointer.
- `pam_session_id(arg)` → (no behavioral docs)
- `pam_session_login_time(arg)` → (no behavioral docs)
- `pam_session_new(arg1, arg2, arg3, arg4, arg5, arg6)` → (no behavioral docs)
- `pam_session_pid(arg)` → (no behavioral docs)
- `pam_session_remote_host(arg)` → (no behavioral docs)
- `pam_session_set_id(arg1, arg2)` → (no behavioral docs)
- `pam_session_set_login_time(arg1, arg2)` → (no behavioral docs)
- `pam_session_set_pid(arg1, arg2)` → (no behavioral docs)
- `pam_session_set_remote_host(arg1, arg2)` → (no behavioral docs)
- `pam_session_set_tty(arg1, arg2)` → (no behavioral docs)
- `pam_session_set_user(arg1, arg2)` → (no behavioral docs)
- `pam_session_tty(arg)` → (no behavioral docs)
- `pam_session_user(arg)` → (no behavioral docs)
- `pam_split_whitespace(arg)` → Split a Str by whitespace (space/tab), skipping consecutive whitespace. Returns vec of Str.
- `pam_user_alloc()` → (no behavioral docs)
- `pam_user_gid(arg)` → (no behavioral docs)
- `pam_user_groups(arg)` → 1.0 API preservation — `groups` getter + 3-arg `set_groups` delegate through the derive accessors.
- `pam_user_groups_arr(arg)` → (no behavioral docs)
- `pam_user_home(arg)` → (no behavioral docs)
- `pam_user_is_system(arg)` → (no behavioral docs)
- `pam_user_set(arg1, arg2, arg3, arg4, arg5, arg6)` → (no behavioral docs)
- `pam_user_set_gid(arg1, arg2)` → (no behavioral docs)
- `pam_user_set_groups(arg1, arg2, arg3)` → (no behavioral docs)
- `pam_user_set_groups_arr(arg1, arg2)` → (no behavioral docs)
- `pam_user_set_home(arg1, arg2)` → (no behavioral docs)
- `pam_user_set_is_system(arg1, arg2)` → (no behavioral docs)
- `pam_user_set_shell(arg1, arg2)` → (no behavioral docs)
- `pam_user_set_uid(arg1, arg2)` → (no behavioral docs)
- `pam_user_set_username(arg1, arg2)` → (no behavioral docs)
- `pam_user_shell(arg)` → (no behavioral docs)
- `pam_user_uid(arg)` → (no behavioral docs)
- `pam_user_username(arg)` → (no behavioral docs)
- `pam_validate_rule(arg)` → Check module path is reasonable and args have no shell metacharacters. Returns Result: Ok(0) on v...
- `pam_validate_username(arg)` → Validate a UNIX username. Rules: max 32 chars, must start with lowercase letter or underscore, ma...

### `secureboot` (src/secureboot.cyr)

- `secureboot_detect_state()` → Detect the current Secure Boot state. Returns Result: Ok(SecureBootState) or Err.
- `secureboot_efi_var_data_size(arg)` → (no behavioral docs)
- `secureboot_efi_var_name(arg)` → (no behavioral docs)
- `secureboot_efi_var_new(arg1, arg2)` → (no behavioral docs)
- `secureboot_efi_var_payload_byte(arg1, arg2)` → Get the payload byte at index (after the 4-byte attributes header).
- `secureboot_efi_var_set_data_size(arg1, arg2)` → (no behavioral docs)
- `secureboot_efi_var_set_name(arg1, arg2)` → (no behavioral docs)
- `secureboot_efi_var_size(arg)` → Get total bytes read.
- `secureboot_enroll_key(arg)` → Enroll a DER-encoded certificate into the MOK list. A reboot is required to complete enrollment. ...
- `secureboot_enrolled_key_new(arg1, arg2, arg3, arg4, arg5)` → (no behavioral docs)
- `secureboot_is_enforcing(arg)` → (no behavioral docs)
- `secureboot_key_fingerprint(arg)` → (no behavioral docs)
- `secureboot_key_issuer(arg)` → (no behavioral docs)
- `secureboot_key_not_after(arg)` → (no behavioral docs)
- `secureboot_key_not_before(arg)` → (no behavioral docs)
- `secureboot_key_set_fingerprint(arg1, arg2)` → (no behavioral docs)
- `secureboot_key_set_issuer(arg1, arg2)` → (no behavioral docs)
- `secureboot_key_set_not_after(arg1, arg2)` → (no behavioral docs)
- `secureboot_key_set_not_before(arg1, arg2)` → (no behavioral docs)
- `secureboot_key_set_subject(arg1, arg2)` → (no behavioral docs)
- `secureboot_key_subject(arg)` → (no behavioral docs)
- `secureboot_list_efi_variables()` → List security-relevant EFI variables from sysfs. Returns Result: Ok(vec_of_efi_vars) or Err.
- `secureboot_list_enrolled_keys()` → List enrolled MOK (Machine Owner Key) certificates. Returns Result: Ok(vec_of_keys) or Err.
- `secureboot_parse_mokutil_list(arg1, arg2)` → Parse mokutil --list-enrolled output into a vec of EnrolledKey structs. Returns vec of key pointers.
- `secureboot_read_efi_variable(arg)` → Read a raw EFI variable from sysfs. path: full path to the EFI variable file. Returns Result: Ok(...
- `secureboot_sig_algorithm(arg)` → (no behavioral docs)
- `secureboot_sig_has_sig(arg)` → (no behavioral docs)
- `secureboot_sig_info_new(arg1, arg2, arg3, arg4)` → (no behavioral docs)
- `secureboot_sig_module(arg)` → (no behavioral docs)
- `secureboot_sig_set_algorithm(arg1, arg2)` → (no behavioral docs)
- `secureboot_sig_set_has_sig(arg1, arg2)` → (no behavioral docs)
- `secureboot_sig_set_module(arg1, arg2)` → (no behavioral docs)
- `secureboot_sig_set_signer(arg1, arg2)` → (no behavioral docs)
- `secureboot_sig_signer(arg)` → (no behavioral docs)
- `secureboot_sign_module(arg1, arg2, arg3)` → Sign a kernel module with a private key and certificate. Uses kmodsign, falls back to sign-file f...
- `secureboot_state_str(arg)` → State to string (returns pointer to static string)
- `secureboot_verify_module(arg)` → Verify a kernel module's signature using modinfo. Returns Result: Ok(sig_info) or Err.

### `security` (src/security.cyr)

- `security_apply_landlock(arg1, arg2)` → rules: vec of fs_rule pointers, count: number of rules Returns Result: Ok(0) on success, Err on f...
- `security_bpf_write_insn(arg1, arg2, arg3, arg4, arg5, arg6)` → Write a BPF sock_filter instruction (8 bytes) to buf at offset.
- `security_create_basic_seccomp_filter()` → Create a basic seccomp filter allowing safe syscalls. Returns Result: Ok(filter_ptr) where payloa...
- `security_create_namespace(arg)` → Create new namespace(s) with specified flags. flags: bitwise OR of NS_NETWORK, NS_MOUNT, NS_PID, ...
- `security_fs_rule_access(arg)` → (no behavioral docs)
- `security_fs_rule_new(arg1, arg2)` → Filesystem rule: { path_ptr, access } path_ptr is a null-terminated C string pointer
- `security_fs_rule_path(arg)` → (no behavioral docs)
- `security_fs_rule_read_only(arg)` → (no behavioral docs)
- `security_fs_rule_read_write(arg)` → (no behavioral docs)
- `security_load_seccomp(arg1, arg2)` → Load a seccomp-BPF filter into the calling process. filter: pointer to BPF bytecode, filter_len: ...
- `security_seccomp_filter_len(arg)` → (no behavioral docs)
- `security_seccomp_filter_ptr(arg)` → Get filter pointer from security_create_basic_seccomp_filter result
- `security_syscall_map_reset()` → (no behavioral docs)
- `security_syscall_name_to_nr(arg)` → Map a syscall name to its x86_64 number. Returns -1 if not found.

### `syscall` (src/syscall.cyr)

- `agnosys_checked_syscall(arg)` → Execute a syscall and return Result: Ok(ret) or Err(syserr). name is a string label for diagnosti...
- `agnosys_free_memory()` → Get free system memory in bytes. Returns Result.
- `agnosys_geteuid()` → Get the current effective user ID.
- `agnosys_getpid()` → Get the current process ID.
- `agnosys_gettid()` → Get the current thread ID.
- `agnosys_getuid()` → Get the current user ID.
- `agnosys_is_root()` → Check if the current process has root privileges.
- `agnosys_total_memory()` → Get total system memory in bytes. Returns Result.
- `agnosys_uname(arg)` → Query uname(2) into a caller-provided buffer. out must point to at least 390 bytes. Returns Resul...
- `agnosys_uptime()` → Get system uptime in seconds. Returns Result.
- `query_sysinfo(arg)` → Query sysinfo(2) into a caller-provided buffer. out must point to at least 120 bytes. Returns Res...
- `sysinfo_free_memory(arg)` → Get free RAM in bytes from a sysinfo pointer.
- `sysinfo_procs(arg)` → Get number of running processes from a sysinfo pointer.
- `sysinfo_total_memory(arg)` → Get total RAM in bytes from a sysinfo pointer. Uses saturating multiplication to prevent overflow.
- `sysinfo_uptime(arg)` → Get uptime in seconds from a sysinfo pointer.
- `uname_hostname(arg)` → Get hostname from a utsname buffer.
- `uname_machine(arg)` → Get machine arch from a utsname buffer.
- `uname_release(arg)` → Get kernel release from a utsname buffer.

### `syscall_aarch64_linux` (src/syscall_aarch64_linux.cyr)

- `agnosys_fsync(arg)` → fsync(2) — flush file to disk.
- `agnosys_rename(arg1, arg2)` → rename(2) equivalent — generic-table has no direct `rename`, route via renameat2(AT_FDCWD, old, A...

### `syscall_x86_64_linux` (src/syscall_x86_64_linux.cyr)

- `agnosys_fsync(arg)` → fsync(2) — flush file to disk.
- `agnosys_rename(arg1, arg2)` → rename(2) — atomic rename. Direct syscall on x86_64.

### `tpm` (src/tpm.cyr)

- `tpm_bank_hex_len(arg)` → (no behavioral docs)
- `tpm_bank_str(arg)` → (no behavioral docs)
- `tpm_detect()` → Check if a TPM 2.0 device is available. Returns 1 if available, 0 if not.
- `tpm_extend_pcr(arg1, arg2, arg3)` → (no behavioral docs)
- `tpm_get_random(arg1, arg2)` → (no behavioral docs)
- `tpm_pcr_selection(arg1, arg2)` → (no behavioral docs)
- `tpm_pcr_value_bank(arg)` → (no behavioral docs)
- `tpm_pcr_value_index(arg)` → (no behavioral docs)
- `tpm_pcr_value_new(arg1, arg2, arg3)` → (no behavioral docs)
- `tpm_pcr_value_set_bank(arg1, arg2)` → (no behavioral docs)
- `tpm_pcr_value_set_index(arg1, arg2)` → (no behavioral docs)
- `tpm_pcr_value_set_value(arg1, arg2)` → (no behavioral docs)
- `tpm_pcr_value_value(arg)` → (no behavioral docs)
- `tpm_read_pcr(arg1, arg2)` → (no behavioral docs)
- `tpm_run_capture(arg1, arg2, arg3)` → (no behavioral docs)
- `tpm_run_checked(arg)` → (no behavioral docs)
- `tpm_seal(arg1, arg2, arg3, arg4, arg5)` → (no behavioral docs)
- `tpm_sealed_context(arg)` → (no behavioral docs)
- `tpm_sealed_new(arg1, arg2)` → (no behavioral docs)
- `tpm_sealed_pcr_sel(arg)` → (no behavioral docs)
- `tpm_sealed_set_context(arg1, arg2)` → (no behavioral docs)
- `tpm_sealed_set_pcr_sel(arg1, arg2)` → (no behavioral docs)
- `tpm_unseal(arg1, arg2, arg3)` → (no behavioral docs)
- `tpm_verify_measured_boot(arg)` → (no behavioral docs)

### `udev` (src/udev.cyr)

- `udev_devinfo_devnode(arg)` → (no behavioral docs)
- `udev_devinfo_devpath(arg)` → (no behavioral docs)
- `udev_devinfo_devtype(arg)` → (no behavioral docs)
- `udev_devinfo_driver(arg)` → (no behavioral docs)
- `udev_devinfo_new()` → (no behavioral docs)
- `udev_devinfo_prop_count(arg)` → (no behavioral docs)
- `udev_devinfo_prop_keys(arg)` → (no behavioral docs)
- `udev_devinfo_prop_vals(arg)` → (no behavioral docs)
- `udev_devinfo_set_devnode(arg1, arg2)` → (no behavioral docs)
- `udev_devinfo_set_devpath(arg1, arg2)` → (no behavioral docs)
- `udev_devinfo_set_devtype(arg1, arg2)` → (no behavioral docs)
- `udev_devinfo_set_driver(arg1, arg2)` → (no behavioral docs)
- `udev_devinfo_set_prop_count(arg1, arg2)` → (no behavioral docs)
- `udev_devinfo_set_prop_keys(arg1, arg2)` → (no behavioral docs)
- `udev_devinfo_set_prop_vals(arg1, arg2)` → (no behavioral docs)
- `udev_devinfo_set_props(arg1, arg2, arg3, arg4)` → (no behavioral docs)
- `udev_devinfo_set_subsystem(arg1, arg2)` → (no behavioral docs)
- `udev_devinfo_set_syspath(arg1, arg2)` → (no behavioral docs)
- `udev_devinfo_subsystem(arg)` → (no behavioral docs)
- `udev_devinfo_syspath(arg)` → (no behavioral docs)
- `udev_get_device_info(arg)` → (no behavioral docs)
- `udev_list_devices(arg1, arg2, arg3)` → List all devices, optionally filtered by subsystem string. subsystem_filter: a null-terminated st...
- `udev_parse_subsystem(arg)` → Parse a subsystem string into a constant
- `udev_parse_udevadm_info(arg)` → Parse a block of udevadm info output (P:/N:/S:/E: prefixed lines). text: null-terminated string o...
- `udev_starts_with(arg1, arg2)` → Check if a string starts with a given prefix
- `udev_validate_rule(arg1, arg2)` → Validate a udev rule. action_keys: array of string pointers to action key names. action_count: nu...

### `update` (src/update.cyr)

- `update_apply(arg1, arg2)` → Write update image to the inactive slot's block device. Returns Result: Ok(0) or Err.
- `update_atomic_copy(arg1, arg2)` → Atomically copy src to dst (via temp + rename). Returns Result: Ok(bytes_copied) or Err.
- `update_atomic_write(arg1, arg2, arg3)` → Atomically write data to a file path. Writes to a temp file first, then renames to the target pat...
- `update_channel_str(arg)` → (no behavioral docs)
- `update_check(arg1, arg2)` → Check for available update by reading a local manifest file. url_or_path: path to manifest JSON f...
- `update_compare_versions(arg1, arg2)` → Compare two CalVer version strings. Returns VER_LESS (-1), VER_EQUAL (0), or VER_GREATER (1). Fal...
- `update_config_backup_dir(arg)` → (no behavioral docs)
- `update_config_device_for_slot(arg1, arg2)` → (no behavioral docs)
- `update_config_max_retries(arg)` → (no behavioral docs)
- `update_config_new()` → (no behavioral docs)
- `update_config_set_backup_dir(arg1, arg2)` → (no behavioral docs)
- `update_config_set_max_retries(arg1, arg2)` → (no behavioral docs)
- `update_config_set_slot_a(arg1, arg2)` → (no behavioral docs)
- `update_config_set_slot_b(arg1, arg2)` → (no behavioral docs)
- `update_config_set_state_file(arg1, arg2)` → (no behavioral docs)
- `update_config_set_url(arg1, arg2)` → (no behavioral docs)
- `update_config_set_verify(arg1, arg2)` → (no behavioral docs)
- `update_config_slot_a(arg)` → (no behavioral docs)
- `update_config_slot_b(arg)` → (no behavioral docs)
- `update_config_state_file(arg)` → (no behavioral docs)
- `update_config_url(arg)` → (no behavioral docs)
- `update_config_verify(arg)` → (no behavioral docs)
- `update_file_compressed(arg)` → (no behavioral docs)
- `update_file_delta_from(arg)` → (no behavioral docs)
- `update_file_new(arg1, arg2, arg3)` → (no behavioral docs)
- `update_file_path(arg)` → (no behavioral docs)
- `update_file_set_compressed(arg1, arg2)` → (no behavioral docs)
- `update_file_set_delta_from(arg1, arg2)` → (no behavioral docs)
- `update_file_set_path(arg1, arg2)` → (no behavioral docs)
- `update_file_set_sha256(arg1, arg2)` → (no behavioral docs)
- `update_file_set_size(arg1, arg2)` → (no behavioral docs)
- `update_file_sha256(arg)` → (no behavioral docs)
- `update_file_size(arg)` → (no behavioral docs)
- `update_get_current_slot()` → Detect current boot slot by reading /proc/cmdline for "agnos.slot=". Falls back to reading the st...
- `update_load_state(arg)` → Load update state from a JSON file. Returns Result: Ok(state_ptr) or Err.
- `update_manifest_changelog(arg)` → (no behavioral docs)
- `update_manifest_channel(arg)` → (no behavioral docs)
- `update_manifest_files(arg)` → (no behavioral docs)
- `update_manifest_min_version(arg)` → (no behavioral docs)
- `update_manifest_new(arg1, arg2, arg3)` → (no behavioral docs)
- `update_manifest_release_date(arg)` → (no behavioral docs)
- `update_manifest_set_changelog(arg1, arg2)` → (no behavioral docs)
- `update_manifest_set_channel(arg1, arg2)` → (no behavioral docs)
- `update_manifest_set_files(arg1, arg2)` → (no behavioral docs)
- `update_manifest_set_min_version(arg1, arg2)` → (no behavioral docs)
- `update_manifest_set_release_date(arg1, arg2)` → (no behavioral docs)
- `update_manifest_set_version(arg1, arg2)` → (no behavioral docs)
- `update_manifest_version(arg)` → (no behavioral docs)
- `update_mark_boot_successful(arg)` → Mark the current boot as successful. Increments boot counter, clears pending update flag. Returns...
- `update_needs_rollback(arg1, arg2)` → Pure function: returns 1 if boot count exceeds max_attempts and there is a pending update (indica...
- `update_other_slot(arg)` → (no behavioral docs)
- `update_parse_version(arg)` → Parse a version string into { year, month, day }. Returns pointer to 24-byte struct, or 0 on pars...
- `update_phase_str(arg)` → (no behavioral docs)
- `update_rollback(arg)` → Roll back to the previous slot. Returns Result: Ok(0) or Err.
- `update_save_state(arg1, arg2)` → Save update state to a JSON file. Returns Result: Ok(0) or Err.
- `update_slot_str(arg)` → (no behavioral docs)
- `update_slot_suffix(arg)` → (no behavioral docs)
- `update_state_boot_count(arg)` → (no behavioral docs)
- `update_state_new(arg1, arg2)` → (no behavioral docs)
- `update_state_pending(arg)` → (no behavioral docs)
- `update_state_rollback_available(arg)` → (no behavioral docs)
- `update_state_set_boot_count(arg1, arg2)` → (no behavioral docs)
- `update_state_set_pending(arg1, arg2)` → (no behavioral docs)
- `update_state_set_rollback(arg1, arg2)` → 1.0 API preservation — `set_rollback` (asymmetric) delegates through `set_rollback_available`.
- `update_state_set_rollback_available(arg1, arg2)` → (no behavioral docs)
- `update_state_set_slot(arg1, arg2)` → (no behavioral docs)
- `update_state_set_version(arg1, arg2)` → (no behavioral docs)
- `update_state_slot(arg)` → (no behavioral docs)
- `update_state_to_json(arg1, arg2)` → Hand-rolled JSON serializer (cstring-pointer fields not yet supported by cyrius #derive(Serialize)).
- `update_state_version(arg)` → (no behavioral docs)
- `update_switch_slot(arg1, arg2)` → Mark a slot as active for the next boot. Writes slot marker for argonaut and optionally sets EFI ...
- `update_validate_version(arg)` → Validate a CalVer version string (YYYY.M.D). Returns Result: Ok(0) or Err.
- `update_verify_manifest(arg)` → Validate structural integrity of an update manifest. Returns Result: Ok(0) or Err. Note: SHA-256 ...


## Notes

- This doc replaces the hand-curated 1.0 prose snapshot from the V1.0.0 freeze. Per-fn descriptions are now extracted programmatically from each fn's leading `#` comment block; fns without behavioral comments show `(no behavioral docs)` and may be polished by hand-editing the source-side comment block (the auto-generator picks up the change on next run).
- Argument names are placeholder (`arg1`, `arg2`, ...) since the snapshot stores arity but not names. For names + types, read the source.
- The machine-checkable companion is `docs/development/api-surface-1.0.snapshot` (one `module::fn/arity` line per public fn) — that's what CI's API-surface gate diffs against.
