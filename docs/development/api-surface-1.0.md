# Agnosys 1.0 API Surface

> Frozen at **1.0.0** (2026-04-17). The 1.0 baseline (556 fns) is the stable contract: removal or signature change of any 1.0-era fn requires a 2.0 bump. Post-1.0 additions (V1.1.x → V1.2.x) are listed inline below; all are additive.
>
> **Auto-generated** from `docs/development/api-surface-1.0.snapshot` + source-comment extraction by `scripts/gen-api-surface-prose.sh`. To regenerate: `scripts/gen-api-surface-prose.sh`. The audit gate (`stage 2/11 "API surface"`) verifies the snapshot stays in sync with the source.


## Summary

- Total public functions: **315**
- Modules: **10**
- 1.0 baseline (frozen): 556 fns
- Post-1.0 additions (V1.1 + V1.2 cycles): -241 fns
- Outliers (fns lacking module prefix): 0


## By module


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
- `fuse_starts_with(arg1, arg2)` → Check if a string starts with a prefix. Thin wrapper over the shared single-pass predicate (publi...
- `fuse_unmount(arg)` → Unmount a FUSE filesystem at the given mountpoint. Returns Result: Ok(0) or Err.
- `fuse_unmount_lazy(arg)` → Lazy unmount via fusermount -uz (for busy mounts).
- `fuse_validate_mountpoint(arg)` → Validate that a path is suitable as a FUSE mountpoint. Checks: not null, not root, exists, is a d...

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
- `netns_run_ip(arg)` → Run an `ip` command. `args` is a vec of cstr argv; element 0 is the absolute command path. exec_v...
- `netns_truncate_veth(arg)` → (no behavioral docs)
- `netns_validate_config(arg)` → (no behavioral docs)

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
- `udev_starts_with(arg1, arg2)` → Check if a string starts with a given prefix. Thin wrapper over the shared single-pass predicate ...
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

### `util` (src/util.cyr)

- `agnodrm_cstr_starts_with(arg1, arg2)` → Does C string `str` start with C string `prefix`? Single-pass: walks `prefix` and compares, stopp...
- `agnodrm_fsync(arg)` → (no behavioral docs)
- `agnodrm_is_hex_char(arg)` → Is `ch` an ASCII hex digit (0-9, a-f, A-F)? Single definition shared by the hash/digest validator...
- `agnodrm_is_name_char(arg)` → Is `ch` valid in a device-mapper / volume name (alphanumeric, `-`, `_`)? Single source for the dm...
- `agnodrm_json_emit_cstr_or_null(arg1, arg2)` → Emit a JSON value for a possibly-null C string into a str_builder: `null` when the pointer is 0, ...
- `agnodrm_read_fd_to_str(arg1, arg2)` → Read up to `cap` bytes from `fd` into a fresh heap buffer, NUL-terminate, and return it as a Str ...
- `agnodrm_rename(arg1, arg2)` → (no behavioral docs)
- `agnodrm_run_capture(arg1, arg2, arg3, arg4)` → Run a subprocess (cstr argv vec) and capture stdout into a caller buffer. Returns Ok(bytes_read) ...
- `agnodrm_run_checked(arg1, arg2)` → Run a subprocess (cstr argv vec) and check for a zero exit code. Returns Ok(0) or Err(errmsg) on ...


## Notes

- This doc replaces the hand-curated 1.0 prose snapshot from the V1.0.0 freeze. Per-fn descriptions are now extracted programmatically from each fn's leading `#` comment block; fns without behavioral comments show `(no behavioral docs)` and may be polished by hand-editing the source-side comment block (the auto-generator picks up the change on next run).
- Argument names are placeholder (`arg1`, `arg2`, ...) since the snapshot stores arity but not names. For names + types, read the source.
- The machine-checkable companion is `docs/development/api-surface-1.0.snapshot` (one `module::fn/arity` line per public fn) — that's what CI's API-surface gate diffs against.
