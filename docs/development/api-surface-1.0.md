# Agnosys 1.0 API Surface

> Frozen at **1.0.0** (2026-04-17). Every function listed here is part of the stable 1.x API contract — removal or signature change requires a 2.0 bump.


## Summary

- Total public functions: 556
- Modules: 20
- Outliers resolved: 139 (all modules now carry their module prefix — no remaining prefix violations)
- Outliers open: 0


## By module


### audit (src/audit.cyr)

Structs: `AuditConst, SysNrAudit, AuditRuleType`.

- `audit_add_rule(handle, rule)` → Add an audit rule
- `audit_agnos_log(action, data, result_code)` → Log via AGNOS custom syscall (SYS_AGNOS_AUDIT_LOG = 520)
- `audit_build_nlmsg(msg_type, payload_ptr, payload_len)` → Build a netlink message header + payload
- `audit_close(handle)` → Close an audit handle
- `audit_config_new()` → Audit config struct
- `audit_config_proc_path(c)` → (no behavioral docs)
- `audit_config_set_netlink(c, val)` → (no behavioral docs)
- `audit_config_set_proc(c, val)` → (no behavioral docs)
- `audit_config_set_proc_path(c, path)` → (no behavioral docs)
- `audit_config_use_netlink(c)` → (no behavioral docs)
- `audit_config_use_proc(c)` → (no behavioral docs)
- `audit_delete_rule(handle, rule)` → Delete an audit rule
- `audit_get_status(handle)` → Get audit subsystem status (AUDIT_GET)
- `audit_handle_config(h)` → (no behavioral docs)
- `audit_handle_fd(h)` → Offsets: fd=0, config=8. Size: 16 bytes.
- `audit_handle_new(fd, config)` → Audit handle struct
- `audit_nlmsg_len(buf)` → Copy payload
- `audit_open(config)` → Open an audit connection
- `audit_read_proc_events(proc_path)` → Read audit events from /proc/agnos/audit
- `audit_recv_raw(handle, buf, buf_len)` → Receive raw netlink message from audit socket
- `audit_rule_file_watch(path, key)` → Create a file watch rule
- `audit_rule_key(r)` → (no behavioral docs)
- `audit_rule_new(rule_type, path, syscall_nr, key)` → Audit rule struct
- `audit_rule_path(r)` → (no behavioral docs)
- `audit_rule_syscall(r)` → (no behavioral docs)
- `audit_rule_syscall_watch(syscall_nr, key)` → Create a file watch rule
- `audit_rule_type(r)` → (no behavioral docs)
- `audit_rule_validate(rule)` → Create a syscall watch rule
- `audit_send_event(handle, event_type, message)` → Send an audit user event
- `audit_send_raw(handle, buf, buf_len)` → Send raw netlink message on audit socket
- `audit_send_rule_msg(handle, rule, msg_type)` → Send an audit rule message (add or delete)
- `audit_set_enabled(handle, enabled)` → Enable or disable the audit subsystem (AUDIT_SET)
- `audit_sockaddr_nl(pid)` → sockaddr_nl struct helper
- `audit_status_backlog(s)` → (no behavioral docs)
- `audit_status_backlog_limit(s)` → (no behavioral docs)
- `audit_status_enabled(s)` → (no behavioral docs)
- `audit_status_failure_action(s)` → (no behavioral docs)
- `audit_status_lost(s)` → (no behavioral docs)
- `audit_status_new()` → Audit status struct
- `audit_status_pid(s)` → (no behavioral docs)


### bootloader (src/bootloader.cyr)

Structs: `BootloaderType`.

- `bootloader_config_default_id(c)` → 5 fields * 8 = 40 bytes
- `bootloader_config_entries(c)` → (no behavioral docs)
- `bootloader_config_entry_count(c)` → (no behavioral docs)
- `bootloader_config_new()` → BootConfig struct
- `bootloader_config_set_default_id(c, v)` → (no behavioral docs)
- `bootloader_config_set_entries(c, arr, count)` → (no behavioral docs)
- `bootloader_config_set_timeout(c, v)` → (no behavioral docs)
- `bootloader_config_set_type(c, v)` → (no behavioral docs)
- `bootloader_config_timeout(c)` → Layout: { bootloader_type, timeout_secs, default_entry_id, entries_arr
- `bootloader_config_type(c)` → Layout: { bootloader_type, timeout_secs, default_entry_id, entries_arr
- `bootloader_entry_id(e)` → Layout: { id, title, linux_path, initrd_path, options, is_default, ver
- `bootloader_entry_initrd(e)` → (no behavioral docs)
- `bootloader_entry_is_default(e)` → (no behavioral docs)
- `bootloader_entry_linux(e)` → 7 fields * 8 = 56 bytes
- `bootloader_entry_new()` → /boot/loader/loader.conf  -> systemd-boot loader config
- `bootloader_entry_options(e)` → (no behavioral docs)
- `bootloader_entry_set_id(e, v)` → (no behavioral docs)
- `bootloader_entry_set_initrd(e, v)` → (no behavioral docs)
- `bootloader_entry_set_is_default(e, v)` → (no behavioral docs)
- `bootloader_entry_set_linux(e, v)` → (no behavioral docs)
- `bootloader_entry_set_options(e, v)` → (no behavioral docs)
- `bootloader_entry_set_title(e, v)` → (no behavioral docs)
- `bootloader_entry_set_version(e, v)` → (no behavioral docs)
- `bootloader_entry_title(e)` → Layout: { id, title, linux_path, initrd_path, options, is_default, ver
- `bootloader_entry_version(e)` → (no behavioral docs)
- `bootloader_danger_reset()` → (no behavioral docs)
- `bootloader_detect()` → Bootloader detection
- `bootloader_extract_value(line, linelen, key_end_pos)` → Extract the value after a key in a line (trim whitespace).
- `bootloader_is_dangerous_token(text, textlen, token)` → Kernel command line validation
- `bootloader_line_starts_with(line, linelen, prefix)` → Parse loader.conf (systemd-boot)
- `bootloader_list_boot_entries(result_arr, max_entries)` → List boot entries (high-level)
- `bootloader_parse_bootctl_list(text, result_arr, max_entries)` → Fallback: try reading /boot/loader/entries/ directly
- `bootloader_parse_loader_conf(text)` → Parse loader.conf file contents.
- `bootloader_type_str(bt)` → Bootloader type to string.
- `bootloader_validate_kernel_cmdline(options)` → Validate kernel command-line parameters.


### certpin (src/certpin.cyr)

Structs: `CertPinResult`.

- `certpin_info_issuer(c)` → CertInfo struct: { subject, issuer, serial, not_before, not_after, sha
- `certpin_info_new()` → Fetch server certificate info via openssl s_client
- `certpin_info_not_after(c)` → (no behavioral docs)
- `certpin_info_not_before(c)` → (no behavioral docs)
- `certpin_info_serial(c)` → Layout: 7 string pointers, 56 bytes total.
- `certpin_info_set_issuer(c, v)` → (no behavioral docs)
- `certpin_info_set_not_after(c, v)` → (no behavioral docs)
- `certpin_info_set_not_before(c, v)` → (no behavioral docs)
- `certpin_info_set_serial(c, v)` → (no behavioral docs)
- `certpin_info_set_sha256_fp(c, v)` → (no behavioral docs)
- `certpin_info_set_spki_sha256(c, v)` → (no behavioral docs)
- `certpin_info_set_subject(c, v)` → (no behavioral docs)
- `certpin_info_sha256_fp(c)` → (no behavioral docs)
- `certpin_info_spki_sha256(c)` → (no behavioral docs)
- `certpin_info_subject(c)` → CertInfo struct: { subject, issuer, serial, not_before, not_after, sha
- `certpin_check_pin_expiry(entry, current_time)` → Check pin expiry against current time.
- `certpin_compute_spki_pin(cert_path)` → Compute the SPKI SHA-256 pin for a PEM certificate file on disk.
- `certpin_ct_streq(a, b)` → Pin verification (pure function)
- `certpin_entry_backup_count(e)` → (no behavioral docs)
- `certpin_entry_backups(e)` → (no behavioral docs)
- `certpin_entry_expires(e)` → (no behavioral docs)
- `certpin_entry_host(e)` → (no behavioral docs)
- `certpin_entry_new(host, expires)` → Pin set struct
- `certpin_entry_pin_count(e)` → (no behavioral docs)
- `certpin_entry_pins(e)` → (no behavioral docs)
- `certpin_entry_set_backups(e, backups_ptr, count)` → (no behavioral docs)
- `certpin_entry_set_pins(e, pins_ptr, count)` → (no behavioral docs)
- `certpin_find_entry(pin_set, host)` → Find the pin entry for a given host in the pin set.
- `certpin_set_count(s)` → (no behavioral docs)
- `certpin_set_enforce(s)` → (no behavioral docs)
- `certpin_set_entries(s)` → Total: 24 bytes.
- `certpin_set_new(enforce)` → CertPinSet: { entries_vec, entry_count, enforce }
- `certpin_set_set_entries(s, entries_ptr, count)` → (no behavioral docs)
- `certpin_validate_pin_format(pin)` → Pin format validation
- `certpin_verify_pin(host, actual_pin, pin_set, current_time)` → Verify a certificate pin against a pin set.


### dmverity (src/dmverity.cyr)

Structs: `VerityHashAlgo, VerityConst`.

- `dmverity_close(name)` → Close (deactivate) a dm-verity volume.
- `dmverity_config_alloc()` → VerityConfig struct
- `dmverity_config_data_block_size(c)` → (no behavioral docs)
- `dmverity_config_data_device(c)` → (no behavioral docs)
- `dmverity_config_hash_algorithm(c)` → (no behavioral docs)
- `dmverity_config_hash_block_size(c)` → (no behavioral docs)
- `dmverity_config_hash_device(c)` → (no behavioral docs)
- `dmverity_config_name(c)` → (no behavioral docs)
- `dmverity_config_root_hash(c)` → (no behavioral docs)
- `dmverity_config_salt(c)` → (no behavioral docs)
- `dmverity_config_set_devices(c, name, data_device, hash_device)` → hash_algorithm(+40) root_hash(+48) salt(+56)
- `dmverity_config_set_params(c, data_bs, hash_bs, algo, root_hash, salt)` → (no behavioral docs)
- `dmverity_config_validate(config)` → Validate a VerityConfig. Returns Ok(0) or Err.
- `dmverity_format(data_device, hash_device, algorithm, salt)` → dm-verity operations
- `dmverity_hash_algo_str(algo)` → Hash algorithm helpers
- `dmverity_hash_hex_len(algo)` → Hash algorithm helpers
- `dmverity_is_hex_char(ch)` → Validation helpers
- `dmverity_is_name_char(ch)` → Check if a byte is valid for a dm name (alphanum, dash, underscore)
- `dmverity_open(config)` → Open (activate) a dm-verity volume.
- `dmverity_run_capture(args, buf, buflen)` → Helper: run veritysetup
- `dmverity_run_checked(args)` → (no behavioral docs)
- `dmverity_status(name)` → Query the status of a dm-verity volume.
- `dmverity_status_corruption_detected(s)` → (no behavioral docs)
- `dmverity_status_is_active(s)` → (no behavioral docs)
- `dmverity_status_is_verified(s)` → (no behavioral docs)
- `dmverity_status_name(s)` → (no behavioral docs)
- `dmverity_status_new(name, is_active, is_verified, corruption_detected, root_hash)` → VerityStatus struct
- `dmverity_status_root_hash(s)` → (no behavioral docs)
- `dmverity_supported()` → Check if dm-verity is supported on this system.
- `dmverity_validate_hex(s, label)` → Check if a byte is a valid hex character
- `dmverity_validate_root_hash(hash, algorithm)` → Validate a root hash: correct length for algorithm, all hex.
- `dmverity_verify(data_device, hash_device, root_hash)` → Verify a dm-verity volume without activating it.


### drm (src/drm.cyr)

Structs: `DrmIoctl, DrmCap, DrmConnectorType, DrmConnStatus, DrmSysNr, DrmVerOff`.

- `drm_close(fd)` → O_RDWR | O_CLOEXEC = 0x80002
- `drm_get_capability(fd, cap)` → Query capability
- `drm_get_driver_version(fd)` → Query driver version
- `drm_list_devices(result_arr, max_cards)` → Device enumeration
- `drm_open(path)` → Open a DRM device
- `drm_supports_dumb_buffer(fd)` → Check if device supports dumb buffers.
- `drm_verinfo_date(v)` → (no behavioral docs)
- `drm_verinfo_desc(v)` → (no behavioral docs)
- `drm_verinfo_major(v)` → (no behavioral docs)
- `drm_verinfo_minor(v)` → (no behavioral docs)
- `drm_verinfo_name(v)` → (no behavioral docs)
- `drm_verinfo_new(major, minor, patch, name, date, desc)` → +0: capability (u64)
- `drm_verinfo_patch(v)` → (no behavioral docs)


### error (src/error.cyr)

Structs: `SysErrorKind, Errno`.

- `err_from_errno(errno)` → Errno-based error creation — packed (zero alloc, hot path)
- `err_from_syscall_ret(ret)` → (no behavioral docs)
- `err_invalid_argument(message)` → Error constructors — with message (heap, cold path)
- `err_invalid_argument_nr()` → (no behavioral docs)
- `err_io(errno, message)` → (no behavioral docs)
- `err_module_not_loaded(module)` → (no behavioral docs)
- `err_not_supported(feature)` → (no behavioral docs)
- `err_not_supported_nr()` → (no behavioral docs)
- `err_permission_denied(operation)` → (no behavioral docs)
- `err_permission_denied_nr(errno)` → Error constructors — packed (fast, no alloc)
- `err_syscall_failed(errno, message)` → Error constructors — with message (heap, cold path)
- `err_syscall_failed_nr(errno)` → Get error message pointer (0 for packed errors)
- `err_unknown(message)` → (no behavioral docs)
- `err_would_block()` → (no behavioral docs)
- `is_syscall_err(ret)` → Propagate error: if res is Err, return it immediately.
- `result_print_err(res)` → Print error from a Result if it's Err, then return the error code.
- `syserr_errno(e)` → Get error kind (works for both packed and heap errors)
- `syserr_kind(e)` → Create a new error with message (heap-allocated, cold path)
- `syserr_message(e)` → Get errno value (works for both packed and heap errors)
- `syserr_new(kind, errno, message)` → Heap error:   pointer to { kind, errno, message_ptr } (24 bytes, value
- `syserr_pack(kind, errno)` → Error representation — dual encoding
- `syserr_print(e)` → Error printing
- `wrap_syscall(ret)` → var res = some_call();


### fuse (src/fuse.cyr)

Structs: `FuseStatus`.

- `fuse_extract_field(line, linelen, field_idx)` → Extract a whitespace-delimited field from a line.
- `fuse_get_status(mountpoint)` → FuseStatus constants
- `fuse_is_available()` → FUSE availability check
- `fuse_list_mounts()` → List FUSE mounts (convenience wrapper)
- `fuse_mount(device, mountpoint, fuse_type, extra_opts)` → Mount FUSE filesystem
- `fuse_mount_device(m)` → (no behavioral docs)
- `fuse_mount_fstype(m)` → (no behavioral docs)
- `fuse_mount_mountpoint(m)` → (no behavioral docs)
- `fuse_mount_new(device, mountpoint, fstype, options)` → Requires: src/error.cyr, lib/syscalls.cyr, lib/process.cyr
- `fuse_mount_options(m)` → (no behavioral docs)
- `fuse_parse_proc_mounts(result_arr, max_mounts, fuse_only)` → Parse /proc/mounts and return FUSE mounts.
- `fuse_starts_with(str, prefix)` → Parse /proc/mounts
- `fuse_unmount(mountpoint)` → Unmount FUSE filesystem
- `fuse_unmount_lazy(mountpoint)` → Lazy unmount (fallback)
- `fuse_validate_mountpoint(path)` → Mountpoint validation


### ima (src/ima.cyr)

Structs: `ImaAction, ImaTarget`.

- `ima_action_str(action)` → String representations
- `ima_get_status()` → Get IMA status
- `ima_is_hex_char(ch)` → ImaPolicyRule validation
- `ima_measurement_filedata_hash(m)` → (no behavioral docs)
- `ima_measurement_filename(m)` → (no behavioral docs)
- `ima_measurement_new(pcr, template_hash, template_name, filedata_hash, filename)` → ImaMeasurement struct
- `ima_measurement_pcr(m)` → (no behavioral docs)
- `ima_measurement_template_hash(m)` → (no behavioral docs)
- `ima_measurement_template_name(m)` → (no behavioral docs)
- `ima_parse_measurements(content)` → Parse IMA measurements from a buffer
- `ima_read_measurements()` → Read IMA measurements from the kernel's measurement file
- `ima_rule_action(r)` → (no behavioral docs)
- `ima_rule_fowner(r)` → (no behavioral docs)
- `ima_rule_fsuuid(r)` → (no behavioral docs)
- `ima_rule_mask(r)` → (no behavioral docs)
- `ima_rule_new(action, target)` → ImaPolicyRule struct
- `ima_rule_obj_type(r)` → (no behavioral docs)
- `ima_rule_set_fowner(r, fowner)` → (no behavioral docs)
- `ima_rule_set_fsuuid(r, fsuuid)` → (no behavioral docs)
- `ima_rule_set_mask(r, mask)` → (no behavioral docs)
- `ima_rule_set_obj_type(r, obj_type)` → (no behavioral docs)
- `ima_rule_set_uid(r, uid)` → (no behavioral docs)
- `ima_rule_target(r)` → (no behavioral docs)
- `ima_rule_to_policy_line(rule)` → Render a rule as a policy line
- `ima_rule_uid(r)` → (no behavioral docs)
- `ima_rule_validate(rule)` → Validate a single rule. Returns Ok(0) or Err.
- `ima_status_active(s)` → (no behavioral docs)
- `ima_status_measurement_count(s)` → (no behavioral docs)
- `ima_status_new(active, measurement_count, policy_loaded)` → ImaStatus struct
- `ima_status_policy_loaded(s)` → (no behavioral docs)
- `ima_target_str(target)` → (no behavioral docs)
- `ima_verify_file_integrity(path)` → Verify file integrity via xattr (security.ima)
- `ima_write_policy(rules)` → Write IMA policy to the kernel (append-only!)


### journald (src/journald.cyr)

Structs: `JournalConst, JournalPriority`.

- `journald_build_args(filter)` → Build journalctl argument string
- `journald_debug(message)` → Send an error-level message to the journal.
- `journald_entry_add_field(e, key, val)` → Add an extra field (key-value pair) to a journal entry
- `journald_entry_field_keys(e)` → (no behavioral docs)
- `journald_entry_field_vals(e)` → (no behavioral docs)
- `journald_entry_message(e)` → (no behavioral docs)
- `journald_entry_new(timestamp, unit, priority, message, pid)` → JournalEntry struct
- `journald_entry_pid(e)` → (no behavioral docs)
- `journald_entry_priority(e)` → (no behavioral docs)
- `journald_entry_timestamp(e)` → (no behavioral docs)
- `journald_entry_unit(e)` → (no behavioral docs)
- `journald_error(message)` → Send a warning-level message to the journal.
- `journald_filter_boot(f)` → (no behavioral docs)
- `journald_filter_grep(f)` → (no behavioral docs)
- `journald_filter_lines(f)` → (no behavioral docs)
- `journald_filter_new()` → JournalFilter struct
- `journald_filter_priority(f)` → (no behavioral docs)
- `journald_filter_set_boot(f, boot)` → (no behavioral docs)
- `journald_filter_set_grep(f, grep)` → (no behavioral docs)
- `journald_filter_set_lines(f, lines)` → (no behavioral docs)
- `journald_filter_set_priority(f, prio)` → (no behavioral docs)
- `journald_filter_set_since(f, since)` → (no behavioral docs)
- `journald_filter_set_unit(f, unit)` → (no behavioral docs)
- `journald_filter_set_until(f, until)` → (no behavioral docs)
- `journald_filter_since(f)` → (no behavioral docs)
- `journald_filter_unit(f)` → (no behavioral docs)
- `journald_filter_until(f)` → (no behavioral docs)
- `journald_get_unit_logs(unit_name, lines)` → Convenience: get last N log entries for a unit
- `journald_info(message)` → Convenience: send info-level log
- `journald_json_get_str(json, key)` → Parse a single JSON line from journalctl --output=json
- `journald_make_sockaddr()` → Send structured log message to journald via unix socket
- `journald_parse_json(json_line)` → Parse a single JSON line from journalctl output into a JournalEntry.
- `journald_query(filter)` → Query journal via journalctl subprocess
- `journald_send(message, priority, identifier)` → Send a structured log message to the journald socket.
- `journald_send_fields(message, priority, identifier, fields_keys, fields_vals)` → Send a structured log with extra key-value fields.
- `journald_warning(message)` → Send an info-level message to the journal.


### logging (src/logging.cyr)

Structs: `LogLevel`.

- `log_debug(message)` → Convenience functions
- `log_error(message)` → Convenience functions
- `log_get_level()` → Skip to next null byte
- `log_info(message)` → Convenience functions
- `log_init_from_env()` → Global log level (module-level state)
- `log_level_prefix(level)` → Log level prefix strings
- `log_msg(level, message)` → Core logging function
- `log_msg_kv(level, message, key, value)` → Log a message with a key=value context pair.
- `log_set_level(level)` → (no behavioral docs)
- `log_trace(message)` → Write newline
- `log_warn(message)` → Convenience functions


### luks (src/luks.cyr)

Structs: `LuksFilesystem, LuksPbkdf, LuksConst`.

- `luks_cipher_str(config)` → Zeroize key material in memory
- `luks_close(name)` → Close (lock) a LUKS volume. Closes the dm-crypt mapping.
- `luks_config_alloc()` → LuksConfig struct
- `luks_config_backing_path(c)` → (no behavioral docs)
- `luks_config_cipher_algo(c)` → (no behavioral docs)
- `luks_config_cipher_mode(c)` → (no behavioral docs)
- `luks_config_default(name, backing_path, mount_point)` → Create a default config with sensible defaults (AES-XTS, 512-bit, Argo
- `luks_config_filesystem(c)` → (no behavioral docs)
- `luks_config_key_size_bits(c)` → (no behavioral docs)
- `luks_config_mount_point(c)` → (no behavioral docs)
- `luks_config_name(c)` → (no behavioral docs)
- `luks_config_pbkdf(c)` → (no behavioral docs)
- `luks_config_set_core(c, name, backing_path, size_mb, mount_point, filesystem)` → key_size_bits(+56) pbkdf(+64)
- `luks_config_set_crypto(c, cipher_algo, cipher_mode, key_size_bits, pbkdf)` → (no behavioral docs)
- `luks_config_size_mb(c)` → (no behavioral docs)
- `luks_config_validate(config)` → Validate a LuksConfig. Returns Ok(0) or Err.
- `luks_format(config, key_ptr, key_len)` → Format a LUKS2 encrypted volume.
- `luks_fs_as_str(fs)` → Filesystem string helpers
- `luks_fs_mkfs_cmd(fs)` → Filesystem string helpers
- `luks_generate_key(size)` → Key generation via getrandom(2)
- `luks_is_name_char(ch)` → Validation helpers
- `luks_keyfile_path()` → Keyfile helpers — per-PID temp file for key material
- `luks_mkfs(device, filesystem)` → Create a filesystem on a device.
- `luks_mount(device, mount_point, filesystem)` → Mount a device at a mount point.
- `luks_open(config, key_ptr, key_len)` → Open (unlock) a LUKS volume. Maps to /dev/mapper/{name}.
- `luks_pbkdf_as_str(pbkdf)` → (no behavioral docs)
- `luks_run_capture(args, buf, buflen)` → LUKS operations — shells out to cryptsetup, losetup, etc.
- `luks_run_checked(args)` → Helper: build argv vec and run with exec_capture, return Ok(bytes_read
- `luks_unmount(mount_point)` → Unmount a mount point.
- `luks_write_keyfile(key_ptr, key_len)` → Write key material to a per-PID keyfile.
- `luks_zeroize_key(key_ptr, size)` → Zeroize key material in memory


### mac (src/mac.cyr)

Structs: `MacSystem, SELinuxMode, AppArmorState`.

- `mac_apparmor_change_profile(profile_name)` → Change the AppArmor profile of the current process
- `mac_apply_agent_profile(agent_type, profiles, profile_count)` → Apply agent MAC profile based on detected MAC system
- `mac_default_profile(agent_type)` → Create a default agent MAC profile from an agent type string
- `mac_detect_system()` → F_OK = 0
- `mac_file_exists(path)` → File existence check — returns 1 if file exists, 0 otherwise
- `mac_get_apparmor_mode()` → Get the current AppArmor mode/profile of this process
- `mac_get_selinux_context()` → Get the current SELinux security context of this process
- `mac_get_selinux_mode()` → SELinux mode query
- `mac_profile_agent_type(p)` → (no behavioral docs)
- `mac_profile_apparmor_name(p)` → (no behavioral docs)
- `mac_profile_new(agent_type)` → Agent MAC profile struct
- `mac_profile_selinux_ctx(p)` → (no behavioral docs)
- `mac_profile_set_apparmor_name(p, name)` → (no behavioral docs)
- `mac_profile_set_selinux_ctx(p, ctx)` → (no behavioral docs)
- `mac_profile_validate(profile, mac_system)` → Validate an agent MAC profile for a given MAC system
- `mac_read_file(path)` → File read helper — read a small file into a Str
- `mac_set_selinux_context(context, on_exec)` → Set the SELinux security context for this process
- `mac_set_selinux_mode(mode)` → Set SELinux enforcement mode
- `mac_write_file(path, data, data_len)` → Create Str from buffer


### netns (src/netns.cyr)

Structs: `TrafficDir, NetProtocol, FwAction`.

- `netns_fw_policy_default_in(p)` → (no behavioral docs)
- `netns_fw_policy_default_out(p)` → (no behavioral docs)
- `netns_fw_policy_new(default_in, default_out)` → FirewallPolicy struct
- `netns_fw_policy_rule_count(p)` → (no behavioral docs)
- `netns_fw_policy_rules(p)` → (no behavioral docs)
- `netns_fw_policy_set_rules(p, rules_arr, count)` → (no behavioral docs)
- `netns_fw_rule_action(r)` → (no behavioral docs)
- `netns_fw_rule_comment(r)` → (no behavioral docs)
- `netns_fw_rule_direction(r)` → (no behavioral docs)
- `netns_fw_rule_new(direction, protocol, port, remote_addr, action, comment)` → FirewallRule struct
- `netns_fw_rule_port(r)` → (no behavioral docs)
- `netns_fw_rule_protocol(r)` → (no behavioral docs)
- `netns_fw_rule_remote_addr(r)` → (no behavioral docs)
- `netns_apply_nftables_ruleset(handle, ruleset)` → Apply nftables ruleset to a namespace
- `netns_concat2(a, b)` → Build a string by concatenating parts
- `netns_concat3(a, b, c)` → (no behavioral docs)
- `netns_config_agent_ip(c)` → (no behavioral docs)
- `netns_config_enable_nat(c)` → (no behavioral docs)
- `netns_config_for_agent(name)` → Create convenience config for an agent
- `netns_config_host_ip(c)` → (no behavioral docs)
- `netns_config_name(c)` → (no behavioral docs)
- `netns_config_new(name, agent_ip, host_ip, prefix_len, enable_nat)` → NetNamespaceConfig struct
- `netns_config_prefix_len(c)` → (no behavioral docs)
- `netns_config_set_dns(c, dns_arr, dns_count)` → (no behavioral docs)
- `netns_create_agent_netns(config)` → Create agent network namespace
- `netns_destroy_agent_netns(handle)` → Destroy agent network namespace
- `netns_generate_agent_ips(agent_name)` → Make positive
- `netns_handle_name(h)` → (no behavioral docs)
- `netns_handle_netns_path(h)` → (no behavioral docs)
- `netns_handle_new(name, veth_host, veth_agent, netns_path)` → NetNamespaceHandle struct
- `netns_handle_veth_agent(h)` → (no behavioral docs)
- `netns_handle_veth_host(h)` → (no behavioral docs)
- `netns_hash_name(name)` → IP address generation from agent name hash
- `netns_render_nftables_ruleset(policy)` → Render a FirewallPolicy into an nftables ruleset string.
- `netns_run_ip(argv)` → Helper: run ip command
- `netns_truncate_veth(base)` → Truncate veth name to 15 chars (Linux max)
- `netns_validate_config(config)` → Validate namespace config
- `netns_nft_action_str(action)` → Helper to append a string to a buffer, return new position.
- `netns_nft_append(buf, pos, str)` → Render nftables ruleset from FirewallPolicy
- `netns_nft_proto_str(proto)` → (no behavioral docs)


### pam (src/pam.cyr)

Structs: `PamServiceId, PamRuleTypeId, PamControlId`.

- `pam_control_name(c)` → (no behavioral docs)
- `pam_get_user_info(username)` → Get user info by username
- `pam_list_services()` → List PAM services (read /etc/pam.d/ directory)
- `pam_list_sessions()` → List active sessions via who command
- `pam_list_users()` → List users from /etc/passwd
- `pam_parse_config(content)` → Parse PAM config file content
- `pam_parse_control(s)` → Parse control flag from Str. Returns control id or -1 on error.
- `pam_parse_passwd_line(line)` → Parse a single /etc/passwd line into a UserInfo struct
- `pam_parse_rule_type(s)` → Parse rule type from Str. Returns type id or -1 on error.
- `pam_parse_who_output(output)` → Parse who output into a vec of SessionInfo
- `pam_read_service_config(service_name)` → Read and parse a PAM service config file
- `pam_render_config(rules)` → Render a full PAM config from a vec of PamRule pointers.
- `pam_render_rule(rule)` → Render PAM rule to string
- `pam_rule_args(r)` → (no behavioral docs)
- `pam_rule_control(r)` → (no behavioral docs)
- `pam_rule_module(r)` → (no behavioral docs)
- `pam_rule_new(rule_type, control, module, args)` → PamRule struct: { rule_type, control, module (Str), args (vec of Str) 
- `pam_rule_type(r)` → (no behavioral docs)
- `pam_rule_type_name(t)` → PAM rule type constants
- `pam_service_name(svc_id)` → Get the config filename for a PAM service ID.
- `pam_session_id(s)` → (no behavioral docs)
- `pam_session_login_time(s)` → (no behavioral docs)
- `pam_session_new(session_id, user, login_time, tty, remote_host, pid)` → SessionInfo struct: { session_id (Str), user (Str), login_time (Str),
- `pam_session_pid(s)` → (no behavioral docs)
- `pam_session_remote_host(s)` → (no behavioral docs)
- `pam_session_tty(s)` → (no behavioral docs)
- `pam_session_user(s)` → (no behavioral docs)
- `pam_split_whitespace(s)` → Split a Str by whitespace (space/tab), skipping consecutive whitespace
- `pam_user_alloc()` → UserInfo struct: { username (Str), uid, gid, home_dir (Str),
- `pam_user_gid(u)` → (no behavioral docs)
- `pam_user_groups(u)` → (no behavioral docs)
- `pam_user_home(u)` → (no behavioral docs)
- `pam_user_is_system(u)` → (no behavioral docs)
- `pam_user_set(u, username, uid, gid, home_dir, shell)` → Layout: +0 username, +8 uid, +16 gid, +24 home_dir,
- `pam_user_set_groups(u, groups, is_system)` → (no behavioral docs)
- `pam_user_shell(u)` → (no behavioral docs)
- `pam_user_uid(u)` → (no behavioral docs)
- `pam_user_username(u)` → (no behavioral docs)
- `pam_validate_rule(rule)` → Validate a PAM rule
- `pam_validate_username(name)` → Username validation


### secureboot (src/secureboot.cyr)

Structs: `SecureBootState`.

- `secureboot_detect_state()` → Secure Boot state detection
- `secureboot_efi_var_data_size(v)` → 2 fields * 8 = 16 bytes
- `secureboot_efi_var_name(v)` → Layout: { name, size }
- `secureboot_efi_var_new(name, size)` → EFI variable listing
- `secureboot_efi_var_payload_byte(data, index)` → Return the buffer with read count in a result struct
- `secureboot_efi_var_size(data)` → Get the payload byte at index (after the 4-byte attributes header).
- `secureboot_enroll_key(der_path)` → MOK key enrollment
- `secureboot_enrolled_key_new(subject, issuer, fingerprint, not_before, not_after)` → EnrolledKey struct
- `secureboot_is_enforcing(state)` → mokutil not available, cannot determine
- `secureboot_key_fingerprint(k)` → (no behavioral docs)
- `secureboot_key_issuer(k)` → (no behavioral docs)
- `secureboot_key_not_after(k)` → (no behavioral docs)
- `secureboot_key_not_before(k)` → (no behavioral docs)
- `secureboot_key_subject(k)` → (no behavioral docs)
- `secureboot_list_efi_variables()` → List security-relevant EFI variables from sysfs.
- `secureboot_list_enrolled_keys()` → List enrolled MOK (Machine Owner Key) certificates.
- `secureboot_parse_mokutil_list(output, outlen)` → List enrolled MOK keys
- `secureboot_read_efi_variable(path)` → EFI variable reading
- `secureboot_sig_algorithm(s)` → (no behavioral docs)
- `secureboot_sig_has_sig(s)` → (no behavioral docs)
- `secureboot_sig_info_new(module_path, has_sig, signer, algo)` → Module signature verification
- `secureboot_sig_module(s)` → (no behavioral docs)
- `secureboot_sig_signer(s)` → (no behavioral docs)
- `secureboot_sign_module(module_path, private_key, certificate)` → Kernel module signing
- `secureboot_state_str(state)` → Helper: check if Secure Boot is enforcing
- `secureboot_verify_module(module_path)` → Verify a kernel module's signature using modinfo.


### security (src/security.cyr)

Structs: `LandlockConst, FsAccess, BpfConst, CloneFlag, NsFlag, SysNrNs`.

- `apply_landlock(rules, count)` → Apply Landlock filesystem restrictions
- `bpf_write_insn(buf, offset, code, jt, jf, k)` → Write a BPF sock_filter instruction (8 bytes) to buf at offset.
- `create_basic_seccomp_filter()` → Create a basic seccomp filter allowing safe syscalls.
- `create_namespace(flags)` → Create new namespace(s) with specified flags.
- `fs_rule_access(r)` → Filesystem rule: { path_ptr, access }
- `fs_rule_new(path, access)` → Filesystem access levels
- `fs_rule_path(r)` → Filesystem rule: { path_ptr, access }
- `fs_rule_read_only(path)` → (no behavioral docs)
- `fs_rule_read_write(path)` → (no behavioral docs)
- `load_seccomp(filter, filter_len)` → Load a seccomp-BPF filter into the calling process.
- `seccomp_filter_len(info)` → Get filter pointer from create_basic_seccomp_filter result
- `seccomp_filter_ptr(info)` → Insn 22: ALLOW
- `syscall_map_reset()` → Syscall name to number mapping (hashmap, O(1) lookup)
- `syscall_name_to_nr(name)` → Map a syscall name to its x86_64 number. Returns -1 if not found.


### syscall (src/syscall.cyr)

Structs: `SysNrExt, SysInfoOffset, SysInfoConst, UtsOffset, UtsConst`.

- `agnosys_free_memory()` → Get total system memory in bytes. Returns Result.
- `agnosys_geteuid()` → Get the current user ID.
- `agnosys_getpid()` → Process identity
- `agnosys_gettid()` → Process identity
- `agnosys_getuid()` → Get the current thread ID.
- `agnosys_is_root()` → Get the current effective user ID.
- `agnosys_total_memory()` → Get system uptime in seconds. Returns Result.
- `agnosys_uname(out)` → Query uname(2) into a caller-provided buffer.
- `agnosys_uptime()` → Get number of running processes from a sysinfo pointer.
- `agnosys_checked_syscall(ret)` → Checked syscall — wraps raw syscall with Result error handling
- `query_sysinfo(out)` → Query sysinfo(2) into a caller-provided buffer.
- `sysinfo_free_memory(info)` → Saturating multiply: if either is 0 or result would overflow, cap it
- `sysinfo_procs(info)` → Get number of running processes from a sysinfo pointer.
- `sysinfo_total_memory(info)` → Get uptime in seconds from a sysinfo pointer.
- `sysinfo_uptime(info)` → Returns Result: Ok(out) or Err(syserr). Zero heap allocation on succes
- `uname_hostname(uts)` → Returns Result: Ok(out) or Err. All uts fields accessible via offsets.
- `uname_machine(uts)` → Get kernel release from a utsname buffer.
- `uname_release(uts)` → Get hostname from a utsname buffer.


### tpm (src/tpm.cyr)

Structs: `TpmPcrBank, TpmConst`.

- `tpm_bank_hex_len(bank)` → (no behavioral docs)
- `tpm_bank_str(bank)` → PCR bank helpers
- `tpm_detect()` → TPM device detection
- `tpm_extend_pcr(bank, index, hash)` → Extend a PCR with a measurement hash
- `tpm_get_random(buf, count)` → Get hardware random bytes from the TPM
- `tpm_pcr_selection(bank, indices)` → Build PCR selection string: "sha256:0,1,7"
- `tpm_pcr_value_bank(v)` → (no behavioral docs)
- `tpm_pcr_value_index(v)` → (no behavioral docs)
- `tpm_pcr_value_new(index, bank, value)` → TpmPcrValue struct
- `tpm_pcr_value_value(v)` → (no behavioral docs)
- `tpm_read_pcr(bank, indices)` → Read PCR values
- `tpm_run_capture(args, buf, buflen)` → Helper: run tpm2-tools command
- `tpm_run_checked(args)` → (no behavioral docs)
- `tpm_seal(bank, pcr_indices, data_ptr, data_len, output_dir)` → Seal data to specific PCR state
- `tpm_sealed_context(s)` → Total: 16 bytes
- `tpm_sealed_new(context_path, pcr_selection)` → SealedSecret struct
- `tpm_sealed_pcr_sel(s)` → (no behavioral docs)
- `tpm_unseal(sealed, buf, buflen)` → Unseal a secret — only succeeds if PCR values match policy
- `tpm_verify_measured_boot(expected)` → Verify measured boot against known-good baseline


### udev (src/udev.cyr)

Structs: `DeviceSubsystem`.

- `udev_devinfo_devnode(d)` → (no behavioral docs)
- `udev_devinfo_devpath(d)` → Layout: 9 * 8 = 72 bytes
- `udev_devinfo_devtype(d)` → (no behavioral docs)
- `udev_devinfo_driver(d)` → (no behavioral docs)
- `udev_devinfo_new()` → DeviceInfo struct
- `udev_devinfo_prop_count(d)` → (no behavioral docs)
- `udev_devinfo_prop_keys(d)` → (no behavioral docs)
- `udev_devinfo_prop_vals(d)` → (no behavioral docs)
- `udev_devinfo_set_devnode(d, v)` → (no behavioral docs)
- `udev_devinfo_set_devpath(d, v)` → (no behavioral docs)
- `udev_devinfo_set_devtype(d, v)` → (no behavioral docs)
- `udev_devinfo_set_driver(d, v)` → (no behavioral docs)
- `udev_devinfo_set_props(d, keys, vals, count)` → (no behavioral docs)
- `udev_devinfo_set_subsystem(d, v)` → (no behavioral docs)
- `udev_devinfo_set_syspath(d, v)` → (no behavioral docs)
- `udev_devinfo_subsystem(d)` → prop_keys and prop_vals are arrays of string pointers
- `udev_devinfo_syspath(d)` → devnode, prop_keys, prop_vals, prop_count }
- `udev_get_device_info(syspath)` → Get device info for a single device by sysfs path
- `udev_list_devices(subsystem_filter, result_arr, max_devices)` → List devices via udevadm info --export-db
- `udev_parse_subsystem(s)` → Parse a subsystem string into a constant
- `udev_parse_udevadm_info(text)` → Parse udevadm info output for a single device
- `udev_starts_with(str, prefix)` → Udev rule validation
- `udev_validate_rule(action_keys, action_count)` → Validate a udev rule.


### update (src/update.cyr)

Structs: `UpdateSlot, UpdatePhase, UpdateChannel`.

- `update_apply(config, manifest)` → Up to date
- `update_atomic_copy(src, dst)` → Atomic file copy
- `update_atomic_write(path, data, data_len)` → Atomic file write
- `update_channel_str(channel)` → Update channel constants
- `update_check(config, current_version)` → Check for available update by reading a local manifest file.
- `update_compare_versions(a, b)` → Version comparison
- `update_config_backup_dir(c)` → (no behavioral docs)
- `update_config_device_for_slot(c, slot)` → (no behavioral docs)
- `update_config_max_retries(c)` → (no behavioral docs)
- `update_config_new()` → UpdateConfig struct
- `update_config_slot_a(c)` → (no behavioral docs)
- `update_config_slot_b(c)` → (no behavioral docs)
- `update_config_state_file(c)` → (no behavioral docs)
- `update_config_url(c)` → (no behavioral docs)
- `update_config_verify(c)` → (no behavioral docs)
- `update_file_compressed(f)` → (no behavioral docs)
- `update_file_delta_from(f)` → (no behavioral docs)
- `update_file_new(path, sha256, size_bytes)` → UpdateFile struct
- `update_file_path(f)` → (no behavioral docs)
- `update_file_sha256(f)` → (no behavioral docs)
- `update_file_size(f)` → (no behavioral docs)
- `update_get_current_slot()` → Slot detection
- `update_load_state(path)` → Load update state from a JSON file.
- `update_manifest_changelog(m)` → (no behavioral docs)
- `update_manifest_channel(m)` → (no behavioral docs)
- `update_manifest_files(m)` → (no behavioral docs)
- `update_manifest_min_version(m)` → (no behavioral docs)
- `update_manifest_new(version, channel, release_date)` → UpdateManifest struct
- `update_manifest_release_date(m)` → (no behavioral docs)
- `update_manifest_version(m)` → (no behavioral docs)
- `update_mark_boot_successful(config)` → Boot confirmation
- `update_needs_rollback(state, max_boot_attempts)` → Pure function: returns 1 if boot count exceeds max_attempts
- `update_other_slot(slot)` → Update slot helpers
- `update_parse_version(version)` → Version validation (CalVer YYYY.M.D)
- `update_phase_str(phase)` → (no behavioral docs)
- `update_rollback(config)` → Rollback
- `update_save_state(state, path)` → Default to slot A
- `update_slot_str(slot)` → (no behavioral docs)
- `update_slot_suffix(slot)` → Update slot helpers
- `update_state_boot_count(s)` → (no behavioral docs)
- `update_state_new(slot, version)` → UpdateState struct
- `update_state_pending(s)` → (no behavioral docs)
- `update_state_rollback_available(s)` → (no behavioral docs)
- `update_state_set_boot_count(s, n)` → (no behavioral docs)
- `update_state_set_pending(s, ver)` → (no behavioral docs)
- `update_state_set_rollback(s, val)` → (no behavioral docs)
- `update_state_set_slot(s, slot)` → (no behavioral docs)
- `update_state_slot(s)` → (no behavioral docs)
- `update_state_version(s)` → (no behavioral docs)
- `update_switch_slot(config, slot)` → Switch active slot
- `update_validate_version(version)` → Validate a CalVer version string (YYYY.M.D).
- `update_verify_manifest(manifest)` → Manifest validation


## Outliers (review before freeze)

All resolved before 1.0 — every public function now carries its module prefix.

| Scope | Before | After | Fns |
|-------|--------|-------|----:|
| certpin cert-info accessors | `certinfo_*` | `certpin_info_*` | 15 |
| security module (full sweep) | `fs_rule_*`, `apply_landlock`, `bpf_write_insn`, `load_seccomp`, `create_basic_seccomp_filter`, `seccomp_filter_*`, `create_namespace`, `syscall_map_reset`, `syscall_name_to_nr` | `security_*` | 14 |
| journald entry/query accessors | `journal_*` | `journald_*` | 36 |
| dmverity accessors | `verity_*` | `dmverity_*` | 32 |
| bootloader entry/config accessors | `boot_entry_*`, `boot_config_*` | `bootloader_entry_*`, `bootloader_config_*` | 25 |
| netns firewall + nftables helpers | `fw_*`, `nft_*` | `netns_fw_*`, `netns_nft_*` | 16 |
| syscall module | `checked_syscall` | `agnosys_checked_syscall` | 1 |
| **Total** | | | **139** |

All renames landed in `[Unreleased]`.

## Design notes

- **No functions exceed the 7-parameter limit**, so no refactoring required on that front.
- **All modules follow the module-prefix convention**: `audit_`, `bootloader_`, `certpin_`, `dmverity_`, `drm_`, `fuse_`, `ima_`, `journald_`, `logging_`/`log_`, `luks_`, `mac_`, `netns_`, `pam_`, `secureboot_`, `security_`, `tpm_`, `udev_`, `update_`, plus `agnosys_`/`sysinfo_`/`uname_`/`query_` in syscall.cyr and `syserr_`/`err_`/`is_`/`result_`/`Ok`/`Err`/etc. in error.cyr.
- **Error conventions**: packed `syserr_pack()` / heap `syserr_new()`, Result tagged union via `Ok(...)` / `Err(...)`.

- **Result convention**: Syscall wrappers return Result via `Ok/Err`. Getters (e.g., `load64` accessors) return raw values; that's fine.
