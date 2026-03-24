//! Seccomp-BPF — syscall filtering.
//!
//! Safe Rust bindings for the Linux seccomp(2) interface. Build a BPF
//! filter program with [`FilterBuilder`], then call [`load`] to enforce it.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::seccomp::{FilterBuilder, Action};
//!
//! let filter = FilterBuilder::new(Action::KillProcess)
//!     .allow_syscall(libc::SYS_read)
//!     .allow_syscall(libc::SYS_write)
//!     .allow_syscall(libc::SYS_exit_group)
//!     .allow_syscall(libc::SYS_brk)
//!     .build();
//!
//! agnosys::seccomp::load(&filter).unwrap();
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;

// ── Constants ───────────────────────────────────────────────────────

// seccomp operations
const SECCOMP_SET_MODE_STRICT: libc::c_uint = 0;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;

// seccomp filter flags
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_LOG: libc::c_ulong = 1 << 1;

// Return actions (top 16 bits)
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const SECCOMP_RET_DATA: u32 = 0x0000_FFFF;

// BPF instruction components
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

// seccomp_data field offsets
const OFFSET_NR: u32 = 0; // offsetof(seccomp_data, nr)
const OFFSET_ARCH: u32 = 4; // offsetof(seccomp_data, arch)

// Architecture audit constant
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

// ── BPF instruction helper ─────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *const SockFilter,
}

#[inline]
const fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[inline]
const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

// ── Public types ────────────────────────────────────────────────────

/// Action to take when a syscall matches (or doesn't match) a filter rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Allow the syscall.
    Allow,
    /// Kill the entire process.
    KillProcess,
    /// Kill just the calling thread.
    KillThread,
    /// Send SIGSYS to the thread.
    Trap,
    /// Return an errno value to the caller.
    Errno(u16),
    /// Notify a ptrace tracer.
    Trace(u16),
    /// Allow but log the syscall.
    Log,
}

impl Action {
    /// Convert to the seccomp return value.
    #[inline]
    #[must_use]
    const fn to_ret(self) -> u32 {
        match self {
            Self::Allow => SECCOMP_RET_ALLOW,
            Self::KillProcess => SECCOMP_RET_KILL_PROCESS,
            Self::KillThread => SECCOMP_RET_KILL_THREAD,
            Self::Trap => SECCOMP_RET_TRAP,
            Self::Errno(e) => SECCOMP_RET_ERRNO | (e as u32 & SECCOMP_RET_DATA),
            Self::Trace(d) => SECCOMP_RET_TRACE | (d as u32 & SECCOMP_RET_DATA),
            Self::Log => SECCOMP_RET_LOG,
        }
    }
}

/// A compiled seccomp-BPF filter program ready to be loaded.
pub struct Filter {
    instructions: Vec<SockFilter>,
}

impl Filter {
    /// Number of BPF instructions in this filter.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Whether the filter is empty (no instructions).
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

/// Builder for seccomp-BPF filters.
///
/// Uses an allowlist approach: specify a default action for unmatched syscalls,
/// then add exceptions for specific syscall numbers.
pub struct FilterBuilder {
    default_action: Action,
    rules: Vec<(libc::c_long, Action)>,
}

impl FilterBuilder {
    /// Create a new filter builder with the given default action for unmatched syscalls.
    ///
    /// The recommended default is [`Action::KillProcess`] for maximum security,
    /// or [`Action::Errno(libc::EPERM as u16)`] for graceful denial.
    #[must_use]
    pub fn new(default_action: Action) -> Self {
        Self {
            default_action,
            rules: Vec::new(),
        }
    }

    /// Allow a specific syscall number.
    #[must_use]
    pub fn allow_syscall(mut self, nr: libc::c_long) -> Self {
        self.rules.push((nr, Action::Allow));
        self
    }

    /// Apply a custom action to a specific syscall number.
    #[must_use]
    pub fn on_syscall(mut self, nr: libc::c_long, action: Action) -> Self {
        self.rules.push((nr, action));
        self
    }

    /// Compile the filter into a loadable BPF program.
    ///
    /// The generated program:
    /// 1. Validates the architecture matches the compile target
    /// 2. Checks the syscall number against each rule
    /// 3. Falls through to the default action
    ///
    /// # Panics
    ///
    /// Panics if more than 254 rules are added (BPF jump offset limit).
    #[must_use]
    pub fn build(self) -> Filter {
        assert!(
            self.rules.len() <= 254,
            "seccomp filter cannot have more than 254 rules (BPF u8 jump offset limit)"
        );
        let rule_count = self.rules.len();
        let mut insns = Vec::with_capacity(4 + rule_count * 2);

        // 1. Load architecture
        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH));

        // 2. Verify architecture — if mismatch, kill process
        insns.push(bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            AUDIT_ARCH_NATIVE,
            1, // jt: skip to next instruction (arch OK)
            0, // jf: fall through to kill
        ));
        insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

        // 3. Load syscall number
        insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));

        // 4. Check each rule
        for (i, (nr, _action)) in self.rules.iter().enumerate() {
            let remaining = rule_count - i - 1;
            insns.push(bpf_jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                *nr as u32,
                (remaining as u8).saturating_add(1), // jt: jump to this rule's return
                0,                                   // jf: check next rule
            ));
        }

        // 5. Default action (no rule matched)
        insns.push(bpf_stmt(BPF_RET | BPF_K, self.default_action.to_ret()));

        // 6. Return actions for each matched rule (in reverse order)
        for (_nr, action) in self.rules.iter().rev() {
            insns.push(bpf_stmt(BPF_RET | BPF_K, action.to_ret()));
        }

        Filter {
            instructions: insns,
        }
    }
}

// ── Loading ─────────────────────────────────────────────────────────

/// Set `PR_SET_NO_NEW_PRIVS` on the calling thread.
///
/// Required before loading a seccomp filter without `CAP_SYS_ADMIN`.
#[inline]
pub fn set_no_new_privs() -> Result<()> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!("prctl(PR_SET_NO_NEW_PRIVS) failed");
        Err(err)
    } else {
        Ok(())
    }
}

/// Load a seccomp-BPF filter on the calling thread.
///
/// Automatically sets `PR_SET_NO_NEW_PRIVS` first.
pub fn load(filter: &Filter) -> Result<()> {
    if filter.is_empty() {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "empty seccomp filter",
        )));
    }
    if filter.len() > 32768 {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "seccomp filter exceeds 32768 instruction limit",
        )));
    }

    set_no_new_privs()?;

    let prog = SockFprog {
        len: filter.instructions.len() as libc::c_ushort,
        filter: filter.instructions.as_ptr(),
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0u64, // flags
            &prog as *const SockFprog,
        )
    };

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        tracing::error!(errno, instructions = filter.len(), "seccomp load failed");
        Err(SysError::from_errno(errno))
    } else {
        tracing::info!(instructions = filter.len(), "seccomp filter loaded");
        Ok(())
    }
}

/// Load a seccomp filter synchronized across all threads in the process.
pub fn load_tsync(filter: &Filter) -> Result<()> {
    if filter.is_empty() {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "empty seccomp filter",
        )));
    }
    if filter.len() > 32768 {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "seccomp filter exceeds 32768 instruction limit",
        )));
    }

    set_no_new_privs()?;

    let prog = SockFprog {
        len: filter.instructions.len() as libc::c_ushort,
        filter: filter.instructions.as_ptr(),
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const SockFprog,
        )
    };

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        tracing::error!(errno, "seccomp tsync load failed");
        Err(SysError::from_errno(errno))
    } else {
        tracing::info!(instructions = filter.len(), "seccomp filter loaded (tsync)");
        Ok(())
    }
}

/// Load a seccomp filter with kernel-level logging of all filter actions.
pub fn load_logged(filter: &Filter) -> Result<()> {
    if filter.is_empty() {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "empty seccomp filter",
        )));
    }
    if filter.len() > 32768 {
        return Err(SysError::InvalidArgument(Cow::Borrowed(
            "seccomp filter exceeds 32768 instruction limit",
        )));
    }

    set_no_new_privs()?;

    let prog = SockFprog {
        len: filter.instructions.len() as libc::c_ushort,
        filter: filter.instructions.as_ptr(),
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_LOG,
            &prog as *const SockFprog,
        )
    };

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        tracing::error!(errno, "seccomp logged load failed");
        Err(SysError::from_errno(errno))
    } else {
        tracing::info!(
            instructions = filter.len(),
            "seccomp filter loaded (logged)"
        );
        Ok(())
    }
}

/// Enter strict seccomp mode (only read/write/_exit/sigreturn allowed).
pub fn strict_mode() -> Result<()> {
    let ret = unsafe { libc::prctl(libc::PR_SET_SECCOMP, SECCOMP_SET_MODE_STRICT) };
    if ret < 0 {
        let err = SysError::last_os_error();
        tracing::error!("seccomp strict mode failed");
        Err(err)
    } else {
        tracing::info!("seccomp strict mode enabled");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Filter>();
        assert_send_sync::<FilterBuilder>();
        assert_send_sync::<Action>();
    };

    // ── Action ──────────────────────────────────────────────────────

    #[test]
    fn action_allow_ret() {
        assert_eq!(Action::Allow.to_ret(), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn action_kill_process_ret() {
        assert_eq!(Action::KillProcess.to_ret(), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn action_kill_thread_ret() {
        assert_eq!(Action::KillThread.to_ret(), SECCOMP_RET_KILL_THREAD);
    }

    #[test]
    fn action_trap_ret() {
        assert_eq!(Action::Trap.to_ret(), SECCOMP_RET_TRAP);
    }

    #[test]
    fn action_errno_ret() {
        let ret = Action::Errno(libc::EPERM as u16).to_ret();
        assert_eq!(ret & !SECCOMP_RET_DATA, SECCOMP_RET_ERRNO);
        assert_eq!(ret & SECCOMP_RET_DATA, libc::EPERM as u32);
    }

    #[test]
    fn action_trace_ret() {
        let ret = Action::Trace(42).to_ret();
        assert_eq!(ret & !SECCOMP_RET_DATA, SECCOMP_RET_TRACE);
        assert_eq!(ret & SECCOMP_RET_DATA, 42);
    }

    #[test]
    fn action_log_ret() {
        assert_eq!(Action::Log.to_ret(), SECCOMP_RET_LOG);
    }

    // ── FilterBuilder ───────────────────────────────────────────────

    #[test]
    fn builder_empty_filter() {
        let filter = FilterBuilder::new(Action::KillProcess).build();
        // arch load + arch check + arch kill + nr load + default ret = 5
        assert_eq!(filter.len(), 5);
        assert!(!filter.is_empty());
    }

    #[test]
    fn builder_one_syscall() {
        let filter = FilterBuilder::new(Action::KillProcess)
            .allow_syscall(libc::SYS_read)
            .build();
        // arch(3) + nr load(1) + 1 check + default ret + 1 action ret = 7
        assert_eq!(filter.len(), 7);
    }

    #[test]
    fn builder_multiple_syscalls() {
        let filter = FilterBuilder::new(Action::Errno(1))
            .allow_syscall(libc::SYS_read)
            .allow_syscall(libc::SYS_write)
            .allow_syscall(libc::SYS_exit_group)
            .build();
        // arch(3) + nr(1) + 3 checks + default(1) + 3 returns = 11
        assert_eq!(filter.len(), 11);
    }

    #[test]
    fn builder_custom_action() {
        let filter = FilterBuilder::new(Action::KillProcess)
            .on_syscall(libc::SYS_openat, Action::Errno(libc::EACCES as u16))
            .build();
        assert_eq!(filter.len(), 7);
    }

    #[test]
    fn builder_chained() {
        let filter = FilterBuilder::new(Action::KillProcess)
            .allow_syscall(libc::SYS_read)
            .allow_syscall(libc::SYS_write)
            .on_syscall(libc::SYS_openat, Action::Log)
            .build();
        assert_eq!(filter.len(), 11);
    }

    // ── Filter validation ───────────────────────────────────────────

    #[test]
    fn load_rejects_empty() {
        let filter = Filter {
            instructions: vec![],
        };
        let err = load(&filter);
        assert!(err.is_err());
    }

    // ── set_no_new_privs ────────────────────────────────────────────

    #[test]
    fn set_no_new_privs_succeeds() {
        // Should always work in any process
        assert!(set_no_new_privs().is_ok());
    }

    // ── Architecture constant ───────────────────────────────────────

    #[test]
    fn audit_arch_is_set() {
        // Verify the constant is nonzero at runtime (value depends on target)
        let arch = AUDIT_ARCH_NATIVE;
        assert!(arch != 0);
    }

    // ── Filter accessors ──────────────────────────────────────────

    #[test]
    fn filter_len_and_is_empty() {
        let f = FilterBuilder::new(Action::Allow).build();
        assert!(!f.is_empty());
        assert!(!f.is_empty());
    }

    // ── load validation ────────────────────────────────────────────

    #[test]
    fn load_tsync_rejects_empty() {
        let filter = Filter {
            instructions: vec![],
        };
        assert!(load_tsync(&filter).is_err());
    }

    // ── Builder with various defaults ──────────────────────────────

    #[test]
    fn builder_default_allow() {
        let f = FilterBuilder::new(Action::Allow).build();
        assert_eq!(f.len(), 5);
    }

    #[test]
    fn builder_default_errno() {
        let f = FilterBuilder::new(Action::Errno(libc::EPERM as u16)).build();
        assert_eq!(f.len(), 5);
    }

    #[test]
    fn builder_default_log() {
        let f = FilterBuilder::new(Action::Log).build();
        assert_eq!(f.len(), 5);
    }

    #[test]
    fn builder_default_trap() {
        let f = FilterBuilder::new(Action::Trap).build();
        assert_eq!(f.len(), 5);
    }

    #[test]
    fn builder_default_kill_thread() {
        let f = FilterBuilder::new(Action::KillThread).build();
        assert_eq!(f.len(), 5);
    }

    // ── Rule limit ─────────────────────────────────────────────────

    #[test]
    fn builder_254_rules_ok() {
        let mut fb = FilterBuilder::new(Action::KillProcess);
        for i in 0..254 {
            fb = fb.allow_syscall(i);
        }
        let f = fb.build();
        // arch(3) + nr(1) + 254 checks + default(1) + 254 returns
        assert_eq!(f.len(), 3 + 1 + 254 + 1 + 254);
    }

    #[test]
    #[should_panic(expected = "BPF u8 jump offset limit")]
    fn builder_255_rules_panics() {
        let mut fb = FilterBuilder::new(Action::KillProcess);
        for i in 0..255 {
            fb = fb.allow_syscall(i);
        }
        let _ = fb.build();
    }

    // ── Action equality ─────────────────────────────────────────────

    #[test]
    fn action_eq() {
        assert_eq!(Action::Allow, Action::Allow);
        assert_ne!(Action::Allow, Action::KillProcess);
        assert_eq!(Action::Errno(1), Action::Errno(1));
        assert_ne!(Action::Errno(1), Action::Errno(2));
        assert_eq!(Action::Trace(5), Action::Trace(5));
        assert_ne!(Action::Trace(5), Action::Trace(6));
    }

    // ── Action clone/copy ──────────────────────────────────────────

    #[test]
    fn action_clone_copy() {
        let a = Action::Errno(42);
        let b = a; // Copy
        #[allow(clippy::clone_on_copy)]
        let c = a.clone(); // Clone
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    // ── Action debug ────────────────────────────────────────────────

    #[test]
    fn action_debug_all_variants() {
        assert!(format!("{:?}", Action::Allow).contains("Allow"));
        assert!(format!("{:?}", Action::KillProcess).contains("KillProcess"));
        assert!(format!("{:?}", Action::KillThread).contains("KillThread"));
        assert!(format!("{:?}", Action::Trap).contains("Trap"));
        assert!(format!("{:?}", Action::Errno(1)).contains("Errno"));
        assert!(format!("{:?}", Action::Trace(1)).contains("Trace"));
        assert!(format!("{:?}", Action::Log).contains("Log"));
    }

    // ── load_logged validation ──────────────────────────────────────

    #[test]
    fn load_logged_rejects_empty() {
        let filter = Filter {
            instructions: vec![],
        };
        assert!(load_logged(&filter).is_err());
    }

    // ── on_syscall action encoding ──────────────────────────────────

    #[test]
    fn on_syscall_with_all_actions() {
        // Verify all action types work in on_syscall
        let filter = FilterBuilder::new(Action::KillProcess)
            .on_syscall(libc::SYS_read, Action::Allow)
            .on_syscall(libc::SYS_write, Action::Errno(libc::EPERM as u16))
            .on_syscall(libc::SYS_openat, Action::Trap)
            .on_syscall(libc::SYS_close, Action::Log)
            .on_syscall(libc::SYS_stat, Action::Trace(1))
            .on_syscall(libc::SYS_fstat, Action::KillThread)
            .build();
        // 6 rules: arch(3) + nr(1) + 6 checks + default(1) + 6 returns = 17
        assert_eq!(filter.len(), 17);
    }

    // ── Builder with default trace ──────────────────────────────────

    #[test]
    fn builder_default_trace() {
        let f = FilterBuilder::new(Action::Trace(99)).build();
        assert_eq!(f.len(), 5);
    }
}
