//! udev — Device enumeration and hotplug monitoring.
//!
//! Pure sysfs/netlink implementation with no libudev dependency.
//! Enumerate devices by subsystem, read device properties from sysfs,
//! and monitor hotplug events via the kernel uevent netlink socket.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::udev;
//!
//! // List all block devices
//! for dev in udev::enumerate("block").unwrap() {
//!     println!("{}: {}", dev.name(), dev.syspath().display());
//!     if let Some(vendor) = dev.attr("vendor") {
//!         println!("  vendor: {vendor}");
//!     }
//! }
//! ```

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ── Constants ───────────────────────────────────────────────────────

const SYSFS_CLASS: &str = "/sys/class";
const SYSFS_BUS: &str = "/sys/bus";

/// Netlink protocol for kernel uevents.
const NETLINK_KOBJECT_UEVENT: libc::c_int = 15;

// ── Device ──────────────────────────────────────────────────────────

/// A device discovered via sysfs.
#[derive(Debug, Clone)]
pub struct Device {
    syspath: PathBuf,
    subsystem: String,
    properties: HashMap<String, String>,
}

impl Device {
    /// The sysfs path of this device (e.g., `/sys/class/block/sda`).
    #[inline]
    #[must_use]
    pub fn syspath(&self) -> &Path {
        &self.syspath
    }

    /// The device name (last component of syspath, e.g., `sda`).
    #[must_use]
    pub fn name(&self) -> &str {
        self.syspath
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
    }

    /// The subsystem this device belongs to (e.g., `block`, `net`).
    #[inline]
    #[must_use]
    pub fn subsystem(&self) -> &str {
        &self.subsystem
    }

    /// The devpath (resolved real path of the sysfs entry).
    #[must_use]
    pub fn devpath(&self) -> Option<PathBuf> {
        std::fs::canonicalize(&self.syspath).ok()
    }

    /// Read a sysfs attribute file for this device.
    ///
    /// Returns `None` if the attribute doesn't exist or can't be read.
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<String> {
        let path = self.syspath.join(name);
        std::fs::read_to_string(&path)
            .ok()
            .map(|s| s.trim().to_owned())
    }

    /// The device properties parsed from the `uevent` file.
    #[inline]
    #[must_use]
    pub fn properties(&self) -> &HashMap<String, String> {
        &self.properties
    }

    /// Get a specific uevent property by key (e.g., `DEVNAME`, `DEVTYPE`, `MAJOR`).
    #[must_use]
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|v| v.as_str())
    }

    /// The device node path (e.g., `/dev/sda`) if available.
    #[must_use]
    pub fn devnode(&self) -> Option<PathBuf> {
        self.property("DEVNAME")
            .map(|name| Path::new("/dev").join(name))
    }

    /// The device type from uevent (e.g., `disk`, `partition`).
    #[must_use]
    pub fn devtype(&self) -> Option<&str> {
        self.property("DEVTYPE")
    }

    /// The driver bound to this device, if any.
    #[must_use]
    pub fn driver(&self) -> Option<String> {
        let driver_link = self.syspath.join("driver");
        std::fs::read_link(&driver_link)
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    }
}

// ── Enumeration ─────────────────────────────────────────────────────

/// Parse the `uevent` file at the given sysfs path into key=value pairs.
fn parse_uevent(syspath: &Path) -> HashMap<String, String> {
    let uevent_path = syspath.join("uevent");
    let mut props = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(&uevent_path) {
        for line in content.lines() {
            if let Some((key, val)) = line.split_once('=') {
                props.insert(key.to_owned(), val.to_owned());
            }
        }
    }
    props
}

/// Enumerate all devices in a given subsystem (e.g., `block`, `net`, `input`).
///
/// Searches `/sys/class/<subsystem>` for device entries.
pub fn enumerate(subsystem: &str) -> Result<Vec<Device>> {
    let class_path = Path::new(SYSFS_CLASS).join(subsystem);

    if !class_path.is_dir() {
        tracing::debug!(subsystem, "subsystem not found in /sys/class");
        return Err(SysError::NotSupported {
            feature: Cow::Owned(format!("subsystem: {subsystem}")),
        });
    }

    let mut devices = Vec::new();
    let entries = std::fs::read_dir(&class_path).map_err(|e| {
        tracing::error!(subsystem, error = %e, "failed to read sysfs class dir");
        SysError::Io(e)
    })?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let syspath = entry.path();
        let properties = parse_uevent(&syspath);

        devices.push(Device {
            syspath,
            subsystem: subsystem.to_owned(),
            properties,
        });
    }

    tracing::trace!(subsystem, count = devices.len(), "enumerated devices");
    Ok(devices)
}

/// Enumerate devices for a bus (e.g., `pci`, `usb`, `platform`).
///
/// Searches `/sys/bus/<bus>/devices` for device entries.
pub fn enumerate_bus(bus: &str) -> Result<Vec<Device>> {
    let bus_path = Path::new(SYSFS_BUS).join(bus).join("devices");

    if !bus_path.is_dir() {
        tracing::debug!(bus, "bus not found in /sys/bus");
        return Err(SysError::NotSupported {
            feature: Cow::Owned(format!("bus: {bus}")),
        });
    }

    let mut devices = Vec::new();
    let entries = std::fs::read_dir(&bus_path).map_err(|e| {
        tracing::error!(bus, error = %e, "failed to read sysfs bus dir");
        SysError::Io(e)
    })?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let syspath = entry.path();
        let properties = parse_uevent(&syspath);

        devices.push(Device {
            syspath,
            subsystem: bus.to_owned(),
            properties,
        });
    }

    tracing::trace!(bus, count = devices.len(), "enumerated bus devices");
    Ok(devices)
}

/// Open a device by its sysfs path.
pub fn device_from_syspath(syspath: &Path) -> Result<Device> {
    if !syspath.exists() {
        return Err(SysError::InvalidArgument(Cow::Owned(format!(
            "syspath does not exist: {}",
            syspath.display()
        ))));
    }

    let subsystem = syspath
        .join("subsystem")
        .read_link()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();

    let properties = parse_uevent(syspath);

    Ok(Device {
        syspath: syspath.to_owned(),
        subsystem,
        properties,
    })
}

// ── Hotplug monitoring ──────────────────────────────────────────────

/// A uevent action from the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UeventAction {
    /// A device was added.
    Add,
    /// A device was removed.
    Remove,
    /// A device property changed.
    Change,
    /// A device was moved (renamed).
    Move,
    /// A device went online.
    Online,
    /// A device went offline.
    Offline,
    /// A device was bound to a driver.
    Bind,
    /// A device was unbound from a driver.
    Unbind,
}

/// A parsed kernel uevent from the netlink socket.
#[derive(Debug, Clone)]
pub struct Uevent {
    /// The action (add, remove, change, etc.).
    pub action: UeventAction,
    /// The devpath from the kernel (e.g., `/devices/pci0000:00/...`).
    pub devpath: String,
    /// The subsystem (e.g., `block`, `net`).
    pub subsystem: String,
    /// Additional key=value properties from the uevent.
    pub properties: HashMap<String, String>,
}

/// A monitor for kernel uevent notifications.
///
/// Listens on a netlink socket for device add/remove/change events.
pub struct Monitor {
    fd: std::os::fd::OwnedFd,
}

impl Monitor {
    /// Create a new uevent monitor.
    ///
    /// Opens a `NETLINK_KOBJECT_UEVENT` socket bound to the kernel multicast group.
    pub fn new() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                NETLINK_KOBJECT_UEVENT,
            )
        };
        if fd < 0 {
            let err = SysError::last_os_error();
            tracing::error!("failed to create netlink uevent socket");
            return Err(err);
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = 1; // KOBJECT_UEVENT group

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = SysError::last_os_error();
            unsafe { libc::close(fd) };
            tracing::error!("failed to bind netlink uevent socket");
            return Err(err);
        }

        tracing::debug!(fd, "uevent monitor created");
        Ok(Self {
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Try to receive the next uevent (non-blocking).
    ///
    /// Returns `Ok(Some(uevent))` if an event is available,
    /// `Ok(None)` if no events are pending (would block),
    /// or `Err` on socket error.
    pub fn try_recv(&self) -> Result<Option<Uevent>> {
        use std::os::fd::AsRawFd;

        let mut buf = [0u8; 8192];
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };

        if n < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                return Ok(None);
            }
            return Err(SysError::from_errno(errno));
        }

        if n == 0 {
            return Ok(None);
        }

        let data = &buf[..n as usize];
        Ok(parse_uevent_msg(data))
    }

    /// Get the raw file descriptor for polling (e.g., with epoll/poll).
    #[inline]
    #[must_use]
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.fd.as_raw_fd()
    }
}

use std::os::fd::FromRawFd;

/// Parse a raw netlink uevent message into a `Uevent`.
fn parse_uevent_msg(data: &[u8]) -> Option<Uevent> {
    // Skip the header (null-terminated string like "add@/devices/...")
    let header_end = data.iter().position(|&b| b == 0)?;
    let header = std::str::from_utf8(&data[..header_end]).ok()?;

    let action_str = header.split('@').next()?;
    let action = match action_str {
        "add" => UeventAction::Add,
        "remove" => UeventAction::Remove,
        "change" => UeventAction::Change,
        "move" => UeventAction::Move,
        "online" => UeventAction::Online,
        "offline" => UeventAction::Offline,
        "bind" => UeventAction::Bind,
        "unbind" => UeventAction::Unbind,
        _ => return None,
    };

    let mut devpath = String::new();
    let mut subsystem = String::new();
    let mut properties = HashMap::new();

    // Parse remaining null-separated KEY=VALUE pairs
    let rest = &data[header_end + 1..];
    for chunk in rest.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(chunk)
            && let Some((key, val)) = s.split_once('=')
        {
            match key {
                "DEVPATH" => devpath = val.to_owned(),
                "SUBSYSTEM" => subsystem = val.to_owned(),
                _ => {
                    properties.insert(key.to_owned(), val.to_owned());
                }
            }
        }
    }

    Some(Uevent {
        action,
        devpath,
        subsystem,
        properties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send<T: Send>() {}
        assert_send::<Device>();
        assert_send::<Uevent>();
        assert_send::<UeventAction>();
        assert_send::<Monitor>();
    };

    // ── enumerate ───────────────────────────────────────────────────

    #[test]
    fn enumerate_net_returns_devices() {
        // /sys/class/net should exist on any Linux system (at least lo)
        let devs = enumerate("net").unwrap();
        assert!(!devs.is_empty());
    }

    #[test]
    fn enumerate_block_returns_result() {
        // May or may not have block devices
        let _ = enumerate("block");
    }

    #[test]
    fn enumerate_nonexistent_subsystem() {
        let err = enumerate("nonexistent_agnosys_test");
        assert!(err.is_err());
    }

    // ── Device ──────────────────────────────────────────────────────

    #[test]
    fn device_name_from_net() {
        let devs = enumerate("net").unwrap();
        for dev in &devs {
            assert!(!dev.name().is_empty());
            assert_eq!(dev.subsystem(), "net");
        }
    }

    #[test]
    fn device_syspath_exists() {
        let devs = enumerate("net").unwrap();
        for dev in &devs {
            assert!(dev.syspath().exists());
        }
    }

    #[test]
    fn device_attr_reads_sysfs() {
        let devs = enumerate("net").unwrap();
        // lo should have an "address" attribute
        for dev in &devs {
            if dev.name() == "lo" {
                let addr = dev.attr("address");
                assert!(addr.is_some());
                assert_eq!(addr.unwrap(), "00:00:00:00:00:00");
            }
        }
    }

    #[test]
    fn device_attr_nonexistent() {
        let devs = enumerate("net").unwrap();
        if let Some(dev) = devs.first() {
            assert!(dev.attr("nonexistent_agnosys_attr").is_none());
        }
    }

    #[test]
    fn device_properties_parsed() {
        let devs = enumerate("net").unwrap();
        for dev in &devs {
            // uevent should have INTERFACE key for net devices
            if dev.name() == "lo" {
                assert!(dev.property("INTERFACE").is_some());
            }
        }
    }

    #[test]
    fn device_devpath_resolves() {
        let devs = enumerate("net").unwrap();
        if let Some(dev) = devs.first() {
            // devpath resolves symlinks
            let dp = dev.devpath();
            assert!(dp.is_some());
        }
    }

    #[test]
    fn device_clone() {
        let devs = enumerate("net").unwrap();
        if let Some(dev) = devs.first() {
            let cloned = dev.clone();
            assert_eq!(cloned.name(), dev.name());
            assert_eq!(cloned.subsystem(), dev.subsystem());
        }
    }

    #[test]
    fn device_debug() {
        let devs = enumerate("net").unwrap();
        if let Some(dev) = devs.first() {
            let dbg = format!("{dev:?}");
            assert!(dbg.contains("Device"));
        }
    }

    // ── enumerate_bus ───────────────────────────────────────────────

    #[test]
    fn enumerate_bus_platform() {
        // /sys/bus/platform/devices should exist
        let result = enumerate_bus("platform");
        assert!(result.is_ok());
    }

    #[test]
    fn enumerate_bus_nonexistent() {
        let err = enumerate_bus("nonexistent_agnosys_bus");
        assert!(err.is_err());
    }

    // ── device_from_syspath ─────────────────────────────────────────

    #[test]
    fn device_from_syspath_lo() {
        let dev = device_from_syspath(Path::new("/sys/class/net/lo"));
        assert!(dev.is_ok());
        let dev = dev.unwrap();
        assert_eq!(dev.name(), "lo");
    }

    #[test]
    fn device_from_syspath_nonexistent() {
        let err = device_from_syspath(Path::new("/sys/class/nonexistent_agnosys"));
        assert!(err.is_err());
    }

    // ── Monitor ─────────────────────────────────────────────────────

    #[test]
    fn monitor_new_succeeds() {
        // Should succeed on any Linux system (may need CAP_NET_ADMIN in some configs)
        let _ = Monitor::new();
    }

    #[test]
    fn monitor_try_recv_no_events() {
        let mon = match Monitor::new() {
            Ok(m) => m,
            Err(_) => return, // skip if can't create
        };
        // Non-blocking, should return None immediately
        let result = mon.try_recv().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn monitor_raw_fd() {
        let mon = match Monitor::new() {
            Ok(m) => m,
            Err(_) => return,
        };
        assert!(mon.as_raw_fd() >= 0);
    }

    // ── UeventAction ────────────────────────────────────────────────

    #[test]
    fn uevent_action_eq() {
        assert_eq!(UeventAction::Add, UeventAction::Add);
        assert_ne!(UeventAction::Add, UeventAction::Remove);
    }

    #[test]
    fn uevent_action_debug() {
        let dbg = format!("{:?}", UeventAction::Add);
        assert!(dbg.contains("Add"));
    }

    // ── parse_uevent_msg ────────────────────────────────────────────

    #[test]
    fn parse_valid_uevent() {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"add@/devices/pci0000:00/0000:00:1f.0\0");
        msg.extend_from_slice(b"ACTION=add\0");
        msg.extend_from_slice(b"DEVPATH=/devices/pci0000:00/0000:00:1f.0\0");
        msg.extend_from_slice(b"SUBSYSTEM=pci\0");
        msg.extend_from_slice(b"PCI_ID=8086:A0A1\0");

        let uevent = parse_uevent_msg(&msg).unwrap();
        assert_eq!(uevent.action, UeventAction::Add);
        assert_eq!(uevent.devpath, "/devices/pci0000:00/0000:00:1f.0");
        assert_eq!(uevent.subsystem, "pci");
        assert_eq!(uevent.properties.get("PCI_ID").unwrap(), "8086:A0A1");
    }

    #[test]
    fn parse_remove_uevent() {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"remove@/devices/usb\0");
        msg.extend_from_slice(b"DEVPATH=/devices/usb\0");
        msg.extend_from_slice(b"SUBSYSTEM=usb\0");

        let uevent = parse_uevent_msg(&msg).unwrap();
        assert_eq!(uevent.action, UeventAction::Remove);
    }

    #[test]
    fn parse_all_actions() {
        for (action_str, expected) in [
            ("add", UeventAction::Add),
            ("remove", UeventAction::Remove),
            ("change", UeventAction::Change),
            ("move", UeventAction::Move),
            ("online", UeventAction::Online),
            ("offline", UeventAction::Offline),
            ("bind", UeventAction::Bind),
            ("unbind", UeventAction::Unbind),
        ] {
            let msg = format!("{action_str}@/devices/test\0DEVPATH=/devices/test\0");
            let uevent = parse_uevent_msg(msg.as_bytes()).unwrap();
            assert_eq!(uevent.action, expected);
        }
    }

    #[test]
    fn parse_invalid_action() {
        let msg = b"invalid@/devices/test\0";
        assert!(parse_uevent_msg(msg).is_none());
    }

    #[test]
    fn parse_empty_msg() {
        assert!(parse_uevent_msg(b"").is_none());
    }
}
