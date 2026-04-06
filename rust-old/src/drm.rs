//! DRM — Direct Rendering Manager interface.
//!
//! Safe Rust bindings for the Linux DRM/KMS subsystem. Enumerate GPU devices,
//! query driver info and capabilities, and inspect display connectors, CRTCs,
//! and encoders.
//!
//! # Example
//!
//! ```no_run
//! use agnosys::drm;
//!
//! let cards = drm::enumerate_cards().unwrap();
//! for path in &cards {
//!     let dev = drm::Device::open(path).unwrap();
//!     let ver = dev.version().unwrap();
//!     println!("{}: {} v{}.{}.{}", path.display(), ver.name, ver.major, ver.minor, ver.patchlevel);
//! }
//! ```
//!
//! # Security Considerations
//!
//! - DRM device access (`/dev/dri/card*`) requires membership in the `video`
//!   group or root privileges.
//! - GPU framebuffer memory may contain sensitive data from other processes
//!   (screen content, composited windows). Callers should not assume GPU
//!   memory is zeroed.
//! - DRM ioctls are inherently `unsafe` at the FFI boundary; this module
//!   wraps them in safe Rust but cannot prevent kernel-level bugs.
//! - Device enumeration reveals GPU hardware, which may be useful for
//!   fingerprinting.
//! - Device paths passed to `Device::open` must be validated to prevent
//!   opening arbitrary file descriptors; only `/dev/dri/card*` paths should
//!   be accepted.
//! - A malicious user with DRM access could craft ioctl sequences to trigger
//!   kernel driver bugs or read stale GPU memory from other sessions;
//!   restrict device access via group membership and avoid running DRM
//!   consumers as root.

use crate::error::{Result, SysError};
use std::borrow::Cow;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

// ── DRM ioctl definitions ───────────────────────────────────────────
//
// DRM ioctls use the 'd' type byte. The ioctl number encoding on Linux:
//   _IOWR('d', nr, size) = direction(2) | size(14) | type(8) | nr(8)

const DRM_IOCTL_BASE: u8 = b'd';

/// Construct a DRM _IOWR ioctl request number.
const fn drm_iowr(nr: u8, size: usize) -> libc::c_ulong {
    // _IOWR = direction 3 (read|write)
    let dir: u64 = 3;
    ((dir << 30) | ((size as u64 & 0x3FFF) << 16) | ((DRM_IOCTL_BASE as u64) << 8) | nr as u64)
        as libc::c_ulong
}

/// Construct a DRM _IOR ioctl request number.
#[allow(dead_code)]
const fn drm_ior(nr: u8, size: usize) -> libc::c_ulong {
    let dir: u64 = 2; // _IOR = read
    ((dir << 30) | ((size as u64 & 0x3FFF) << 16) | ((DRM_IOCTL_BASE as u64) << 8) | nr as u64)
        as libc::c_ulong
}

// ioctl numbers
const DRM_IOCTL_VERSION: libc::c_ulong = drm_iowr(0x00, std::mem::size_of::<DrmVersion>());
const DRM_IOCTL_GET_CAP: libc::c_ulong = drm_iowr(0x0C, std::mem::size_of::<DrmGetCap>());
const DRM_IOCTL_MODE_GETRESOURCES: libc::c_ulong =
    drm_iowr(0xA0, std::mem::size_of::<DrmModeCardRes>());
const DRM_IOCTL_MODE_GETCONNECTOR: libc::c_ulong =
    drm_iowr(0xA7, std::mem::size_of::<DrmModeGetConnector>());

// ── Safety caps for kernel-reported sizes ────────────────────────────

/// Maximum string length we'll allocate for DRM version fields.
const MAX_VERSION_STRING: u64 = 4096;
/// Maximum count of resources (CRTCs, connectors, etc.) we'll allocate for.
const MAX_RESOURCE_COUNT: u32 = 1024;

// ── Kernel structures ───────────────────────────────────────────────

#[repr(C)]
#[derive(Default)]
struct DrmVersion {
    version_major: i32,
    version_minor: i32,
    version_patchlevel: i32,
    name_len: u64,
    name: u64, // pointer as u64
    date_len: u64,
    date: u64,
    desc_len: u64,
    desc: u64,
}

#[repr(C)]
#[derive(Default)]
struct DrmGetCap {
    capability: u64,
    value: u64,
}

#[repr(C)]
#[derive(Default)]
struct DrmModeCardRes {
    fb_id_ptr: u64,
    crtc_id_ptr: u64,
    connector_id_ptr: u64,
    encoder_id_ptr: u64,
    count_fbs: u32,
    count_crtcs: u32,
    count_connectors: u32,
    count_encoders: u32,
    min_width: u32,
    max_width: u32,
    min_height: u32,
    max_height: u32,
}

#[repr(C)]
#[derive(Default)]
struct DrmModeGetConnector {
    encoders_ptr: u64,
    modes_ptr: u64,
    props_ptr: u64,
    prop_values_ptr: u64,
    count_modes: u32,
    count_props: u32,
    count_encoders: u32,
    encoder_id: u32,
    connector_id: u32,
    connector_type: u32,
    connector_type_id: u32,
    connection: u32,
    mm_width: u32,
    mm_height: u32,
    subpixel: u32,
    pad: u32,
}

// ── DRM capability IDs ──────────────────────────────────────────────

/// DRM capability identifiers for [`Device::get_cap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u64)]
pub enum Cap {
    /// Device supports dumb buffers (for software rendering).
    DumbBuffer = 0x01,
    /// Device supports vblank high-resolution timestamps.
    VblankHighCrtc = 0x02,
    /// Device supports dumb buffer preferred depth.
    DumbPreferredDepth = 0x03,
    /// Device prefers shadow buffers.
    DumbPreferShadow = 0x04,
    /// Device supports PRIME (buffer sharing).
    Prime = 0x05,
    /// Device supports monotonic timestamps.
    TimestampMonotonic = 0x06,
    /// Device supports async page flip.
    AsyncPageFlip = 0x07,
    /// Width of cursor supported by device.
    CursorWidth = 0x08,
    /// Height of cursor supported by device.
    CursorHeight = 0x09,
    /// Device supports adding framebuffers with modifiers.
    AddFb2Modifiers = 0x10,
    /// Page flip target supported.
    PageFlipTarget = 0x11,
    /// Device supports CRTC in vblank events.
    CrtcInVblankEvent = 0x12,
    /// Device supports syncobj.
    SyncObj = 0x13,
    /// Device supports timeline syncobj.
    SyncObjTimeline = 0x14,
    /// Device supports atomic modesetting.
    AtomicAsyncPageFlip = 0x15,
}

// ── Connector types ─────────────────────────────────────────────────

/// Display connector type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectorType {
    Unknown,
    VGA,
    DVII,
    DVID,
    DVIA,
    Composite,
    SVideo,
    LVDS,
    Component,
    NinePinDIN,
    DisplayPort,
    HDMIA,
    HDMIB,
    TV,
    EDP,
    Virtual,
    DSI,
    DPI,
    Writeback,
    SPI,
    USB,
    Other(u32),
}

impl ConnectorType {
    fn from_kernel(t: u32) -> Self {
        match t {
            0 => Self::Unknown,
            1 => Self::VGA,
            2 => Self::DVII,
            3 => Self::DVID,
            4 => Self::DVIA,
            5 => Self::Composite,
            6 => Self::SVideo,
            7 => Self::LVDS,
            8 => Self::Component,
            9 => Self::NinePinDIN,
            10 => Self::DisplayPort,
            11 => Self::HDMIA,
            12 => Self::HDMIB,
            13 => Self::TV,
            14 => Self::EDP,
            15 => Self::Virtual,
            16 => Self::DSI,
            17 => Self::DPI,
            18 => Self::Writeback,
            19 => Self::SPI,
            20 => Self::USB,
            other => Self::Other(other),
        }
    }
}

/// Connector connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Unknown,
}

impl ConnectionStatus {
    fn from_kernel(s: u32) -> Self {
        match s {
            1 => Self::Connected,
            2 => Self::Disconnected,
            _ => Self::Unknown,
        }
    }
}

// ── Public types ────────────────────────────────────────────────────

/// DRM driver version information.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Version {
    pub major: i32,
    pub minor: i32,
    pub patchlevel: i32,
    pub name: String,
    pub date: String,
    pub desc: String,
}

/// Display mode resources (counts of CRTCs, connectors, encoders).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ModeResources {
    pub crtc_ids: Vec<u32>,
    pub connector_ids: Vec<u32>,
    pub encoder_ids: Vec<u32>,
    pub fb_ids: Vec<u32>,
    pub min_width: u32,
    pub max_width: u32,
    pub min_height: u32,
    pub max_height: u32,
}

/// Information about a display connector.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ConnectorInfo {
    pub id: u32,
    pub connector_type: ConnectorType,
    pub connector_type_id: u32,
    pub status: ConnectionStatus,
    pub mm_width: u32,
    pub mm_height: u32,
    pub encoder_id: u32,
    pub count_modes: u32,
    pub count_encoders: u32,
}

// ── Device enumeration ──────────────────────────────────────────────

/// List DRM card device paths (e.g., `/dev/dri/card0`, `/dev/dri/card1`).
#[must_use = "enumerated cards should be used"]
pub fn enumerate_cards() -> Result<Vec<PathBuf>> {
    let dri_path = Path::new("/dev/dri");
    if !dri_path.is_dir() {
        return Err(SysError::NotSupported {
            feature: Cow::Borrowed("DRM (/dev/dri not found)"),
        });
    }

    let mut cards = Vec::new();
    let entries = std::fs::read_dir(dri_path).map_err(|e| {
        tracing::error!(error = %e, "failed to read /dev/dri");
        SysError::Io(e)
    })?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("card") {
            cards.push(entry.path());
        }
    }

    cards.sort();
    tracing::trace!(count = cards.len(), "enumerated DRM cards");
    Ok(cards)
}

/// List DRM render node paths (e.g., `/dev/dri/renderD128`).
#[must_use = "enumerated render nodes should be used"]
pub fn enumerate_render_nodes() -> Result<Vec<PathBuf>> {
    let dri_path = Path::new("/dev/dri");
    if !dri_path.is_dir() {
        return Err(SysError::NotSupported {
            feature: Cow::Borrowed("DRM (/dev/dri not found)"),
        });
    }

    let mut nodes = Vec::new();
    let entries = std::fs::read_dir(dri_path).map_err(|e| {
        tracing::error!(error = %e, "failed to read /dev/dri");
        SysError::Io(e)
    })?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("renderD") {
            nodes.push(entry.path());
        }
    }

    nodes.sort();
    tracing::trace!(count = nodes.len(), "enumerated DRM render nodes");
    Ok(nodes)
}

// ── Device handle ───────────────────────────────────────────────────

/// An open DRM device.
///
/// Wraps a file descriptor to a `/dev/dri/card*` or `/dev/dri/renderD*` node.
#[non_exhaustive]
pub struct Device {
    fd: OwnedFd,
    path: PathBuf,
}

impl Device {
    /// Open a DRM device by path.
    pub fn open(path: &Path) -> Result<Self> {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| SysError::InvalidArgument(Cow::Borrowed("path contains null byte")))?;

        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = SysError::last_os_error();
            tracing::error!(path = %path.display(), "failed to open DRM device");
            return Err(err);
        }

        tracing::debug!(path = %path.display(), fd, "opened DRM device");
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            path: path.to_owned(),
        })
    }

    /// The path this device was opened from.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Query the DRM driver version.
    #[must_use = "version info should be used"]
    pub fn version(&self) -> Result<Version> {
        // First call: get lengths
        let mut ver = DrmVersion::default();
        self.ioctl(DRM_IOCTL_VERSION, &mut ver)?;

        // Allocate buffers (capped to prevent malicious/buggy kernel reports)
        let mut name_buf = vec![0u8; ver.name_len.min(MAX_VERSION_STRING) as usize];
        let mut date_buf = vec![0u8; ver.date_len.min(MAX_VERSION_STRING) as usize];
        let mut desc_buf = vec![0u8; ver.desc_len.min(MAX_VERSION_STRING) as usize];
        ver.name_len = name_buf.len() as u64;
        ver.date_len = date_buf.len() as u64;
        ver.desc_len = desc_buf.len() as u64;

        // Second call: fill buffers
        ver.name = name_buf.as_mut_ptr() as u64;
        ver.date = date_buf.as_mut_ptr() as u64;
        ver.desc = desc_buf.as_mut_ptr() as u64;
        self.ioctl(DRM_IOCTL_VERSION, &mut ver)?;

        let name = String::from_utf8_lossy(&name_buf).into_owned();
        let date = String::from_utf8_lossy(&date_buf).into_owned();
        let desc = String::from_utf8_lossy(&desc_buf).into_owned();

        tracing::trace!(
            driver = %name,
            major = ver.version_major,
            minor = ver.version_minor,
            "queried DRM version"
        );

        Ok(Version {
            major: ver.version_major,
            minor: ver.version_minor,
            patchlevel: ver.version_patchlevel,
            name,
            date,
            desc,
        })
    }

    /// Query a DRM capability.
    ///
    /// Returns the capability value, or 0 if not supported.
    #[must_use = "capability value should be used"]
    pub fn get_cap(&self, cap: Cap) -> Result<u64> {
        let mut get_cap = DrmGetCap {
            capability: cap as u64,
            value: 0,
        };
        match self.ioctl(DRM_IOCTL_GET_CAP, &mut get_cap) {
            Ok(()) => Ok(get_cap.value),
            Err(SysError::InvalidArgument(_)) => Ok(0), // unsupported cap
            Err(e) => Err(e),
        }
    }

    /// Query display mode resources (connectors, CRTCs, encoders, framebuffers).
    #[must_use = "mode resources should be used"]
    pub fn mode_resources(&self) -> Result<ModeResources> {
        // First call: get counts
        let mut res = DrmModeCardRes::default();
        self.ioctl(DRM_IOCTL_MODE_GETRESOURCES, &mut res)?;

        // Allocate arrays (capped to prevent malicious/buggy kernel reports)
        res.count_fbs = res.count_fbs.min(MAX_RESOURCE_COUNT);
        res.count_crtcs = res.count_crtcs.min(MAX_RESOURCE_COUNT);
        res.count_connectors = res.count_connectors.min(MAX_RESOURCE_COUNT);
        res.count_encoders = res.count_encoders.min(MAX_RESOURCE_COUNT);

        let mut fb_ids = vec![0u32; res.count_fbs as usize];
        let mut crtc_ids = vec![0u32; res.count_crtcs as usize];
        let mut connector_ids = vec![0u32; res.count_connectors as usize];
        let mut encoder_ids = vec![0u32; res.count_encoders as usize];

        // Second call: fill arrays
        res.fb_id_ptr = fb_ids.as_mut_ptr() as u64;
        res.crtc_id_ptr = crtc_ids.as_mut_ptr() as u64;
        res.connector_id_ptr = connector_ids.as_mut_ptr() as u64;
        res.encoder_id_ptr = encoder_ids.as_mut_ptr() as u64;
        self.ioctl(DRM_IOCTL_MODE_GETRESOURCES, &mut res)?;

        tracing::trace!(
            crtcs = res.count_crtcs,
            connectors = res.count_connectors,
            encoders = res.count_encoders,
            "queried DRM mode resources"
        );

        Ok(ModeResources {
            crtc_ids,
            connector_ids,
            encoder_ids,
            fb_ids,
            min_width: res.min_width,
            max_width: res.max_width,
            min_height: res.min_height,
            max_height: res.max_height,
        })
    }

    /// Query information about a specific connector by ID.
    #[must_use = "connector info should be used"]
    pub fn connector_info(&self, connector_id: u32) -> Result<ConnectorInfo> {
        let mut conn = DrmModeGetConnector {
            connector_id,
            ..Default::default()
        };
        // First call: get metadata (no arrays)
        self.ioctl(DRM_IOCTL_MODE_GETCONNECTOR, &mut conn)?;

        tracing::trace!(
            connector_id,
            connector_type = conn.connector_type,
            status = conn.connection,
            "queried DRM connector"
        );

        Ok(ConnectorInfo {
            id: conn.connector_id,
            connector_type: ConnectorType::from_kernel(conn.connector_type),
            connector_type_id: conn.connector_type_id,
            status: ConnectionStatus::from_kernel(conn.connection),
            mm_width: conn.mm_width,
            mm_height: conn.mm_height,
            encoder_id: conn.encoder_id,
            count_modes: conn.count_modes,
            count_encoders: conn.count_encoders,
        })
    }

    /// Check if the device supports dumb buffers (software rendering).
    #[must_use = "capability result should be checked"]
    pub fn supports_dumb_buffer(&self) -> Result<bool> {
        self.get_cap(Cap::DumbBuffer).map(|v| v != 0)
    }

    // ── Internal ioctl helper ───────────────────────────────────────

    fn ioctl<T>(&self, request: libc::c_ulong, arg: &mut T) -> Result<()> {
        // Cast request to the platform's ioctl type (i32 on musl, u64 on glibc)
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), request as _, arg as *mut T) };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            Err(SysError::from_errno(errno))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── compile-time guarantees ──────────────────────────────────────

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Device>();
        assert_send_sync::<Version>();
        assert_send_sync::<ModeResources>();
        assert_send_sync::<ConnectorInfo>();
        assert_send_sync::<Cap>();
        assert_send_sync::<ConnectorType>();
        assert_send_sync::<ConnectionStatus>();
    };

    // ── Enumeration ─────────────────────────────────────────────────

    #[test]
    fn enumerate_cards_returns_result() {
        let _ = enumerate_cards();
    }

    #[test]
    fn enumerate_render_nodes_returns_result() {
        let _ = enumerate_render_nodes();
    }

    #[test]
    fn enumerate_cards_paths_start_with_card() {
        if let Ok(cards) = enumerate_cards() {
            for card in &cards {
                let name = card.file_name().unwrap().to_string_lossy();
                assert!(name.starts_with("card"));
            }
        }
    }

    #[test]
    fn enumerate_render_nodes_paths_start_with_render() {
        if let Ok(nodes) = enumerate_render_nodes() {
            for node in &nodes {
                let name = node.file_name().unwrap().to_string_lossy();
                assert!(name.starts_with("renderD"));
            }
        }
    }

    #[test]
    fn enumerate_cards_sorted() {
        if let Ok(cards) = enumerate_cards() {
            for window in cards.windows(2) {
                assert!(window[0] <= window[1]);
            }
        }
    }

    // ── Device open ─────────────────────────────────────────────────

    #[test]
    fn device_open_nonexistent() {
        let err = Device::open(Path::new("/dev/dri/card999"));
        assert!(err.is_err());
    }

    #[test]
    fn device_open_null_byte() {
        let err = Device::open(Path::new("/dev/dri/\0bad"));
        assert!(err.is_err());
    }

    // ── Conditional tests (need a GPU) ──────────────────────────────

    fn open_first_card() -> Option<Device> {
        let cards = enumerate_cards().ok()?;
        let path = cards.first()?;
        Device::open(path).ok()
    }

    #[test]
    fn device_version_on_real_gpu() {
        let dev = match open_first_card() {
            Some(d) => d,
            None => return,
        };
        let ver = dev.version().unwrap();
        assert!(!ver.name.is_empty());
        assert!(ver.major >= 0);
    }

    #[test]
    fn device_path_matches() {
        let cards = match enumerate_cards() {
            Ok(c) if !c.is_empty() => c,
            _ => return,
        };
        let dev = match Device::open(&cards[0]) {
            Ok(d) => d,
            Err(_) => return,
        };
        assert_eq!(dev.path(), cards[0]);
    }

    #[test]
    fn device_get_cap_dumb_buffer() {
        let dev = match open_first_card() {
            Some(d) => d,
            None => return,
        };
        let _ = dev.get_cap(Cap::DumbBuffer);
    }

    #[test]
    fn device_supports_dumb_buffer() {
        let dev = match open_first_card() {
            Some(d) => d,
            None => return,
        };
        let _ = dev.supports_dumb_buffer();
    }

    #[test]
    fn device_mode_resources() {
        let dev = match open_first_card() {
            Some(d) => d,
            None => return,
        };
        let res = match dev.mode_resources() {
            Ok(r) => r,
            Err(_) => return, // render-only nodes can't do mode queries
        };
        // Should have at least something
        assert!(res.max_width > 0 || res.connector_ids.is_empty());
    }

    #[test]
    fn device_connector_info() {
        let dev = match open_first_card() {
            Some(d) => d,
            None => return,
        };
        let res = match dev.mode_resources() {
            Ok(r) => r,
            Err(_) => return,
        };
        for &cid in &res.connector_ids {
            let info = dev.connector_info(cid).unwrap();
            assert_eq!(info.id, cid);
        }
    }

    // ── ConnectorType ───────────────────────────────────────────────

    #[test]
    fn connector_type_from_kernel_all() {
        assert_eq!(ConnectorType::from_kernel(0), ConnectorType::Unknown);
        assert_eq!(ConnectorType::from_kernel(1), ConnectorType::VGA);
        assert_eq!(ConnectorType::from_kernel(2), ConnectorType::DVII);
        assert_eq!(ConnectorType::from_kernel(3), ConnectorType::DVID);
        assert_eq!(ConnectorType::from_kernel(4), ConnectorType::DVIA);
        assert_eq!(ConnectorType::from_kernel(5), ConnectorType::Composite);
        assert_eq!(ConnectorType::from_kernel(6), ConnectorType::SVideo);
        assert_eq!(ConnectorType::from_kernel(7), ConnectorType::LVDS);
        assert_eq!(ConnectorType::from_kernel(8), ConnectorType::Component);
        assert_eq!(ConnectorType::from_kernel(9), ConnectorType::NinePinDIN);
        assert_eq!(ConnectorType::from_kernel(10), ConnectorType::DisplayPort);
        assert_eq!(ConnectorType::from_kernel(11), ConnectorType::HDMIA);
        assert_eq!(ConnectorType::from_kernel(12), ConnectorType::HDMIB);
        assert_eq!(ConnectorType::from_kernel(13), ConnectorType::TV);
        assert_eq!(ConnectorType::from_kernel(14), ConnectorType::EDP);
        assert_eq!(ConnectorType::from_kernel(15), ConnectorType::Virtual);
        assert_eq!(ConnectorType::from_kernel(16), ConnectorType::DSI);
        assert_eq!(ConnectorType::from_kernel(17), ConnectorType::DPI);
        assert_eq!(ConnectorType::from_kernel(18), ConnectorType::Writeback);
        assert_eq!(ConnectorType::from_kernel(19), ConnectorType::SPI);
        assert_eq!(ConnectorType::from_kernel(20), ConnectorType::USB);
        assert_eq!(ConnectorType::from_kernel(999), ConnectorType::Other(999));
    }

    #[test]
    fn connector_type_debug() {
        let dbg = format!("{:?}", ConnectorType::HDMIA);
        assert!(dbg.contains("HDMIA"));
    }

    #[test]
    fn connector_type_eq() {
        assert_eq!(ConnectorType::VGA, ConnectorType::VGA);
        assert_ne!(ConnectorType::VGA, ConnectorType::HDMIA);
        assert_eq!(ConnectorType::Other(5), ConnectorType::Other(5));
        assert_ne!(ConnectorType::Other(5), ConnectorType::Other(6));
    }

    #[test]
    fn connector_type_clone_copy() {
        let a = ConnectorType::HDMIA;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    // ── ConnectionStatus ────────────────────────────────────────────

    #[test]
    fn connection_status_from_kernel() {
        assert_eq!(
            ConnectionStatus::from_kernel(1),
            ConnectionStatus::Connected
        );
        assert_eq!(
            ConnectionStatus::from_kernel(2),
            ConnectionStatus::Disconnected
        );
        assert_eq!(ConnectionStatus::from_kernel(3), ConnectionStatus::Unknown);
        assert_eq!(ConnectionStatus::from_kernel(0), ConnectionStatus::Unknown);
    }

    #[test]
    fn connection_status_debug() {
        let dbg = format!("{:?}", ConnectionStatus::Connected);
        assert!(dbg.contains("Connected"));
    }

    #[test]
    fn connection_status_clone_copy() {
        let a = ConnectionStatus::Connected;
        let b = a;
        assert_eq!(a, b);
    }

    // ── Cap ─────────────────────────────────────────────────────────

    #[test]
    fn cap_values() {
        assert_eq!(Cap::DumbBuffer as u64, 0x01);
        assert_eq!(Cap::Prime as u64, 0x05);
        assert_eq!(Cap::SyncObj as u64, 0x13);
    }

    #[test]
    fn cap_all_values() {
        assert_eq!(Cap::VblankHighCrtc as u64, 0x02);
        assert_eq!(Cap::DumbPreferredDepth as u64, 0x03);
        assert_eq!(Cap::DumbPreferShadow as u64, 0x04);
        assert_eq!(Cap::TimestampMonotonic as u64, 0x06);
        assert_eq!(Cap::AsyncPageFlip as u64, 0x07);
        assert_eq!(Cap::CursorWidth as u64, 0x08);
        assert_eq!(Cap::CursorHeight as u64, 0x09);
        assert_eq!(Cap::AddFb2Modifiers as u64, 0x10);
        assert_eq!(Cap::PageFlipTarget as u64, 0x11);
        assert_eq!(Cap::CrtcInVblankEvent as u64, 0x12);
        assert_eq!(Cap::SyncObjTimeline as u64, 0x14);
        assert_eq!(Cap::AtomicAsyncPageFlip as u64, 0x15);
    }

    #[test]
    fn cap_debug() {
        let dbg = format!("{:?}", Cap::DumbBuffer);
        assert!(dbg.contains("DumbBuffer"));
    }

    #[test]
    fn cap_eq() {
        assert_eq!(Cap::DumbBuffer, Cap::DumbBuffer);
        assert_ne!(Cap::DumbBuffer, Cap::Prime);
    }

    #[test]
    fn cap_clone_copy() {
        let a = Cap::Prime;
        let b = a;
        assert_eq!(a, b);
    }

    // ── Version ─────────────────────────────────────────────────────

    #[test]
    fn version_debug() {
        let v = Version {
            major: 1,
            minor: 2,
            patchlevel: 3,
            name: "test".into(),
            date: "20260101".into(),
            desc: "test driver".into(),
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("test"));
    }

    #[test]
    fn version_clone() {
        let v = Version {
            major: 1,
            minor: 0,
            patchlevel: 0,
            name: "drv".into(),
            date: "".into(),
            desc: "".into(),
        };
        let v2 = v.clone();
        assert_eq!(v.name, v2.name);
        assert_eq!(v.major, v2.major);
    }

    // ── ModeResources ───────────────────────────────────────────────

    #[test]
    fn mode_resources_debug() {
        let r = ModeResources {
            crtc_ids: vec![1],
            connector_ids: vec![2],
            encoder_ids: vec![3],
            fb_ids: vec![],
            min_width: 0,
            max_width: 3840,
            min_height: 0,
            max_height: 2160,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("3840"));
    }

    // ── ConnectorInfo ───────────────────────────────────────────────

    #[test]
    fn connector_info_debug() {
        let c = ConnectorInfo {
            id: 42,
            connector_type: ConnectorType::HDMIA,
            connector_type_id: 1,
            status: ConnectionStatus::Connected,
            mm_width: 530,
            mm_height: 300,
            encoder_id: 10,
            count_modes: 5,
            count_encoders: 1,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("HDMIA"));
        assert!(dbg.contains("Connected"));
    }

    // ── Render nodes ─────────────────────────────────────────────────

    #[test]
    fn enumerate_render_nodes_sorted() {
        if let Ok(nodes) = enumerate_render_nodes() {
            for window in nodes.windows(2) {
                assert!(window[0] <= window[1]);
            }
        }
    }

    // ── GPU-conditional: multiple caps ───────────────────────────────

    #[test]
    fn device_get_multiple_caps() {
        let dev = match open_first_card() {
            Some(d) => d,
            None => return,
        };
        // Query several caps — all should return without error
        let _ = dev.get_cap(Cap::Prime);
        let _ = dev.get_cap(Cap::TimestampMonotonic);
        let _ = dev.get_cap(Cap::CursorWidth);
        let _ = dev.get_cap(Cap::CursorHeight);
        let _ = dev.get_cap(Cap::SyncObj);
    }

    #[test]
    fn device_version_fields_populated() {
        let dev = match open_first_card() {
            Some(d) => d,
            None => return,
        };
        let ver = dev.version().unwrap();
        assert!(!ver.name.is_empty());
        // date and desc may be empty for some drivers but should be valid strings
        let _ = ver.date;
        let _ = ver.desc;
    }

    // ── Struct clone tests ──────────────────────────────────────────

    #[test]
    fn connector_info_clone() {
        let c = ConnectorInfo {
            id: 1,
            connector_type: ConnectorType::HDMIA,
            connector_type_id: 1,
            status: ConnectionStatus::Connected,
            mm_width: 0,
            mm_height: 0,
            encoder_id: 0,
            count_modes: 0,
            count_encoders: 0,
        };
        let c2 = c.clone();
        assert_eq!(c.id, c2.id);
        assert_eq!(c.connector_type, c2.connector_type);
    }

    #[test]
    fn mode_resources_clone() {
        let r = ModeResources {
            crtc_ids: vec![1, 2],
            connector_ids: vec![3],
            encoder_ids: vec![],
            fb_ids: vec![],
            min_width: 0,
            max_width: 1920,
            min_height: 0,
            max_height: 1080,
        };
        let r2 = r.clone();
        assert_eq!(r.crtc_ids, r2.crtc_ids);
        assert_eq!(r.max_width, r2.max_width);
    }

    // ── ioctl helpers ───────────────────────────────────────────────

    #[test]
    fn drm_iowr_encodes_correctly() {
        // DRM_IOCTL_VERSION = _IOWR('d', 0x00, sizeof(DrmVersion))
        let val = DRM_IOCTL_VERSION;
        let nr = val & 0xFF;
        let type_byte = (val >> 8) & 0xFF;
        assert_eq!(nr, 0x00);
        assert_eq!(type_byte, b'd' as libc::c_ulong);
    }

    #[test]
    fn drm_ioctl_mode_getresources_nr() {
        let nr = DRM_IOCTL_MODE_GETRESOURCES & 0xFF;
        assert_eq!(nr, 0xA0);
    }

    #[test]
    fn drm_ioctl_get_cap_nr() {
        let nr = DRM_IOCTL_GET_CAP & 0xFF;
        assert_eq!(nr, 0x0C);
    }
}
