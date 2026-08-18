//! Check that an XDP program is attached to an interface using the libbpf-rs
//! API (no `bpftool` or `ip` subprocess dependency).
//!
//! Detection strategies, in order:
//!   1. Modern XDP via `bpf_link_create`: scan link objects for an XDP link
//!      whose `ifindex` matches the interface.
//!   2. XDP programs whose `bpf_prog_info.ifindex` matches the interface
//!      (set by some attachment paths).
//!   3. Legacy XDP via `bpf_set_link_xdp_fd` (used by `ip link set dev … xdp`):
//!      no link object is created and `ifindex` is 0 in `bpf_prog_info`.
//!      If the daemon was started with `--prog-id <N>`, we verify that program
//!      `N` is loaded and is of type `BPF_PROG_TYPE_XDP` — this is the most
//!      reliable signal for legacy attachments.
//!   4. As a last resort (no `--prog-id`), check for *any* XDP program loaded
//!      in the current network namespace.

use std::ffi::CString;
use std::os::unix::fs::MetadataExt;

use anyhow::{Result, anyhow};
use libbpf_rs::query::{LinkInfoIter, LinkTypeInfo, ProgInfoIter};
use libbpf_rs::ProgramType;

/// Result of XDP attachment check.
#[derive(Debug)]
pub struct AttachInfo {
    pub attached: bool,
    /// id of loaded XDP program, if found.
    pub prog_id: Option<u32>,
    /// human-readable description of the found attachment for diagnostics.
    pub raw: String,
}

/// Check that XDP is attached to interface `iface`.
///
/// `known_prog_id` is the daemon's own XDP program id (from `--prog-id`).
/// When provided, it enables reliable detection of legacy `bpf_set_link_xdp_fd`
/// attachments where `bpf_prog_info.ifindex` is 0 and no BPF link exists.
pub fn check_xdp_attached(iface: &str, known_prog_id: Option<u32>) -> Result<AttachInfo> {
    let ifindex = match if_nameto_index(iface) {
        Some(idx) => idx,
        None => return Err(anyhow!("interface '{iface}' does not exist")),
    };

    // 1. Modern XDP: scan BPF link objects. `bpf_link_get_next_id` enumerates
    //    all links. For XDP attached via bpf_link_create there will be a
    //    BPF_LINK_TYPE_XDP link whose `ifindex` matches the interface.
    for link in LinkInfoIter::default() {
        if matches!(&link.info, LinkTypeInfo::Xdp(xdp) if xdp.ifindex == ifindex) {
            return Ok(AttachInfo {
                attached: true,
                prog_id: Some(link.prog_id),
                raw: format!(
                    "xdp link id {} -> prog {} on ifindex {}",
                    link.id, link.prog_id, ifindex
                ),
            });
        }
    }

    // 2. XDP programs whose bpf_prog_info.ifindex is set and matches.
    for prog in ProgInfoIter::default() {
        if prog.ty == ProgramType::Xdp && prog.ifindex == ifindex {
            return Ok(AttachInfo {
                attached: true,
                prog_id: Some(prog.id),
                raw: format!(
                    "xdp program '{}' (id {}) attached to ifindex {}",
                    prog.name.to_string_lossy(),
                    prog.id,
                    ifindex
                ),
            });
        }
    }

    // 3. Legacy XDP via bpf_set_link_xdp_fd: the kernel does not create a
    //    BPF link object, and `bpf_prog_info.ifindex` is left at 0.
    //    We cannot determine the exact interface from bpf_prog_info alone.
    //    If the daemon was started with --prog-id, verify that specific program
    //    is loaded as XDP. Otherwise fall back to any XDP program in the
    //    current network namespace.
    let current_netns = current_netns_ino();
    let mut scanned_xdp: Vec<(u32, String, u32)> = Vec::new();
    for prog in ProgInfoIter::default() {
        if prog.ty != ProgramType::Xdp {
            continue;
        }
        scanned_xdp.push((prog.id, prog.name.to_string_lossy().to_string(), prog.ifindex));
        let by_prog_id = known_prog_id.is_some_and(|pid| prog.id == pid);
        let in_same_netns = current_netns.is_some_and(|ino| prog.netns_ino == ino);

        // Exact match by known prog_id is the most reliable.
        if by_prog_id {
            return Ok(AttachInfo {
                attached: true,
                prog_id: Some(prog.id),
                raw: format!(
                    "xdp program '{}' (id {}) attached to ifindex {} \
                     (legacy bpf_set_link_xdp_fd: ifindex=0 in prog_info, \
                     matched by --prog-id {})",
                    prog.name.to_string_lossy(),
                    prog.id,
                    ifindex,
                    pid_display(&known_prog_id)
                ),
            });
        }

        // Fallback: any XDP program in the same network namespace.
        // (bpf_prog_info.netns_ino may be 0 for some kernels/XDP attachment
        // paths, so this only catches programs where it is populated.)
        if in_same_netns {
            return Ok(AttachInfo {
                attached: true,
                prog_id: Some(prog.id),
                raw: format!(
                    "xdp program '{}' (id {}) found in netns {} \
                     (ifindex not set — legacy attachment)",
                    prog.name.to_string_lossy(),
                    prog.id,
                    current_netns.unwrap()
                ),
            });
        }
    }

    // If a known prog_id was provided but not found, and we found other XDP
    // programs, report the first one — the program may have been reloaded
    // with a new id.
    if let Some(first) = scanned_xdp.first() {
        return Ok(AttachInfo {
            attached: true,
            prog_id: Some(first.0),
            raw: format!(
                "xdp program '{}' (id {}) found (ifindex not set — legacy). \
                 known --prog-id was {}, but that program was not found in the \
                 loaded program list — it may have been reloaded",
                first.1,
                first.0,
                pid_display(&known_prog_id)
            ),
        });
    }

    Ok(AttachInfo {
        attached: false,
        prog_id: None,
        raw: format!("no xdp attachment found for ifindex {}", ifindex),
    })
}

/// Return the inode of the current process's network namespace.
///
/// This corresponds to `bpf_prog_info.netns_ino` for programs loaded in this
/// namespace. Returns `None` if `/proc/self/ns/net` is unavailable.
fn current_netns_ino() -> Option<u64> {
    let stat = std::fs::metadata("/proc/self/ns/net").ok()?;
    Some(stat.ino())
}

/// Human-readable representation of the known prog_id option.
fn pid_display(pid: &Option<u32>) -> String {
    pid.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string())
}

/// Resolve an interface name to its kernel ifindex via libc.
fn if_nameto_index(iface: &str) -> Option<u32> {
    let cstr = CString::new(iface.as_bytes()).ok()?;
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}
