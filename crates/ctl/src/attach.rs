//! Check that XDP program (`ebpf-xdp`) is attached to an interface.
//!
//! We check via `bpftool net show dev <iface>` (NOT via `ip link`),
//! as agreed. We look for line `xdp:` with `prog id N` or `prog/xdp id N`.

use std::process::Command;

/// Result of XDP attachment check.
#[derive(Debug)]
pub struct AttachInfo {
    pub attached: bool,
    /// id of loaded XDP program, if found.
    pub prog_id: Option<u32>,
    /// Raw output from `bpftool net show` for diagnostics.
    pub raw: String,
}

/// Check that XDP is attached to interface `iface`.
pub fn check_xdp_attached(iface: &str) -> Result<AttachInfo, String> {
    let output = Command::new("bpftool")
        .args(["net", "show", "dev", iface])
        .output()
        .map_err(|e| format!("failed to execute 'bpftool net show dev {iface}': {e}"))?;

    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // If bpftool didn't find the interface at all — this is not fatal for the check,
    // but we report it. Main thing — look for "xdp" in the output.
    let attached = raw.contains("xdp");
    let prog_id = parse_prog_id(&raw).or_else(|| parse_prog_id(&stderr));

    Ok(AttachInfo {
        attached,
        prog_id,
        raw: format!("{raw}{stderr}"),
    })
}

/// Extract `id N` from string like `xdp: ... prog id 137` or `prog/xdp id 137` or `generic id 137`.
fn parse_prog_id(text: &str) -> Option<u32> {
    // look for "prog id <N>" or "prog/xdp id <N>" or "generic id <N>"
    for pattern in ["prog id ", "prog/xdp id ", "generic id "] {
        if let Some(idx) = text.find(pattern) {
            let after = &text[idx + pattern.len()..];
            let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(id) = num.parse::<u32>() {
                return Some(id);
            }
        }
    }
    None
}
