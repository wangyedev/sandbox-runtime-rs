//! Seccomp filter loading and management.

use std::path::{Path, PathBuf};

use crate::config::SeccompConfig;
use crate::error::SandboxError;
use crate::utils::get_arch;

/// Get the path to the seccomp BPF filter for the current architecture.
pub fn get_bpf_path(config: Option<&SeccompConfig>) -> Result<PathBuf, SandboxError> {
    // Check custom config first
    if let Some(cfg) = config {
        if let Some(ref path) = cfg.bpf_path {
            let p = PathBuf::from(path);
            if p.exists() {
                return Ok(p);
            }
        }
    }

    let arch = get_arch();

    // Check various locations for the BPF filter
    let locations = [
        // Relative to working directory
        format!("vendor/seccomp/{}/unix-block.bpf", arch),
        // Relative to executable
        format!("../vendor/seccomp/{}/unix-block.bpf", arch),
        // Embedded location (relative to crate root)
        format!("../../vendor/seccomp/{}/unix-block.bpf", arch),
    ];

    for location in &locations {
        let path = PathBuf::from(location);
        if path.exists() {
            return Ok(path);
        }

        // Also try relative to current exe
        if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                let full_path = exe_dir.join(location);
                if full_path.exists() {
                    return Ok(full_path);
                }
            }
        }
    }

    Err(SandboxError::Seccomp(format!(
        "Could not find seccomp BPF filter for architecture '{}'. Checked: {:?}",
        arch, locations
    )))
}

/// Get the path to the apply-seccomp binary for the current architecture.
pub fn get_apply_seccomp_path(config: Option<&SeccompConfig>) -> Result<PathBuf, SandboxError> {
    // Check custom config first
    if let Some(cfg) = config {
        if let Some(ref path) = cfg.apply_path {
            let p = PathBuf::from(path);
            if p.exists() {
                return Ok(p);
            }
        }
    }

    let arch = get_arch();

    // Check various locations
    let locations = [
        format!("vendor/seccomp/{}/apply-seccomp", arch),
        format!("../vendor/seccomp/{}/apply-seccomp", arch),
        format!("../../vendor/seccomp/{}/apply-seccomp", arch),
    ];

    for location in &locations {
        let path = PathBuf::from(location);
        if path.exists() {
            return Ok(path);
        }

        if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                let full_path = exe_dir.join(location);
                if full_path.exists() {
                    return Ok(full_path);
                }
            }
        }
    }

    Err(SandboxError::Seccomp(format!(
        "Could not find apply-seccomp binary for architecture '{}'. Checked: {:?}",
        arch, locations
    )))
}

/// Check if seccomp is available on the current system.
pub fn is_seccomp_available(config: Option<&SeccompConfig>) -> bool {
    get_bpf_path(config).is_ok() && get_apply_seccomp_path(config).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_arch() {
        let arch = get_arch();
        assert!(arch == "x64" || arch == "arm64" || arch == "unknown");
    }
}
