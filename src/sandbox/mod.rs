//! Platform-specific sandbox implementations.

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

use crate::config::SandboxRuntimeConfig;
use crate::error::SandboxError;
use crate::utils::Platform;

/// Check if sandboxing dependencies are available for the current platform.
pub fn check_dependencies(platform: Platform) -> Result<(), SandboxError> {
    match platform {
        Platform::MacOS => {
            // sandbox-exec is built into macOS
            Ok(())
        }
        Platform::Linux => {
            #[cfg(target_os = "linux")]
            {
                if !linux::check_bwrap() {
                    return Err(SandboxError::MissingDependency(
                        "bubblewrap (bwrap) is required for Linux sandboxing".to_string(),
                    ));
                }
                if !linux::check_socat() {
                    return Err(SandboxError::MissingDependency(
                        "socat is required for Linux network sandboxing".to_string(),
                    ));
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(SandboxError::UnsupportedPlatform(
                    "Linux sandbox code not compiled on this platform".to_string(),
                ))
            }
        }
    }
}

/// Wrap a command with platform-specific sandboxing.
pub async fn wrap_command(
    command: &str,
    config: &SandboxRuntimeConfig,
    platform: Platform,
    http_proxy_port: Option<u16>,
    socks_proxy_port: Option<u16>,
    #[cfg(target_os = "linux")] http_socket_path: Option<&str>,
    #[cfg(target_os = "linux")] socks_socket_path: Option<&str>,
    shell: Option<&str>,
    enable_log_monitor: bool,
) -> Result<WrapResult, SandboxError> {
    match platform {
        Platform::MacOS => {
            #[cfg(target_os = "macos")]
            {
                let (wrapped, log_tag) = macos::wrap_command(
                    command,
                    config,
                    http_proxy_port,
                    socks_proxy_port,
                    shell,
                    enable_log_monitor,
                )?;
                Ok(WrapResult {
                    command: wrapped,
                    log_tag,
                    warnings: vec![],
                })
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(SandboxError::UnsupportedPlatform(
                    "macOS sandbox code not compiled on this platform".to_string(),
                ))
            }
        }
        Platform::Linux => {
            #[cfg(target_os = "linux")]
            {
                let cwd = std::env::current_dir()?;
                let (wrapped, warnings) = linux::generate_bwrap_command(
                    command,
                    config,
                    &cwd,
                    http_socket_path,
                    socks_socket_path,
                    http_proxy_port.unwrap_or(3128),
                    socks_proxy_port.unwrap_or(1080),
                    shell,
                )?;
                Ok(WrapResult {
                    command: wrapped,
                    log_tag: None,
                    warnings,
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(SandboxError::UnsupportedPlatform(
                    "Linux sandbox code not compiled on this platform".to_string(),
                ))
            }
        }
    }
}

/// Result of wrapping a command with sandbox.
#[derive(Debug)]
pub struct WrapResult {
    /// The wrapped command string.
    pub command: String,
    /// Log tag for violation monitoring (macOS only).
    pub log_tag: Option<String>,
    /// Warnings generated during wrapping.
    pub warnings: Vec<String>,
}
