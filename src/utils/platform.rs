//! Platform detection utilities.

/// Supported platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Linux,
}

impl Platform {
    /// Detect the current platform.
    /// Note: All Linux including WSL returns Linux. Use `get_wsl_version()` to detect WSL1 (unsupported).
    pub fn current() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            Some(Platform::MacOS)
        }
        #[cfg(target_os = "linux")]
        {
            // WSL2+ is treated as Linux (same sandboxing)
            // WSL1 is also returned as Linux but will fail is_supported() check
            Some(Platform::Linux)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }

    /// Check if the current platform is supported.
    /// Returns false for unsupported platforms and WSL1.
    pub fn is_supported() -> bool {
        match Self::current() {
            Some(Platform::Linux) => {
                // WSL1 doesn't support bubblewrap
                get_wsl_version() != Some("1".to_string())
            }
            Some(Platform::MacOS) => true,
            None => false,
        }
    }

    /// Get the platform name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Platform::MacOS => "macOS",
            Platform::Linux => "Linux",
        }
    }
}

/// Get the current platform, if supported.
pub fn current_platform() -> Option<Platform> {
    Platform::current()
}

/// Check if running on macOS.
#[inline]
pub fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

/// Check if running on Linux.
#[inline]
pub fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

/// Get the CPU architecture.
pub fn get_arch() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unknown"
    }
}

/// Get the WSL version (1 or 2+) if running in WSL.
/// Returns None if not running in WSL.
pub fn get_wsl_version() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;

        let proc_version = match fs::read_to_string("/proc/version") {
            Ok(content) => content,
            Err(_) => return None,
        };

        // Check for explicit WSL version markers (e.g., "WSL2", "WSL3", etc.)
        // Use a simple pattern match since we can't use regex easily here
        let proc_lower = proc_version.to_lowercase();

        // Look for "wsl" followed by a digit
        if let Some(pos) = proc_lower.find("wsl") {
            let after_wsl = &proc_version[pos + 3..];
            if let Some(ch) = after_wsl.chars().next() {
                if ch.is_ascii_digit() {
                    return Some(ch.to_string());
                }
            }
        }

        // If no explicit WSL version but contains Microsoft, assume WSL1
        // This handles the original WSL1 format: "4.4.0-19041-Microsoft"
        if proc_lower.contains("microsoft") {
            return Some("1".to_string());
        }

        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_arch() {
        let arch = get_arch();
        assert!(arch == "x64" || arch == "arm64" || arch == "unknown");
    }

    #[test]
    fn test_platform_current() {
        let platform = Platform::current();
        #[cfg(target_os = "macos")]
        assert_eq!(platform, Some(Platform::MacOS));
        #[cfg(target_os = "linux")]
        assert_eq!(platform, Some(Platform::Linux));
    }

    #[test]
    fn test_get_wsl_version_non_linux() {
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(get_wsl_version(), None);
        }
    }
}
