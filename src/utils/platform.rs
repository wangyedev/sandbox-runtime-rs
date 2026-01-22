//! Platform detection utilities.

/// Supported platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Linux,
}

impl Platform {
    /// Detect the current platform.
    pub fn current() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            Some(Platform::MacOS)
        }
        #[cfg(target_os = "linux")]
        {
            Some(Platform::Linux)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }

    /// Check if the current platform is supported.
    pub fn is_supported() -> bool {
        Self::current().is_some()
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
