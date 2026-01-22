//! CLI entry point for the sandbox runtime (srt).

use std::process::ExitCode;

use sandbox_runtime::cli::Cli;
use sandbox_runtime::config::{load_config, load_default_config};
use sandbox_runtime::manager::SandboxManager;
use sandbox_runtime::utils::init_debug_logging;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse_args();

    // Initialize logging
    init_debug_logging(cli.debug);

    // Load configuration
    let config = match cli.get_settings_path() {
        Some(path) if path.exists() => match load_config(&path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error loading config from {:?}: {}", path, e);
                return ExitCode::from(1);
            }
        },
        _ => match load_default_config() {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error loading default config: {}", e);
                return ExitCode::from(1);
            }
        },
    };

    // Get command to execute
    let (command, _shell_mode) = match cli.get_command() {
        Some(cmd) => cmd,
        None => {
            eprintln!("No command specified. Use -c <command> or provide command as arguments.");
            return ExitCode::from(1);
        }
    };

    // Initialize sandbox manager
    let manager = SandboxManager::new();
    if let Err(e) = manager.initialize(config).await {
        eprintln!("Failed to initialize sandbox: {}", e);
        return ExitCode::from(1);
    }

    // Wrap and execute the command
    let wrapped_command = match manager.wrap_with_sandbox(&command, None, None).await {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("Failed to wrap command: {}", e);
            manager.reset().await;
            return ExitCode::from(1);
        }
    };

    tracing::debug!("Wrapped command: {}", wrapped_command);

    // Execute the wrapped command
    let status = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&wrapped_command)
        .status()
        .await;

    // Cleanup
    manager.reset().await;

    match status {
        Ok(status) => {
            if let Some(code) = status.code() {
                ExitCode::from(code as u8)
            } else {
                // Terminated by signal
                ExitCode::from(128)
            }
        }
        Err(e) => {
            eprintln!("Failed to execute command: {}", e);
            ExitCode::from(1)
        }
    }
}
