//! Subcommand `exec`: Spawns a supervised child process with ephemeral proxy routing.
//!
//! Automatically starts an ephemeral proxy on a local port and injects `ANTHROPIC_BASE_URL`,
//! `OPENAI_BASE_URL`, `HTTP_PROXY`, and `HTTPS_PROXY` into the target process.
//! Cleanly shuts down the proxy when the child process exits, ensuring zero risk of
//! orphaned settings or broken network connectivity.

use std::error::Error;

/// Runs a command in a supervised child process with transparent LLM Firewall proxying.
///
/// # Arguments
/// * `cmd_args` - The command and arguments to execute, e.g. `["claude"]` or `["openhands", "--run"]`.
pub async fn run_exec(cmd_args: &[String]) -> Result<i32, Box<dyn Error>> {
    if cmd_args.is_empty() {
        return Err("No command specified. Usage: llm-firewall exec -- <command> [args...]".into());
    }

    let program = &cmd_args[0];
    let args = &cmd_args[1..];

    // Start ephemeral proxy on OS-assigned loopback port
    let server = crate::start_ephemeral_server(0).await?;
    let port = server.port;

    let proxy_url = format!("http://127.0.0.1:{}", port);
    let openai_url = format!("http://127.0.0.1:{}/v1", port);

    tracing::info!(
        port = port,
        program = program,
        "Supervised agent runner active. Forwarding Claude/OpenAI calls through LLM Firewall."
    );

    // Spawn child process with scoped environment variables
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .env("ANTHROPIC_BASE_URL", &proxy_url)
        .env("OPENAI_BASE_URL", &openai_url)
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("ALL_PROXY", &proxy_url)
        .env("all_proxy", &proxy_url)
        .spawn()
        .map_err(|e| format!("Failed to spawn command '{}': {}", program, e))?;

    // Wait for child process to complete
    let exit_status = child.wait().await?;

    // Gracefully shut down the ephemeral server
    server.shutdown().await;

    Ok(exit_status.code().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_exec_child_env_isolation() {
        // Run a simple command echo/printenv under exec to verify environment injection
        #[cfg(unix)]
        {
            let cmd_args = vec![
                "sh".to_string(),
                "-c".to_string(),
                "test -n \"$ANTHROPIC_BASE_URL\" && test -n \"$OPENAI_BASE_URL\"".to_string(),
            ];
            let code = run_exec(&cmd_args).await.unwrap();
            assert_eq!(
                code, 0,
                "Child process should receive injected environment variables"
            );
        }
    }
}
