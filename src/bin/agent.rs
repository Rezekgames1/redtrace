use redtrace::agent::{
    self, AgentConfig, AgentRuntime, DEFAULT_FLUSH_EVENTS, DEFAULT_HEARTBEAT, DEFAULT_POLL,
    SpoolLimits,
};
use std::path::PathBuf;
use std::time::Duration;

const USAGE: &str = "redtrace-agent — lightweight remote log collector for RED//TRACE

Usage:
  redtrace-agent --enroll FILE.redtrace-enroll.json [--state-dir DIR] [--install]
  redtrace-agent --server https://<server-host>:9711 --token-file <private-file> [options]

Enrollment:
  --enroll FILE      consume a one-time package, save private identity and start collection
  --install          configure startup at user login; otherwise run in foreground
  Keep redtrace-agent and redtrace-service-agent together in the extracted agent bundle.

Required:
  --server URL        RED//TRACE ingest endpoint, e.g. https://siem.example:9711
  --token-file FILE   private file containing the issued agent token
                      (or REDTRACE_AGENT_TOKEN / REDTRACE_AGENT_TOKEN_FILE)

Options:
  --name NAME         display name of this host (default: hostname)
  --state-dir DIR     exclusively owned private disk spool and checkpoints
                      (default: REDTRACE_AGENT_STATE, ~/.redtrace-agent,
                       %LOCALAPPDATA%\\redtrace-agent on Windows)
  --poll SECONDS      local collection interval (default: 5)
  --heartbeat SECONDS heartbeat interval when idle (default: 30)
  --lookback WINDOW   initial lookback, e.g. 15m, 1h, 1d (default: 15m)
  --spool-events N    pending event cap (default: 20000, maximum: 100000)
  --spool-bytes N     pending encoded byte cap (default: 33554432, maximum: 1073741824)
  --quarantine-bytes N quarantine byte cap (default: 67108864, maximum: 1073741824)

Environment:
  REDTRACE_AGENT_SERVER, REDTRACE_AGENT_TOKEN, REDTRACE_AGENT_TOKEN_FILE, REDTRACE_AGENT_NAME,
  REDTRACE_AGENT_STATE may be used instead of the matching flags.
  REDTRACE_AGENT_CA accepts a PEM CA certificate for a private PKI.
  REDTRACE_AGENT_SPOOL_EVENTS, REDTRACE_AGENT_SPOOL_BYTES,
  REDTRACE_AGENT_QUARANTINE_BYTES configure the matching limits.

Security:
  remote transport requires HTTPS with certificate verification.
  Plain HTTP is accepted only for loopback. --token is a deprecated loopback-only option.
  Collection progress advances after durable local enqueue; server ACK progress commits
  before pending record deletion. Delivery is at-least-once with server UID deduplication.
";

struct Options {
    server: Option<String>,
    token: Option<String>,
    token_file: Option<PathBuf>,
    name: Option<String>,
    state_dir: Option<PathBuf>,
    poll: Option<u64>,
    heartbeat: Option<u64>,
    lookback: Option<String>,
    spool_events: Option<u64>,
    spool_bytes: Option<u64>,
    quarantine_bytes: Option<u64>,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        server: None,
        token: None,
        token_file: None,
        name: None,
        state_dir: None,
        poll: None,
        heartbeat: None,
        lookback: None,
        spool_events: None,
        spool_bytes: None,
        quarantine_bytes: None,
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut index = 0;
    while index < args.len() {
        if !seen.insert(&args[index]) {
            return Err(format!("duplicate {}", args[index]));
        }
        let argument = args[index].as_str();
        let mut value = || {
            index += 1;
            args.get(index)
                .filter(|value| !value.starts_with("--") && !value.is_empty())
                .cloned()
                .ok_or_else(|| format!("missing value for {argument}"))
        };
        match argument {
            "--server" => options.server = Some(value()?),
            "--token" => options.token = Some(value()?),
            "--token-file" => options.token_file = Some(PathBuf::from(value()?)),
            "--name" => options.name = Some(value()?),
            "--state-dir" => options.state_dir = Some(PathBuf::from(value()?)),
            "--poll" => {
                let parsed = value()?;
                options.poll = Some(
                    parsed
                        .parse::<u64>()
                        .map_err(|_| format!("invalid --poll value: {parsed}"))?,
                );
            }
            "--heartbeat" => {
                let parsed = value()?;
                options.heartbeat = Some(
                    parsed
                        .parse::<u64>()
                        .map_err(|_| format!("invalid --heartbeat value: {parsed}"))?,
                );
            }
            "--lookback" => options.lookback = Some(value()?),
            "--spool-events" | "--spool-bytes" | "--quarantine-bytes" => {
                let parsed = value()?
                    .parse::<u64>()
                    .map_err(|_| format!("invalid {argument} value"))?;
                match argument {
                    "--spool-events" => options.spool_events = Some(parsed),
                    "--spool-bytes" => options.spool_bytes = Some(parsed),
                    _ => options.quarantine_bytes = Some(parsed),
                }
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        index += 1;
    }
    if options.token.is_some() && options.token_file.is_some() {
        return Err("--token and --token-file cannot be combined".into());
    }
    Ok(options)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print!("{USAGE}");
        return;
    }
    let enrollment = parse_enrollment(&args).unwrap_or_else(|error| configuration_error(&error));
    if let Some(options) = enrollment {
        let result = (|| -> std::io::Result<()> {
            let state =
                std::path::absolute(options.state_dir.unwrap_or_else(agent::default_state_dir))?;
            let binary = std::env::current_exe()?
                .parent()
                .ok_or_else(|| redtrace::service::invalid("agent binary directory unavailable"))?
                .join(if cfg!(windows) {
                    "redtrace-service-agent.exe"
                } else {
                    "redtrace-service-agent"
                });
            let binary = redtrace::service::protected_binary(&binary).map_err(|error| {
                std::io::Error::other(format!("redtrace-service-agent is missing or unprotected; extract the complete agent bundle: {error}"))
            })?;
            let enrolled = redtrace::enrollment::install_package(&options.package, &state)?;
            println!("Agent {} enrolled", enrolled.id);
            let config = state.join("service.json");
            if options.install {
                println!(
                    "{}",
                    redtrace::provision::install_user(&binary, &config, true)?
                );
            } else {
                let status = std::process::Command::new(binary)
                    .args(["--persistent", "--config"])
                    .arg(config)
                    .status()?;
                if !status.success() {
                    return Err(std::io::Error::other(
                        "enrolled agent stopped with an error",
                    ));
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("redtrace-agent: {error}");
            std::process::exit(2);
        }
        return;
    }
    let options = match parse_args(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("redtrace-agent: {error}\n\nUse --help for usage.");
            std::process::exit(2);
        }
    };
    let server = options
        .server
        .or_else(|| std::env::var("REDTRACE_AGENT_SERVER").ok())
        .unwrap_or_else(|| {
            eprintln!("redtrace-agent: --server is required\n\n{USAGE}");
            std::process::exit(2);
        });
    let endpoint = agent::parse_server(&server).unwrap_or_else(|error| configuration_error(&error));
    let token = resolve_token(options.token, options.token_file, &server)
        .unwrap_or_else(|error| configuration_error(&error));
    let defaults = SpoolLimits::default();
    let limits = SpoolLimits {
        max_events: usize::try_from(configured_limit(
            options.spool_events,
            "REDTRACE_AGENT_SPOOL_EVENTS",
            defaults.max_events as u64,
        ))
        .unwrap_or_else(|_| configuration_error("invalid spool event cap")),
        max_bytes: configured_limit(
            options.spool_bytes,
            "REDTRACE_AGENT_SPOOL_BYTES",
            defaults.max_bytes,
        ),
        max_quarantine_bytes: configured_limit(
            options.quarantine_bytes,
            "REDTRACE_AGENT_QUARANTINE_BYTES",
            defaults.max_quarantine_bytes,
        ),
        ..defaults
    }
    .validate()
    .unwrap_or_else(|error| configuration_error(&error.to_string()));
    let name = options
        .name
        .or_else(|| std::env::var("REDTRACE_AGENT_NAME").ok())
        .unwrap_or_else(agent::default_agent_name);
    let config = AgentConfig {
        server: server.clone(),
        token,
        name,
        state_dir: options.state_dir.unwrap_or_else(agent::default_state_dir),
        poll: options
            .poll
            .map(|seconds| Duration::from_secs(seconds.clamp(1, 3600)))
            .unwrap_or(DEFAULT_POLL),
        heartbeat: options
            .heartbeat
            .map(|seconds| Duration::from_secs(seconds.clamp(5, 3600)))
            .unwrap_or(DEFAULT_HEARTBEAT),
        flush_events: DEFAULT_FLUSH_EVENTS,
        outbox_cap: limits.max_events,
        lookback: options.lookback.clone(),
    };
    if let Some(lookback) = &config.lookback {
        unsafe { std::env::set_var("REDTRACE_LOOKBACK", lookback) };
    }
    let mut runtime = match AgentRuntime::new_with_spool_limits(config.clone(), limits) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!(
                "redtrace-agent: cannot open state directory {}: {error}",
                config.state_dir.display()
            );
            std::process::exit(3);
        }
    };
    agent::log(&format!(
        "starting: server={}, name={}, state_dir={}, poll={}s, spool_events={}, spool_bytes={}",
        config.server,
        config.name,
        config.state_dir.display(),
        config.poll.as_secs(),
        limits.max_events,
        limits.max_bytes
    ));
    let mut backoff = Duration::from_secs(1);
    let mut retry_at = std::time::Instant::now();
    loop {
        runtime.collect();
        if runtime.outbox.is_failed() {
            agent::log(
                "durable spool unavailable; exiting for recovery with pending records preserved",
            );
            std::process::exit(3);
        }
        if std::time::Instant::now() >= retry_at {
            let delivered = runtime.flush(&endpoint);
            if runtime.outbox.is_failed() {
                agent::log("durable spool progress unavailable; exiting for recovery");
                std::process::exit(3);
            }
            if delivered || runtime.outbox.is_empty() {
                backoff = Duration::from_secs(1);
                retry_at = std::time::Instant::now();
            } else {
                agent::log(&format!(
                    "retrying in {}s ({} events, {} bytes durably buffered)",
                    backoff.as_secs(),
                    runtime.outbox.len(),
                    runtime.outbox.size_bytes()
                ));
                retry_at = std::time::Instant::now() + backoff;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
        runtime.heartbeat_if_due(&endpoint);
        std::thread::sleep(runtime.config.poll);
    }
}

fn configuration_error(message: &str) -> ! {
    eprintln!("redtrace-agent: {message}\n\nUse --help for usage.");
    std::process::exit(2)
}

fn configured_limit(flag: Option<u64>, name: &str, default: u64) -> u64 {
    flag.unwrap_or_else(|| match std::env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| configuration_error(&format!("invalid {name}"))),
        Err(std::env::VarError::NotPresent) => default,
        Err(_) => configuration_error(&format!("invalid {name}")),
    })
}

fn resolve_token(
    flag: Option<String>,
    file: Option<PathBuf>,
    server: &str,
) -> Result<String, String> {
    if let Some(token) = flag {
        let url = reqwest::Url::parse(server).map_err(|_| "invalid server origin")?;
        if !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")) {
            return Err("--token is not permitted for remote servers; use REDTRACE_AGENT_TOKEN or --token-file".into());
        }
        agent::log(
            "--token exposes credentials in process arguments; use environment or a private token file",
        );
        agent::validate_token(&token).map_err(|error| error.to_string())?;
        return Ok(token);
    }
    if let Some(path) =
        file.or_else(|| std::env::var_os("REDTRACE_AGENT_TOKEN_FILE").map(PathBuf::from))
    {
        return agent::read_token_file(&path)
            .map_err(|_| "private token file could not be read or validated".into());
    }
    let token = std::env::var("REDTRACE_AGENT_TOKEN")
        .map_err(|_| "agent token environment variable or private file is required")?;
    agent::validate_token(&token).map_err(|error| error.to_string())?;
    Ok(token)
}

struct EnrollmentOptions {
    package: PathBuf,
    state_dir: Option<PathBuf>,
    install: bool,
}
fn parse_enrollment(args: &[String]) -> Result<Option<EnrollmentOptions>, String> {
    if !args.iter().any(|arg| arg == "--enroll") {
        return Ok(None);
    }
    let mut package = None;
    let mut state_dir = None;
    let mut install = false;
    let mut seen = std::collections::BTreeSet::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if !seen.insert(argument) {
            return Err(format!("duplicate {argument}"));
        }
        match argument.as_str() {
            "--install" => install = true,
            "--enroll" | "--state-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .filter(|value| !value.starts_with("--") && !value.is_empty())
                    .ok_or_else(|| format!("missing value for {argument}"))?;
                if argument == "--enroll" {
                    package = Some(PathBuf::from(value));
                } else {
                    state_dir = Some(PathBuf::from(value));
                }
            }
            _ => {
                return Err(format!(
                    "{argument} cannot be combined with --enroll; the package supplies connection and collection settings"
                ));
            }
        }
        index += 1;
    }
    Ok(Some(EnrollmentOptions {
        package: package.ok_or("--enroll requires a package file")?,
        state_dir,
        install,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn enrollment_rejects_ignored_and_duplicate_flags_before_redeeming() {
        for input in [
            vec!["--enroll"],
            vec!["--enroll", "--install"],
            vec![
                "--enroll",
                "fixture.json",
                "--server",
                "https://example.test",
            ],
            vec!["--enroll", "fixture.json", "--enroll", "second.json"],
            vec!["--enroll", "fixture.json", "--install", "--install"],
        ] {
            assert!(parse_enrollment(&args(&input)).is_err(), "{input:?}");
        }
        let options = parse_enrollment(&args(&[
            "--install",
            "--state-dir",
            "private",
            "--enroll",
            "fixture.json",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(options.package, PathBuf::from("fixture.json"));
        assert_eq!(options.state_dir, Some(PathBuf::from("private")));
        assert!(options.install);
    }
    #[test]
    fn legacy_parser_rejects_duplicate_and_missing_values() {
        assert!(
            parse_args(&args(&[
                "--server",
                "https://one.test",
                "--server",
                "https://two.test"
            ]))
            .is_err()
        );
        assert!(parse_args(&args(&["--server", "--name", "device"])).is_err());
    }
}
