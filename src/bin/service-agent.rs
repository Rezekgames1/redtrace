use redtrace::{
    agent::{self, AgentConfig, AgentRuntime, DEFAULT_FLUSH_EVENTS, SpoolLimits},
    service::{self, ServiceConfig, Shutdown},
};
use std::{
    io,
    path::Path,
    time::{Duration, Instant},
};

fn main() {
    if let Err(error) = entry() {
        eprintln!("redtrace-service-agent: {error}");
        std::process::exit(2);
    }
}

fn entry() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut scm = false;
    let mut config = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--persistent" => {}
            "--windows-service" => scm = true,
            "--config" => {
                index += 1;
                config = Some(ServiceConfig::load(Path::new(
                    args.get(index)
                        .ok_or_else(|| service::invalid("missing configuration"))?,
                ))?);
            }
            _ => {
                return Err(service::invalid(
                    "usage: redtrace-service-agent --persistent --config ABSOLUTE_PRIVATE_JSON [--windows-service]",
                ));
            }
        }
        index += 1;
    }
    let config =
        config.ok_or_else(|| service::invalid("explicit private configuration is required"))?;
    config.apply();
    let run = move |shutdown| run_agent(config, shutdown);
    #[cfg(windows)]
    if scm {
        return service::windows::dispatch("REDTRACEAgent", run);
    }
    #[cfg(not(windows))]
    if scm {
        return Err(service::invalid("Windows SCM mode is unavailable"));
    }
    run(Shutdown::new())
}

fn number(name: &str, default: u64, maximum: u64) -> io::Result<u64> {
    let value = std::env::var(name).map_or(Ok(default), |value| {
        value
            .parse::<u64>()
            .map_err(|_| service::invalid("invalid agent service limit"))
    })?;
    if value == 0 || value > maximum {
        return Err(service::invalid("invalid agent service limit"));
    }
    Ok(value)
}

fn run_agent(config: ServiceConfig, shutdown: Shutdown) -> io::Result<()> {
    service::protected_binary(&std::env::current_exe()?)?;
    service::private_directory(&config.data_dir)?;
    let server = std::env::var("REDTRACE_AGENT_SERVER")
        .map_err(|_| service::invalid("agent server is required"))?;
    let endpoint =
        agent::parse_server(&server).map_err(|_| service::invalid("invalid agent server"))?;
    let token_file = std::env::var_os("REDTRACE_AGENT_TOKEN_FILE")
        .ok_or_else(|| service::invalid("private agent token file is required"))?;
    let token_file = std::path::PathBuf::from(token_file);
    service::protected_file(&token_file)?;
    let token = agent::read_token_file(&token_file)?;
    let defaults = SpoolLimits::default();
    let limits = SpoolLimits {
        max_events: number(
            "REDTRACE_AGENT_SPOOL_EVENTS",
            defaults.max_events as u64,
            100_000,
        )? as usize,
        max_bytes: number(
            "REDTRACE_AGENT_SPOOL_BYTES",
            defaults.max_bytes,
            1024 * 1024 * 1024,
        )?,
        max_quarantine_bytes: number(
            "REDTRACE_AGENT_QUARANTINE_BYTES",
            defaults.max_quarantine_bytes,
            1024 * 1024 * 1024,
        )?,
        ..defaults
    }
    .validate()?;
    let agent_config = AgentConfig {
        server,
        token,
        name: std::env::var("REDTRACE_AGENT_NAME").unwrap_or_else(|_| agent::default_agent_name()),
        state_dir: config.data_dir,
        poll: Duration::from_secs(number("REDTRACE_AGENT_POLL_SECONDS", 5, 3600)?),
        heartbeat: Duration::from_secs(number("REDTRACE_AGENT_HEARTBEAT_SECONDS", 30, 3600)?),
        flush_events: DEFAULT_FLUSH_EVENTS,
        outbox_cap: limits.max_events,
        lookback: std::env::var("REDTRACE_LOOKBACK").ok(),
    };
    let mut agent = AgentRuntime::new_with_spool_limits(agent_config.clone(), limits)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let signal = shutdown.listen();
    #[cfg(windows)]
    service::windows::ready();
    agent::log("persistent agent ready");
    let mut retry_at = Instant::now();
    let mut backoff = Duration::from_secs(1);
    while !shutdown.requested() {
        if std::env::var("REDTRACE_COLLECT_LOCAL").as_deref() != Ok("0") {
            agent.collect();
        }
        if agent.outbox.is_failed() {
            return Err(io::Error::other(
                "agent durable spool failed; pending records preserved",
            ));
        }
        if shutdown.requested() {
            break;
        }
        if Instant::now() >= retry_at {
            if agent.flush(&endpoint) || agent.outbox.is_empty() {
                backoff = Duration::from_secs(1);
            } else {
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
            retry_at = Instant::now() + backoff;
        }
        if agent.outbox.is_failed() {
            return Err(io::Error::other(
                "agent durable progress failed; pending records preserved",
            ));
        }
        if shutdown.requested() {
            break;
        }
        agent.heartbeat_if_due(&endpoint);
        runtime.block_on(async {
            tokio::select! {
                _ = shutdown.wait() => {},
                _ = tokio::time::sleep(agent.config.poll) => {},
            }
        });
    }
    signal.abort();
    agent::log("service stopped; unacknowledged records remain in the durable spool");
    Ok(())
}
