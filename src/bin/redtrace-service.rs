use redtrace::service::{self, ServiceConfig};
use std::{
    io,
    path::{Path, PathBuf},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("redtrace-service: {error}");
        std::process::exit(2);
    }
}

fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let action = args.first().map(String::as_str).ok_or_else(|| service::invalid("usage: redtrace-service <validate|systemd-template|install|start|stop|remove> --binary ABSOLUTE --config ABSOLUTE [--identity ACCOUNT] [--password-file PRIVATE] [--agent]"))?;
    let mut binary = None;
    let mut config = None;
    let mut identity = None;
    let mut password = None;
    let mut agent = false;
    let mut index = 1;
    while index < args.len() {
        let option = &args[index];
        if option == "--agent" {
            agent = true;
            index += 1;
            continue;
        }
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| service::invalid("missing option value"))?;
        match option.as_str() {
            "--binary" => binary = Some(PathBuf::from(value)),
            "--config" => config = Some(PathBuf::from(value)),
            "--identity" => identity = Some(value.clone()),
            "--password-file" => password = Some(PathBuf::from(value)),
            _ => return Err(service::invalid("unknown provisioning option")),
        }
        index += 1;
    }
    let binary = binary.ok_or_else(|| service::invalid("absolute binary is required"))?;
    let config =
        config.ok_or_else(|| service::invalid("absolute private configuration is required"))?;
    service::protected_binary(&binary)?;
    ServiceConfig::load(&config)?;
    match action {
        "validate" => println!("Protected binary and private configuration validated."),
        "systemd-template" | "systemd-user-template" => {
            let template = service::systemd_template(
                &binary,
                &config,
                identity
                    .as_deref()
                    .ok_or_else(|| service::invalid("explicit service identity is required"))?,
                agent,
            )?;
            let template = if action == "systemd-user-template" {
                template
                    .lines()
                    .filter(|line| !line.starts_with("User="))
                    .map(|line| {
                        if line == "WantedBy=multi-user.target" {
                            "WantedBy=default.target"
                        } else {
                            line
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n"
            } else {
                template
            };
            print!("{template}");
        }
        "install" => install(
            &binary,
            &config,
            identity
                .as_deref()
                .ok_or_else(|| service::invalid("explicit service identity is required"))?,
            password.as_deref(),
            agent,
        )?,
        "start" | "stop" | "remove" => manage(action, &binary, &config, agent)?,
        _ => return Err(service::invalid("unknown provisioning action")),
    }
    Ok(())
}

#[cfg(windows)]
fn install(
    binary: &Path,
    config: &Path,
    identity: &str,
    password: Option<&Path>,
    agent: bool,
) -> io::Result<()> {
    service::windows::install(binary, config, identity, password, agent)
}
#[cfg(not(windows))]
fn install(_: &Path, _: &Path, _: &str, _: Option<&Path>, _: bool) -> io::Result<()> {
    Err(service::invalid(
        "use systemd-template and the system service manager on Linux",
    ))
}

#[cfg(windows)]
fn manage(action: &str, binary: &Path, config: &Path, agent: bool) -> io::Result<()> {
    service::windows::manage(action, binary, config, agent)
}
#[cfg(not(windows))]
fn manage(_: &str, _: &Path, _: &Path, _: bool) -> io::Result<()> {
    Err(service::invalid("use the system service manager on Linux"))
}
