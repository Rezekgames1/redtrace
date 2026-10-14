use redtrace::{
    backup,
    config::{Config, Profile},
    control::Listener,
    pki::Pki,
    provision, service,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    path::{Path, PathBuf},
};
const USAGE: &str = "REDTRACE setup and recovery
  redtrace-admin collector --data-dir ABSOLUTE --host LAN-IP-OR-DNS [--port 9711] [--profile basic|extended] [--install]
  redtrace-admin install-service --binary ABSOLUTE --config ABSOLUTE [--agent] [--identity ACCOUNT] [--password-file PRIVATE]
  redtrace-admin backup --data-dir ABSOLUTE --output ABSOLUTE.rtbackup
  redtrace-admin restore --backup FILE --target NEW-ABSOLUTE-DIRECTORY
  redtrace-admin inspect --backup FILE
  redtrace-admin validate --config FILE

--install and install-service without --identity configure startup at user login.
--identity selects a system service; run with the required administration rights.
The collector command configures a stopped collector; foreground startup is:
  redtrace --persistent --config ABSOLUTE/service.json
";

struct Arguments {
    action: String,
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}
impl Arguments {
    fn parse(arguments: &[String]) -> io::Result<Self> {
        let action = arguments.first().map(String::as_str).unwrap_or("help");
        let (values, flags): (&[&str], &[&str]) = match action {
            "help" | "--help" | "-h" => (&[], &[]),
            "collector" => (
                &["--data-dir", "--host", "--port", "--profile"],
                &["--install"],
            ),
            "install-service" => (
                &["--binary", "--config", "--identity", "--password-file"],
                &["--agent"],
            ),
            "backup" => (&["--data-dir", "--output"], &[]),
            "restore" => (&["--backup", "--target"], &[]),
            "inspect" => (&["--backup"], &[]),
            "validate" => (&["--config"], &[]),
            _ => return Err(service::invalid("unknown action; use --help for usage")),
        };
        let mut parsed = Self {
            action: action.into(),
            values: BTreeMap::new(),
            flags: BTreeSet::new(),
        };
        let mut index = 1;
        while index < arguments.len() {
            let argument = &arguments[index];
            if flags.contains(&argument.as_str()) {
                if !parsed.flags.insert(argument.clone()) {
                    return Err(service::invalid(&format!("duplicate {argument}")));
                }
            } else if values.contains(&argument.as_str()) {
                index += 1;
                let value = arguments
                    .get(index)
                    .filter(|value| !value.starts_with("--") && !value.is_empty())
                    .ok_or_else(|| service::invalid(&format!("missing value for {argument}")))?;
                if parsed
                    .values
                    .insert(argument.clone(), value.clone())
                    .is_some()
                {
                    return Err(service::invalid(&format!("duplicate {argument}")));
                }
            } else {
                return Err(service::invalid(&format!(
                    "unknown option for {action}: {argument}"
                )));
            }
            index += 1;
        }
        if parsed.option("--password-file").is_some() && parsed.option("--identity").is_none() {
            return Err(service::invalid("--password-file requires --identity"));
        }
        Ok(parsed)
    }
    fn option(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
    fn required(&self, name: &str) -> io::Result<&str> {
        self.option(name)
            .ok_or_else(|| service::invalid(&format!("{name} is required")))
    }
    fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("redtrace-admin: {error}");
        std::process::exit(2);
    }
}
fn run() -> io::Result<()> {
    let args = Arguments::parse(&std::env::args().skip(1).collect::<Vec<_>>())?;
    let option = |name: &str| args.option(name);
    let required = |name: &str| args.required(name);
    match args.action.as_str() {
        "collector" => {
            let service_path = configure_collector(&args)?;
            if args.flag("--install") {
                println!(
                    "{}",
                    provision::install_user(&collector_binary()?, &service_path, false)?
                );
            } else {
                println!(
                    "Start with: redtrace --persistent --config {}",
                    service_path.display()
                );
            }
        }
        "backup" => {
            let data = PathBuf::from(required("--data-dir")?);
            let _locks = backup::offline_lock(&data)?;
            let manifest = backup::create(&data, Path::new(required("--output")?))?;
            println!(
                "Saved {} files, {} bytes",
                manifest.files.len(),
                manifest.total_bytes
            );
        }
        "restore" => {
            let manifest = backup::restore(
                Path::new(required("--backup")?),
                Path::new(required("--target")?),
            )?;
            println!(
                "Restored {} files. Start collector with --config in the restored directory; the previous data directory is retained.",
                manifest.files.len()
            );
        }
        "inspect" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&backup::inspect(Path::new(required("--backup")?))?)
                    .map_err(io::Error::other)?
            );
        }
        "validate" => {
            Config::load(Path::new(required("--config")?))?;
            println!("Configuration valid");
        }
        "install-service" => {
            let binary = Path::new(required("--binary")?);
            let config = Path::new(required("--config")?);
            let agent = args.flag("--agent");
            let message = if let Some(identity) = option("--identity") {
                provision::install_system(
                    binary,
                    config,
                    agent,
                    identity,
                    option("--password-file").map(Path::new),
                )?
            } else {
                provision::install_user(binary, config, agent)?
            };
            println!("{message}");
        }
        _ => print!("{USAGE}"),
    }
    Ok(())
}

fn collector_binary() -> io::Result<PathBuf> {
    let path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| service::invalid("binary directory unavailable"))?
        .join(if cfg!(windows) {
            "redtrace.exe"
        } else {
            "redtrace"
        });
    service::protected_binary(&path)
}

fn configure_collector(args: &Arguments) -> io::Result<PathBuf> {
    let data = PathBuf::from(args.required("--data-dir")?);
    service::absolute_path(&data)?;
    let host = args.required("--host")?;
    let port = args
        .option("--port")
        .unwrap_or("9711")
        .parse::<u16>()
        .map_err(|_| service::invalid("invalid collector port"))?;
    if port == 0 {
        return Err(service::invalid("port must be nonzero"));
    }
    let profile = match args.option("--profile") {
        None => None,
        Some("basic") => Some(Profile::Basic),
        Some("extended") => Some(Profile::Extended),
        _ => return Err(service::invalid("profile must be basic or extended")),
    };
    let ipv6 = host.parse::<std::net::Ipv6Addr>().is_ok();
    let origin_host = if ipv6 {
        format!("[{host}]")
    } else {
        host.into()
    };
    let listener = Listener {
        bind: format!("{}:{port}", if ipv6 { "[::]" } else { "0.0.0.0" }),
        server: format!("https://{origin_host}:{port}"),
    };
    redtrace::agent::parse_server(&listener.server).map_err(io::Error::other)?;
    if args.flag("--install") {
        collector_binary()?;
    }
    service::private_directory(&data)?;
    let _locks = setup_locks(&data)?;
    let config_path = data.join("config.json");
    let config = match profile {
        Some(profile) => Config::for_profile(profile),
        None => Config::load(&config_path)?,
    };
    let service_path = data.join("service.json");
    if service_path.exists() {
        let service_config = service::ServiceConfig::load(&service_path)?;
        if std::fs::canonicalize(service_config.data_dir)? != std::fs::canonicalize(&data)? {
            return Err(service::invalid(
                "existing service configuration belongs to another data directory",
            ));
        }
    }
    let pki = Pki::new(data.join("pki"));
    match pki.status()? {
        Some(state) if state.hosts.iter().any(|san| san == host) => {}
        Some(mut state) => {
            state.hosts.push(host.into());
            pki.provision(state.hosts, false)?;
        }
        None => {
            pki.provision(vec![host.into()], false)?;
        }
    }
    config.save(&config_path)?;
    service::write_private(
        &data.join("listener.json"),
        &serde_json::to_vec_pretty(&listener).map_err(io::Error::other)?,
    )?;
    if !service_path.exists() {
        service::write_private(
            &service_path,
            &serde_json::to_vec_pretty(&serde_json::json!({"data_dir":data,"environment":{}}))
                .map_err(io::Error::other)?,
        )?;
    }
    println!("Configured collector {}", listener.server);
    Ok(service_path)
}

fn setup_locks(data: &Path) -> io::Result<Vec<File>> {
    ["active.lock", "catalog.lock"]
        .into_iter()
        .map(|name| {
            let path = data.join(name);
            let file = if path.exists() {
                service::protected_file(&path)?;
                File::options().read(true).write(true).open(path)?
            } else {
                service::create_private_file(&path)?
            };
            file.try_lock().map_err(|_| {
                service::invalid(
                    "collector is running; configure it through the GUI or stop it first",
                )
            })?;
            Ok(file)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn rejects_unknown_duplicate_missing_and_ignored_options() {
        for input in [
            vec!["collctor"],
            vec!["collector", "--port"],
            vec!["collector", "--host", "--install"],
            vec!["collector", "--port", "9711", "--port", "9712"],
            vec!["collector", "--install", "--install"],
            vec!["backup", "--agent"],
            vec!["install-service", "--password-file", "private"],
        ] {
            assert!(Arguments::parse(&args(&input)).is_err(), "{input:?}");
        }
    }
    #[test]
    fn repeated_collector_setup_preserves_config_and_updates_certificate_hosts() {
        let data = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "redtrace-admin-{}",
                service::random_secret().unwrap()
            ));
        let setup = |host| {
            Arguments::parse(&args(&[
                "collector",
                "--data-dir",
                data.to_str().unwrap(),
                "--host",
                host,
            ]))
            .unwrap()
        };
        configure_collector(&setup("localhost")).unwrap();
        let config = Config {
            exclude: "source=fixture".into(),
            ..Config::default()
        };
        config.save(&data.join("config.json")).unwrap();
        configure_collector(&setup("127.0.0.1")).unwrap();
        assert_eq!(Config::load(&data.join("config.json")).unwrap(), config);
        assert_eq!(
            Pki::new(data.join("pki")).status().unwrap().unwrap().hosts,
            ["localhost", "127.0.0.1"]
        );
        let locks = setup_locks(&data).unwrap();
        assert!(configure_collector(&setup("localhost")).is_err());
        drop(locks);
        std::fs::remove_dir_all(data).unwrap();
    }
}
