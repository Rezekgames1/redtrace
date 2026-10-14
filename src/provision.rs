//! Explicit provisioning actions; normal collection never edits service managers.
use crate::service::{self, invalid};
use std::{io, path::Path, process::Command};

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    let result = Command::new(program).args(args).output()?;
    if result.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&result.stderr)
                .chars()
                .take(512)
                .collect::<String>()
        )))
    }
}
pub fn launchd(
    binary: &Path,
    config: &Path,
    agent: bool,
    identity: Option<&str>,
) -> io::Result<String> {
    service::protected_binary(binary)?;
    service::ServiceConfig::load(config)?;
    let xml = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let label = if agent {
        "com.redlabs.redtrace.agent"
    } else {
        "com.redlabs.redtrace.collector"
    };
    let user = if let Some(user) = identity {
        if user.is_empty()
            || user.len() > 64
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(invalid("invalid launchd identity"));
        }
        format!("<key>UserName</key><string>{}</string>", xml(user))
    } else {
        String::new()
    };
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{}</string><string>--persistent</string><string>--config</string><string>{}</string></array>{user}<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer><key>ProcessType</key><string>Background</string><key>LowPriorityIO</key><true/><key>Nice</key><integer>10</integer></dict></plist>\n",
        xml(&binary.to_string_lossy()),
        xml(&config.to_string_lossy())
    ))
}

pub fn install_user(binary: &Path, config: &Path, agent: bool) -> io::Result<String> {
    let binary = service::protected_binary(binary)?;
    service::ServiceConfig::load(config)?;
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| invalid("user home unavailable"))?;
        let directory = std::path::PathBuf::from(home).join(".config/systemd/user");
        let identity = std::env::var("USER").map_err(|_| invalid("user identity unavailable"))?;
        let template = service::systemd_template(&binary, config, &identity, agent)?;
        let template = template
            .lines()
            .filter(|l| !l.starts_with("User="))
            .map(|l| {
                if l == "WantedBy=multi-user.target" {
                    "WantedBy=default.target"
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let name = if agent {
            "redtrace-agent.service"
        } else {
            "redtrace.service"
        };
        let path = directory.join(name);
        owned_target(&path, &binary, config)?;
        service::write_protected_metadata(&path, template.as_bytes())?;
        run("systemctl", &["--user", "daemon-reload"])?;
        run("systemctl", &["--user", "enable", "--now", name])?;
        return Ok("systemd user service installed; boot without login uses user lingering".into());
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| invalid("user home unavailable"))?;
        let label = if agent {
            "com.redlabs.redtrace.agent"
        } else {
            "com.redlabs.redtrace.collector"
        };
        let path = std::path::PathBuf::from(home)
            .join("Library/LaunchAgents")
            .join(format!("{label}.plist"));
        owned_target(&path, &binary, config)?;
        let template = launchd(&binary, config, agent, None)?;
        service::write_protected_metadata(&path, template.as_bytes())?;
        let domain = format!("gui/{}", unsafe { libc::geteuid() });
        start_launchd(&domain, label, &path, &binary, config)?;
        return Ok("launchd user agent installed; starts at login".into());
    }
    #[cfg(windows)]
    {
        let name = if agent {
            "REDTRACEAgent"
        } else {
            "REDTRACECollector"
        };
        let exists = Command::new("schtasks")
            .args(["/Query", "/TN", name, "/XML"])
            .output()?;
        if exists.status.success()
            && !String::from_utf8_lossy(&exists.stdout)
                .contains(&binary.to_string_lossy().replace('&', "&amp;"))
        {
            return Err(invalid(
                "an unrelated scheduled task already uses this name",
            ));
        }
        let command = format!(
            "\"{}\" --persistent --config \"{}\"",
            binary.display(),
            config.display()
        );
        run(
            "schtasks",
            &[
                "/Create", "/TN", name, "/SC", "ONLOGON", "/TR", &command, "/RL", "LIMITED", "/IT",
                "/F",
            ],
        )?;
        run("schtasks", &["/Run", "/TN", name])?;
        return Ok("Windows user task installed; starts at login without a stored password".into());
    }
    #[allow(unreachable_code)]
    Err(invalid("unsupported service platform"))
}
#[cfg(not(windows))]
fn owned_target(path: &Path, binary: &Path, config: &Path) -> io::Result<()> {
    if path.exists() {
        let content =
            String::from_utf8(service::read_private(path, 64 * 1024)?).map_err(io::Error::other)?;
        let contains_path = |path: &Path| -> io::Result<bool> {
            let value = path
                .to_str()
                .ok_or_else(|| invalid("service path not UTF-8"))?;
            let escaped = value
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;");
            Ok(content.contains(value) || content.contains(&escaped))
        };
        if !contains_path(binary)? || !contains_path(config)? {
            return Err(invalid(
                "service target belongs to a different executable or configuration",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn start_launchd(
    domain: &str,
    label: &str,
    path: &Path,
    binary: &Path,
    config: &Path,
) -> io::Result<()> {
    let target = format!("{domain}/{label}");
    let loaded = Command::new("launchctl")
        .args(["print", &target])
        .output()?;
    if loaded.status.success() {
        let state = String::from_utf8_lossy(&loaded.stdout);
        if !state.contains(
            binary
                .to_str()
                .ok_or_else(|| invalid("invalid binary path"))?,
        ) || !state.contains(
            config
                .to_str()
                .ok_or_else(|| invalid("invalid config path"))?,
        ) {
            return Err(invalid(
                "loaded launchd service belongs to another executable or configuration",
            ));
        }
        // No -k: a repeated install must not kill a collector that is already running.
        run("launchctl", &["kickstart", &target])
    } else {
        run(
            "launchctl",
            &[
                "bootstrap",
                domain,
                path.to_str().ok_or_else(|| invalid("invalid plist path"))?,
            ],
        )
    }
}

pub fn install_system(
    binary: &Path,
    config: &Path,
    agent: bool,
    identity: &str,
    password: Option<&Path>,
) -> io::Result<String> {
    #[cfg(not(windows))]
    let _ = password;
    service::protected_binary(binary)?;
    service::ServiceConfig::load(config)?;
    #[cfg(windows)]
    {
        crate::service::windows::install(binary, config, identity, password, agent)?;
        crate::service::windows::manage("start", binary, config, agent)?;
        return Ok("Windows SCM service installed".into());
    }
    #[cfg(target_os = "linux")]
    {
        let name = if agent {
            "redtrace-agent.service"
        } else {
            "redtrace.service"
        };
        let path = std::path::PathBuf::from("/etc/systemd/system").join(name);
        owned_target(&path, binary, config)?;
        let template = service::systemd_template(binary, config, identity, agent)?;
        service::write_protected_metadata(&path, template.as_bytes())?;
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "--now", name])?;
        return Ok("systemd service installed".into());
    }
    #[cfg(target_os = "macos")]
    {
        let label = if agent {
            "com.redlabs.redtrace.agent"
        } else {
            "com.redlabs.redtrace.collector"
        };
        let path =
            std::path::PathBuf::from("/Library/LaunchDaemons").join(format!("{label}.plist"));
        owned_target(&path, binary, config)?;
        let template = launchd(binary, config, agent, Some(identity))?;
        service::write_protected_metadata(&path, template.as_bytes())?;
        start_launchd("system", label, &path, binary, config)?;
        return Ok("launchd system daemon installed".into());
    }
    #[allow(unreachable_code)]
    {
        let _ = (password, identity);
        Err(invalid("unsupported platform"))
    }
}
