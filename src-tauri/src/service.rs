use redtrace::service::{self, LocalSession};
use std::{
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tauri::{AppHandle, Manager};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandChild;

pub struct Backend {
    pub child: Option<CommandChild>,
    pub session: Option<LocalSession>,
    pub terminated: Arc<AtomicBool>,
}

pub fn binary() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("REDTRACE_SERVICE_BINARY") {
        return Ok(PathBuf::from(path));
    }
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or_else(|| service::invalid("desktop executable has no parent"))?;
    Ok(directory.join(if cfg!(windows) {
        "redtrace.exe"
    } else {
        "redtrace"
    }))
}

pub fn persistent() -> io::Result<Option<LocalSession>> {
    let data = std::env::var_os("REDTRACE_SERVICE_DATA_DIR")
        .or_else(|| std::env::var_os("REDTRACE_DATA_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(redtrace::storage::data_directory);
    let session = std::env::var_os("REDTRACE_SESSION_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| data.join("session.json"));
    match std::env::var("REDTRACE_DESKTOP_MODE").as_deref() {
        Ok("persistent") => {}
        Ok("portable") => return Ok(None),
        Err(_) if session.exists() => {}
        Err(_) => return Ok(None),
        _ => return Err(service::invalid("invalid desktop lifecycle mode")),
    }
    let session = service::attach(&session, &binary()?, &data)?;
    if session.identity.address != "127.0.0.1:9710".parse().unwrap() {
        return Err(service::invalid(
            "desktop frontend requires the configured 127.0.0.1:9710 endpoint",
        ));
    }
    Ok(Some(session))
}

impl Backend {
    pub fn stop(mut self) {
        let Some(child) = self.child.take() else {
            return;
        };
        let Some(session) = self.session.take() else {
            let _ = child.kill();
            return;
        };
        if service::request_stop(&session, true).is_ok() {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !self.terminated.load(Ordering::Acquire) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        if !self.terminated.load(Ordering::Acquire) {
            let _ = child.kill();
        }
    }
}

#[tauri::command]
pub async fn enable_background(app: AppHandle) -> Result<String, String> {
    tokio::task::spawn_blocking(move || -> io::Result<String> {
        let data = {
            let managed = app.state::<super::BackendProcess>();
            let guard = managed.0.lock().unwrap_or_else(|e| e.into_inner());
            let backend = guard
                .as_ref()
                .ok_or_else(|| service::invalid("collector state unavailable"))?;
            if backend.child.is_none() {
                return Ok("Фоновый сбор уже подключён".into());
            }
            backend
                .session
                .as_ref()
                .ok_or_else(|| service::invalid("collector session unavailable"))?
                .identity
                .data_dir
                .clone()
        };
        let config = data.join("desktop-service.json");
        let binary = binary()?;
        let environment: std::collections::BTreeMap<_, _> = std::env::vars()
            .filter(|(name, _)| {
                name.starts_with("REDTRACE_")
                    && !matches!(
                        name.as_str(),
                        "REDTRACE_API_TOKEN"
                            | "REDTRACE_AGENT_TOKEN"
                            | "REDTRACE_ALLOW_UNAUTHENTICATED"
                            | "REDTRACE_DATA_DIR"
                            | "REDTRACE_API_BIND"
                            | "REDTRACE_SERVICE_MODE"
                            | "REDTRACE_SESSION_FILE"
                            | "REDTRACE_DESKTOP_MODE"
                            | "REDTRACE_SERVICE_BINARY"
                            | "REDTRACE_SERVICE_DATA_DIR"
                    )
            })
            .collect();
        service::write_private(
            &config,
            &serde_json::to_vec_pretty(
                &serde_json::json!({"data_dir":data,"environment":environment}),
            )
            .map_err(io::Error::other)?,
        )?;
        service::ServiceConfig::load(&config)?;
        let backend = app
            .state::<super::BackendProcess>()
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| service::invalid("collector state unavailable"))?;
        backend.stop();
        let installed = redtrace::provision::install_user(&binary, &config, false);
        let mut attached = None;
        for _ in 0..100 {
            if let Ok(session) = service::attach(&data.join("session.json"), &binary, &data) {
                attached = Some(session);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if let Some(session) = attached {
            *app.state::<super::AuthToken>()
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = session.token.clone();
            *app.state::<super::BackendProcess>()
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(Backend {
                child: None,
                session: Some(session),
                terminated: Arc::new(AtomicBool::new(false)),
            });
            return installed;
        }
        let token = app
            .state::<super::AuthToken>()
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (mut events, child) = app
            .shell()
            .sidecar("redtrace")
            .map_err(io::Error::other)?
            .env("REDTRACE_API_TOKEN", &token)
            .env("REDTRACE_SERVICE_MODE", "portable")
            .env("REDTRACE_API_BIND", "127.0.0.1:9710")
            .env("REDTRACE_DATA_DIR", &data)
            .spawn()
            .map_err(io::Error::other)?;
        let pid = child.pid();
        let terminated = Arc::new(AtomicBool::new(false));
        let ended = terminated.clone();
        tauri::async_runtime::spawn(async move {
            while let Some(event) = events.recv().await {
                if matches!(
                    event,
                    tauri_plugin_shell::process::CommandEvent::Terminated(_)
                ) {
                    ended.store(true, Ordering::Release);
                }
            }
        });
        let mut session = None;
        for _ in 0..100 {
            if let Ok(ready) = service::portable_session(
                "127.0.0.1:9710".parse().map_err(io::Error::other)?,
                &token,
                pid,
                &binary,
            ) {
                session = Some(ready);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        *app.state::<super::BackendProcess>()
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Backend {
            child: Some(child),
            session,
            terminated,
        });
        Err(installed.err().unwrap_or_else(|| {
            service::invalid("service installed but collector did not start; verify its status")
        }))
    })
    .await
    .map_err(|_| "background provisioning worker failed".to_owned())?
    .map_err(|e| e.to_string())
}
