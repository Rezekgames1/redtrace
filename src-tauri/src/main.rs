#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tauri::{Manager, RunEvent};
use tauri_plugin_shell::ShellExt;

mod service;

#[cfg(windows)]
mod audit;

struct BackendProcess(Mutex<Option<service::Backend>>);
struct AuthToken(Mutex<String>);

#[tauri::command]
fn api_token(token: tauri::State<'_, AuthToken>) -> String {
    token.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn session_token() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("generate local API session token");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init());
    #[cfg(windows)]
    let builder = builder
        .manage(audit::AuditOperation(tokio::sync::Mutex::new(None)))
        .manage(audit::SysmonCandidate(tokio::sync::Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            api_token,
            service::enable_background,
            audit::audit_helper_status,
            audit::audit_execute,
            audit::sysmon_preview
        ]);
    #[cfg(not(windows))]
    let builder = builder.invoke_handler(tauri::generate_handler![
        api_token,
        service::enable_background
    ]);
    let app = builder
        .setup(|app| {
            if let Some(session) = service::persistent()? {
                app.manage(AuthToken(Mutex::new(session.token.clone())));
                app.manage(BackendProcess(Mutex::new(Some(service::Backend {
                    child: None,
                    session: Some(session),
                    terminated: Arc::new(AtomicBool::new(false)),
                }))));
                return Ok(());
            }
            let token = session_token();
            app.manage(AuthToken(Mutex::new(token.clone())));
            let sidecar = app
                .shell()
                .sidecar("redtrace")?
                .env("REDTRACE_API_TOKEN", &token)
                .env("REDTRACE_SERVICE_MODE", "portable")
                .env("REDTRACE_API_BIND", "127.0.0.1:9710");
            let (mut events, child) = sidecar.spawn()?;
            let pid = child.pid();
            let terminated = Arc::new(AtomicBool::new(false));
            let ended = terminated.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(event) = events.recv().await {
                    match event {
                        tauri_plugin_shell::process::CommandEvent::Stdout(bytes) => {
                            eprintln!("{}", String::from_utf8_lossy(&bytes));
                        }
                        tauri_plugin_shell::process::CommandEvent::Stderr(bytes) => {
                            eprintln!("{}", String::from_utf8_lossy(&bytes));
                        }
                        tauri_plugin_shell::process::CommandEvent::Terminated(_) => {
                            ended.store(true, Ordering::Release);
                        }
                        _ => {}
                    }
                }
            });
            let binary = service::binary()?;
            let mut session = None;
            for _ in 0..100 {
                if terminated.load(Ordering::Acquire) {
                    break;
                }
                if let Ok(ready) = redtrace::service::portable_session(
                    "127.0.0.1:9710".parse().unwrap(),
                    &token,
                    pid,
                    &binary,
                ) {
                    session = Some(ready);
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if session.is_none() {
                let _ = child.kill();
                return Err(redtrace::service::invalid(
                    "desktop-owned collector could not be authenticated",
                )
                .into());
            }
            app.manage(BackendProcess(Mutex::new(Some(service::Backend {
                child: Some(child),
                session,
                terminated,
            }))));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("build RED//TRACE desktop shell");

    app.run(|handle, event| {
        if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. })
            && let Some(child) = handle
                .state::<BackendProcess>()
                .0
                .lock()
                .expect("lock backend process")
                .take()
        {
            child.stop();
        }
    });
}
