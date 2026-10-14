use redtrace::audit::helper::{self, HelperRequest, HelperResponse};
use std::{os::windows::io::AsRawHandle, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::windows::named_pipe::ServerOptions,
};
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Pipes::GetNamedPipeClientProcessId,
        Threading::{GetExitCodeProcess, GetProcessId},
    },
    UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
};

#[derive(serde::Serialize)]
pub struct HelperStatus {
    executor_available: bool,
    mode: &'static str,
    reason: &'static str,
}

pub struct AuditOperation(pub tokio::sync::Mutex<Option<ElevatedProcess>>);
pub struct SysmonCandidate(pub tokio::sync::Mutex<Option<Vec<u8>>>);

#[tauri::command]
pub async fn sysmon_preview(
    binary_path: String,
    candidate: tauri::State<'_, SysmonCandidate>,
) -> Result<redtrace::audit::sysmon::SysmonPreview, String> {
    let (preview, bytes) =
        tokio::task::spawn_blocking(move || redtrace::audit::sysmon::preview(&binary_path))
            .await
            .map_err(|_| "Sysmon preview task failed")??;
    *candidate.0.lock().await = Some(bytes);
    Ok(preview)
}

pub struct ElevatedProcess {
    handle: usize,
    pid: u32,
}

impl ElevatedProcess {
    fn running(&self) -> bool {
        let mut code = 0;
        unsafe { GetExitCodeProcess(self.handle as _, &mut code) == 0 || code == 259 }
    }
}

impl Drop for ElevatedProcess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle as _);
        }
    }
}

fn helper_path() -> Result<std::path::PathBuf, String> {
    Ok(std::env::current_exe()
        .map_err(|_| "desktop executable unavailable")?
        .parent()
        .ok_or("desktop directory unavailable")?
        .join("redtrace-audit-helper.exe"))
}

#[tauri::command]
pub fn audit_helper_status() -> HelperStatus {
    let readiness = trusted_helper();
    let enabled = readiness.is_ok();
    HelperStatus {
        executor_available: enabled,
        mode: if enabled {
            "administrator_installed_helper"
        } else {
            "preview_only"
        },
        reason: if enabled {
            "Административная установка: защищённые binaries, pin helper, UAC, snapshot и проверка результата."
        } else {
            "Установите REDTRACE через административный установщик в Program Files; helper должен совпадать с этой сборкой."
        },
    }
}

fn trusted_helper() -> Result<redtrace::audit::deployment::ProtectedExecutable, String> {
    let expected =
        option_env!("REDTRACE_AUDIT_HELPER_SHA256").ok_or("build helper digest unavailable")?;
    let path = helper_path()?;
    let mut file = redtrace::audit::deployment::executable(&path)?;
    if !file.digest()?.eq_ignore_ascii_case(expected) {
        return Err("installed helper digest mismatch; reinstall this build".into());
    }
    Ok(file)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn launch(path: &std::path::Path, pipe: &str) -> Result<ElevatedProcess, String> {
    let verb = wide("runas");
    let executable = wide(&path.to_string_lossy());
    let parameters = wide(&format!("--pipe {pipe} --parent {}", std::process::id()));
    let mut information: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    information.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    information.fMask = SEE_MASK_NOCLOSEPROCESS;
    information.lpVerb = verb.as_ptr();
    information.lpFile = executable.as_ptr();
    information.lpParameters = parameters.as_ptr();
    information.nShow = 0;
    if unsafe { ShellExecuteExW(&mut information) } == 0 {
        return Err("UAC cancelled or helper could not start".into());
    }
    if information.hProcess.is_null() {
        return Err("helper process handle unavailable".into());
    }
    let pid = unsafe { GetProcessId(information.hProcess) };
    if pid == 0 {
        unsafe {
            CloseHandle(information.hProcess);
        }
        return Err("helper PID unavailable".into());
    }
    Ok(ElevatedProcess {
        handle: information.hProcess as usize,
        pid,
    })
}

#[tauri::command]
pub async fn audit_execute(
    request: HelperRequest,
    operation: tauri::State<'_, AuditOperation>,
    candidate: tauri::State<'_, SysmonCandidate>,
) -> Result<HelperResponse, String> {
    let mut guard = operation.0.lock().await;
    if guard.as_ref().is_some_and(ElevatedProcess::running) {
        return Err("previous elevated operation is still running; state may be unknown".into());
    }
    guard.take();
    let _trusted_binary = trusted_helper()?;
    helper::validate(&request)?;
    let payload = if let HelperRequest::InstallSysmon { binary_length, .. } = &request {
        let bytes = candidate
            .0
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or("preview the selected Sysmon binary first")?;
        if bytes.len() != *binary_length {
            return Err("Sysmon preview changed".into());
        }
        Some(bytes)
    } else {
        None
    };
    let path = helper_path()?;
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| "IPC nonce generation failed")?;
    let pipe_name = format!(
        "\\\\.\\pipe\\redtrace-audit-{}",
        redtrace::ingest::hex(&random)
    );
    let mut pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&pipe_name)
        .map_err(|_| "audit IPC creation failed")?;
    let executable = path.clone();
    let name = pipe_name.clone();
    let process = tokio::task::spawn_blocking(move || launch(&executable, &name))
        .await
        .map_err(|_| "helper launch task failed")??;
    let pid = process.pid;
    *guard = Some(process);
    tokio::time::timeout(Duration::from_secs(120), pipe.connect())
        .await
        .map_err(|_| "helper IPC connection timed out")?
        .map_err(|_| "helper IPC connection failed")?;
    let mut client_pid = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle().cast(), &mut client_pid) } == 0
        || client_pid != pid
        || !helper::peer_matches(pid, &path)
    {
        return Err("helper IPC identity mismatch".into());
    }
    let mut body =
        serde_json::to_vec(&request).map_err(|_| "audit request serialization failed")?;
    body.push(b'\n');
    pipe.write_all(&body)
        .await
        .map_err(|_| "audit IPC write failed")?;
    if let Some(payload) = payload {
        pipe.write_all(&payload)
            .await
            .map_err(|_| "Sysmon IPC payload transfer failed")?;
    }
    let mut reader = BufReader::new(pipe.take(16384));
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(120), reader.read_line(&mut line))
        .await
        .map_err(|_| "audit helper response timed out; preserve snapshot for recovery")?
        .map_err(|_| "audit helper response failed")?;
    serde_json::from_str(&line).map_err(|_| "invalid audit helper response".into())
}
