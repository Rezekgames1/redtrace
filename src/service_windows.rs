use super::{Shutdown, invalid};
use std::{
    io,
    path::Path,
    ptr,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicPtr, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR},
    Storage::FileSystem::DELETE,
    System::Services::*,
};

type Runner = Box<dyn FnOnce(Shutdown) -> io::Result<()> + Send>;
static RUNNER: OnceLock<Mutex<Option<Runner>>> = OnceLock::new();
static STOP: OnceLock<Shutdown> = OnceLock::new();
static NAME: OnceLock<Vec<u16>> = OnceLock::new();
static STATUS: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(ptr::null_mut());
static RESULT: OnceLock<Mutex<Option<io::Result<()>>>> = OnceLock::new();

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn report(state: u32, error: u32) {
    let handle = STATUS.load(Ordering::Acquire);
    if handle.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if error == 0 {
            0
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
        dwServiceSpecificExitCode: error,
        dwCheckPoint: u32::from(matches!(
            state,
            SERVICE_START_PENDING | SERVICE_STOP_PENDING
        )),
        dwWaitHint: if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
            45_000
        } else {
            0
        },
    };
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

pub fn ready() {
    report(SERVICE_RUNNING, 0);
}

unsafe extern "system" fn control(
    code: u32,
    _: u32,
    _: *mut std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 0);
            if let Some(stop) = STOP.get() {
                stop.request();
            }
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(NAME.get().unwrap().as_ptr(), Some(control), ptr::null_mut())
    };
    if handle.is_null() {
        *RESULT.get().unwrap().lock().unwrap() = Some(Err(io::Error::last_os_error()));
        return;
    }
    STATUS.store(handle, Ordering::Release);
    report(SERVICE_START_PENDING, 0);
    let runner = RUNNER.get().unwrap().lock().unwrap().take().unwrap();
    let result = runner(STOP.get().unwrap().clone());
    report(SERVICE_STOPPED, u32::from(result.is_err()));
    *RESULT.get().unwrap().lock().unwrap() = Some(result);
}

pub fn dispatch(
    name: &str,
    run: impl FnOnce(Shutdown) -> io::Result<()> + Send + 'static,
) -> io::Result<()> {
    NAME.set(wide(name))
        .map_err(|_| invalid("service dispatcher already initialized"))?;
    RUNNER
        .set(Mutex::new(Some(Box::new(run))))
        .map_err(|_| invalid("service dispatcher already initialized"))?;
    STOP.set(Shutdown::new())
        .map_err(|_| invalid("service dispatcher already initialized"))?;
    RESULT
        .set(Mutex::new(None))
        .map_err(|_| invalid("service dispatcher already initialized"))?;
    let entries = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: NAME.get().unwrap().as_ptr().cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    RESULT
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .take()
        .unwrap_or_else(|| Err(io::Error::other("service did not start")))
}

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

fn command(binary: &Path, config: &Path) -> io::Result<Vec<u16>> {
    super::protected_binary(binary)?;
    super::ServiceConfig::load(config)?;
    Ok(wide(&format!(
        "\"{}\" --windows-service --persistent --config \"{}\"",
        binary.display(),
        config.display()
    )))
}

pub fn install(
    binary: &Path,
    config: &Path,
    identity: &str,
    password_file: Option<&Path>,
    agent: bool,
) -> io::Result<()> {
    if identity.trim().is_empty()
        || identity.contains(['\0', '\r', '\n'])
        || matches!(
            identity.to_ascii_lowercase().as_str(),
            "localsystem" | "system" | "nt authority\\system" | "root"
        )
    {
        return Err(invalid(
            "an explicit non-System service identity is required",
        ));
    }
    let command = command(binary, config)?;
    let password = password_file
        .map(|path| super::read_private(path, 4096))
        .transpose()?;
    let mut password = password
        .map(|bytes| {
            String::from_utf8(bytes).map(|value| wide(value.trim_end_matches(['\r', '\n'])))
        })
        .transpose()
        .map_err(|_| invalid("invalid service credential file"))?;
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CREATE_SERVICE) };
    if scm.is_null() {
        return Err(io::Error::last_os_error());
    }
    let scm = ServiceHandle(scm);
    let name = wide(if agent { "REDTRACEAgent" } else { "REDTRACE" });
    let service = unsafe {
        CreateServiceW(
            scm.0,
            name.as_ptr(),
            name.as_ptr(),
            SERVICE_CHANGE_CONFIG | DELETE,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            wide(identity).as_ptr(),
            password
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
        )
    };
    if let Some(password) = &mut password {
        password.fill(0);
    }
    if service.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = ServiceHandle(service);
    let result = (|| {
        let mut actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 15_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 60_000,
            },
        ];
        let policy = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86400,
            lpRebootMsg: ptr::null_mut(),
            lpCommand: ptr::null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        if unsafe {
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                (&policy as *const SERVICE_FAILURE_ACTIONSW).cast(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let flag = SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: 1,
        };
        if unsafe {
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                (&flag as *const SERVICE_FAILURE_ACTIONS_FLAG).cast(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let delayed = SERVICE_DELAYED_AUTO_START_INFO {
            fDelayedAutostart: 1,
        };
        if unsafe {
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                (&delayed as *const SERVICE_DELAYED_AUTO_START_INFO).cast(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            DeleteService(service.0);
        }
    }
    result
}

pub fn manage(action: &str, binary: &Path, config: &Path, agent: bool) -> io::Result<()> {
    let expected = command(binary, config)?;
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return Err(io::Error::last_os_error());
    }
    let scm = ServiceHandle(scm);
    let access = match action {
        "start" => SERVICE_START,
        "stop" => SERVICE_STOP,
        "remove" => DELETE,
        _ => return Err(invalid("unknown service action")),
    };
    let name = wide(if agent { "REDTRACEAgent" } else { "REDTRACE" });
    let service = unsafe { OpenServiceW(scm.0, name.as_ptr(), access | SERVICE_QUERY_CONFIG) };
    if service.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = ServiceHandle(service);
    let mut size = 0;
    unsafe {
        QueryServiceConfigW(service.0, ptr::null_mut(), 0, &mut size);
    }
    let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    if unsafe { QueryServiceConfigW(service.0, buffer.as_mut_ptr().cast(), size, &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    let mut length = 0;
    unsafe {
        while *config.lpBinaryPathName.add(length) != 0 {
            length += 1;
        }
    }
    if unsafe { std::slice::from_raw_parts(config.lpBinaryPathName, length) }
        != &expected[..expected.len() - 1]
    {
        return Err(invalid("registered service binary/config mismatch"));
    }
    let success = match action {
        "start" => unsafe { StartServiceW(service.0, 0, ptr::null()) },
        "stop" => {
            let mut status = unsafe { std::mem::zeroed() };
            unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) }
        }
        "remove" => unsafe { DeleteService(service.0) },
        _ => unreachable!(),
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
