use super::helper::{self, HelperResponse};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, Path, Prefix},
    process::Command,
    ptr,
};
use windows_sys::Win32::{Foundation::GetLastError, Security::WinTrust::*, System::Services::*};

pub const APPROVED_SHA256: &str =
    "83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352";
pub const MAX_BINARY_BYTES: usize = 16 * 1024 * 1024;
const CONFIGURATION: &str = include_str!("../../assets/windows/sysmon-redtrace.xml");

#[derive(Serialize)]
pub struct SysmonPreview {
    pub version: &'static str,
    pub publisher: &'static str,
    pub signature: &'static str,
    pub sha256: &'static str,
    pub configuration_sha256: String,
    pub configuration: &'static str,
    pub installed: bool,
    pub binary_length: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SysmonSnapshot {
    version: u16,
    id: String,
    binary_sha256: String,
    configuration_sha256: String,
    configuration_dump_sha256: String,
    state: String,
    service_key_time: u64,
}

fn service_key_time() -> Result<u64, String> {
    use windows_sys::Win32::{Foundation::FILETIME, System::Registry::*};
    let path = helper::wide("SYSTEM\\CurrentControlSet\\Services\\Sysmon64");
    let mut key = ptr::null_mut();
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    } != 0
    {
        return Err("Sysmon service identity unavailable".into());
    }
    let mut time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let status = unsafe {
        RegQueryInfoKeyW(
            key,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut time,
        )
    };
    unsafe {
        RegCloseKey(key);
    }
    if status != 0 {
        return Err("Sysmon service identity query failed".into());
    }
    Ok((u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime))
}

fn commit_snapshot(directory: &Path, snapshot: &SysmonSnapshot) -> Result<(), String> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| "snapshot temp ID failed")?;
    let temporary = directory.join(format!("sysmon-{}.json", crate::ingest::hex(&random)));
    let mut file = helper::protected_create(&temporary)?;
    serde_json::to_writer(&mut file, snapshot).map_err(|_| "Sysmon snapshot write failed")?;
    file.sync_all().map_err(|_| "Sysmon snapshot sync failed")?;
    drop(file);
    fs::rename(temporary, directory.join("sysmon.json"))
        .map_err(|_| "Sysmon snapshot commit failed".into())
}

fn digest(bytes: &[u8]) -> String {
    crate::ingest::hex(&crate::ingest::sha256(bytes)).to_ascii_uppercase()
}

fn signature(path: &Path, file: &fs::File) -> Result<(), String> {
    let path = helper::wide(&path.to_string_lossy());
    let mut information = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.as_raw_handle().cast(),
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut information;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
    }
    if status == 0 {
        Ok(())
    } else {
        Err(format!(
            "Sysmon Authenticode verification failed (0x{:08x})",
            status as u32
        ))
    }
}

pub fn preview(path: &str) -> Result<(SysmonPreview, Vec<u8>), String> {
    let path = Path::new(path);
    if path.as_os_str().len() > 1024
        || !path.is_absolute()
        || !matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("select a local absolute Sysmon64.exe path".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000)
        .open(path)
        .map_err(|_| "selected binary cannot be read")?;
    let metadata = file.metadata().map_err(|_| "binary metadata unavailable")?;
    if !metadata.is_file()
        || metadata.file_attributes() & 0x400 != 0
        || metadata.len() > MAX_BINARY_BYTES as u64
    {
        return Err("invalid Sysmon binary file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BINARY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "binary read failed")?;
    if bytes.len() > MAX_BINARY_BYTES || digest(&bytes) != APPROVED_SHA256 {
        return Err("binary is not the approved Microsoft Sysmon 15.22 artifact".into());
    }
    signature(path, &file)?;
    Ok((
        SysmonPreview {
            version: "15.22",
            publisher: "Microsoft Windows Publisher / Microsoft Corporation",
            signature: "Valid",
            sha256: APPROVED_SHA256,
            configuration_sha256: digest(CONFIGURATION.as_bytes()),
            configuration: CONFIGURATION,
            installed: service_present()?,
            binary_length: bytes.len(),
        },
        bytes,
    ))
}

pub fn service_present() -> Result<bool, String> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err("service manager cannot be queried".into());
    }
    let mut present = false;
    let mut error = None;
    for name in ["Sysmon", "Sysmon64", "SysmonDrv"] {
        let name = helper::wide(name);
        let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
        if !service.is_null() {
            present = true;
            unsafe {
                CloseServiceHandle(service);
            }
        } else if unsafe { GetLastError() } != 1060 {
            error = Some("existing Sysmon state cannot be confirmed".into());
            break;
        }
    }
    unsafe {
        CloseServiceHandle(manager);
    }
    if let Some(error) = error {
        Err(error)
    } else {
        Ok(present)
    }
}

fn service_running() -> Result<bool, String> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err("service manager cannot be queried".into());
    }
    let name = helper::wide("Sysmon64");
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        unsafe {
            CloseServiceHandle(manager);
        }
        return Ok(false);
    }
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    let okay = unsafe { QueryServiceStatus(service, &mut status) };
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if okay == 0 {
        return Err("Sysmon service status query failed".into());
    }
    Ok(status.dwCurrentState == SERVICE_RUNNING)
}

fn vendor_command(path: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new(path)
        .args(args)
        .output()
        .map_err(|_| "Sysmon command could not start")?;
    if !output.status.success() {
        let text = [
            String::from_utf8_lossy(&output.stdout).replace('\0', ""),
            String::from_utf8_lossy(&output.stderr).replace('\0', ""),
        ]
        .join("\n");
        let diagnostic = text
            .lines()
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                ["error", "invalid", "failed", "unknown", "schema"]
                    .iter()
                    .any(|word| lower.contains(word))
                    && !line.contains(":\\")
                    && !line.contains("\\\\")
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!(
            "Sysmon command failed: {}: {}",
            output.status,
            diagnostic.chars().take(1024).collect::<String>()
        ));
    }
    let mut bytes = output.stdout;
    bytes.extend(output.stderr);
    if bytes.len() > 512 * 1024 {
        return Err("Sysmon diagnostic output exceeds limit".into());
    }
    Ok(bytes)
}

pub(super) fn install(payload: Vec<u8>) -> Result<HelperResponse, String> {
    if payload.len() > MAX_BINARY_BYTES || digest(&payload) != APPROVED_SHA256 {
        return Err("Sysmon payload hash mismatch".into());
    }
    if service_present()? {
        return Err("Sysmon already exists; existing configuration will not be replaced".into());
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| "Sysmon snapshot ID generation failed")?;
    let id = crate::ingest::hex(&random);
    let directory = helper::snapshot_directory(&id)?;
    helper::protected_directory(directory.parent().ok_or("snapshot root missing")?, true)?;
    helper::protected_directory(&directory, false)?;
    let executable = directory.join("Sysmon64.exe");
    let mut file = helper::protected_create(&executable)?;
    file.write_all(&payload)
        .map_err(|_| "protected payload write failed")?;
    file.sync_all()
        .map_err(|_| "protected payload sync failed")?;
    drop(file);
    let binary = helper::protected_open(&executable)?;
    signature(&executable, &binary)?;
    let configuration = directory.join("sysmon.xml");
    let mut file = helper::protected_create(&configuration)?;
    file.write_all(CONFIGURATION.as_bytes())
        .map_err(|_| "configuration write failed")?;
    file.sync_all().map_err(|_| "configuration sync failed")?;
    drop(file);
    let config = configuration.to_string_lossy().to_string();
    let mut snapshot = SysmonSnapshot {
        version: 1,
        id: id.clone(),
        binary_sha256: APPROVED_SHA256.into(),
        configuration_sha256: digest(CONFIGURATION.as_bytes()),
        configuration_dump_sha256: String::new(),
        state: "installing".into(),
        service_key_time: 0,
    };
    let mut file = helper::protected_create(&directory.join("sysmon.json"))?;
    serde_json::to_writer(&mut file, &snapshot).map_err(|_| "Sysmon snapshot write failed")?;
    file.sync_all().map_err(|_| "Sysmon snapshot sync failed")?;
    drop(file);
    let result = (|| -> Result<(), String> {
        vendor_command(&executable, &["-accepteula", "-i", &config])?;
        snapshot.configuration_dump_sha256 = digest(&vendor_command(&executable, &["-c"])?);
        if !service_running()? {
            return Err(
                "Sysmon installed but service not running; preserve snapshot for recovery".into(),
            );
        }
        snapshot.service_key_time = service_key_time()?;
        snapshot.state = "installed".into();
        commit_snapshot(&directory, &snapshot)
    })();
    Ok(match result {
        Ok(()) => HelperResponse {
            success: true,
            snapshot_id: Some(id),
            applied_actions: vec!["sysmon".into()],
            verified: true,
            error: None,
            ..HelperResponse::default()
        },
        Err(error) => HelperResponse {
            success: false,
            snapshot_id: Some(id),
            applied_actions: Vec::new(),
            verified: false,
            error: Some(format!("Sysmon state requires inspection: {error}")),
            ..HelperResponse::default()
        },
    })
}

pub(super) fn remove(id: &str) -> Result<HelperResponse, String> {
    let directory = helper::snapshot_directory(id)?;
    let _root = helper::protected_open(directory.parent().ok_or("snapshot root missing")?)?;
    let _directory = helper::protected_open(&directory)?;
    let file = helper::protected_open(&directory.join("sysmon.json"))?;
    let mut bytes = Vec::new();
    file.take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| "Sysmon snapshot read failed")?;
    if bytes.len() > 16384 {
        return Err("Sysmon snapshot exceeds limit".into());
    }
    let mut snapshot: SysmonSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| "invalid Sysmon snapshot")?;
    if snapshot.version != 1
        || snapshot.id != id
        || snapshot.binary_sha256 != APPROVED_SHA256
        || snapshot.configuration_sha256 != digest(CONFIGURATION.as_bytes())
    {
        return Err("Sysmon snapshot identity mismatch".into());
    }
    if service_present()? {
        if snapshot.state != "installed" || snapshot.configuration_dump_sha256.is_empty() {
            return Err(
                "incomplete Sysmon installation; inspect the preserved snapshot before removal"
                    .into(),
            );
        }
        if service_key_time()? != snapshot.service_key_time {
            return Err("Sysmon installation identity changed; removal conflict".into());
        }
        let executable = directory.join("Sysmon64.exe");
        let mut file = helper::protected_open(&executable)?;
        let mut payload = Vec::new();
        (&mut file)
            .take(MAX_BINARY_BYTES as u64 + 1)
            .read_to_end(&mut payload)
            .map_err(|_| "protected binary read failed")?;
        if digest(&payload) != APPROVED_SHA256 {
            return Err("protected binary hash mismatch".into());
        }
        signature(&executable, &file)?;
        if digest(&vendor_command(&executable, &["-c"])?) != snapshot.configuration_dump_sha256 {
            return Err("Sysmon configuration changed; removal conflict".into());
        }
        vendor_command(&executable, &["-u"])?;
    }
    if service_present()? {
        return Err("Sysmon removal verification failed".into());
    }
    snapshot.state = "removed".into();
    commit_snapshot(&directory, &snapshot)?;
    Ok(HelperResponse {
        success: true,
        snapshot_id: Some(id.into()),
        applied_actions: Vec::new(),
        verified: true,
        error: None,
        ..HelperResponse::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_sysmon_files_cannot_be_approved() {
        let path =
            std::env::temp_dir().join(format!("redtrace-fake-sysmon-{}.exe", std::process::id()));
        fs::write(&path, b"not a Microsoft binary").unwrap();
        assert!(preview(path.to_str().unwrap()).is_err());
        fs::remove_file(path).unwrap();
        assert!(preview("\\\\host\\share\\Sysmon64.exe").is_err());
    }
}
