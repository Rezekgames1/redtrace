use super::windows::{self, AuditAction, AuditApplyRequest, AuditBackend, CommandSpec};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    process::Command,
    ptr,
};
use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authentication::Identity::{AuditFree, AuditQuerySystemPolicy},
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL},
        System::{
            Pipes::GetNamedPipeServerProcessId,
            Registry::*,
            SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW},
            Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
            },
        },
        UI::Shell::IsUserAnAdmin,
    },
    core::GUID,
};

const REGISTRY: [(&str, &str); 2] = [
    (
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
        "ProcessCreationIncludeCmdLine_Enabled",
    ),
    (
        "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        "EnableScriptBlockLogging",
    ),
];

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperRequest {
    Status {},
    Apply {
        profile: String,
        action_ids: Vec<String>,
        confirmation: String,
    },
    Rollback {
        snapshot_id: String,
        confirmation: String,
    },
    InstallSysmon {
        binary_sha256: String,
        binary_length: usize,
        confirmation: String,
    },
    RemoveSysmon {
        snapshot_id: String,
        confirmation: String,
    },
    GrantLogRead {
        confirmation: String,
    },
    RestoreLogRead {
        snapshot_id: String,
        confirmation: String,
    },
}

#[derive(Default, Serialize, Deserialize)]
pub struct HelperResponse {
    pub success: bool,
    pub snapshot_id: Option<String>,
    pub applied_actions: Vec<String>,
    pub verified: bool,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<AuditState>,
}

#[derive(Serialize, Deserialize)]
pub struct RegistryState {
    pub present: bool,
    pub kind: Option<u32>,
    pub dword: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct AuditState {
    pub policy: BTreeMap<String, u32>,
    pub process_command_line: RegistryState,
    pub powershell_script_block: RegistryState,
    pub sysmon_installed: bool,
    pub audit_snapshot: Option<String>,
    pub read_access_snapshot: Option<String>,
    pub sysmon_snapshot: Option<String>,
}

fn registry_state(index: usize) -> Result<RegistryState, String> {
    let value = registry_read(index)?;
    Ok(RegistryState {
        present: value.is_some(),
        kind: value.as_ref().map(|value| value.kind),
        dword: value
            .as_ref()
            .filter(|value| value.kind == REG_DWORD && value.bytes.len() == 4)
            .map(|value| u32::from_le_bytes(value.bytes.as_slice().try_into().unwrap())),
    })
}

fn effective_state() -> Result<AuditState, String> {
    Ok(AuditState {
        policy: ["logon", "account-lockout", "process-creation"]
            .into_iter()
            .map(|id| Ok((id.into(), read_policy(id)? & 3)))
            .collect::<Result<_, String>>()?,
        process_command_line: registry_state(0)?,
        powershell_script_block: registry_state(1)?,
        sysmon_installed: super::sysmon::service_present()?,
        audit_snapshot: latest_snapshot_for("snapshot.json")?,
        read_access_snapshot: latest_snapshot_for("read-access.json")?,
        sysmon_snapshot: latest_snapshot_for("sysmon.json")?,
    })
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
struct RegistryValue {
    kind: u32,
    bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    id: String,
    registry: Vec<Option<RegistryValue>>,
    policy: BTreeMap<String, u32>,
    actions: Vec<String>,
}

const SNAPSHOT_SECURITY: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const SNAPSHOT_OWNER_DACL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

struct SecurityDescriptor(*mut std::ffi::c_void);

struct TransactionLock(windows_sys::Win32::Foundation::HANDLE);

struct PeerProcess(windows_sys::Win32::Foundation::HANDLE);

impl Drop for PeerProcess {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

impl TransactionLock {
    fn acquire() -> Result<Self, String> {
        use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
        let descriptor = descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let name = wide("Global\\REDTRACE-Audit-Transaction");
        let handle = unsafe { CreateMutexW(&attributes, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err("audit transaction lock unavailable".into());
        }
        let wait = unsafe { WaitForSingleObject(handle, 30000) };
        if wait != 0 && wait != 0x80 {
            unsafe {
                CloseHandle(handle);
            }
            return Err("another audit transaction is running".into());
        }
        Ok(Self(handle))
    }
}

impl Drop for TransactionLock {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn descriptor() -> Result<SecurityDescriptor, String> {
    let mut descriptor = ptr::null_mut();
    let sddl = wide(SNAPSHOT_SECURITY);
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err("snapshot security descriptor failed".into());
    }
    Ok(SecurityDescriptor(descriptor))
}

pub(super) fn protected_open(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .custom_flags(0x02000000 | 0x00200000)
        .open(path)
        .map_err(|_| "protected snapshot open failed")?;
    if file
        .metadata()
        .map_err(|_| "snapshot metadata unavailable")?
        .file_attributes()
        & 0x400
        != 0
    {
        return Err("snapshot reparse point rejected".into());
    }
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err("snapshot security query failed".into());
    }
    let descriptor = SecurityDescriptor(descriptor);
    let mut text = ptr::null_mut();
    let mut length = 0;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut text,
            &mut length,
        )
    } == 0
    {
        return Err("snapshot security verification failed".into());
    }
    let actual = unsafe {
        let buffer = std::slice::from_raw_parts(text, length as usize);
        let length = buffer
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..length])
    };
    unsafe {
        LocalFree(text.cast());
    }
    if actual.replace("D:PAI", "D:P") != SNAPSHOT_OWNER_DACL {
        return Err("snapshot owner or ACL is untrusted".into());
    }
    Ok(file)
}

pub(super) fn protected_directory(path: &Path, existing_allowed: bool) -> Result<(), String> {
    let descriptor = descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path_wide = wide(&path.to_string_lossy());
    if unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) } == 0
        && !(existing_allowed && unsafe { GetLastError() } == 183)
    {
        return Err("protected snapshot directory creation failed".into());
    }
    protected_open(path)?;
    Ok(())
}

pub(super) fn protected_create(path: &Path) -> Result<File, String> {
    let descriptor = descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path = wide(&path.to_string_lossy());
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            0xc0000000,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err("protected snapshot file creation failed".into());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(super) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

pub(super) fn windows_directory(system: bool) -> Result<PathBuf, String> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe {
        if system {
            GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)
        } else {
            GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)
        }
    };
    if length == 0 || length as usize >= buffer.len() {
        return Err("Windows directory lookup failed".into());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buffer[..length as usize],
    )))
}

pub(super) fn snapshot_directory(id: &str) -> Result<PathBuf, String> {
    if id.len() != 32 || !id.bytes().all(|value| value.is_ascii_hexdigit()) {
        return Err("invalid snapshot ID".into());
    }
    Ok(windows_directory(true)?
        .join("REDTRACE-audit-snapshots")
        .join(id))
}

fn execute(program: &str, args: &[String]) -> Result<(), String> {
    if !matches!(program, "auditpol.exe" | "reg.exe" | "icacls.exe") {
        return Err("program is not allowlisted".into());
    }
    let output = Command::new(windows_directory(true)?.join(program))
        .args(args)
        .output()
        .map_err(|_| format!("could not launch {program}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{program} failed with {}", output.status))
    }
}

fn registry_read(index: usize) -> Result<Option<RegistryValue>, String> {
    let (path, name) = REGISTRY[index];
    let path = wide(path);
    let name = wide(name);
    let mut key = ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if status == 2 {
        return Ok(None);
    }
    if status != 0 {
        return Err(format!("registry open failed ({status})"));
    }
    let result = (|| {
        let mut kind = 0;
        let mut size = 0;
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                &mut size,
            )
        };
        if status == 2 {
            return Ok(None);
        }
        if status != 0 || size > 65536 {
            return Err("registry value query failed".into());
        }
        let mut bytes = vec![0u8; size as usize];
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut size,
            )
        };
        if status != 0 {
            return Err("registry value read failed".into());
        }
        bytes.truncate(size as usize);
        Ok(Some(RegistryValue { kind, bytes }))
    })();
    unsafe {
        RegCloseKey(key);
    }
    result
}

fn registry_restore(index: usize, previous: &Option<RegistryValue>) -> Result<(), String> {
    let (path, name) = REGISTRY[index];
    let path = wide(path);
    let name = wide(name);
    let mut key = ptr::null_mut();
    let mut disposition = 0;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            ptr::null(),
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            ptr::null(),
            &mut key,
            &mut disposition,
        )
    };
    if status != 0 {
        return Err("registry restore open failed".into());
    }
    let status = unsafe {
        match previous {
            Some(value) => RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                value.kind,
                value.bytes.as_ptr(),
                value.bytes.len() as u32,
            ),
            None => RegDeleteValueW(key, name.as_ptr()),
        }
    };
    unsafe {
        RegCloseKey(key);
    }
    if status == 0 || (previous.is_none() && status == 2) {
        Ok(())
    } else {
        Err("registry restore failed".into())
    }
}

fn policy_guid(id: &str) -> Result<GUID, String> {
    match id {
        "logon" => Ok(GUID::from_u128(0x0cce9215_69ae_11d9_bed3_505054503030)),
        "account-lockout" => Ok(GUID::from_u128(0x0cce9235_69ae_11d9_bed3_505054503030)),
        "process-creation" => Ok(GUID::from_u128(0x0cce922b_69ae_11d9_bed3_505054503030)),
        _ => Err("unsupported audit action".into()),
    }
}

fn read_policy(id: &str) -> Result<u32, String> {
    let guid = policy_guid(id)?;
    let mut result = ptr::null_mut();
    if !unsafe { AuditQuerySystemPolicy(&guid, 1, &mut result) } || result.is_null() {
        return Err("audit policy query failed".into());
    }
    let value = unsafe { (*result).AuditingInformation };
    unsafe {
        AuditFree(result.cast());
    }
    Ok(value)
}

struct Backend {
    id: String,
    actions: Vec<String>,
}

fn registry_indices(actions: &[String]) -> Vec<usize> {
    let mut indices = Vec::new();
    if actions.iter().any(|action| action == "process-creation") {
        indices.push(0);
    }
    if actions
        .iter()
        .any(|action| action == "powershell-script-block")
    {
        indices.push(1);
    }
    indices
}

fn target_policy(id: &str) -> Option<u32> {
    match id {
        "logon" => Some(3),
        "account-lockout" | "process-creation" => Some(1),
        _ => None,
    }
}

fn policy_guid_text(id: &str) -> Result<&'static str, String> {
    match id {
        "logon" => Ok("{0CCE9215-69AE-11D9-BED3-505054503030}"),
        "account-lockout" => Ok("{0CCE9235-69AE-11D9-BED3-505054503030}"),
        "process-creation" => Ok("{0CCE922B-69AE-11D9-BED3-505054503030}"),
        _ => Err("unsupported audit subcategory".into()),
    }
}

fn latest_snapshot_id() -> Result<String, String> {
    latest_snapshot_for("snapshot.json")?.ok_or("no complete snapshot available".into())
}

fn latest_snapshot_for(filename: &str) -> Result<Option<String>, String> {
    let root = windows_directory(true)?.join("REDTRACE-audit-snapshots");
    if !root.exists() {
        return Ok(None);
    }
    let _guard = protected_open(&root)?;
    let mut candidates = Vec::new();
    for entry in fs::read_dir(&root)
        .map_err(|_| "snapshot enumeration failed")?
        .flatten()
    {
        let id = entry.file_name().to_string_lossy().to_string();
        if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        if protected_open(&entry.path()).is_err() {
            continue;
        }
        let path = entry.path().join(filename);
        let Ok(file) = protected_open(&path) else {
            continue;
        };
        let mut bytes = Vec::new();
        if file.take(1024 * 1024 + 1).read_to_end(&mut bytes).is_err() || bytes.len() > 1024 * 1024
        {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if value.get("id").and_then(serde_json::Value::as_str) != Some(id.as_str()) {
            continue;
        }
        if filename == "sysmon.json"
            && value.get("state").and_then(serde_json::Value::as_str) != Some("installed")
        {
            continue;
        }
        if let Ok(metadata) = fs::metadata(path)
            && let Ok(time) = metadata.modified()
        {
            candidates.push((time, id));
        }
    }
    candidates.sort();
    Ok(candidates.pop().map(|(_, id)| id))
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<(), String> {
    validate(&HelperRequest::Apply {
        profile: "recommended-workstation".into(),
        action_ids: snapshot.actions.clone(),
        confirmation: windows::CONFIRMATION_TEXT.into(),
    })?;
    if snapshot.registry.len() != REGISTRY.len()
        || snapshot
            .registry
            .iter()
            .flatten()
            .any(|value| value.bytes.len() > 65536)
    {
        return Err("invalid registry snapshot".into());
    }
    let expected: std::collections::BTreeSet<_> = snapshot
        .actions
        .iter()
        .filter(|id| target_policy(id).is_some())
        .cloned()
        .collect();
    let actual: std::collections::BTreeSet<_> = snapshot.policy.keys().cloned().collect();
    if expected != actual || snapshot.policy.values().any(|value| *value > 3) {
        return Err("snapshot policy selection does not match".into());
    }
    Ok(())
}

impl AuditBackend for Backend {
    type Snapshot = Snapshot;

    fn snapshot(&mut self) -> Result<Snapshot, String> {
        let path = snapshot_directory(&self.id)?;
        protected_directory(path.parent().ok_or("snapshot parent missing")?, true)?;
        protected_directory(&path, false)?;
        execute(
            "auditpol.exe",
            &[
                "/backup".into(),
                format!("/file:{}", path.join("audit.csv").display()),
            ],
        )?;
        let backup_descriptor = descriptor()?;
        let backup_path = wide(&path.join("audit.csv").to_string_lossy());
        if unsafe {
            windows_sys::Win32::Security::SetFileSecurityW(
                backup_path.as_ptr(),
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION,
                backup_descriptor.0,
            )
        } == 0
        {
            return Err("audit backup protection failed".into());
        }
        let mut policy = BTreeMap::new();
        for id in &self.actions {
            if target_policy(id).is_some() {
                policy.insert(id.clone(), read_policy(id)? & 3);
            }
        }
        let registry = (0..REGISTRY.len())
            .map(registry_read)
            .collect::<Result<Vec<_>, _>>()?;
        let snapshot = Snapshot {
            id: self.id.clone(),
            registry,
            policy,
            actions: self.actions.clone(),
        };
        let mut file = protected_create(&path.join("snapshot.json"))?;
        serde_json::to_writer(&mut file, &snapshot).map_err(|_| "snapshot serialization failed")?;
        file.sync_all()
            .map_err(|_| "snapshot synchronization failed")?;
        Ok(snapshot)
    }

    fn apply(&mut self, command: &CommandSpec) -> Result<(), String> {
        execute(
            command.program,
            &command
                .args
                .iter()
                .map(|arg| (*arg).into())
                .collect::<Vec<_>>(),
        )
    }

    fn verify(&mut self, action: &AuditAction) -> Result<(), String> {
        if let Some(expected) = target_policy(action.id)
            && read_policy(action.id)? & 3 != expected
        {
            return Err("effective audit policy does not match".into());
        }
        let registry = match action.id {
            "process-creation" => Some(0),
            "powershell-script-block" => Some(1),
            _ => None,
        };
        if let Some(index) = registry
            && registry_read(index)?
                != Some(RegistryValue {
                    kind: REG_DWORD,
                    bytes: 1u32.to_le_bytes().to_vec(),
                })
        {
            return Err("effective registry value does not match".into());
        }
        Ok(())
    }

    fn rollback(&mut self, snapshot: &Snapshot) -> Result<(), String> {
        validate_snapshot(snapshot)?;
        if snapshot.id != self.id {
            return Err("snapshot does not match".into());
        }
        for (id, value) in &snapshot.policy {
            let current = read_policy(id)? & 3;
            if current != *value && Some(current) != target_policy(id) {
                return Err("audit policy changed after apply; rollback conflict".into());
            }
        }
        let target_registry = Some(RegistryValue {
            kind: REG_DWORD,
            bytes: 1u32.to_le_bytes().to_vec(),
        });
        for index in registry_indices(&snapshot.actions) {
            let current = registry_read(index)?;
            if current != snapshot.registry[index] && current != target_registry {
                return Err("registry changed after apply; rollback conflict".into());
            }
        }
        for (id, value) in &snapshot.policy {
            execute(
                "auditpol.exe",
                &[
                    "/set".into(),
                    format!("/subcategory:{}", policy_guid_text(id)?),
                    format!(
                        "/success:{}",
                        if value & 1 != 0 { "enable" } else { "disable" }
                    ),
                    format!(
                        "/failure:{}",
                        if value & 2 != 0 { "enable" } else { "disable" }
                    ),
                ],
            )?;
        }
        for index in registry_indices(&snapshot.actions) {
            registry_restore(index, &snapshot.registry[index])?;
        }
        for (id, value) in &snapshot.policy {
            if read_policy(id)? & 3 != *value {
                return Err("audit rollback verification failed".into());
            }
        }
        for index in registry_indices(&snapshot.actions) {
            if registry_read(index)? != snapshot.registry[index] {
                return Err("registry rollback verification failed".into());
            }
        }
        Ok(())
    }
}

pub fn validate(request: &HelperRequest) -> Result<(), String> {
    match request {
        HelperRequest::Status {} => {}
        HelperRequest::Apply {
            profile,
            action_ids,
            confirmation,
        } => {
            if profile != "recommended-workstation"
                || confirmation != windows::CONFIRMATION_TEXT
                || action_ids.is_empty()
                || action_ids.len() > 4
            {
                return Err("explicit confirmation and valid profile are required".into());
            }
            let mut unique = std::collections::HashSet::new();
            for id in action_ids {
                if !matches!(
                    id.as_str(),
                    "logon" | "account-lockout" | "process-creation" | "powershell-script-block"
                ) || !unique.insert(id)
                {
                    return Err("unsupported or duplicate action".into());
                }
            }
        }
        HelperRequest::Rollback {
            snapshot_id,
            confirmation,
        } => {
            if confirmation != "ROLLBACK REDTRACE AUDIT" {
                return Err("explicit rollback confirmation required".into());
            }
            snapshot_directory(snapshot_id)?;
        }
        HelperRequest::InstallSysmon {
            binary_sha256,
            binary_length,
            confirmation,
        } => {
            if binary_sha256 != super::sysmon::APPROVED_SHA256
                || *binary_length == 0
                || *binary_length > super::sysmon::MAX_BINARY_BYTES
                || confirmation != "INSTALL REDTRACE SYSMON"
            {
                return Err("approved Sysmon binary and explicit confirmation required".into());
            }
        }
        HelperRequest::RemoveSysmon {
            snapshot_id,
            confirmation,
        } => {
            snapshot_directory(snapshot_id)?;
            if confirmation != "REMOVE REDTRACE SYSMON" {
                return Err("explicit Sysmon removal confirmation required".into());
            }
        }
        HelperRequest::GrantLogRead { confirmation } => {
            if confirmation != "GRANT REDTRACE LOG READ" {
                return Err("explicit read-only grant confirmation required".into());
            }
        }
        HelperRequest::RestoreLogRead {
            snapshot_id,
            confirmation,
        } => {
            snapshot_directory(snapshot_id)?;
            if confirmation != "RESTORE REDTRACE LOG READ" {
                return Err("explicit log ACL restore confirmation required".into());
            }
        }
    }
    Ok(())
}

pub fn peer_matches(pid: u32, expected: &Path) -> bool {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return false;
    }
    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;
    let okay = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut size) };
    unsafe {
        CloseHandle(process);
    }
    if okay == 0 {
        return false;
    }
    let actual = PathBuf::from(String::from_utf16_lossy(&buffer[..size as usize]));
    match (fs::canonicalize(actual), fs::canonicalize(expected)) {
        (Ok(actual), Ok(expected)) => actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy()),
        _ => false,
    }
}

fn execute_request(
    request: HelperRequest,
    payload: Option<Vec<u8>>,
    peer_pid: u32,
) -> Result<HelperResponse, String> {
    validate(&request)?;
    if unsafe { IsUserAnAdmin() } == 0 {
        return Err("elevation is required".into());
    }
    let _transaction = TransactionLock::acquire()?;
    match request {
        HelperRequest::Status {} => Ok(HelperResponse {
            success: true,
            verified: true,
            state: Some(effective_state()?),
            ..HelperResponse::default()
        }),
        HelperRequest::GrantLogRead { .. } => super::read_access::grant(peer_pid),
        HelperRequest::RestoreLogRead { snapshot_id, .. } => {
            super::read_access::restore(&snapshot_id)
        }
        HelperRequest::InstallSysmon { .. } => {
            super::sysmon::install(payload.ok_or("Sysmon payload missing")?)
        }
        HelperRequest::RemoveSysmon { snapshot_id, .. } => super::sysmon::remove(&snapshot_id),
        HelperRequest::Apply {
            profile,
            action_ids,
            confirmation,
        } => {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).map_err(|_| "snapshot ID generation failed")?;
            let id = crate::ingest::hex(&random);
            let mut backend = Backend {
                id: id.clone(),
                actions: action_ids.clone(),
            };
            let report = match windows::apply_transaction(
                &AuditApplyRequest {
                    profile,
                    action_ids,
                    confirmation,
                },
                &mut backend,
            ) {
                Ok(report) => report,
                Err(error) => {
                    return Ok(HelperResponse {
                        success: false,
                        snapshot_id: Some(id),
                        applied_actions: Vec::new(),
                        verified: false,
                        error: Some(error.to_string()),
                        ..HelperResponse::default()
                    });
                }
            };
            Ok(HelperResponse {
                success: true,
                snapshot_id: Some(id),
                applied_actions: report.applied_actions,
                verified: report.verified,
                error: None,
                ..HelperResponse::default()
            })
        }
        HelperRequest::Rollback { snapshot_id, .. } => {
            let snapshot_id = if snapshot_id == "0".repeat(32) {
                latest_snapshot_id()?
            } else {
                snapshot_id
            };
            let directory = snapshot_directory(&snapshot_id)?;
            let root = protected_open(directory.parent().ok_or("snapshot root missing")?)?;
            let directory_handle = protected_open(&directory)?;
            let file = protected_open(&directory.join("snapshot.json"))?;
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "snapshot read failed")?;
            if bytes.len() > 1024 * 1024 {
                return Err("snapshot exceeds size limit".into());
            }
            let snapshot: Snapshot =
                serde_json::from_slice(&bytes).map_err(|_| "invalid snapshot")?;
            let mut backend = Backend {
                id: snapshot_id.clone(),
                actions: snapshot.actions.clone(),
            };
            backend.rollback(&snapshot)?;
            drop(directory_handle);
            drop(root);
            Ok(HelperResponse {
                success: true,
                snapshot_id: Some(snapshot_id),
                applied_actions: Vec::new(),
                verified: true,
                error: None,
                ..HelperResponse::default()
            })
        }
    }
}

pub fn serve() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 || args[0] != "--pipe" || args[2] != "--parent" {
        return Err("helper accepts only desktop IPC".into());
    }
    let nonce = args[1]
        .strip_prefix("\\\\.\\pipe\\redtrace-audit-")
        .ok_or("invalid pipe name")?;
    if nonce.len() != 64 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid pipe nonce".into());
    }
    let expected_pid: u32 = args[3].parse().map_err(|_| "invalid parent PID")?;
    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .security_qos_flags(0x00010000)
        .open(&args[1])
        .map_err(|_| "IPC connection failed")?;
    let mut server_pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut server_pid) } == 0
        || server_pid != expected_pid
    {
        return Err("IPC server identity mismatch".into());
    }
    let desktop = std::env::current_exe()
        .map_err(|_| "helper path unavailable")?
        .parent()
        .ok_or("helper directory unavailable")?
        .join("redtrace-desktop.exe");
    let _trusted_desktop = super::deployment::executable(&desktop)?;
    if !peer_matches(server_pid, &desktop) {
        return Err("IPC peer is not the desktop application".into());
    }
    let peer =
        PeerProcess(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid) });
    if peer.0.is_null() {
        return Err("authenticated desktop process unavailable".into());
    }
    if !peer_matches(server_pid, &desktop) {
        return Err("desktop identity changed".into());
    }
    let mut line = String::new();
    let payload;
    let request;
    {
        let mut reader = BufReader::new(&mut pipe);
        (&mut reader)
            .take(16384)
            .read_line(&mut line)
            .map_err(|_| "IPC read failed")?;
        request =
            serde_json::from_str::<HelperRequest>(&line).map_err(|_| "invalid helper request")?;
        validate(&request)?;
        payload = if let HelperRequest::InstallSysmon { binary_length, .. } = &request {
            let mut bytes = vec![0u8; *binary_length];
            reader
                .read_exact(&mut bytes)
                .map_err(|_| "incomplete Sysmon payload")?;
            Some(bytes)
        } else {
            None
        };
    }
    let mut response =
        execute_request(request, payload, expected_pid).unwrap_or_else(|error| HelperResponse {
            success: false,
            snapshot_id: None,
            applied_actions: Vec::new(),
            verified: false,
            error: Some(error),
            ..HelperResponse::default()
        });
    if response.success && response.state.is_none() {
        response.state = effective_state().ok();
    }
    serde_json::to_writer(&mut pipe, &response).map_err(|_| "IPC response failed")?;
    pipe.write_all(b"\n").map_err(|_| "IPC response failed")?;
    pipe.flush().map_err(|_| "IPC flush failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_require_allowlisted_actions_and_confirmation() {
        let request = HelperRequest::Apply {
            profile: "recommended-workstation".into(),
            action_ids: vec!["logon".into()],
            confirmation: windows::CONFIRMATION_TEXT.into(),
        };
        assert!(validate(&request).is_ok());
        let request = HelperRequest::Apply {
            profile: "recommended-workstation".into(),
            action_ids: vec!["sysmon".into()],
            confirmation: windows::CONFIRMATION_TEXT.into(),
        };
        assert!(validate(&request).is_err());
        let request = HelperRequest::Rollback {
            snapshot_id: "..\\unsafe".into(),
            confirmation: "ROLLBACK REDTRACE AUDIT".into(),
        };
        assert!(validate(&request).is_err());
    }

    #[test]
    fn snapshot_selection_determines_restore_scope() {
        let mut snapshot = Snapshot {
            id: "a".repeat(32),
            actions: vec!["powershell-script-block".into()],
            registry: vec![None, None],
            policy: BTreeMap::new(),
        };
        assert!(validate_snapshot(&snapshot).is_ok());
        assert_eq!(registry_indices(&snapshot.actions), vec![1]);
        snapshot.policy.insert("logon".into(), 3);
        assert!(validate_snapshot(&snapshot).is_err());
        snapshot.actions = vec!["logon".into()];
        assert!(validate_snapshot(&snapshot).is_ok());
        assert!(registry_indices(&snapshot.actions).is_empty());
        snapshot.policy.clear();
        assert!(validate_snapshot(&snapshot).is_err());
    }

    #[test]
    fn ordinary_user_owned_files_are_not_trusted_snapshots() {
        let path = std::env::temp_dir().join(format!(
            "redtrace-untrusted-snapshot-{}.json",
            std::process::id()
        ));
        fs::write(&path, b"{}").unwrap();
        assert!(protected_open(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
