use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    },
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
};

pub struct ProtectedExecutable {
    file: File,
    _directory: File,
}

impl ProtectedExecutable {
    pub fn digest(&mut self) -> Result<String, String> {
        let mut bytes = Vec::new();
        (&mut self.file)
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "helper binary read failed")?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("helper binary exceeds size limit".into());
        }
        Ok(crate::ingest::hex(&crate::ingest::sha256(&bytes)))
    }
}

fn program_files() -> Result<PathBuf, String> {
    let mut text = ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, ptr::null_mut(), &mut text) } != 0
        || text.is_null()
    {
        return Err("Program Files lookup failed".into());
    }
    let mut length = 0;
    unsafe {
        while length < 32768 && *text.add(length) != 0 {
            length += 1;
        }
    }
    let value = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(text, length)) };
    unsafe {
        CoTaskMemFree(text.cast());
    }
    if length == 32768 {
        return Err("invalid Program Files path".into());
    }
    Ok(value.into())
}

fn mask(value: &str) -> Option<u32> {
    if let Some(hex) = value.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok();
    }
    let mut bits = 0;
    if !value.len().is_multiple_of(2) {
        return None;
    }
    for right in value.as_bytes().chunks_exact(2) {
        bits |= match right {
            b"FA" => 0x001f01ff,
            b"FR" => 0x00120089,
            b"FX" => 0x001200a0,
            b"FW" => 0x00120116,
            b"GA" => 0x10000000,
            b"GW" => 0x40000000,
            b"GR" => 0x80000000,
            b"GX" => 0x20000000,
            b"RC" => 0x00020000,
            b"SD" => 0x00010000,
            b"WD" => 0x00040000,
            b"WO" => 0x00080000,
            _ => return None,
        };
    }
    Some(bits)
}

fn trusted_acl(sddl: &str) -> bool {
    let Some(value) = sddl.strip_prefix("O:") else {
        return false;
    };
    let end = ["G:", "D:", "S:"]
        .iter()
        .filter_map(|tag| value.find(tag))
        .min()
        .unwrap_or(value.len());
    let owner = &value[..end];
    if owner != "BA" && owner != "SY" {
        return false;
    }
    let Some(dacl) = sddl.split_once("D:").map(|(_, value)| value) else {
        return false;
    };
    if !dacl.contains('(') {
        return false;
    }
    for ace in dacl.split('(').skip(1) {
        let Some(ace) = ace.split(')').next() else {
            return false;
        };
        let parts: Vec<_> = ace.split(';').collect();
        if parts.len() != 6 || !matches!(parts[0], "A" | "D") {
            return false;
        }
        if parts[0] == "D" {
            continue;
        }
        let Some(bits) = mask(parts[2]) else {
            return false;
        };
        if bits & 0x500d0156 != 0 && !matches!(parts[5], "BA" | "SY") {
            return false;
        }
    }
    true
}

fn security(file: &File) -> Result<(), String> {
    let mut descriptor = ptr::null_mut();
    if unsafe {
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
    } != 0
    {
        return Err("installed binary security query failed".into());
    }
    let mut text = ptr::null_mut();
    let mut length = 0;
    let success = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut text,
            &mut length,
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    if success == 0 {
        return Err("installed binary security descriptor unavailable".into());
    }
    let value =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(text, length as usize)) };
    unsafe {
        LocalFree(text.cast());
    }
    if !trusted_acl(value.trim_end_matches('\0')) {
        return Err(
            "installation must be owned by Administrators/System and deny non-admin writes".into(),
        );
    }
    Ok(())
}

fn protected_open(path: &Path, directory: bool) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x00200000 | if directory { 0x02000000 } else { 0 })
        .open(path)
        .map_err(|_| "installed file cannot be opened safely")?;
    let metadata = file
        .metadata()
        .map_err(|_| "installed file metadata unavailable")?;
    if metadata.file_attributes() & 0x400 != 0 || metadata.is_dir() != directory {
        return Err("installation reparse point or file type rejected".into());
    }
    security(&file)?;
    Ok(file)
}

pub fn executable(path: &Path) -> Result<ProtectedExecutable, String> {
    let directory = path
        .parent()
        .ok_or("installed executable directory missing")?;
    let base = program_files()?
        .canonicalize()
        .map_err(|_| "Program Files canonical path unavailable")?;
    let parent = directory
        .parent()
        .ok_or("installation must be inside Program Files")?
        .canonicalize()
        .map_err(|_| "installation parent unavailable")?;
    if !parent
        .to_string_lossy()
        .eq_ignore_ascii_case(&base.to_string_lossy())
    {
        return Err("install REDTRACE per-machine in Program Files to enable audit".into());
    }
    let directory = protected_open(directory, true)?;
    let file = protected_open(path, false)?;
    Ok(ProtectedExecutable {
        file,
        _directory: directory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_acl_allows_users_read_execute_but_never_modify() {
        assert!(trusted_acl(
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
        ));
        assert!(trusted_acl(
            "O:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FRFX;;;BU)"
        ));
        for acl in [
            "O:WDD:P(A;;FA;;;BA)",
            "O:BAD:P(A;;FW;;;BU)",
            "O:BAD:P(A;;WD;;;AU)",
            "O:BAD:P(A;;GA;;;WD)",
            "O:BAD:P(A;;0x40;;;BU)",
            "O:BAD:",
            "O:BAD:P(A;;unknown;;;BU)",
        ] {
            assert!(!trusted_acl(acl), "{acl}");
        }
    }

    #[test]
    fn user_writable_development_files_are_not_installed_executables() {
        assert!(executable(&std::env::current_exe().unwrap()).is_err());
    }
}
