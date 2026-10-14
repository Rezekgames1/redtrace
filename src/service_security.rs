use super::{SessionIdentity, invalid};
use std::{
    fs::{self, File},
    io,
    path::Path,
};

pub(super) fn no_redirects(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                #[cfg(windows)]
                let redirected = {
                    use std::os::windows::fs::MetadataExt;
                    metadata.file_attributes() & 0x400 != 0
                };
                #[cfg(not(windows))]
                let redirected = metadata.file_type().is_symlink();
                if redirected {
                    return Err(invalid("service path traverses a redirected path"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn validate(path: &Path, directory: bool, private: bool) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    let uid = unsafe { libc::geteuid() };
    if (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || (private && (metadata.uid() != uid || metadata.mode() & 0o077 != 0))
        || (!private
            && ((metadata.uid() != uid && metadata.uid() != 0) || metadata.mode() & 0o022 != 0))
    {
        return Err(invalid(
            "service file ownership or permissions are not private/protected",
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn create_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(unix)]
pub(super) fn create_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(unix)]
pub(super) fn replace(source: &Path, target: &Path) -> io::Result<()> {
    fs::rename(source, target)
}

#[cfg(unix)]
pub(super) fn current_owner() -> io::Result<String> {
    Ok(unsafe { libc::geteuid() }.to_string())
}

#[cfg(target_os = "linux")]
pub(super) fn process_start(pid: u32) -> io::Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .map(str::to_owned)
        .ok_or_else(|| invalid("invalid process identity"))
}

#[cfg(target_os = "linux")]
pub(super) fn verify_listener(identity: &SessionIdentity) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let root = format!("/proc/{}", identity.pid);
    if fs::metadata(&root)?.uid().to_string() != identity.owner
        || fs::read_link(format!("{root}/exe"))? != identity.executable
        || process_start(identity.pid)? != identity.process_start
    {
        return Err(invalid("local listener process identity mismatch"));
    }
    let table = if identity.address.is_ipv4() {
        "tcp"
    } else {
        "tcp6"
    };
    let expected_ip = match identity.address.ip() {
        std::net::IpAddr::V4(ip) => format!("{:08X}", u32::from_le_bytes(ip.octets())),
        std::net::IpAddr::V6(ip) => ip
            .octets()
            .chunks_exact(4)
            .map(|part| format!("{:08X}", u32::from_le_bytes(part.try_into().unwrap())))
            .collect(),
    };
    let endpoint = format!("{expected_ip}:{:04X}", identity.address.port());
    let table = fs::read_to_string(format!("/proc/net/{table}"))?;
    let inodes: Vec<_> = table
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() > 9
                && fields[1] == endpoint
                && fields[3] == "0A"
                && fields[7] == identity.owner)
                .then(|| fields[9].to_owned())
        })
        .collect();
    for entry in fs::read_dir(format!("{root}/fd"))? {
        let entry = entry?;
        if let Ok(target) = fs::read_link(entry.path())
            && inodes
                .iter()
                .any(|inode| target == Path::new(&format!("socket:[{inode}]")))
        {
            return Ok(());
        }
    }
    Err(invalid(
        "local listener is not owned by the expected process",
    ))
}

#[cfg(target_os = "macos")]
fn mac_process(pid: u32) -> io::Result<libc::proc_bsdinfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    let copied = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as i32,
        )
    };
    if copied != size as i32 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() })
}

#[cfg(target_os = "macos")]
pub(super) fn process_start(pid: u32) -> io::Result<String> {
    let info = mac_process(pid)?;
    Ok(format!(
        "{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    ))
}

#[cfg(target_os = "macos")]
pub(super) fn verify_listener(identity: &SessionIdentity) -> io::Result<()> {
    let info = mac_process(identity.pid)?;
    let mut path = [0u8; 4096];
    let size = unsafe {
        libc::proc_pidpath(
            identity.pid as i32,
            path.as_mut_ptr().cast(),
            path.len() as u32,
        )
    };
    if size <= 0 {
        return Err(io::Error::last_os_error());
    }
    let end = path
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(path.len());
    let path = std::str::from_utf8(&path[..end])
        .map_err(|_| invalid("invalid listener executable path"))?;
    if info.pbi_uid.to_string() != identity.owner
        || Path::new(path) != identity.executable
        || process_start(identity.pid)? != identity.process_start
    {
        return Err(invalid("local listener process identity mismatch"));
    }
    let output = std::process::Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            "-a",
            "-p",
            &identity.pid.to_string(),
            "-iTCP",
            "-sTCP:LISTEN",
            "-Fpn",
        ])
        .output()?;
    let name = format!("n{}", identity.address);
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == name)
    {
        return Err(invalid(
            "local listener is not owned by the expected process",
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(super) fn process_start(_: u32) -> io::Result<String> {
    Ok(String::new())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(super) fn verify_listener(_: &SessionIdentity) -> io::Result<()> {
    Err(invalid(
        "persistent attachment is supported on Windows and Linux",
    ))
}

#[cfg(windows)]
pub(super) use windows::*;

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                GetNamedSecurityInfoW, SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION, GetAce, GetTokenInformation, OWNER_SECURITY_INFORMATION,
            SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        },
        System::Threading::{
            GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        },
    };

    fn wide(value: &Path) -> Vec<u16> {
        value.as_os_str().encode_wide().chain([0]).collect()
    }

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Local(*mut std::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    fn user(process: HANDLE) -> io::Result<Vec<usize>> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Handle(token);
        let mut size = 0;
        unsafe {
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut size);
        }
        let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }

    fn sid_text(sid: *mut std::ffi::c_void) -> io::Result<String> {
        let mut text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allocated = Local(text.cast());
        let mut length = 0;
        unsafe {
            while *text.add(length) != 0 {
                length += 1;
            }
        }
        let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        drop(allocated);
        Ok(result)
    }

    fn process_owner(process: HANDLE) -> io::Result<String> {
        let buffer = user(process)?;
        sid_text(unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid })
    }

    pub(in crate::service) fn current_owner() -> io::Result<String> {
        process_owner(unsafe { GetCurrentProcess() })
    }

    pub(in crate::service) fn validate(
        path: &Path,
        directory: bool,
        private: bool,
    ) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
            return Err(invalid("nonregular service path"));
        }
        let mut owner = ptr::null_mut();
        let mut acl: *mut ACL = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let result = unsafe {
            GetNamedSecurityInfoW(
                wide(path).as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let _descriptor = Local(descriptor);
        let current = current_owner()?;
        let actual_owner = sid_text(owner)?;
        let trusted = |sid: &str| {
            sid == current
                || sid == "S-1-5-18"
                || (!private
                    && matches!(
                        sid,
                        "S-1-5-32-544"
                            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
                    ))
        };
        if !trusted(&actual_owner) || (private && actual_owner != current) || acl.is_null() {
            return Err(invalid("service path owner/DACL mismatch"));
        }
        let mut permits_current = false;
        for index in 0..unsafe { (*acl).AceCount } {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if header.AceType != 0 {
                return Err(invalid("unsupported service path ACE"));
            }
            if header.AceFlags & 0x08 != 0 {
                continue;
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
            let name = sid_text(sid)?;
            if (private || allowed.Mask & 0xd01f0156 != 0) && !trusted(&name) {
                return Err(invalid("service path grants untrusted access"));
            }
            if name == current {
                permits_current = true;
            }
        }
        if private && !permits_current {
            return Err(invalid("service path does not grant its owner access"));
        }
        Ok(())
    }

    fn attributes(directory: bool) -> io::Result<(Local, SECURITY_ATTRIBUTES)> {
        let sid = current_owner()?;
        let flags = if directory { "OICI" } else { "" };
        let sddl: Vec<_> = format!("O:{sid}D:P(A;{flags};FA;;;SY)(A;{flags};FA;;;{sid})")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((
            Local(descriptor),
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
        ))
    }

    pub(in crate::service) fn create_directory(path: &Path) -> io::Result<()> {
        let (_descriptor, attributes) = attributes(true)?;
        if unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(in crate::service) fn create_file(path: &Path) -> io::Result<File> {
        let (_descriptor, attributes) = attributes(false)?;
        let handle = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                0xc0000000,
                7,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    pub(in crate::service) fn replace(source: &Path, target: &Path) -> io::Result<()> {
        if unsafe {
            MoveFileExW(
                wide(source).as_ptr(),
                wide(target).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn process(pid: u32) -> io::Result<Handle> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Handle(handle))
    }

    pub(in crate::service) fn process_start(pid: u32) -> io::Result<String> {
        let process = process(pid)?;
        let mut created: FILETIME = unsafe { std::mem::zeroed() };
        let mut other: [FILETIME; 3] = unsafe { std::mem::zeroed() };
        if unsafe {
            GetProcessTimes(
                process.0,
                &mut created,
                &mut other[0],
                &mut other[1],
                &mut other[2],
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(((created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64).to_string())
    }

    pub(in crate::service) fn verify_listener(identity: &SessionIdentity) -> io::Result<()> {
        use windows_sys::Win32::{
            NetworkManagement::IpHelper::{
                GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
                TCP_TABLE_OWNER_PID_LISTENER,
            },
            Networking::WinSock::{AF_INET, AF_INET6},
        };
        let process = process(identity.pid)?;
        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &mut size) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let executable =
            std::path::PathBuf::from(String::from_utf16_lossy(&buffer[..size as usize]));
        if fs::canonicalize(executable)? != identity.executable
            || process_owner(process.0)? != identity.owner
            || process_start(identity.pid)? != identity.process_start
        {
            return Err(invalid("local listener process identity mismatch"));
        }
        let family = if identity.address.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        let mut size = 0;
        unsafe {
            GetExtendedTcpTable(
                ptr::null_mut(),
                &mut size,
                0,
                family as u32,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            );
        }
        let mut table = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        let status = unsafe {
            GetExtendedTcpTable(
                table.as_mut_ptr().cast(),
                &mut size,
                0,
                family as u32,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let matched = if let std::net::IpAddr::V4(ip) = identity.address.ip() {
            let table = unsafe { &*table.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>() };
            unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) }
                .iter()
                .any(|row| {
                    row.dwOwningPid == identity.pid
                        && row.dwLocalAddr == u32::from_le_bytes(ip.octets())
                        && u16::from_be(row.dwLocalPort as u16) == identity.address.port()
                })
        } else {
            let table = unsafe { &*table.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>() };
            let std::net::IpAddr::V6(ip) = identity.address.ip() else {
                unreachable!()
            };
            unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) }
                .iter()
                .any(|row| {
                    row.dwOwningPid == identity.pid
                        && row.ucLocalAddr == ip.octets()
                        && u16::from_be(row.dwLocalPort as u16) == identity.address.port()
                })
        };
        if !matched {
            return Err(invalid(
                "local listener is not owned by the expected process",
            ));
        }
        Ok(())
    }
}
