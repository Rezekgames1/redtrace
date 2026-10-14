use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn regular(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || redirected(&metadata) {
        return Err(invalid("agent state contains a nonregular file"));
    }
    Ok(())
}

fn redirected(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn check_parents(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors().filter(|path| !path.as_os_str().is_empty()) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if !metadata.is_dir() || redirected(&metadata) => {
                return Err(invalid("agent state directory traverses a redirected path"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn private_directory(path: &Path) -> io::Result<()> {
    check_parents(path)?;
    if !path.exists() {
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty())
            && !parent.exists()
        {
            private_directory(parent)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        #[cfg(windows)]
        windows::create_directory(path)?;
        #[cfg(not(any(unix, windows)))]
        fs::create_dir(path)?;
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            sync_directory(parent)?;
        }
    }
    protect(path, true)
}

fn protect(path: &Path, directory: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )?;
    }
    #[cfg(windows)]
    windows::protect(path, directory)?;
    Ok(())
}

pub(super) fn private_file(path: &Path) -> io::Result<()> {
    regular(path)?;
    protect(path, false)
}

pub(super) fn new_file(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        windows::create_file(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.write(true).read(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }
}

pub(super) fn ownership(path: &Path) -> io::Result<File> {
    let file = if path.exists() {
        private_file(path)?;
        OpenOptions::new().read(true).write(true).open(path)?
    } else {
        new_file(path)?
    };
    file.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            "another agent owns this state directory",
        ),
        fs::TryLockError::Error(error) => error,
    })?;
    Ok(file)
}

pub(super) fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    private_file(path)?;
    let file = File::open(path)?;
    if file.metadata()?.len() > limit {
        return Err(invalid("agent state file exceeds its size limit"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("agent state file exceeds its size limit"));
    }
    Ok(bytes)
}

pub(super) fn temporary(path: &Path) -> PathBuf {
    path.with_extension("tmp")
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = temporary(path);
    let mut file = new_file(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    replace(&temporary, path)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| invalid("state file has no parent"))?,
    )
}

pub(super) fn replace(source: &Path, target: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        if unsafe {
            MoveFileExW(
                windows::wide(source).as_ptr(),
                windows::wide(target).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, target)
    }
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            },
            DACL_SECURITY_INFORMATION, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION,
            SECURITY_ATTRIBUTES, SetFileSecurityW, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct Descriptor(*mut std::ffi::c_void);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    pub(super) fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain([0]).collect()
    }

    fn descriptor(directory: bool) -> io::Result<Descriptor> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut length = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length);
        }
        let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        let success = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        };
        unsafe {
            CloseHandle(token);
        }
        if success == 0 {
            return Err(io::Error::last_os_error());
        }
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut size = 0;
        unsafe {
            while *text.add(size) != 0 {
                size += 1;
            }
        }
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, size) });
        unsafe {
            LocalFree(text.cast());
        }
        let inheritance = if directory { "OICI" } else { "" };
        let sddl: Vec<_> = format!("D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;{sid})")
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
        Ok(Descriptor(descriptor))
    }

    pub(super) fn protect(path: &Path, directory: bool) -> io::Result<()> {
        let descriptor = descriptor(directory)?;
        if unsafe {
            SetFileSecurityW(
                wide(path).as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn create_directory(path: &Path) -> io::Result<()> {
        let descriptor = descriptor(true)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        if unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn create_file(path: &Path) -> io::Result<File> {
        let descriptor = descriptor(false)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
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
}
