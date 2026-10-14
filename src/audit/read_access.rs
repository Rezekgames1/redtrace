use super::helper::{self, HelperResponse};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, process::Command, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
};

const CHANNELS: [&str; 2] = ["Security", "Microsoft-Windows-Sysmon/Operational"];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelAccess {
    before: String,
    after: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessSnapshot {
    version: u16,
    id: String,
    user_sid: String,
    channels: BTreeMap<String, ChannelAccess>,
}

fn peer_sid(pid: u32) -> Result<String, String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err("desktop process token unavailable".into());
    }
    let mut token = ptr::null_mut();
    let okay = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    unsafe {
        CloseHandle(process);
    }
    if okay == 0 {
        return Err("desktop process token query failed".into());
    }
    let result = (|| {
        let mut size = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
        }
        if size == 0 || size > 65536 {
            return Err("invalid token user size".into());
        }
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } == 0
        {
            return Err("token user read failed".into());
        }
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err("user SID rendering failed".into());
        }
        let mut length = 0;
        unsafe {
            while length < 184 && *text.add(length) != 0 {
                length += 1;
            }
        }
        let sid = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(text, length)) };
        unsafe {
            LocalFree(text.cast());
        }
        if !sid.starts_with("S-1-")
            || !sid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'S' | b'-'))
        {
            return Err("invalid token SID".into());
        }
        Ok(sid)
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}

fn command(args: &[String]) -> Result<String, String> {
    let output = Command::new(helper::windows_directory(true)?.join("wevtutil.exe"))
        .args(args)
        .output()
        .map_err(|_| "channel configuration command failed")?;
    if !output.status.success() {
        return Err(format!("channel configuration failed: {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout).replace('\0', ""))
}

fn access(channel: &str) -> Result<String, String> {
    if !CHANNELS.contains(&channel) {
        return Err("channel is not allowlisted".into());
    }
    command(&["gl".into(), channel.into()])?
        .lines()
        .find_map(|line| {
            line.strip_prefix("channelAccess:")
                .map(|sddl| sddl.trim().to_string())
        })
        .ok_or("channel ACL unavailable".into())
}

fn append_read(before: &str, sid: &str) -> Result<String, String> {
    if !before.contains("D:") {
        return Err("channel DACL missing".into());
    }
    let ace = format!("(A;;0x1;;;{sid})");
    if before.contains(&ace) {
        return Ok(before.into());
    }
    let boundary = before.find("S:").unwrap_or(before.len());
    let after = format!("{}{}{}", &before[..boundary], ace, &before[boundary..]);
    let mut descriptor = ptr::null_mut();
    let text = helper::wide(&after);
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, ptr::null_mut())
    } == 0
    {
        return Err("read-only channel ACL invalid".into());
    }
    unsafe {
        LocalFree(descriptor);
    }
    Ok(after)
}

fn set_access(channel: &str, sddl: &str) -> Result<(), String> {
    if !CHANNELS.contains(&channel) {
        return Err("channel is not allowlisted".into());
    }
    command(&["sl".into(), channel.into(), format!("/ca:{sddl}")])?;
    if access(channel)? != sddl {
        return Err("channel ACL verification failed".into());
    }
    Ok(())
}

pub(super) fn grant(pid: u32) -> Result<HelperResponse, String> {
    let sid = peer_sid(pid)?;
    let mut channels = BTreeMap::new();
    for channel in CHANNELS {
        let before = access(channel)?;
        let after = append_read(&before, &sid)?;
        channels.insert(channel.into(), ChannelAccess { before, after });
    }
    if channels.values().all(|state| state.before == state.after) {
        return Ok(HelperResponse {
            success: true,
            snapshot_id: None,
            applied_actions: Vec::new(),
            verified: true,
            error: None,
            ..HelperResponse::default()
        });
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| "ACL snapshot ID failed")?;
    let id = crate::ingest::hex(&random);
    let directory = helper::snapshot_directory(&id)?;
    helper::protected_directory(directory.parent().ok_or("snapshot root missing")?, true)?;
    helper::protected_directory(&directory, false)?;
    let snapshot = AccessSnapshot {
        version: 1,
        id: id.clone(),
        user_sid: sid,
        channels,
    };
    let mut file = helper::protected_create(&directory.join("read-access.json"))?;
    serde_json::to_writer(&mut file, &snapshot).map_err(|_| "ACL snapshot write failed")?;
    file.sync_all().map_err(|_| "ACL snapshot sync failed")?;
    drop(file);
    let result = (|| {
        for (channel, state) in &snapshot.channels {
            set_access(channel, &state.after)?;
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        let mut failures = Vec::new();
        for (channel, state) in &snapshot.channels {
            match access(channel) {
                Ok(current) if current == state.before => {}
                Ok(current) if current == state.after => {
                    if set_access(channel, &state.before).is_err() {
                        failures.push(channel.clone());
                    }
                }
                _ => failures.push(channel.clone()),
            }
        }
        return Ok(HelperResponse {
            success: false,
            snapshot_id: Some(id),
            applied_actions: Vec::new(),
            verified: false,
            error: Some(format!(
                "read ACL grant failed: {error}; rollback: {}",
                if failures.is_empty() {
                    "verified"
                } else {
                    "requires inspection"
                }
            )),
            ..HelperResponse::default()
        });
    }
    Ok(HelperResponse {
        success: true,
        snapshot_id: Some(id),
        applied_actions: vec!["log-read-access".into()],
        verified: true,
        error: None,
        ..HelperResponse::default()
    })
}

pub(super) fn restore(id: &str) -> Result<HelperResponse, String> {
    let directory = helper::snapshot_directory(id)?;
    let _root = helper::protected_open(directory.parent().ok_or("snapshot root missing")?)?;
    let _directory = helper::protected_open(&directory)?;
    let file = helper::protected_open(&directory.join("read-access.json"))?;
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "ACL snapshot read failed")?;
    if bytes.len() > 65536 {
        return Err("ACL snapshot exceeds limit".into());
    }
    let snapshot: AccessSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| "invalid ACL snapshot")?;
    if snapshot.version != 1
        || snapshot.id != id
        || snapshot.channels.len() != 2
        || CHANNELS
            .iter()
            .any(|channel| !snapshot.channels.contains_key(*channel))
    {
        return Err("ACL snapshot scope mismatch".into());
    }
    for (channel, state) in &snapshot.channels {
        if state.after != append_read(&state.before, &snapshot.user_sid)? {
            return Err("ACL snapshot does not contain only read access".into());
        }
        let current = access(channel)?;
        if current != state.after && current != state.before {
            return Err("channel ACL changed after grant; restore conflict".into());
        }
    }
    for (channel, state) in &snapshot.channels {
        set_access(channel, &state.before)?;
    }
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
    fn read_grant_preserves_owner_group_and_sacl() {
        let before = "O:BAG:SYD:(A;;0x7;;;BA)S:(AU;SA;0x1;;;WD)";
        let after = append_read(before, "S-1-5-21-1-2-3-1001").unwrap();
        assert_eq!(
            after,
            "O:BAG:SYD:(A;;0x7;;;BA)(A;;0x1;;;S-1-5-21-1-2-3-1001)S:(AU;SA;0x1;;;WD)"
        );
        assert_eq!(append_read(&after, "S-1-5-21-1-2-3-1001").unwrap(), after);
    }
}
