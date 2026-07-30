#![cfg(windows)]

use std::collections::BTreeMap;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::time::Duration;

use fairypam_agent_input::{GuardianClient, GuardianProcessClient, ReleaseReason};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupPrivilegeValueW,
    TokenIntegrityLevel, TokenPrivileges, TokenRestrictedSids, TokenSessionId,
    SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

fn owned(handle: HANDLE) -> OwnedHandle {
    // SAFETY: the successful Win32 call transfers one owned handle to this test.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

fn process_token(process: HANDLE) -> OwnedHandle {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.expect("process token must open");
    owned(token)
}

fn token_information(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> Vec<usize> {
    let mut bytes = 0_u32;
    let _ =
        unsafe { GetTokenInformation(HANDLE(token.as_raw_handle()), class, None, 0, &mut bytes) };
    assert!(bytes > 0, "token information size must be reported");
    let mut buffer = vec![0_usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
    unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            class,
            Some(buffer.as_mut_ptr().cast()),
            bytes,
            &mut bytes,
        )
    }
    .expect("token information must be readable");
    buffer
}

fn session_id(token: &OwnedHandle) -> u32 {
    let value = token_information(token, TokenSessionId);
    unsafe { *value.as_ptr().cast::<u32>() }
}

fn integrity_rid(token: &OwnedHandle) -> u32 {
    let value = token_information(token, TokenIntegrityLevel);
    let label = unsafe { &*value.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
    let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
    assert!(count > 0, "integrity SID must contain one sub-authority");
    unsafe { *GetSidSubAuthority(label.Label.Sid, u32::from(count - 1)) }
}

#[test]
#[ignore = "requires a built Windows Guardian executable"]
fn privilege_limited_guardian_process_starts() {
    let executable = PathBuf::from(
        std::env::var_os("FAIRYPAM_TEST_GUARDIAN_EXE")
            .expect("FAIRYPAM_TEST_GUARDIAN_EXE must name the built Guardian"),
    );
    let mut guardian = GuardianProcessClient::spawn(
        &executable,
        BTreeMap::new(),
        Duration::from_millis(300),
        None,
    )
    .expect("privilege-limited Guardian must start and complete registration");

    assert!(guardian.child_id() > 0);
    assert_eq!(guardian.isolation_status(), None);
    let current_token = process_token(unsafe { GetCurrentProcess() });
    let child_process = owned(
        unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                guardian.child_id(),
            )
        }
        .expect("Guardian process must remain queryable"),
    );
    let child_token = process_token(HANDLE(child_process.as_raw_handle()));
    assert_eq!(session_id(&child_token), session_id(&current_token));
    assert_eq!(integrity_rid(&child_token), integrity_rid(&current_token));

    let restricted = token_information(&child_token, TokenRestrictedSids);
    assert_eq!(
        unsafe { &*restricted.as_ptr().cast::<TOKEN_GROUPS>() }.GroupCount,
        0
    );
    let privileges = token_information(&child_token, TokenPrivileges);
    let privileges = unsafe { &*privileges.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let mut expected = LUID::default();
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), SE_CHANGE_NOTIFY_NAME, &mut expected) }
        .expect("SeChangeNotifyPrivilege LUID must resolve");
    let entries = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    let enabled = entries
        .iter()
        .filter(|entry| entry.Attributes.contains(SE_PRIVILEGE_ENABLED))
        .collect::<Vec<_>>();
    assert_eq!(enabled.len(), 1);
    assert_eq!(enabled[0].Luid, expected);

    guardian
        .release_all(ReleaseReason::EmergencyStop)
        .expect("privilege-limited Guardian must acknowledge ReleaseAll");
}
