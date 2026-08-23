//! Restricted-token construction without privilege escalation.

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;

use anyhow::{bail, Result};

pub type RawHandle = *mut c_void;
type Handle = RawHandle;
type Dword = u32;

const DISABLE_MAX_PRIVILEGE: Dword = 0x1;
const TOKEN_ASSIGN_PRIMARY: Dword = 0x0001;
const TOKEN_DUPLICATE: Dword = 0x0002;
const TOKEN_QUERY: Dword = 0x0008;
const TOKEN_ADJUST_DEFAULT: Dword = 0x0080;
const SECURITY_IMPERSONATION: Dword = 2;
const TOKEN_PRIMARY: Dword = 1;
const ERROR_INVALID_HANDLE: Dword = 6;

#[link(name = "advapi32")]
extern "system" {
    fn CreateRestrictedToken(
        existing_token: Handle,
        flags: Dword,
        disable_sid_count: Dword,
        sids_to_disable: *const c_void,
        delete_privilege_count: Dword,
        privileges_to_delete: *const c_void,
        restricting_sid_count: Dword,
        restricting_sids: *const c_void,
        new_token: *mut Handle,
    ) -> i32;
    fn DuplicateTokenEx(
        existing_token: Handle,
        desired_access: Dword,
        token_attributes: *mut c_void,
        impersonation_level: Dword,
        token_type: Dword,
        new_token: *mut Handle,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> Dword;
}

/// Create a restricted primary token from a token handle owned by the caller.
/// No privilege is enabled and no token is opened implicitly.
///
/// # Safety
///
/// `source` must be a live Windows token handle owned by the caller and remain
/// valid for the duration of the call.
pub unsafe fn create_primary(source: RawHandle) -> Result<OwnedHandle> {
    if source.is_null() || source == (-1isize as Handle) {
        bail!(
            "invalid source token handle (error {})",
            ERROR_INVALID_HANDLE
        );
    }
    let mut restricted: Handle = null_mut();
    let ok = CreateRestrictedToken(
        source,
        DISABLE_MAX_PRIVILEGE,
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        &mut restricted,
    );
    if ok == 0 || restricted.is_null() {
        bail!("CreateRestrictedToken failed with {}", GetLastError());
    }

    let mut primary: Handle = null_mut();
    let ok = DuplicateTokenEx(
        restricted,
        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
        null_mut(),
        SECURITY_IMPERSONATION,
        TOKEN_PRIMARY,
        &mut primary,
    );
    let _ = CloseHandle(restricted);
    if ok == 0 || primary.is_null() {
        bail!(
            "DuplicateTokenEx(TokenPrimary) failed with {}",
            GetLastError()
        );
    }
    Ok(OwnedHandle::from_raw_handle(primary.cast()))
}

pub fn raw(handle: &OwnedHandle) -> RawHandle {
    handle.as_raw_handle().cast()
}

pub const fn contract() -> &'static str {
    "restricted primary token; no privilege enablement or elevation"
}
