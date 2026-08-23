//! Token integrity-level operations used by the Windows sandbox contract.
//!
//! The function in this module only adjusts a token handle supplied by the
//! caller.  It does not open arbitrary processes, enable privileges, or
//! change the integrity of the parent process.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::copy_nonoverlapping;

use anyhow::{bail, Result};

pub type RawHandle = *mut c_void;
type Handle = RawHandle;
type Dword = u32;

const TOKEN_INTEGRITY_LEVEL: Dword = 25;
const SECURITY_MANDATORY_LABEL_ATTRIBUTE: Dword = 0x20;
const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
#[cfg(test)]
const ERROR_SUCCESS: u32 = 0;

#[repr(C)]
struct TokenMandatoryLabel {
    label: SidAndAttributes,
}

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: Dword,
}

#[repr(C)]
struct OneSubAuthoritySid {
    revision: u8,
    sub_authority_count: u8,
    identifier_authority: [u8; 6],
    sub_authority: u32,
}

#[link(name = "advapi32")]
extern "system" {
    fn SetTokenInformation(
        token_handle: Handle,
        token_information_class: Dword,
        token_information: *const c_void,
        token_information_length: Dword,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

/// Set a caller-owned primary or impersonation token to low integrity.
///
/// The token must have `TOKEN_ADJUST_DEFAULT` access.  This is an explicit
/// operation; failure is returned to the caller and never treated as a
/// best-effort downgrade.
///
/// # Safety
///
/// `token` must be a live Windows token handle owned by the caller and remain
/// valid for the duration of the call.
pub unsafe fn set_low_integrity(token: RawHandle) -> Result<()> {
    if token.is_null() {
        bail!("cannot set integrity on a null token");
    }

    let sid = OneSubAuthoritySid {
        revision: 1,
        sub_authority_count: 1,
        // SECURITY_MANDATORY_LABEL_AUTHORITY = {0, 0, 0, 0, 0, 16}.
        identifier_authority: [0, 0, 0, 0, 0, 16],
        sub_authority: SECURITY_MANDATORY_LOW_RID,
    };

    // Keep the SID immediately after the label and preserve pointer
    // alignment.  `Vec<usize>` is aligned for every pointer-sized ABI field.
    let sid_offset =
        (size_of::<TokenMandatoryLabel>() + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
    let total = sid_offset + size_of::<OneSubAuthoritySid>();
    let words = total.div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; words];
    let base = storage.as_mut_ptr().cast::<u8>();
    let sid_ptr = base.add(sid_offset);
    copy_nonoverlapping(
        (&sid as *const OneSubAuthoritySid).cast::<u8>(),
        sid_ptr,
        size_of::<OneSubAuthoritySid>(),
    );
    let label = base.cast::<TokenMandatoryLabel>();
    (*label).label.sid = sid_ptr.cast();
    (*label).label.attributes = SECURITY_MANDATORY_LABEL_ATTRIBUTE;

    let ok = SetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, label.cast(), total as Dword);
    if ok == 0 {
        bail!(
            "SetTokenInformation(TokenIntegrityLevel) failed with {}",
            GetLastError()
        );
    }
    Ok(())
}

/// This backend has no privileged probe: the caller's token handle and access
/// mask determine whether the operation can succeed.  The function exists so
/// doctor/reporting code can state that integrity is an explicit token step,
/// not an implied property of a restricted-token fallback.
pub const fn contract() -> &'static str {
    "low-integrity token adjustment is explicit and fail-closed"
}

#[cfg(test)]
mod tests {
    #[test]
    fn low_rid_is_not_medium() {
        assert_eq!(super::SECURITY_MANDATORY_LOW_RID, 0x1000);
        assert_eq!(super::ERROR_SUCCESS, 0);
    }
}
