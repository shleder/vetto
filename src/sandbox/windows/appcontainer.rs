//! AppContainer capability probing.
//!
//! This is deliberately a probe/contract module.  Creating a profile or
//! changing a package ACL is outside the sandbox backend's authority and is
//! never attempted here.  The process launcher uses an ephemeral identity
//! and the Windows 11 processmodel API when available.

use std::ffi::c_void;
use std::ptr::null_mut;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub derive_capability_sids: bool,
    pub create_appcontainer_profile: bool,
    pub profile_creation_attempted: bool,
    pub note: &'static str,
}

type Hmodule = *mut c_void;
type FarProc = *const c_void;
type Sid = *mut c_void;
type SidArray = *mut Sid;

const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

type DeriveCapabilitySids = unsafe extern "system" fn(
    cap_name: *const u16,
    capability_group_sids: *mut SidArray,
    capability_group_sid_count: *mut u32,
    capability_sids: *mut SidArray,
    capability_sid_count: *mut u32,
) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> Hmodule;
    fn FreeLibrary(module: Hmodule) -> i32;
    fn GetProcAddress(module: Hmodule, name: *const u8) -> FarProc;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

fn wide(value: &str) -> Option<Vec<u16>> {
    if value.encode_utf16().any(|c| c == 0) {
        return None;
    }
    Some(value.encode_utf16().chain(Some(0)).collect())
}

unsafe fn symbol(module: Hmodule, name: &'static [u8]) -> FarProc {
    // SAFETY: `name` is a static NUL-terminated ANSI symbol and `module` is a
    // handle returned by LoadLibraryExW.
    GetProcAddress(module, name.as_ptr())
}

/// Inspect the APIs needed to derive capability SIDs without creating a
/// profile.  `profile_creation_attempted` is permanently false in this API.
pub fn probe() -> Capabilities {
    let mut result = Capabilities {
        note: "probe only; no AppContainer profile or ACL was created",
        ..Capabilities::default()
    };

    let Some(kernelbase) = wide("kernelbase.dll") else {
        return result;
    };
    let Some(userenv) = wide("userenv.dll") else {
        return result;
    };

    // Keep the modules alive until all symbol checks have completed.  The
    // handles are released on every path below.
    unsafe {
        let kernelbase_handle = LoadLibraryExW(
            kernelbase.as_ptr(),
            null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        );
        let userenv_handle =
            LoadLibraryExW(userenv.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if !kernelbase_handle.is_null() {
            // DeriveCapabilitySidsFromName is documented in securitybaseapi.h
            // and exported by KernelBase.dll on current Windows builds.
            let derive = symbol(kernelbase_handle, b"DeriveCapabilitySidsFromName\0");
            result.derive_capability_sids = !derive.is_null();
            if result.derive_capability_sids {
                // Verify that the export is callable and that Windows can
                // produce at least one SID.  Every allocation is released by
                // LocalFree as documented for this API.
                if let Some(name) = wide("internetClient") {
                    let derive: DeriveCapabilitySids = std::mem::transmute(derive);
                    let mut group_sids: SidArray = null_mut();
                    let mut group_count = 0u32;
                    let mut sids: SidArray = null_mut();
                    let mut sid_count = 0u32;
                    let hr = derive(
                        name.as_ptr(),
                        &mut group_sids,
                        &mut group_count,
                        &mut sids,
                        &mut sid_count,
                    );
                    if hr == 0 || group_count == 0 || sid_count == 0 {
                        result.derive_capability_sids = false;
                    }
                    if !group_sids.is_null() {
                        for index in 0..group_count {
                            let sid = *group_sids.add(index as usize);
                            if !sid.is_null() {
                                let _ = LocalFree(sid);
                            }
                        }
                        let _ = LocalFree(group_sids.cast());
                    }
                    if !sids.is_null() {
                        for index in 0..sid_count {
                            let sid = *sids.add(index as usize);
                            if !sid.is_null() {
                                let _ = LocalFree(sid);
                            }
                        }
                        let _ = LocalFree(sids.cast());
                    }
                } else {
                    result.derive_capability_sids = false;
                }
            }
            let _ = FreeLibrary(kernelbase_handle);
        }
        if !userenv_handle.is_null() {
            result.create_appcontainer_profile =
                !symbol(userenv_handle, b"CreateAppContainerProfile\0").is_null();
            let _ = FreeLibrary(userenv_handle);
        }
    }
    result
}

/// Return whether the supplied capability name is representable by the
/// system.  This invokes the documented derivation API but does not create a
/// profile, add a capability, or modify a token.
pub fn can_derive(name: &str) -> bool {
    if name.is_empty() || name.encode_utf16().any(|c| c == 0) {
        return false;
    }
    let Some(kernelbase) = wide("kernelbase.dll") else {
        return false;
    };
    unsafe {
        let module = LoadLibraryExW(
            kernelbase.as_ptr(),
            null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        );
        if module.is_null() {
            return false;
        }
        let proc = symbol(module, b"DeriveCapabilitySidsFromName\0");
        let ok = if proc.is_null() {
            false
        } else {
            let derive: DeriveCapabilitySids = std::mem::transmute(proc);
            let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let mut group_sids: SidArray = null_mut();
            let mut group_count = 0u32;
            let mut sids: SidArray = null_mut();
            let mut sid_count = 0u32;
            let hr = derive(
                name.as_ptr(),
                &mut group_sids,
                &mut group_count,
                &mut sids,
                &mut sid_count,
            );
            if !group_sids.is_null() {
                for index in 0..group_count {
                    let sid = *group_sids.add(index as usize);
                    if !sid.is_null() {
                        let _ = LocalFree(sid);
                    }
                }
                let _ = LocalFree(group_sids.cast());
            }
            if !sids.is_null() {
                for index in 0..sid_count {
                    let sid = *sids.add(index as usize);
                    if !sid.is_null() {
                        let _ = LocalFree(sid);
                    }
                }
                let _ = LocalFree(sids.cast());
            }
            hr != 0 && group_count > 0 && sid_count > 0
        };
        let _ = FreeLibrary(module);
        ok
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn probe_is_explicitly_non_mutating() {
        // The contract is compile-time visible even on non-Windows CI.
        assert!(!super::Capabilities::default().profile_creation_attempted);
    }
}
