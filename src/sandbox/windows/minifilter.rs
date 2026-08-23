//! Runtime contract for an already-installed Windows minifilter.
//!
//! This module never creates a service, copies a `.sys`, starts a driver, or
//! changes an altitude.  A selected minifilter is considered usable only
//! when its service is present, its read-only `ImagePath` matches the requested
//! `.sys`, the image exists, Authenticode verification succeeds without
//! network retrieval, and the service reports `RUNNING`. Otherwise the caller
//! receives an error and must fail closed.

use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};

use anyhow::{bail, Result};

type Handle = *mut c_void;
type Dword = u32;
type Bool = i32;

const HKEY_LOCAL_MACHINE: Handle = 0x8000_0002usize as Handle;
const KEY_READ: Dword = 0x0002_0019;
const SERVICE_QUERY_STATUS: Dword = 0x0004;
const SC_MANAGER_CONNECT: Dword = 0x0001;
const SC_STATUS_PROCESS_INFO: Dword = 0;
const SERVICE_RUNNING: Dword = 0x0004;
const WTD_UI_NONE: Dword = 2;
const WTD_CHOICE_FILE: Dword = 1;
const WTD_STATEACTION_VERIFY: Dword = 1;
const WTD_STATEACTION_CLOSE: Dword = 2;
const WTD_CACHE_ONLY_URL_RETRIEVAL: Dword = 0x0000_0100;
const INVALID_FILE_ATTRIBUTES: Dword = u32::MAX;
const FILE_ATTRIBUTE_DIRECTORY: Dword = 0x0000_0010;
const REG_SZ: Dword = 1;
const REG_EXPAND_SZ: Dword = 2;
const MAX_SERVICE_IMAGE_BYTES: Dword = 64 * 1024;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
    data1: 0x00aa_c56b,
    data2: 0xcd44,
    data3: 0x11d0,
    data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};

#[repr(C)]
struct WintrustFileInfo {
    cb_struct: Dword,
    file_path: *const u16,
    file: Handle,
    known_subject: *mut Guid,
}

#[repr(C)]
union WintrustDataChoice {
    file: *mut WintrustFileInfo,
    catalog: *mut c_void,
}

#[repr(C)]
struct WintrustData {
    cb_struct: Dword,
    policy_callback_data: *mut c_void,
    sip_client_data: *mut c_void,
    ui_choice: Dword,
    revocation_checks: Dword,
    union_choice: Dword,
    choice: WintrustDataChoice,
    state_action: Dword,
    state_data: Handle,
    url_reference: *mut u16,
    provider_flags: Dword,
    ui_context: Dword,
    signature_settings: *mut c_void,
}

#[repr(C)]
struct ServiceStatusProcess {
    service_type: Dword,
    current_state: Dword,
    controls_accepted: Dword,
    win32_exit_code: Dword,
    service_specific_exit_code: Dword,
    check_point: Dword,
    wait_hint: Dword,
    process_id: Dword,
    flags: Dword,
}

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(
        key: Handle,
        sub_key: *const u16,
        options: Dword,
        desired: Dword,
        result: *mut Handle,
    ) -> Dword;
    fn RegCloseKey(key: Handle) -> Dword;
    fn RegQueryValueExW(
        key: Handle,
        value_name: *const u16,
        reserved: *mut Dword,
        value_type: *mut Dword,
        data: *mut u8,
        data_size: *mut Dword,
    ) -> Dword;
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: Dword) -> Handle;
    fn OpenServiceW(manager: Handle, name: *const u16, access: Dword) -> Handle;
    fn QueryServiceStatusEx(
        service: Handle,
        info_level: Dword,
        buffer: *mut u8,
        buffer_size: Dword,
        needed: *mut Dword,
    ) -> Bool;
    fn CloseServiceHandle(handle: Handle) -> Bool;
}

#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(hwnd: Handle, action_id: *const Guid, data: *mut c_void) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetFileAttributesW(path: *const u16) -> Dword;
    fn GetWindowsDirectoryW(buffer: *mut u16, size: Dword) -> Dword;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinifilterContract {
    pub service_name: String,
    pub driver_path: String,
}

impl MinifilterContract {
    pub fn new(service_name: impl Into<String>, driver_path: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            driver_path: driver_path.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinifilterCapabilities {
    pub service_present: bool,
    pub image_present: bool,
    pub signed: bool,
    pub runtime_loaded: bool,
    /// The service's read-only `ImagePath` value matches the requested image.
    /// A running service with a different image must never satisfy selection.
    pub service_image_matches: bool,
    pub install_attempted: bool,
    pub note: String,
}

/// Read-only service/image/signature/runtime probe.
pub fn capabilities(contract: &MinifilterContract) -> MinifilterCapabilities {
    let service_present = service_present(&contract.service_name);
    let image_present =
        Path::new(&contract.driver_path).is_absolute() && file_present(&contract.driver_path);
    let signed = image_present && verify_signature(&contract.driver_path);
    let runtime_loaded = service_present && service_running(&contract.service_name);
    let service_image_matches = service_present
        && image_present
        && service_image_matches_contract(&contract.service_name, &contract.driver_path);
    let note = if service_present
        && image_present
        && signed
        && runtime_loaded
        && service_image_matches
    {
        "existing signed minifilter appears loaded; no driver state was changed".to_string()
    } else {
        "minifilter unavailable or service image does not match; selection must fail closed; installation/start is out of scope".to_string()
    };
    MinifilterCapabilities {
        service_present,
        image_present,
        signed,
        runtime_loaded,
        service_image_matches,
        install_attempted: false,
        note,
    }
}

/// Validate the contract and return an observation-only handle.  There is no
/// method on the returned value that can install or start a driver.
pub fn select(contract: MinifilterContract) -> Result<SelectedMinifilter> {
    if contract.service_name.is_empty()
        || contract.driver_path.is_empty()
        || !Path::new(&contract.driver_path).is_absolute()
        || !Path::new(&contract.driver_path)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sys"))
        || contract
            .service_name
            .chars()
            .any(|character| matches!(character, '\\' | '/' | '\0'))
    {
        bail!("minifilter contract requires a service name and driver path");
    }
    let caps = capabilities(&contract);
    if !caps.service_present {
        bail!(
            "minifilter service {:?} is absent; no driver was installed",
            contract.service_name
        );
    }
    if !caps.image_present {
        bail!(
            "minifilter image {:?} is absent; no driver was installed",
            contract.driver_path
        );
    }
    if !caps.signed {
        bail!(
            "minifilter image {:?} failed Authenticode verification",
            contract.driver_path
        );
    }
    if !caps.runtime_loaded {
        bail!(
            "minifilter service {:?} is not running; refusing to claim enforcement",
            contract.service_name
        );
    }
    if !caps.service_image_matches {
        bail!("minifilter service {:?} ImagePath does not match the requested signed driver; refusing to claim enforcement", contract.service_name);
    }
    Ok(SelectedMinifilter { contract, caps })
}

#[derive(Clone, Debug)]
pub struct SelectedMinifilter {
    contract: MinifilterContract,
    caps: MinifilterCapabilities,
}

impl SelectedMinifilter {
    pub fn contract(&self) -> &MinifilterContract {
        &self.contract
    }
    pub fn capabilities(&self) -> &MinifilterCapabilities {
        &self.caps
    }
    pub const fn enforcement_note() -> &'static str {
        "selected driver is observed as loaded; this crate does not install, configure, or attest its filtering semantics"
    }
}

fn service_present(name: &str) -> bool {
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{name}");
    let Ok(mut wide) = wide(&path) else {
        return false;
    };
    let mut key: Handle = null_mut();
    let status =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide.as_mut_ptr(), 0, KEY_READ, &mut key) };
    if status == 0 && !key.is_null() {
        unsafe {
            let _ = RegCloseKey(key);
        }
        true
    } else {
        false
    }
}

/// Read the service's configured image path without opening a write handle or
/// changing service state.  A service name by itself is not enough evidence:
/// Windows can have a running service whose image is not the driver selected
/// by the caller.
fn service_image_matches_contract(service: &str, requested_path: &str) -> bool {
    let Some(actual) = service_image_path(service) else {
        return false;
    };
    let Some(requested) = normalize_image_path(requested_path) else {
        return false;
    };
    actual.eq_ignore_ascii_case(&requested)
}

fn service_image_path(name: &str) -> Option<String> {
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\{name}");
    let mut key_path = wide(&path).ok()?;
    let mut key: Handle = null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path.as_mut_ptr(),
            0,
            KEY_READ,
            &mut key,
        )
    };
    if status != 0 || key.is_null() {
        return None;
    }
    let result = (|| {
        let mut value_name = wide("ImagePath").ok()?;
        let mut value_type = 0u32;
        let mut byte_count = 0u32;
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_mut_ptr(),
                null_mut(),
                &mut value_type,
                null_mut(),
                &mut byte_count,
            )
        };
        if status != 0
            || byte_count == 0
            || byte_count > MAX_SERVICE_IMAGE_BYTES
            || byte_count % 2 != 0
        {
            return None;
        }
        let mut data = vec![0u16; byte_count as usize / 2];
        let mut returned = byte_count;
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_mut_ptr(),
                null_mut(),
                &mut value_type,
                data.as_mut_ptr().cast(),
                &mut returned,
            )
        };
        if status != 0 {
            return None;
        }
        if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
            return None;
        }
        let words = (returned as usize / 2).min(data.len());
        let raw = String::from_utf16(&data[..words]).ok()?;
        normalize_image_path(&raw)
    })();
    unsafe {
        let _ = RegCloseKey(key);
    }
    result
}

/// Normalize only the forms emitted by the Windows service manager.  If a
/// path contains arguments, an unsupported variable, or a relative prefix,
/// return `None` instead of guessing which image is loaded.
fn normalize_image_path(raw: &str) -> Option<String> {
    let mut value = raw.trim().trim_end_matches('\0').trim().to_string();
    if value.is_empty() {
        return None;
    }
    if value.starts_with('"') {
        if !value.ends_with('"') || value.len() < 2 {
            return None;
        }
        value = value[1..value.len() - 1].to_string();
    } else if value.contains('"') || value.split_whitespace().count() > 1 {
        return None;
    }
    value = value.replace('/', "\\");
    let lower = value.to_ascii_lowercase();
    if lower.starts_with(r"\systemroot\") {
        let root = windows_root()?;
        value = format!("{}{}", root, &value[r"\systemroot".len()..]);
    } else if lower.starts_with("%systemroot%\\") {
        let root = windows_root()?;
        value = format!("{}{}", root, &value["%systemroot%".len()..]);
    } else if lower.starts_with(r"\??\") || lower.starts_with(r"\\?\") {
        value = value[4..].to_string();
    }
    if !Path::new(&value).is_absolute() || value.contains('%') {
        return None;
    }
    Some(value.trim_end_matches('\\').to_ascii_lowercase())
}

fn windows_root() -> Option<String> {
    let mut buffer = vec![0u16; 260];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as Dword) };
    if length == 0 {
        return None;
    }
    if length as usize >= buffer.len() {
        buffer.resize(length as usize + 1, 0);
        let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as Dword) };
        if length == 0 || length as usize >= buffer.len() {
            return None;
        }
        return String::from_utf16(&buffer[..length as usize]).ok();
    }
    String::from_utf16(&buffer[..length as usize]).ok()
}

fn service_running(name: &str) -> bool {
    let Ok(mut wide) = wide(name) else {
        return false;
    };
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return false;
    }
    let service = unsafe { OpenServiceW(manager, wide.as_mut_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        unsafe {
            let _ = CloseServiceHandle(manager);
        }
        return false;
    }
    let mut status = ServiceStatusProcess {
        service_type: 0,
        current_state: 0,
        controls_accepted: 0,
        win32_exit_code: 0,
        service_specific_exit_code: 0,
        check_point: 0,
        wait_hint: 0,
        process_id: 0,
        flags: 0,
    };
    let mut needed = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut ServiceStatusProcess).cast(),
            std::mem::size_of::<ServiceStatusProcess>() as Dword,
            &mut needed,
        )
    };
    unsafe {
        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(manager);
    }
    ok != 0 && status.current_state == SERVICE_RUNNING
}

fn file_present(path: &str) -> bool {
    let Ok(mut wide) = wide(path) else {
        return false;
    };
    let attrs = unsafe { GetFileAttributesW(wide.as_mut_ptr()) };
    attrs != INVALID_FILE_ATTRIBUTES && attrs & FILE_ATTRIBUTE_DIRECTORY == 0
}

fn verify_signature(path: &str) -> bool {
    let Ok(mut wide) = wide(path) else {
        return false;
    };
    let mut file_info = WintrustFileInfo {
        cb_struct: std::mem::size_of::<WintrustFileInfo>() as Dword,
        file_path: wide.as_mut_ptr(),
        file: null_mut(),
        known_subject: null_mut(),
    };
    let mut data = WintrustData {
        cb_struct: std::mem::size_of::<WintrustData>() as Dword,
        policy_callback_data: null_mut(),
        sip_client_data: null_mut(),
        ui_choice: WTD_UI_NONE,
        revocation_checks: 0,
        union_choice: WTD_CHOICE_FILE,
        choice: WintrustDataChoice {
            file: &mut file_info,
        },
        state_action: WTD_STATEACTION_VERIFY,
        state_data: null_mut(),
        url_reference: null_mut(),
        provider_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ui_context: 0,
        signature_settings: null_mut(),
    };
    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            (&mut data as *mut WintrustData).cast(),
        )
    };
    data.state_action = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            null_mut(),
            &WINTRUST_ACTION_GENERIC_VERIFY_V2,
            (&mut data as *mut WintrustData).cast(),
        );
    }
    status == 0
}

fn wide(value: &str) -> Result<Vec<u16>> {
    if value.encode_utf16().any(|c| c == 0) {
        bail!("wide string contains NUL");
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn selection_contract_is_fail_closed_for_missing_driver() {
        let contract = super::MinifilterContract::new(
            "vetto-test-minifilter-that-should-not-exist",
            "C:\\Windows\\System32\\drivers\\vetto-test-minifilter.sys",
        );
        assert!(super::select(contract).is_err());
    }
}
