//! Opt-in Windows Event Log writer.
//!
//! Opening an existing source is supported.  Registering a new source means
//! writing `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\...` and usually
//! requires an administrator; this module reports that distinction and never
//! performs that registration itself.

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use anyhow::{bail, Result};

type Handle = *mut c_void;
type Dword = u32;
type Bool = i32;
type Hkey = *mut c_void;

const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002usize as Hkey;
const KEY_READ: Dword = 0x0002_0019;
const EVENTLOG_INFORMATION_TYPE: u16 = 0x0004;
const ERROR_SUCCESS: Dword = 0;

#[link(name = "advapi32")]
extern "system" {
    fn RegisterEventSourceW(server_name: *const u16, source_name: *const u16) -> Handle;
    fn DeregisterEventSource(event_log: Handle) -> Bool;
    fn ReportEventW(
        event_log: Handle,
        event_type: u16,
        category: u16,
        event_id: Dword,
        user_sid: *const c_void,
        num_strings: u16,
        data_size: Dword,
        strings: *const *const u16,
        raw_data: *const c_void,
    ) -> Bool;
    fn RegOpenKeyExW(
        key: Hkey,
        sub_key: *const u16,
        options: Dword,
        desired: Dword,
        result: *mut Hkey,
    ) -> Dword;
    fn RegCloseKey(key: Hkey) -> Dword;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> Dword;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventLogCapabilities {
    pub api_available: bool,
    pub source_registered: bool,
    pub registration_requires_admin: bool,
    pub writable_without_registration: bool,
    pub note: String,
}

/// Read-only source registration probe.  It does not call RegisterEventSourceW
/// and does not write the registry.
pub fn capabilities(source: &str) -> EventLogCapabilities {
    if source.is_empty()
        || source.encode_utf16().any(|c| c == 0)
        || source.contains('\\')
        || source.contains('/')
    {
        return EventLogCapabilities {
            api_available: true,
            source_registered: false,
            registration_requires_admin: true,
            writable_without_registration: false,
            note: "invalid source name".to_string(),
        };
    }
    let source_registered = source_is_registered(source);
    EventLogCapabilities {
        api_available: true,
        source_registered,
        registration_requires_admin: true,
        writable_without_registration: source_registered,
        note: if source_registered {
            "existing source may be opened; no source registration was attempted".to_string()
        } else {
            "source is absent; registration is an admin-owned operation and was not attempted"
                .to_string()
        },
    }
}

fn source_is_registered(source: &str) -> bool {
    let path = format!("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\{source}");
    let mut wide = match wide(&path) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let mut key: Hkey = null_mut();
    let status =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide.as_mut_ptr(), 0, KEY_READ, &mut key) };
    if status == ERROR_SUCCESS && !key.is_null() {
        unsafe {
            let _ = RegCloseKey(key);
        }
        true
    } else {
        false
    }
}

/// A handle to an already registered classic Event Log source.
pub struct EventLogWriter {
    handle: Handle,
    source: String,
}

impl std::fmt::Debug for EventLogWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventLogWriter")
            .field("source", &self.source)
            .field("open", &(!self.handle.is_null()))
            .finish()
    }
}

impl EventLogWriter {
    /// Open a source only when it is already registered.  `allow_registration`
    /// is intentionally rejected: it exists to make the admin boundary
    /// explicit to callers without allowing this library to write HKLM.
    pub fn open(source: &str, allow_registration: bool) -> Result<Self> {
        if source.is_empty()
            || source.encode_utf16().any(|c| c == 0)
            || source.contains('\\')
            || source.contains('/')
        {
            bail!("event source is empty or contains NUL");
        }
        if allow_registration && !source_is_registered(source) {
            bail!(
                "event source registration requires an administrator and is not performed by vetto"
            );
        }
        if !source_is_registered(source) {
            bail!("event source is not registered; register it out-of-band with an administrator");
        }
        let mut wide = wide(source)?;
        let handle = unsafe { RegisterEventSourceW(null(), wide.as_mut_ptr()) };
        if handle.is_null() {
            bail!("RegisterEventSourceW failed with {}", unsafe {
                GetLastError()
            });
        }
        Ok(Self {
            handle,
            source: source.to_string(),
        })
    }

    /// Write an informational event using the source's existing message
    /// catalog.  This is observational/reporting output; it never changes
    /// firewall or sandbox policy.
    pub fn write_notice(&self, event_id: Dword, message: &str) -> Result<()> {
        if message.encode_utf16().any(|c| c == 0) {
            bail!("event message contains NUL");
        }
        let mut wide = wide(message)?;
        let strings = [wide.as_mut_ptr() as *const u16];
        let ok = unsafe {
            ReportEventW(
                self.handle,
                EVENTLOG_INFORMATION_TYPE,
                0,
                event_id,
                null(),
                1,
                0,
                strings.as_ptr(),
                null(),
            )
        };
        if ok == 0 {
            bail!("ReportEventW failed with {}", unsafe { GetLastError() });
        }
        Ok(())
    }

    /// Explicitly document the admin-only operation without exposing a
    /// hidden registration path.
    pub fn registration_requirement() -> &'static str {
        "registering a new Event Log source requires an administrator; this API never writes HKLM"
    }
}

impl Drop for EventLogWriter {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = DeregisterEventSource(self.handle);
            }
            self.handle = null_mut();
        }
    }
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
    fn missing_source_is_not_claimed_writable() {
        let caps = super::capabilities("vetto-test-source-that-should-not-exist");
        assert!(caps.registration_requires_admin);
        assert!(!caps.writable_without_registration || caps.source_registered);
    }
}
