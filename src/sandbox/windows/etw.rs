//! Windows ETW observation with honest unprivileged fallbacks.
//!
//! ETW is an observation stream, not an enforcement primitive.  A private
//! real-time session is attempted when the current token can create one and
//! the kernel process provider can be enabled.  If either step is denied, the
//! caller can use `ReadDirectoryChangesW` for filesystem changes and process
//! handle polling for exit state.  Neither fallback claims complete syscall
//! or network visibility.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{copy_nonoverlapping, null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

type Handle = *mut c_void;
type Dword = u32;
type Bool = i32;
type TraceHandle = u64;

const TRUE: Bool = 1;
const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const EVENT_TRACE_REAL_TIME_MODE: Dword = 0x0000_0100;
const WNODE_FLAG_TRACED_GUID: Dword = 0x0002_0000;
const EVENT_TRACE_CONTROL_STOP: Dword = 1;
const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u8 = 1;
const TRACE_LEVEL_INFORMATION: u8 = 4;
const ERROR_SUCCESS: Dword = 0;
const FILE_LIST_DIRECTORY: Dword = 0x0001;
const FILE_SHARE_READ: Dword = 0x0000_0001;
const FILE_SHARE_WRITE: Dword = 0x0000_0002;
const FILE_SHARE_DELETE: Dword = 0x0000_0004;
const OPEN_EXISTING: Dword = 3;
const FILE_FLAG_BACKUP_SEMANTICS: Dword = 0x0200_0000;
const FILE_NOTIFY_CHANGE_FILE_NAME: Dword = 0x0000_0001;
const FILE_NOTIFY_CHANGE_DIR_NAME: Dword = 0x0000_0002;
const FILE_NOTIFY_CHANGE_ATTRIBUTES: Dword = 0x0000_0004;
const FILE_NOTIFY_CHANGE_SIZE: Dword = 0x0000_0008;
const FILE_NOTIFY_CHANGE_LAST_WRITE: Dword = 0x0000_0010;
const FILE_NOTIFY_CHANGE_CREATION: Dword = 0x0000_0040;
const FILE_NOTIFY_CHANGE_SECURITY: Dword = 0x0000_0100;
const SYNCHRONIZE: Dword = 0x0010_0000;
const PROCESS_QUERY_LIMITED_INFORMATION: Dword = 0x1000;
const WAIT_OBJECT_0: Dword = 0;
const WAIT_TIMEOUT: Dword = 0x102;

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

// Microsoft-Windows-Kernel-Process provider.  ETW provider enablement is
// observation only; this module never changes provider configuration.
const KERNEL_PROCESS_PROVIDER: Guid = Guid {
    data1: 0x22fb_2cd6,
    data2: 0x0e7b,
    data3: 0x422b,
    data4: [0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16],
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WnodeHeader {
    buffer_size: Dword,
    provider_id: Dword,
    historical_context: u64,
    time_stamp: i64,
    guid: Guid,
    client_context: Dword,
    flags: Dword,
}

#[repr(C)]
struct EventTraceProperties {
    wnode: WnodeHeader,
    buffer_size: Dword,
    minimum_buffers: Dword,
    maximum_buffers: Dword,
    maximum_file_size: Dword,
    log_file_mode: Dword,
    flush_timer: Dword,
    enable_flags: Dword,
    age_limit: Dword,
    number_of_buffers: Dword,
    free_buffers: Dword,
    events_lost: Dword,
    buffers_written: Dword,
    log_buffers_lost: Dword,
    real_time_buffers_lost: Dword,
    logger_thread_id: Handle,
    log_file_name_offset: Dword,
    logger_name_offset: Dword,
}

#[repr(C)]
struct FileNotifyInformationHeader {
    next_entry_offset: Dword,
    action: Dword,
    file_name_length: Dword,
}

#[link(name = "advapi32")]
extern "system" {
    fn StartTraceW(
        session_handle: *mut TraceHandle,
        instance_name: *const u16,
        properties: *mut EventTraceProperties,
    ) -> Dword;
    fn EnableTraceEx2(
        trace_handle: TraceHandle,
        provider_id: *const Guid,
        control_code: u8,
        level: u8,
        match_any_keyword: u64,
        match_all_keyword: u64,
        timeout: Dword,
        enable_parameters: *const c_void,
    ) -> Dword;
    fn ControlTraceW(
        trace_handle: TraceHandle,
        instance_name: *const u16,
        properties: *mut EventTraceProperties,
        control_code: Dword,
    ) -> Dword;
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        file_name: *const u16,
        desired_access: Dword,
        share_mode: Dword,
        security_attributes: *mut c_void,
        creation_disposition: Dword,
        flags_and_attributes: Dword,
        template_file: Handle,
    ) -> Handle;
    fn ReadDirectoryChangesW(
        directory: Handle,
        buffer: *mut c_void,
        buffer_length: Dword,
        watch_subtree: Bool,
        notify_filter: Dword,
        bytes_returned: *mut Dword,
        overlapped: *mut c_void,
        completion_routine: *mut c_void,
    ) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
    fn OpenProcess(desired_access: Dword, inherit_handle: Bool, process_id: Dword) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: Dword) -> Dword;
    fn GetLastError() -> Dword;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtwCapabilities {
    pub api_available: bool,
    pub private_session_started: bool,
    pub kernel_process_provider_enabled: bool,
    pub decoded_event_stream: bool,
    pub fallback: &'static str,
    pub note: String,
}

#[derive(Debug)]
pub struct EtwSession {
    handle: TraceHandle,
    name: Vec<u16>,
    // The native structure requires pointer alignment. Keep the backing
    // allocation word-aligned instead of casting a `Vec<u8>` whose alignment
    // is only one byte in Rust's type contract.
    properties: Vec<u64>,
    pub capabilities: EtwCapabilities,
}

impl EtwSession {
    /// Start a private real-time ETW session and enable process observations.
    /// The session intentionally has no persistence and no enforcement.
    pub fn start() -> Result<Self> {
        let id = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let name = format!("vetto-etw-{id:016x}-{nonce:016x}");
        let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let total = size_of::<EventTraceProperties>() + name_wide.len() * size_of::<u16>();
        let words = total.div_ceil(size_of::<u64>());
        let mut properties = vec![0u64; words];
        let props = properties.as_mut_ptr().cast::<EventTraceProperties>();
        unsafe {
            (*props).wnode.buffer_size = total as Dword;
            (*props).wnode.flags = WNODE_FLAG_TRACED_GUID;
            (*props).log_file_mode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).minimum_buffers = 2;
            (*props).maximum_buffers = 64;
            (*props).logger_name_offset = size_of::<EventTraceProperties>() as Dword;
            copy_nonoverlapping(
                name_wide.as_ptr().cast::<u8>(),
                properties
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(size_of::<EventTraceProperties>()),
                name_wide.len() * size_of::<u16>(),
            );
        }
        let mut handle = 0u64;
        let status = unsafe { StartTraceW(&mut handle, name_wide.as_ptr(), props) };
        if status != ERROR_SUCCESS || handle == 0 {
            bail!("ETW StartTraceW failed with status 0x{status:08x}; use directory/process polling fallback");
        }
        let provider_status = unsafe {
            EnableTraceEx2(
                handle,
                &KERNEL_PROCESS_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION,
                u64::MAX,
                0,
                0,
                null(),
            )
        };
        if provider_status != ERROR_SUCCESS {
            unsafe {
                let _ = ControlTraceW(handle, null(), props, EVENT_TRACE_CONTROL_STOP);
            }
            bail!("ETW kernel process provider enable failed with status 0x{provider_status:08x}");
        }
        Ok(Self {
            handle,
            name: name_wide,
            properties,
            capabilities: EtwCapabilities {
                api_available: true,
                private_session_started: true,
                kernel_process_provider_enabled: true,
                // A consumer callback is deliberately not fabricated.  The
                // caller can add one with a dedicated OpenTrace/ProcessTrace
                // consumer; this session's fallback labels remain honest.
                decoded_event_stream: false,
                fallback: "ReadDirectoryChangesW + process handle polling",
                note: "ETW provider session is observation-only; this API does not claim decoded syscall coverage".to_string(),
            },
        })
    }

    pub fn is_active(&self) -> bool {
        self.handle != 0
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        if self.handle == 0 {
            return;
        }
        let props = self.properties.as_mut_ptr().cast::<EventTraceProperties>();
        unsafe {
            let _ = ControlTraceW(
                self.handle,
                self.name.as_ptr(),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        self.handle = 0;
    }
}

/// Start ETW if possible and otherwise return a capability result explaining
/// which unprivileged observation primitives should be used.
pub fn capability_probe() -> EtwCapabilities {
    match EtwSession::start() {
        Ok(session) => {
            let caps = session.capabilities.clone();
            drop(session);
            caps
        }
        Err(error) => EtwCapabilities {
            api_available: true,
            private_session_started: false,
            kernel_process_provider_enabled: false,
            decoded_event_stream: false,
            fallback: "ReadDirectoryChangesW + process handle polling",
            note: format!("ETW unavailable ({error}); fallback is observation-only"),
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryEvent {
    pub root: PathBuf,
    pub relative_path: PathBuf,
    pub action: DirectoryAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryAction {
    Created,
    Removed,
    Modified,
    RenamedOldName,
    RenamedNewName,
    Unknown(u32),
}

/// A best-effort observer backed by ReadDirectoryChangesW.  Dropping it asks
/// the thread to stop; a blocked OS read may finish only after the next file
/// notification, so callers must not use this as a hard shutdown primitive.
pub struct DirectoryObserver {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl DirectoryObserver {
    pub fn spawn<F>(root: &Path, callback: F) -> Result<Self>
    where
        F: Fn(DirectoryEvent) + Send + 'static,
    {
        if !root.is_absolute() {
            bail!("directory observer root must be absolute");
        }
        if root
            .as_os_str()
            .encode_wide()
            .any(|character| character == 0)
        {
            bail!("directory observer root contains an embedded NUL");
        }
        let root = root.to_path_buf();
        let mut wide: Vec<u16> = root.as_os_str().encode_wide().chain(Some(0)).collect();
        let directory = unsafe {
            CreateFileW(
                wide.as_mut_ptr(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        if directory.is_null() || directory == INVALID_HANDLE_VALUE {
            bail!(
                "ReadDirectoryChangesW directory open failed with {}",
                unsafe { GetLastError() }
            );
        }
        let directory = unsafe { OwnedHandle::from_raw_handle(directory.cast()) };
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("vetto-read-directory-changes".to_string())
            .spawn(move || {
                let _directory = directory;
                let mut buffer = vec![0u8; 64 * 1024];
                while !stop_thread.load(Ordering::Relaxed) {
                    let mut bytes = 0u32;
                    let ok = unsafe {
                        ReadDirectoryChangesW(
                            _directory.as_raw_handle().cast(),
                            buffer.as_mut_ptr().cast(),
                            buffer.len() as Dword,
                            TRUE,
                            FILE_NOTIFY_CHANGE_FILE_NAME
                                | FILE_NOTIFY_CHANGE_DIR_NAME
                                | FILE_NOTIFY_CHANGE_ATTRIBUTES
                                | FILE_NOTIFY_CHANGE_SIZE
                                | FILE_NOTIFY_CHANGE_LAST_WRITE
                                | FILE_NOTIFY_CHANGE_CREATION
                                | FILE_NOTIFY_CHANGE_SECURITY,
                            &mut bytes,
                            null_mut(),
                            null_mut(),
                        )
                    };
                    if ok == 0 || bytes == 0 {
                        break;
                    }
                    for event in parse_directory_events(&root, &buffer[..bytes as usize]) {
                        callback(event);
                    }
                }
            })
            .context("spawn ReadDirectoryChangesW observer")?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for DirectoryObserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Do not join a potentially blocked synchronous ReadDirectoryChangesW
        // call.  The handle is closed by the thread when it exits.
        let _ = self.thread.take();
    }
}

fn parse_directory_events(root: &Path, buffer: &[u8]) -> Vec<DirectoryEvent> {
    let mut events = Vec::new();
    let mut offset = 0usize;
    while offset + size_of::<FileNotifyInformationHeader>() <= buffer.len() {
        let header = unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .add(offset)
                    .cast::<FileNotifyInformationHeader>(),
            )
        };
        let name_start = offset + size_of::<FileNotifyInformationHeader>();
        let name_len = header.file_name_length as usize;
        if name_len % 2 != 0 || name_start.saturating_add(name_len) > buffer.len() {
            break;
        }
        let name = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().add(name_start).cast::<u16>(), name_len / 2)
        };
        if let Ok(name) = String::from_utf16(name) {
            let action = match header.action {
                1 => DirectoryAction::Created,
                2 => DirectoryAction::Removed,
                3 => DirectoryAction::Modified,
                4 => DirectoryAction::RenamedOldName,
                5 => DirectoryAction::RenamedNewName,
                other => DirectoryAction::Unknown(other),
            };
            events.push(DirectoryEvent {
                root: root.to_path_buf(),
                relative_path: PathBuf::from(name),
                action,
            });
        }
        if header.next_entry_offset == 0 {
            break;
        }
        let next = header.next_entry_offset as usize;
        if next < size_of::<FileNotifyInformationHeader>() {
            break;
        }
        offset = offset.saturating_add(next);
    }
    events
}

/// Poll a process handle for exit without claiming complete process tracing.
pub fn process_exited(process_id: u32, timeout: Duration) -> Result<bool> {
    let process = unsafe {
        OpenProcess(
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            process_id,
        )
    };
    if process.is_null() || process == INVALID_HANDLE_VALUE {
        bail!("OpenProcess for polling failed with {}", unsafe {
            GetLastError()
        });
    }
    let milliseconds = timeout.as_millis().min(Dword::MAX as u128) as Dword;
    let result = unsafe { WaitForSingleObject(process, milliseconds) };
    unsafe {
        let _ = CloseHandle(process);
    }
    match result {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        other => bail!("WaitForSingleObject failed with status 0x{other:08x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_parser_uses_honest_actions() {
        let mut buffer = Vec::new();
        let name: Vec<u16> = "file.txt".encode_utf16().collect();
        let record_size = size_of::<FileNotifyInformationHeader>() + name.len() * 2;
        buffer.resize(record_size, 0);
        let header = FileNotifyInformationHeader {
            next_entry_offset: 0,
            action: 3,
            file_name_length: (name.len() * 2) as Dword,
        };
        unsafe {
            std::ptr::write_unaligned(
                buffer.as_mut_ptr().cast::<FileNotifyInformationHeader>(),
                header,
            );
            copy_nonoverlapping(
                name.as_ptr().cast::<u8>(),
                buffer
                    .as_mut_ptr()
                    .add(size_of::<FileNotifyInformationHeader>()),
                name.len() * 2,
            );
        }
        let events = parse_directory_events(Path::new("C:\\root"), &buffer);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, DirectoryAction::Modified);
        assert_eq!(events[0].relative_path, PathBuf::from("file.txt"));
    }
}
