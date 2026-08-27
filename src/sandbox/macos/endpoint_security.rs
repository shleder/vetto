//! Endpoint Security AUTH and NOTIFY integration.
//!
//! Apple requires the `com.apple.developer.endpoint-security.client` entitlement,
//! TCC approval, and root privileges.
//!
//! When available and opted-in via `--features endpoint-security`, this module
//! registers an active AUTH client subscribing to `AUTH_EXEC`, `AUTH_OPEN`,
//! `AUTH_UNLINK`, and `AUTH_RENAME` events, responding within kernel deadlines.
//! If gates are not met, vetto falls back to Seatbelt-only enforcement.

use std::ffi::{c_char, c_void, CString};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

#[cfg(feature = "endpoint-security")]
use std::sync::atomic::{AtomicBool, Ordering};

use crate::events::bus::EventBus;
use crate::events::types::{now, Event};
use crate::policy::Policy;

const RTLD_LAZY: i32 = 0x1;
const RTLD_LOCAL: i32 = 0x4;

#[cfg(feature = "endpoint-security")]
const ES_NEW_CLIENT_SUCCESS: u32 = 0;
#[cfg(feature = "endpoint-security")]
const ES_RETURN_SUCCESS: u32 = 0;

pub const ES_ACTION_TYPE_AUTH: u32 = 0;
pub const ES_ACTION_TYPE_NOTIFY: u32 = 1;

pub const ES_AUTH_RESULT_ALLOW: u32 = 0;
pub const ES_AUTH_RESULT_DENY: u32 = 1;

pub const ES_EVENT_TYPE_AUTH_EXEC: u32 = 0;
pub const ES_EVENT_TYPE_AUTH_OPEN: u32 = 1;
pub const ES_EVENT_TYPE_AUTH_RENAME: u32 = 6;
pub const ES_EVENT_TYPE_AUTH_UNLINK: u32 = 7;
pub const ES_EVENT_TYPE_NOTIFY_EXEC: u32 = 9;
pub const ES_EVENT_TYPE_NOTIFY_OPEN: u32 = 10;
pub const ES_EVENT_TYPE_NOTIFY_RENAME: u32 = 15;
pub const ES_EVENT_TYPE_NOTIFY_UNLINK: u32 = 16;

#[cfg(feature = "endpoint-security")]
static CLIENT_ACTIVE: AtomicBool = AtomicBool::new(false);

#[link(name = "System")]
extern "C" {
    fn dlopen(path: *const c_char, mode: i32) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct es_string_token_t {
    pub length: usize,
    pub data: *const libc::c_char,
}

impl es_string_token_t {
    pub fn as_str(&self) -> Option<&str> {
        if self.data.is_null() || self.length == 0 {
            return None;
        }
        unsafe {
            let slice = std::slice::from_raw_parts(self.data as *const u8, self.length);
            std::str::from_utf8(slice).ok()
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct es_file_t {
    pub path: es_string_token_t,
    pub path_truncated: bool,
    pub stat: libc::stat,
}

#[repr(C)]
#[derive(Debug)]
pub struct es_process_t {
    pub audit_token: [u32; 8],
    pub ppid: libc::pid_t,
    pub original_ppid: libc::pid_t,
    pub group_id: libc::pid_t,
    pub session_id: libc::pid_t,
    pub codesigning_flags: u32,
    pub is_platform_binary: bool,
    pub is_es_client: bool,
    pub cdhash: [u8; 20],
    pub signing_id: es_string_token_t,
    pub team_id: es_string_token_t,
    pub executable: *mut es_file_t,
    pub tty: *mut es_file_t,
    pub start_time: libc::timeval,
}

#[repr(C)]
#[derive(Debug)]
pub struct es_event_exec_t {
    pub target: *mut es_process_t,
    pub script: *mut es_file_t,
    pub cwd: *mut es_file_t,
    pub last_fd: libc::c_int,
}

#[repr(C)]
#[derive(Debug)]
pub struct es_event_open_t {
    pub fflag: i32,
    pub file: *mut es_file_t,
    pub reserved: [u8; 64],
}

#[repr(C)]
#[derive(Debug)]
pub struct es_event_unlink_t {
    pub target: *mut es_file_t,
    pub parent_dir: *mut es_file_t,
    pub reserved: [u8; 64],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct es_rename_destination_new_path_t {
    pub dir: *mut es_file_t,
    pub filename: es_string_token_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union es_rename_destination_t {
    pub existing_file: *mut es_file_t,
    pub new_path: es_rename_destination_new_path_t,
}

#[repr(C)]
pub struct es_event_rename_t {
    pub destination_type: u32,
    pub destination: es_rename_destination_t,
    pub source: *mut es_file_t,
    pub reserved: [u8; 64],
}

#[repr(C)]
pub union es_events_t {
    pub exec: std::mem::ManuallyDrop<es_event_exec_t>,
    pub open: std::mem::ManuallyDrop<es_event_open_t>,
    pub unlink: std::mem::ManuallyDrop<es_event_unlink_t>,
    pub rename: std::mem::ManuallyDrop<es_event_rename_t>,
}

#[repr(C)]
pub union es_action_t {
    pub auth: u32,
    pub notify: u32,
}

#[repr(C)]
pub struct es_message_t {
    pub version: u32,
    pub time: libc::timespec,
    pub mach_time: u64,
    pub event_type: u32,
    pub action_type: u32,
    pub action: es_action_t,
    pub event: es_events_t,
    pub thread: *mut c_void,
    pub global_seq_num: u64,
    pub opaque: [u8; 64],
    pub process: *mut es_process_t,
}

/// Runtime state exposed to `doctor` and integrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSecurityCapabilities {
    pub feature_enabled: bool,
    pub framework_available: bool,
    pub new_client_symbol: bool,
    pub subscribe_symbol: bool,
    pub respond_auth_symbol: bool,
    pub delete_client_symbol: bool,
    pub entitlement_present: bool,
    pub privileged: bool,
    pub client_active: bool,
    pub reason: String,
}

impl EndpointSecurityCapabilities {
    pub fn runtime_ready(&self) -> bool {
        self.feature_enabled
            && self.framework_available
            && self.new_client_symbol
            && self.subscribe_symbol
            && self.respond_auth_symbol
            && self.delete_client_symbol
            && self.entitlement_present
            && self.privileged
    }
}

/// Probe framework exports and signed entitlement state without creating an ES
/// client or modifying TCC/privilege state.
pub fn capabilities() -> EndpointSecurityCapabilities {
    let feature_enabled = cfg!(feature = "endpoint-security");
    let framework = if feature_enabled {
        framework_handle()
    } else {
        None
    };
    let (new_client, subscribe, respond_auth, delete_client) = match framework {
        Some(handle) => (
            symbol(handle, "es_new_client"),
            symbol(handle, "es_subscribe"),
            symbol(handle, "es_respond_auth_result"),
            symbol(handle, "es_delete_client"),
        ),
        None => (false, false, false, false),
    };
    let entitlement_present = feature_enabled && endpoint_security_entitlement_present();
    let privileged = feature_enabled && unsafe { libc::geteuid() == 0 };
    let reason = if !feature_enabled {
        "feature endpoint-security is disabled; Seatbelt remains the enforcement boundary"
            .to_string()
    } else if framework.is_none() {
        "EndpointSecurity.framework is unavailable on this host".to_string()
    } else if !(new_client && subscribe && respond_auth && delete_client) {
        "EndpointSecurity symbols are incomplete; no client will be created".to_string()
    } else if !entitlement_present {
        "signed binary does not advertise com.apple.developer.endpoint-security.client; Apple entitlement is required"
            .to_string()
    } else if !privileged {
        "process is not running with root privilege that Endpoint Security requires".to_string()
    } else {
        "framework, symbols, and entitlement are verified; AUTH engine ready".to_string()
    };
    EndpointSecurityCapabilities {
        feature_enabled,
        framework_available: framework.is_some(),
        new_client_symbol: new_client,
        subscribe_symbol: subscribe,
        respond_auth_symbol: respond_auth,
        delete_client_symbol: delete_client,
        entitlement_present,
        privileged,
        client_active: endpoint_security_client_active(),
        reason,
    }
}

/// Human-readable capability line for doctor/statusline/report wiring.
pub fn status() -> String {
    let caps = capabilities();
    format!(
        "Endpoint Security: {}; feature={}, framework={}, entitlement={}, privileged={}, client-active={}",
        caps.reason,
        yes_no(caps.feature_enabled),
        yes_no(caps.framework_available),
        yes_no(caps.entitlement_present),
        yes_no(caps.privileged),
        yes_no(caps.client_active),
    )
}

/// Spawn the Endpoint Security engine if runtime gates are satisfied.
pub fn spawn_if_available(bus: &EventBus) -> Option<String> {
    spawn_auth_engine(bus, Arc::new(Policy::default()))
}

/// Spawn the Endpoint Security AUTH engine with active path policy enforcement.
pub fn spawn_auth_engine(bus: &EventBus, policy: Arc<Policy>) -> Option<String> {
    let caps = capabilities();
    if !caps.runtime_ready() {
        return Some(format!(
            "Endpoint Security inactive: {} (Seatbelt remains primary enforcement)",
            caps.reason
        ));
    }

    #[cfg(feature = "endpoint-security")]
    {
        match create_auth_client(bus.clone(), policy) {
            Ok(()) => Some("Endpoint Security AUTH client active".to_string()),
            Err(error) => Some(format!(
                "Endpoint Security client unavailable: {error} (Seatbelt remains enforcement)"
            )),
        }
    }
    #[cfg(not(feature = "endpoint-security"))]
    {
        let _ = (bus, policy);
        Some("Endpoint Security inactive: compile feature is disabled".to_string())
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(feature = "endpoint-security")]
fn endpoint_security_client_active() -> bool {
    CLIENT_ACTIVE.load(Ordering::Acquire)
}

#[cfg(not(feature = "endpoint-security"))]
fn endpoint_security_client_active() -> bool {
    false
}

fn framework_handle() -> Option<*mut c_void> {
    let path =
        CString::new("/System/Library/Frameworks/EndpointSecurity.framework/EndpointSecurity")
            .expect("static framework path");
    let handle = unsafe { dlopen(path.as_ptr(), RTLD_LAZY | RTLD_LOCAL) };
    (!handle.is_null()).then_some(handle)
}

fn symbol(handle: *mut c_void, name: &str) -> bool {
    let name = match CString::new(name) {
        Ok(name) => name,
        Err(_) => return false,
    };
    !unsafe { dlsym(handle, name.as_ptr()) }.is_null()
}

fn endpoint_security_entitlement_present() -> bool {
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };
    let output = match Command::new("/usr/bin/codesign")
        .args(["--display", "--entitlements", ":-"])
        .arg(&executable)
        .output()
    {
        Ok(output) => output,
        Err(_) => return false,
    };
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let key = "com.apple.developer.endpoint-security.client";
    if !text.contains(key) {
        return false;
    }
    let value = text.split_once(key).map(|(_, rest)| rest).unwrap_or("");
    value.contains("<true/>") || value.contains("<true />") || value.contains(">true<")
}

#[cfg(feature = "endpoint-security")]
fn create_auth_client(bus: EventBus, policy: Arc<Policy>) -> anyhow::Result<()> {
    use block2::RcBlock;

    type EsClient = *mut c_void;
    type NewClient = unsafe extern "C" fn(*mut EsClient, *const c_void) -> u32;
    type Subscribe = unsafe extern "C" fn(EsClient, *const u32, u32) -> u32;
    type RespondAuth = unsafe extern "C" fn(EsClient, *const es_message_t, u32, bool) -> u32;
    type DeleteClient = unsafe extern "C" fn(EsClient) -> u32;

    let handle = framework_handle()
        .ok_or_else(|| anyhow::anyhow!("EndpointSecurity.framework not loaded"))?;
    let new_client: NewClient =
        unsafe { std::mem::transmute(symbol_address(handle, "es_new_client")?) };
    let subscribe: Subscribe =
        unsafe { std::mem::transmute(symbol_address(handle, "es_subscribe")?) };
    let respond_auth: RespondAuth =
        unsafe { std::mem::transmute(symbol_address(handle, "es_respond_auth_result")?) };
    let delete_client: DeleteClient =
        unsafe { std::mem::transmute(symbol_address(handle, "es_delete_client")?) };

    let handler_policy = Arc::clone(&policy);
    let handler_bus = bus.clone();

    let handler: RcBlock<dyn Fn(EsClient, *const c_void)> =
        RcBlock::new(move |client: EsClient, raw_message: *const c_void| {
            if raw_message.is_null() {
                return;
            }
            let message = raw_message.cast::<es_message_t>();
            let msg = unsafe { &*message };
            if msg.action_type == ES_ACTION_TYPE_AUTH {
                let (auth_result, target_path) = evaluate_auth_event(msg, &handler_policy);
                if auth_result == ES_AUTH_RESULT_DENY {
                    if let Some(path) = target_path {
                        handler_bus.publish(Event::BlockedAttempt {
                            ts: now(),
                            pid: unsafe { (*msg.process).ppid as u32 },
                            comm: "endpoint-security".to_string(),
                            path,
                            source: "endpoint-security".to_string(),
                        });
                    }
                }
                // Respond immediately before kernel timeout
                unsafe {
                    respond_auth(
                        client,
                        message,
                        auth_result,
                        auth_result == ES_AUTH_RESULT_ALLOW,
                    );
                }
            } else {
                handler_bus.publish(Event::Notice {
                    ts: now(),
                    message: format!("endpoint-security event type {}", msg.event_type),
                });
            }
        });

    let handler_ptr = RcBlock::into_raw(handler);
    let mut client: EsClient = std::ptr::null_mut();
    let result = unsafe { new_client(&mut client, handler_ptr.cast()) };
    if result != ES_NEW_CLIENT_SUCCESS || client.is_null() {
        unsafe {
            let _ = RcBlock::<dyn Fn(EsClient, *const c_void)>::from_raw(handler_ptr);
        }
        return Err(anyhow::anyhow!("es_new_client returned {result}"));
    }

    let events = [
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_RENAME,
    ];
    let result = unsafe { subscribe(client, events.as_ptr(), events.len() as u32) };
    if result != ES_RETURN_SUCCESS {
        unsafe { delete_client(client) };
        unsafe {
            let _ = RcBlock::<dyn Fn(EsClient, *const c_void)>::from_raw(handler_ptr);
        }
        return Err(anyhow::anyhow!("es_subscribe returned {result}"));
    }
    CLIENT_ACTIVE.store(true, Ordering::Release);
    Ok(())
}

#[cfg(feature = "endpoint-security")]
fn evaluate_auth_event(msg: &es_message_t, policy: &Policy) -> (u32, Option<String>) {
    match msg.event_type {
        ES_EVENT_TYPE_AUTH_OPEN => {
            let open_event = unsafe { &msg.event.open };
            if !open_event.file.is_null() {
                let file = unsafe { &*open_event.file };
                if let Some(path_str) = file.path.as_str() {
                    let path = Path::new(path_str);
                    let is_write = (open_event.fflag
                        & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC))
                        != 0;
                    if policy
                        .deny_resolved
                        .iter()
                        .any(|d| path.starts_with(&d.path))
                    {
                        return (ES_AUTH_RESULT_DENY, Some(path_str.to_string()));
                    }
                    if is_write && !policy.in_write_scope(path) {
                        return (ES_AUTH_RESULT_DENY, Some(path_str.to_string()));
                    }
                    if !is_write && !policy.in_read_scope(path) {
                        return (ES_AUTH_RESULT_DENY, Some(path_str.to_string()));
                    }
                    return (ES_AUTH_RESULT_ALLOW, Some(path_str.to_string()));
                }
            }
            (ES_AUTH_RESULT_ALLOW, None)
        }
        ES_EVENT_TYPE_AUTH_UNLINK => {
            let unlink_event = unsafe { &msg.event.unlink };
            if !unlink_event.target.is_null() {
                let file = unsafe { &*unlink_event.target };
                if let Some(path_str) = file.path.as_str() {
                    let path = Path::new(path_str);
                    if policy
                        .deny_resolved
                        .iter()
                        .any(|d| path.starts_with(&d.path))
                    {
                        return (ES_AUTH_RESULT_DENY, Some(path_str.to_string()));
                    }
                    if !policy.in_write_scope(path) {
                        return (ES_AUTH_RESULT_DENY, Some(path_str.to_string()));
                    }
                    return (ES_AUTH_RESULT_ALLOW, Some(path_str.to_string()));
                }
            }
            (ES_AUTH_RESULT_ALLOW, None)
        }
        ES_EVENT_TYPE_AUTH_EXEC => (ES_AUTH_RESULT_ALLOW, None),
        ES_EVENT_TYPE_AUTH_RENAME => (ES_AUTH_RESULT_ALLOW, None),
        _ => (ES_AUTH_RESULT_ALLOW, None),
    }
}

#[cfg(feature = "endpoint-security")]
fn symbol_address(handle: *mut c_void, name: &str) -> anyhow::Result<*mut c_void> {
    let name = CString::new(name).map_err(|_| anyhow::anyhow!("invalid symbol name"))?;
    let ptr = unsafe { dlsym(handle, name.as_ptr()) };
    if ptr.is_null() {
        Err(anyhow::anyhow!(
            "EndpointSecurity symbol {name:?} is unavailable"
        ))
    } else {
        Ok(ptr)
    }
}
