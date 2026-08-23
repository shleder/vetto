//! Optional Endpoint Security integration.
//!
//! Endpoint Security is not a drop-in replacement for Seatbelt and is never
//! treated as the enforcement backend here. Apple requires the
//! `com.apple.developer.endpoint-security.client` entitlement, TCC approval,
//! and (on supported macOS versions) a privileged client. The feature below
//! dynamically checks the framework/symbols and the signed entitlements. If
//! those gates are not all present, vetto keeps the FSEvents observation path
//! and reports the exact fallback instead of claiming an ES feed.

use std::ffi::{c_char, c_void, CString};
use std::path::Path;
use std::process::Command;

#[cfg(feature = "endpoint-security")]
use std::sync::atomic::{AtomicBool, Ordering};

use crate::events::bus::EventBus;
use crate::events::types::{now, Event};

const RTLD_LAZY: i32 = 0x1;
const RTLD_LOCAL: i32 = 0x4;
#[cfg(feature = "endpoint-security")]
const ES_NEW_CLIENT_SUCCESS: u32 = 0;
#[cfg(feature = "endpoint-security")]
const ES_RETURN_SUCCESS: u32 = 0;
const ES_EVENT_TYPE_NOTIFY_EXEC: u32 = 9;
const ES_EVENT_TYPE_NOTIFY_OPEN: u32 = 10;

#[cfg(feature = "endpoint-security")]
static CLIENT_ACTIVE: AtomicBool = AtomicBool::new(false);

#[link(name = "System")]
extern "C" {
    fn dlopen(path: *const c_char, mode: i32) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// Runtime state exposed to `doctor` and integrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSecurityCapabilities {
    pub feature_enabled: bool,
    pub framework_available: bool,
    pub new_client_symbol: bool,
    pub subscribe_symbol: bool,
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
            && self.delete_client_symbol
            && self.entitlement_present
            && self.privileged
    }
}

/// Probe framework exports and signed entitlement state without creating an ES
/// client or modifying TCC/privilege state.
pub fn capabilities() -> EndpointSecurityCapabilities {
    let feature_enabled = cfg!(feature = "endpoint-security");
    // Keep the framework probe behind the compile-time opt-in as well. A
    // default build should not even load EndpointSecurity.framework merely to
    // report that the optional integration is disabled.
    let framework = if feature_enabled {
        framework_handle()
    } else {
        None
    };
    let (new_client, subscribe, delete_client) = match framework {
        Some(handle) => (
            symbol(handle, "es_new_client"),
            symbol(handle, "es_subscribe"),
            symbol(handle, "es_delete_client"),
        ),
        None => (false, false, false),
    };
    let entitlement_present = feature_enabled && endpoint_security_entitlement_present();
    // Apple reports a non-privileged caller as an ES client creation failure;
    // detect the obvious case up front and never attempt hidden elevation.
    let privileged = feature_enabled && unsafe { libc::geteuid() == 0 };
    let reason = if !feature_enabled {
        "feature endpoint-security is disabled; FSEvents remains the observation feed".to_string()
    } else if framework.is_none() {
        "EndpointSecurity.framework is unavailable on this host".to_string()
    } else if !(new_client && subscribe && delete_client) {
        "EndpointSecurity symbols are incomplete; no client will be created".to_string()
    } else if !entitlement_present {
        "signed binary does not advertise com.apple.developer.endpoint-security.client; Apple entitlement is required"
            .to_string()
    } else if !privileged {
        "process is not running with the privilege Endpoint Security requires; no elevation is attempted"
            .to_string()
    } else {
        "framework, symbols, and entitlement appear present; TCC/root gates are checked only when a client is created"
            .to_string()
    };
    EndpointSecurityCapabilities {
        feature_enabled,
        framework_available: framework.is_some(),
        new_client_symbol: new_client,
        subscribe_symbol: subscribe,
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
        "Endpoint Security: {}; feature={}, framework={}, entitlement={}, privileged={}, client-active={} (not an enforcement boundary)",
        caps.reason,
        yes_no(caps.feature_enabled),
        yes_no(caps.framework_available),
        yes_no(caps.entitlement_present),
        yes_no(caps.privileged),
        yes_no(caps.client_active),
    )
}

/// Try to create an optional notify-only client.  This function is intentionally
/// explicit and is not called by the Seatbelt backend automatically: an
/// entitled ES client may require root/TCC approval and a user must opt in via
/// the feature. It publishes opaque, honestly-labelled notifications because
/// decoding `es_message_t` is SDK-version sensitive; FSEvents remains the
/// path-labelled change feed.
pub fn spawn_if_available(bus: &EventBus) -> Option<String> {
    let caps = capabilities();
    if !caps.runtime_ready() {
        return Some(format!(
            "Endpoint Security inactive: {} (FSEvents change feed remains observation-only)",
            caps.reason
        ));
    }

    #[cfg(feature = "endpoint-security")]
    {
        match create_notify_client(bus.clone()) {
            Ok(()) => Some(
                "Endpoint Security notify client active (opaque event labels; Seatbelt remains enforcement)"
                    .to_string(),
            ),
            Err(error) => Some(format!(
                "Endpoint Security client unavailable: {error} (FSEvents change feed remains observation-only)"
            )),
        }
    }
    #[cfg(not(feature = "endpoint-security"))]
    {
        let _ = bus;
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
    // SAFETY: static NUL-terminated path and dlopen flags; the returned handle
    // is intentionally kept loaded for the process lifetime.
    let handle = unsafe { dlopen(path.as_ptr(), RTLD_LAZY | RTLD_LOCAL) };
    (!handle.is_null()).then_some(handle)
}

fn symbol(handle: *mut c_void, name: &str) -> bool {
    let name = match CString::new(name) {
        Ok(name) => name,
        Err(_) => return false,
    };
    // SAFETY: handle came from dlopen and the name is a valid C string.
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
    // `codesign --display --entitlements :-` emits plist XML for normal
    // signatures. Require a true value so a declared false entitlement does
    // not count as capability.
    let value = text.split_once(key).map(|(_, rest)| rest).unwrap_or("");
    value.contains("<true/>") || value.contains("<true />") || value.contains(">true<")
}

#[cfg(feature = "endpoint-security")]
fn create_notify_client(bus: EventBus) -> anyhow::Result<()> {
    use block2::RcBlock;

    type EsClient = *mut c_void;
    type NewClient = unsafe extern "C" fn(*mut EsClient, *const c_void) -> u32;
    type Subscribe = unsafe extern "C" fn(EsClient, *const u32, u32) -> u32;
    type DeleteClient = unsafe extern "C" fn(EsClient) -> u32;

    let handle = framework_handle()
        .ok_or_else(|| anyhow::anyhow!("EndpointSecurity.framework not loaded"))?;
    // SAFETY: symbol pointers are checked above and cast to the documented C
    // signatures for this feature-gated runtime path.
    let new_client: NewClient =
        unsafe { std::mem::transmute(symbol_address(handle, "es_new_client")?) };
    let subscribe: Subscribe =
        unsafe { std::mem::transmute(symbol_address(handle, "es_subscribe")?) };
    let delete_client: DeleteClient =
        unsafe { std::mem::transmute(symbol_address(handle, "es_delete_client")?) };

    let handler: RcBlock<dyn Fn(EsClient, *const c_void)> =
        RcBlock::new(move |_client: EsClient, _message: *const c_void| {
            bus.publish(Event::Notice {
                ts: now(),
                message:
                    "endpoint-security notify event (opaque message; not a FileObserved read label)"
                        .to_string(),
            });
        });
    let handler_ptr = RcBlock::into_raw(handler);
    let mut client: EsClient = std::ptr::null_mut();
    // SAFETY: `handler_ptr` is a copied Objective-C block with the documented
    // `(es_client_t *, const es_message_t *)` shape; client points to local
    // output storage. The block is intentionally leaked for this process-wide
    // async client lifetime.
    let result = unsafe { new_client(&mut client, handler_ptr.cast()) };
    if result != ES_NEW_CLIENT_SUCCESS || client.is_null() {
        // SAFETY: on failure Endpoint Security did not take ownership of the
        // block pointer; reconstructing it drops the +1 reference.
        unsafe {
            let _ = RcBlock::<dyn Fn(EsClient, *const c_void)>::from_raw(handler_ptr);
        }
        return Err(anyhow::anyhow!("es_new_client returned {result}"));
    }
    let events = [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_OPEN];
    // SAFETY: client is live and events points to two valid notification enum
    // values for the current Endpoint Security ABI.
    let result = unsafe { subscribe(client, events.as_ptr(), events.len() as u32) };
    if result != ES_RETURN_SUCCESS {
        // SAFETY: client was created successfully and must be deleted on the
        // same thread before dropping the retained handler block.
        unsafe { delete_client(client) };
        // SAFETY: the raw pointer still owns the +1 block reference because
        // Endpoint Security rejected the subscription.
        unsafe {
            let _ = RcBlock::<dyn Fn(EsClient, *const c_void)>::from_raw(handler_ptr);
        }
        return Err(anyhow::anyhow!("es_subscribe returned {result}"));
    }
    CLIENT_ACTIVE.store(true, Ordering::Release);
    Ok(())
}

#[cfg(feature = "endpoint-security")]
fn symbol_address(handle: *mut c_void, name: &str) -> anyhow::Result<*mut c_void> {
    let name = CString::new(name).map_err(|_| anyhow::anyhow!("invalid symbol name"))?;
    // SAFETY: handle came from dlopen and name is NUL-terminated.
    let ptr = unsafe { dlsym(handle, name.as_ptr()) };
    if ptr.is_null() {
        Err(anyhow::anyhow!(
            "EndpointSecurity symbol {name:?} is unavailable"
        ))
    } else {
        Ok(ptr)
    }
}

#[allow(dead_code)]
fn _path_is_absolute(path: &Path) -> bool {
    path.is_absolute()
}
