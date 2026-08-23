//! Opt-in Windows Filtering Platform policy backend.
//!
//! This module is intentionally narrower than a general Windows Firewall
//! manager.  It uses a dynamic WFP session, a private sub-layer, and
//! process-image plus pinned TCP/IP conditions.  WFP's user-mode ALE layers do
//! not expose a reliable process-ID condition, so `install_for_process` is
//! fail-closed; callers that explicitly accept executable-image scope can use
//! `install_for_image`.  Domains are never handed to WFP.  A broker must
//! resolve them and provide pinned `SocketAddr` values.
//!
//! No function in this file requests elevation, starts a broker, writes a
//! persistent firewall rule, or invokes `netsh`.  All objects are dynamic and
//! are removed on lease drop (and automatically when the WFP session closes).

use std::ffi::c_void;
use std::mem::size_of;
#[cfg(test)]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

type Handle = *mut c_void;
type Dword = u32;
type Bool = i32;

const ERROR_SUCCESS: Dword = 0;
const RPC_C_AUTHN_DEFAULT: Dword = 0xffff_ffff;
const RPC_C_AUTHN_WINNT: Dword = 10;
const PROCESS_QUERY_LIMITED_INFORMATION: Dword = 0x1000;
const TOKEN_QUERY: Dword = 0x0008;
const TOKEN_ELEVATION: Dword = 20;
const SECURITY_MAX_SID_SIZE: Dword = 68;
const WIN_BUILTIN_ADMINISTRATORS_SID: Dword = 26;
const FWP_EMPTY: Dword = 0;
const FWP_UINT8: Dword = 1;
const FWP_UINT16: Dword = 2;
const FWP_UINT32: Dword = 3;
const FWP_UINT64: Dword = 4;
const FWP_BYTE_ARRAY16_TYPE: Dword = 11;
const FWP_BYTE_BLOB_TYPE: Dword = 12;
const FWP_MATCH_EQUAL: Dword = 0;
const FWP_ACTION_BLOCK: Dword = 0x0000_0001;
const FWP_ACTION_PERMIT: Dword = 0x0000_0002;
const FWPM_SESSION_FLAG_DYNAMIC: Dword = 0x0000_0001;
const FWP_FILTER_FLAG_NONE: Dword = 0;
const FWPM_SUBLAYER_FLAG_NONE: Dword = 0;

static NEXT_SCOPE: AtomicU64 = AtomicU64::new(1);

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl Guid {
    const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }
}

// Built-in WFP identifiers from fwpmu.h.  They are values, not provider
// objects; no system object is changed by holding these constants.
const FWPM_LAYER_ALE_AUTH_CONNECT_V4: Guid = Guid::new(
    0xc38d57d1,
    0x05a7,
    0x4c33,
    [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
);
const FWPM_LAYER_ALE_AUTH_CONNECT_V6: Guid = Guid::new(
    0x4a72393b,
    0x319f,
    0x44bc,
    [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
);
const FWPM_CONDITION_ALE_APP_ID: Guid = Guid::new(
    0xd78e1e87,
    0x8644,
    0x4ea5,
    [0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71],
);
const FWPM_CONDITION_IP_REMOTE_ADDRESS_V4: Guid = Guid::new(
    0x1febb610,
    0x3bcc,
    0x45e1,
    [0xbc, 0x36, 0x2e, 0x06, 0x7e, 0x2c, 0xb1, 0x86],
);
const FWPM_CONDITION_IP_REMOTE_ADDRESS_V6: Guid = Guid::new(
    0x246e1d8c,
    0x8bee,
    0x4018,
    [0x9b, 0x98, 0x31, 0xd4, 0x58, 0x2f, 0x33, 0x61],
);
const FWPM_CONDITION_IP_REMOTE_PORT: Guid = Guid::new(
    0xc35a604d,
    0xd22b,
    0x4e1a,
    [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b],
);
const FWPM_CONDITION_IP_PROTOCOL: Guid = Guid::new(
    0x3971ef2b,
    0x623e,
    0x4f64,
    [0x94, 0x9c, 0x1d, 0x84, 0xf3, 0xc5, 0x71, 0xe8],
);

#[repr(C)]
struct FwpByteBlob {
    size: Dword,
    data: *mut u8,
}

#[repr(C)]
struct FwpByteArray16 {
    byte_array16: [u8; 16],
}

#[repr(C)]
union FwpValueUnion {
    uint8: u8,
    uint16: u16,
    uint32: u32,
    uint64: u64,
    byte_array16: *mut FwpByteArray16,
    byte_blob: *mut FwpByteBlob,
}

#[repr(C)]
struct FwpValue {
    type_: Dword,
    value: FwpValueUnion,
}

#[repr(C)]
union FwpConditionUnion {
    uint8: u8,
    uint16: u16,
    uint32: u32,
    uint64: u64,
    byte_array16: *mut FwpByteArray16,
    byte_blob: *mut FwpByteBlob,
}

#[repr(C)]
struct FwpConditionValue {
    type_: Dword,
    value: FwpConditionUnion,
}

#[repr(C)]
struct FwpmDisplayData {
    name: *mut u16,
    description: *mut u16,
}

#[repr(C)]
struct FwpmSession {
    session_key: Guid,
    display_data: FwpmDisplayData,
    flags: Dword,
    txn_wait_timeout_in_msec: Dword,
    process_id: Dword,
    sid: *mut c_void,
    username: *mut u16,
    kernel_mode: Bool,
}

#[repr(C)]
struct FwpmSublayer {
    sub_layer_key: Guid,
    display_data: FwpmDisplayData,
    flags: Dword,
    provider_key: *mut Guid,
    provider_data: FwpByteBlob,
    weight: u16,
}

#[repr(C)]
struct FwpmFilterCondition {
    field_key: Guid,
    match_type: Dword,
    condition_value: FwpConditionValue,
}

#[repr(C)]
struct FwpmAction {
    type_: Dword,
    filter_type: Guid,
}

#[repr(C)]
union FwpmFilterContext {
    raw_context: u64,
    provider_context_key: Guid,
}

#[repr(C)]
struct FwpmFilter {
    filter_key: Guid,
    display_data: FwpmDisplayData,
    flags: Dword,
    provider_key: *mut Guid,
    provider_data: FwpByteBlob,
    layer_key: Guid,
    sub_layer_key: Guid,
    weight: FwpValue,
    num_filter_conditions: Dword,
    filter_condition: *mut FwpmFilterCondition,
    action: FwpmAction,
    context: FwpmFilterContext,
    reserved: *mut Guid,
    filter_id: u64,
    effective_weight: FwpValue,
}

#[link(name = "fwpuclnt")]
extern "system" {
    fn FwpmEngineOpen0(
        server_name: *const u16,
        authn_service: Dword,
        auth_identity: *const c_void,
        session: *const FwpmSession,
        engine_handle: *mut Handle,
    ) -> Dword;
    fn FwpmEngineClose0(engine_handle: Handle) -> Dword;
    fn FwpmTransactionBegin0(engine_handle: Handle, flags: Dword) -> Dword;
    fn FwpmTransactionCommit0(engine_handle: Handle) -> Dword;
    fn FwpmTransactionAbort0(engine_handle: Handle) -> Dword;
    fn FwpmSubLayerAdd0(
        engine_handle: Handle,
        sub_layer: *const FwpmSublayer,
        security_descriptor: *mut c_void,
    ) -> Dword;
    fn FwpmSubLayerDeleteByKey0(engine_handle: Handle, key: *const Guid) -> Dword;
    fn FwpmFilterAdd0(
        engine_handle: Handle,
        filter: *const FwpmFilter,
        security_descriptor: *mut c_void,
        id: *mut u64,
    ) -> Dword;
    fn FwpmFilterDeleteByKey0(engine_handle: Handle, key: *const Guid) -> Dword;
    fn FwpmFilterGetByKey0(
        engine_handle: Handle,
        key: *const Guid,
        filter: *mut *mut FwpmFilter,
    ) -> Dword;
    fn FwpmGetAppIdFromFileName0(file_name: *const u16, app_id: *mut *mut FwpByteBlob) -> Dword;
    fn FwpmFreeMemory0(memory: *mut *mut c_void) -> Dword;
}

#[repr(C)]
struct TokenElevation {
    token_is_elevated: Dword,
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: Handle, desired_access: Dword, token: *mut Handle) -> Bool;
    fn GetTokenInformation(
        token: Handle,
        information_class: Dword,
        information: *mut c_void,
        information_length: Dword,
        return_length: *mut Dword,
    ) -> Bool;
    fn CreateWellKnownSid(
        sid_type: Dword,
        domain_sid: *const c_void,
        sid: *mut c_void,
        sid_size: *mut Dword,
    ) -> Bool;
    fn CheckTokenMembership(
        token: Handle,
        sid_to_check: *const c_void,
        is_member: *mut Bool,
    ) -> Bool;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn OpenProcess(desired_access: Dword, inherit_handle: Bool, process_id: Dword) -> Handle;
    fn QueryFullProcessImageNameW(
        process: Handle,
        flags: Dword,
        exe_name: *mut u16,
        size: *mut Dword,
    ) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
    fn GetLastError() -> Dword;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    Off,
    Allowlist,
    Strict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl PinnedEndpoint {
    pub fn new(addr: IpAddr, port: u16) -> Result<Self> {
        if port == 0 || is_non_routable(addr) {
            bail!("WFP endpoint is unspecified, multicast, or otherwise invalid: {addr}:{port}");
        }
        Ok(Self { addr, port })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedPolicy {
    pub mode: NetworkMode,
    pub endpoints: Vec<PinnedEndpoint>,
    /// Optional loopback endpoint for a broker.  The broker must resolve and
    /// connect to external peers itself; no TLS interception is implied.
    pub broker_loopback: Option<PinnedEndpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallCapabilities {
    pub api_available: bool,
    pub engine_readable: bool,
    pub elevated_admin_token: bool,
    pub can_attempt_write: bool,
    pub process_id_scope: bool,
    pub note: String,
}

/// Probe WFP and token state without adding a filter or requesting elevation.
pub fn capabilities() -> FirewallCapabilities {
    let mut result = FirewallCapabilities {
        api_available: true,
        engine_readable: false,
        elevated_admin_token: false,
        can_attempt_write: false,
        process_id_scope: false,
        note: "WFP ALE exposes executable-image scope, not a reliable process-ID condition; use broker or explicit image scope".to_string(),
    };
    let mut engine = null_mut();
    let status =
        unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_DEFAULT, null(), null(), &mut engine) };
    if status == ERROR_SUCCESS && !engine.is_null() {
        result.engine_readable = true;
        unsafe {
            let _ = FwpmEngineClose0(engine);
        }
    } else {
        result.note =
            format!("WFP engine probe failed with status 0x{status:08x}; no policy was attempted");
    }
    // An elevated-admin probe is deliberately conservative.  WFP itself is
    // the authority; a positive token bit only permits an attempt and never
    // causes one here.  The actual write is checked transactionally below.
    result.elevated_admin_token = elevated_admin_token();
    result.can_attempt_write = result.engine_readable && result.elevated_admin_token;
    result
}

fn elevated_admin_token() -> bool {
    // This is a read-only token inspection.  It never calls ShellExecute,
    // runas, or any elevation broker.  A positive result only permits a
    // transactional WFP attempt; the attempt still has to succeed and pass
    // read-back before the lease is marked enforced.
    unsafe {
        let process = GetCurrentProcess();
        let mut token = null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 || token.is_null() {
            return false;
        }
        let mut elevation = TokenElevation {
            token_is_elevated: 0,
        };
        let mut returned = 0;
        let elevated = GetTokenInformation(
            token,
            TOKEN_ELEVATION,
            (&mut elevation as *mut TokenElevation).cast(),
            size_of::<TokenElevation>() as Dword,
            &mut returned,
        ) != 0
            && elevation.token_is_elevated != 0;
        let mut sid_storage = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut sid_size = SECURITY_MAX_SID_SIZE;
        let sid_ok = CreateWellKnownSid(
            WIN_BUILTIN_ADMINISTRATORS_SID,
            null(),
            sid_storage.as_mut_ptr().cast(),
            &mut sid_size,
        ) != 0;
        let mut member: Bool = 0;
        let member_ok = sid_ok
            && CheckTokenMembership(token, sid_storage.as_ptr().cast(), &mut member) != 0
            && member != 0;
        let _ = CloseHandle(token);
        elevated && member_ok
    }
}

/// Process-ID scoped rules cannot be safely expressed by the user-mode ALE
/// condition set.  Refuse rather than silently applying a rule to every
/// process with the same executable path.
pub fn install_for_process(_process_id: u32, _policy: &PinnedPolicy) -> Result<FirewallLease> {
    bail!(
        "WFP process-ID scope is unavailable in the supported ALE layers; refusing a broad image rule; use broker loopback or explicit install_for_image"
    )
}

/// Install a dynamic WFP policy scoped to an executable image.  This is an
/// explicit opt-in because every process using that image is covered for the
/// lifetime of the returned lease.
pub fn install_for_image(image_path: &str, policy: &PinnedPolicy) -> Result<FirewallLease> {
    if image_path.is_empty()
        || image_path.encode_utf16().any(|c| c == 0)
        || !Path::new(image_path).is_absolute()
    {
        bail!("image path must be absolute, non-empty, and NUL-free");
    }
    match &policy.mode {
        NetworkMode::Off => {
            return Ok(FirewallLease {
                engine: null_mut(),
                sublayer_key: None,
                filters: Vec::new(),
                enforced: false,
                scope: Scope::Inactive,
            });
        }
        NetworkMode::Allowlist | NetworkMode::Strict => {}
    }
    if policy.endpoints.is_empty() && policy.broker_loopback.is_none() {
        bail!(
            "allowlist/strict WFP policy requires at least one pinned endpoint or broker loopback"
        );
    }
    if policy.endpoints.len() > 1024 {
        bail!("WFP pinned endpoint list is too large");
    }
    let caps = capabilities();
    if !caps.engine_readable {
        bail!("WFP engine is not readable; refusing to attempt policy installation");
    }
    if !caps.elevated_admin_token {
        bail!("WFP policy installation requires an already-elevated administrator token; no elevation was requested");
    }
    if policy
        .endpoints
        .iter()
        .any(|endpoint| is_loopback(endpoint.addr))
    {
        bail!("loopback endpoints must be supplied through broker_loopback, not the external endpoint list");
    }
    let mut endpoints = policy.endpoints.clone();
    if let Some(broker) = &policy.broker_loopback {
        if !is_loopback(broker.addr) {
            bail!("broker endpoint must be loopback");
        }
        endpoints.push(broker.clone());
    }
    endpoints.sort_by_key(|endpoint| (endpoint.addr, endpoint.port));
    endpoints.dedup();
    for endpoint in &endpoints {
        if is_loopback(endpoint.addr) {
            if endpoint.port == 0 {
                bail!("broker endpoint port must be non-zero");
            }
        } else {
            PinnedEndpoint::new(endpoint.addr, endpoint.port)?;
        }
    }

    let scope_id = NEXT_SCOPE.fetch_add(1, Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let session_name = format!("vetto-wfp-{scope_id:016x}-{nonce:016x}");
    let sublayer_name = format!("vetto sandbox {scope_id:016x}");
    let description = "ephemeral fail-closed pinned endpoint policy";
    let mut session_wide = wide(&session_name)?;
    let mut sublayer_wide = wide(&sublayer_name)?;
    let mut description_wide = wide(description)?;
    let session_key = unique_guid(scope_id, nonce as u64);
    let sublayer_key = unique_guid(
        scope_id ^ 0x5a5a_5a5a_5a5a_5a5a,
        nonce.rotate_left(17) as u64,
    );
    let session = FwpmSession {
        session_key,
        display_data: FwpmDisplayData {
            name: session_wide.as_mut_ptr(),
            description: description_wide.as_mut_ptr(),
        },
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        txn_wait_timeout_in_msec: 5_000,
        process_id: 0,
        sid: null_mut(),
        username: null_mut(),
        kernel_mode: 0,
    };

    let mut engine: Handle = null_mut();
    let mut status =
        unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine) };
    if status != ERROR_SUCCESS || engine.is_null() {
        // Retry with the documented default authentication service only; this
        // is still a read/write attempt by the caller's current token and no
        // elevation is requested.
        if !engine.is_null() {
            unsafe {
                let _ = FwpmEngineClose0(engine);
            }
            engine = null_mut();
        }
        status =
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_DEFAULT, null(), &session, &mut engine) };
    }
    if status != ERROR_SUCCESS || engine.is_null() {
        bail!("FwpmEngineOpen0 failed with status 0x{status:08x}; no policy was installed");
    }

    let mut app_id: *mut FwpByteBlob = null_mut();
    let image_wide = wide(image_path)?;
    status = unsafe { FwpmGetAppIdFromFileName0(image_wide.as_ptr(), &mut app_id) };
    if status != ERROR_SUCCESS || app_id.is_null() {
        unsafe {
            let _ = FwpmEngineClose0(engine);
        }
        bail!("FwpmGetAppIdFromFileName0 failed with status 0x{status:08x}");
    }

    let mut lease = FirewallLease {
        engine,
        sublayer_key: Some(sublayer_key),
        filters: Vec::new(),
        enforced: false,
        scope: Scope::ExecutableImage {
            image_path: image_path.to_string(),
            session_name,
        },
    };

    let sublayer = FwpmSublayer {
        sub_layer_key: sublayer_key,
        display_data: FwpmDisplayData {
            name: sublayer_wide.as_mut_ptr(),
            description: description_wide.as_mut_ptr(),
        },
        flags: FWPM_SUBLAYER_FLAG_NONE,
        provider_key: null_mut(),
        provider_data: FwpByteBlob {
            size: 0,
            data: null_mut(),
        },
        weight: 0x7fff,
    };

    status = unsafe { FwpmTransactionBegin0(engine, 0) };
    if status == ERROR_SUCCESS {
        status = unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) };
    }
    if status != ERROR_SUCCESS {
        unsafe {
            let _ = FwpmTransactionAbort0(engine);
            free_blob(app_id);
        }
        // The session is dynamic, so closing it also removes a partially
        // created sublayer.  `lease` owns the handle and will close it.
        drop(lease);
        bail!("WFP sublayer transaction failed with status 0x{status:08x}");
    }

    let mut filter_conditions = Vec::new();
    // Default-deny is expressed as one terminating block per IP family,
    // scoped to the executable image.  Endpoint permits below carry a higher
    // weight and are the only exceptions.
    for layer in [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ] {
        let key = unique_guid(scope_id ^ layer.data1 as u64, layer.data2 as u64);
        filter_conditions.clear();
        filter_conditions.push(app_condition(app_id));
        let filter_name = format!("vetto default block {scope_id:016x} {key:?}");
        let mut filter_wide = wide(&filter_name)?;
        let filter = FwpmFilter {
            filter_key: key,
            display_data: FwpmDisplayData {
                name: filter_wide.as_mut_ptr(),
                description: description_wide.as_mut_ptr(),
            },
            flags: FWP_FILTER_FLAG_NONE,
            provider_key: null_mut(),
            provider_data: FwpByteBlob {
                size: 0,
                data: null_mut(),
            },
            layer_key: layer,
            sub_layer_key: sublayer_key,
            weight: FwpValue {
                type_: FWP_UINT64,
                value: FwpValueUnion { uint64: 1 },
            },
            num_filter_conditions: 1,
            filter_condition: filter_conditions.as_mut_ptr(),
            action: FwpmAction {
                type_: FWP_ACTION_BLOCK,
                filter_type: Guid::new(0, 0, 0, [0; 8]),
            },
            context: FwpmFilterContext { raw_context: 0 },
            reserved: null_mut(),
            filter_id: 0,
            effective_weight: FwpValue {
                type_: FWP_EMPTY,
                value: FwpValueUnion { uint8: 0 },
            },
        };
        status = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), null_mut()) };
        if status != ERROR_SUCCESS {
            break;
        }
        lease.filters.push((key, FWP_ACTION_BLOCK));
    }
    for endpoint in &endpoints {
        if status != ERROR_SUCCESS {
            break;
        }
        let key = unique_guid(scope_id ^ endpoint.port as u64, endpoint_hash(endpoint));
        filter_conditions.clear();
        filter_conditions.push(app_condition(app_id));
        let address_storage;
        let address_condition = match endpoint.addr {
            IpAddr::V4(address) => {
                address_storage = FwpByteArray16 {
                    byte_array16: [0; 16],
                };
                let value = FwpConditionValue {
                    type_: FWP_UINT32,
                    value: FwpConditionUnion {
                        uint32: u32::from_be_bytes(address.octets()),
                    },
                };
                FwpmFilterCondition {
                    field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS_V4,
                    match_type: FWP_MATCH_EQUAL,
                    condition_value: value,
                }
            }
            IpAddr::V6(address) => {
                address_storage = FwpByteArray16 {
                    byte_array16: address.octets(),
                };
                let pointer = &address_storage as *const FwpByteArray16 as *mut FwpByteArray16;
                FwpmFilterCondition {
                    field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS_V6,
                    match_type: FWP_MATCH_EQUAL,
                    condition_value: FwpConditionValue {
                        type_: FWP_BYTE_ARRAY16_TYPE,
                        value: FwpConditionUnion {
                            byte_array16: pointer,
                        },
                    },
                }
            }
        };
        // Prevent the address storage from being optimized away before the
        // FwpmFilterAdd0 call; it is used synchronously below.
        let _ = &address_storage;
        filter_conditions.push(address_condition);
        // Pinned endpoints are the TCP broker/peer contract. Keep UDP and
        // other transports blocked by the default-deny filters rather than
        // accidentally permitting a different protocol to the same port.
        filter_conditions.push(FwpmFilterCondition {
            field_key: FWPM_CONDITION_IP_PROTOCOL,
            match_type: FWP_MATCH_EQUAL,
            condition_value: FwpConditionValue {
                type_: FWP_UINT8,
                value: FwpConditionUnion { uint8: 6 }, // IPPROTO_TCP
            },
        });
        filter_conditions.push(FwpmFilterCondition {
            field_key: FWPM_CONDITION_IP_REMOTE_PORT,
            match_type: FWP_MATCH_EQUAL,
            condition_value: FwpConditionValue {
                type_: FWP_UINT16,
                value: FwpConditionUnion {
                    uint16: endpoint.port,
                },
            },
        });
        let filter_name = format!("vetto permit {scope_id:016x} {key:?}");
        let mut filter_wide = wide(&filter_name)?;
        let filter = FwpmFilter {
            filter_key: key,
            display_data: FwpmDisplayData {
                name: filter_wide.as_mut_ptr(),
                description: description_wide.as_mut_ptr(),
            },
            flags: FWP_FILTER_FLAG_NONE,
            provider_key: null_mut(),
            provider_data: FwpByteBlob {
                size: 0,
                data: null_mut(),
            },
            layer_key: layer_for(endpoint.addr),
            sub_layer_key: sublayer_key,
            weight: FwpValue {
                type_: FWP_UINT64,
                value: FwpValueUnion { uint64: 15 },
            },
            num_filter_conditions: filter_conditions.len() as Dword,
            filter_condition: filter_conditions.as_mut_ptr(),
            action: FwpmAction {
                type_: FWP_ACTION_PERMIT,
                filter_type: Guid::new(0, 0, 0, [0; 8]),
            },
            context: FwpmFilterContext { raw_context: 0 },
            reserved: null_mut(),
            filter_id: 0,
            effective_weight: FwpValue {
                type_: FWP_EMPTY,
                value: FwpValueUnion { uint8: 0 },
            },
        };
        status = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), null_mut()) };
        if status != ERROR_SUCCESS {
            break;
        }
        lease.filters.push((key, FWP_ACTION_PERMIT));
    }

    if status == ERROR_SUCCESS {
        status = unsafe { FwpmTransactionCommit0(engine) };
        if status != ERROR_SUCCESS {
            // Commit failure must not leave a transaction open while cleanup
            // proceeds. The dynamic session is still the final safety net,
            // but an explicit abort makes rollback deterministic.
            unsafe {
                let _ = FwpmTransactionAbort0(engine);
            }
        }
    } else {
        unsafe {
            let _ = FwpmTransactionAbort0(engine);
        }
    }
    unsafe {
        free_blob(app_id);
    }
    if status != ERROR_SUCCESS {
        drop(lease);
        bail!("WFP policy transaction failed with status 0x{status:08x}");
    }

    // A policy is not reported as enforced until every key can be read back
    // from BFE with the expected action and at least one condition.
    let failed_key = lease.filters.iter().find_map(|(key, expected)| {
        // SAFETY: `engine` is the live WFP engine owned by `lease`; every key
        // was returned by a successful filter-add call in this transaction.
        (!unsafe { readback_matches(engine, key, *expected) }).then_some(*key)
    });
    if let Some(key) = failed_key {
        drop(lease);
        bail!("WFP read-back failed for filter {key:?}; policy was removed");
    }
    lease.enforced = true;
    Ok(lease)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Inactive,
    ExecutableImage {
        image_path: String,
        session_name: String,
    },
}

pub struct FirewallLease {
    engine: Handle,
    sublayer_key: Option<Guid>,
    filters: Vec<(Guid, Dword)>,
    enforced: bool,
    scope: Scope,
}

impl std::fmt::Debug for FirewallLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirewallLease")
            .field("scope", &self.scope)
            .field("filters", &self.filters.len())
            .field("enforced", &self.enforced)
            .finish()
    }
}

impl FirewallLease {
    pub fn enforced(&self) -> bool {
        self.enforced
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}

impl Drop for FirewallLease {
    fn drop(&mut self) {
        if self.engine.is_null() {
            return;
        }
        unsafe {
            // Explicit deletes make cleanup transactional even before the
            // dynamic session handle is closed.  Ignore cleanup errors: the
            // dynamic session close remains the final safety net.
            for (key, _) in self.filters.iter().rev() {
                let _ = FwpmFilterDeleteByKey0(self.engine, key);
            }
            if let Some(key) = &self.sublayer_key {
                let _ = FwpmSubLayerDeleteByKey0(self.engine, key);
            }
            let _ = FwpmEngineClose0(self.engine);
            self.engine = null_mut();
        }
    }
}

fn app_condition(app_id: *mut FwpByteBlob) -> FwpmFilterCondition {
    FwpmFilterCondition {
        field_key: FWPM_CONDITION_ALE_APP_ID,
        match_type: FWP_MATCH_EQUAL,
        condition_value: FwpConditionValue {
            type_: FWP_BYTE_BLOB_TYPE,
            value: FwpConditionUnion { byte_blob: app_id },
        },
    }
}

fn layer_for(addr: IpAddr) -> Guid {
    match addr {
        IpAddr::V4(_) => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        IpAddr::V6(_) => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    }
}

fn is_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(value) => value.is_loopback(),
        IpAddr::V6(value) => value.is_loopback(),
    }
}

fn is_non_routable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(value) => {
            let octets = value.octets();
            value.is_unspecified()
                || value.is_loopback()
                || value.is_private()
                || value.is_multicast()
                || value.is_broadcast()
                || value.is_link_local()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 169 && octets[1] == 254 && octets[2] == 169 && octets[3] == 254)
        }
        IpAddr::V6(value) => {
            let segments = value.segments();
            let mapped_or_compatible_v4 = segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && (segments[5] == 0xffff || segments[5] == 0);
            let mapped_v4 = if mapped_or_compatible_v4 {
                Some(Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    segments[6] as u8,
                    (segments[7] >> 8) as u8,
                    segments[7] as u8,
                ))
            } else {
                None
            };
            value.is_unspecified()
                || value.is_loopback()
                || value.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x0064 && segments[1] == 0xff9b)
                || mapped_v4.is_some_and(|address| is_non_routable(IpAddr::V4(address)))
        }
    }
}

fn endpoint_hash(endpoint: &PinnedEndpoint) -> u64 {
    let mut hash = endpoint.port as u64;
    match endpoint.addr {
        IpAddr::V4(value) => {
            for octet in value.octets() {
                hash = hash.rotate_left(5) ^ octet as u64;
            }
        }
        IpAddr::V6(value) => {
            for octet in value.octets() {
                hash = hash.rotate_left(5) ^ octet as u64;
            }
        }
    }
    hash
}

fn unique_guid(seed: u64, salt: u64) -> Guid {
    let a = 0x5645_5454u32 ^ seed as u32 ^ (salt as u32).rotate_left(7);
    let b = 0x70f0u16 ^ (seed >> 32) as u16;
    let c = 0x4f31u16 ^ (salt >> 32) as u16;
    let mut data4 = [0u8; 8];
    data4[..4].copy_from_slice(&(seed ^ 0x9e37_79b9_7f4a_7c15).to_le_bytes()[..4]);
    data4[4..].copy_from_slice(&(salt ^ 0xd1b5_4a32_d192_ed03).to_le_bytes()[..4]);
    Guid::new(a, b, c, data4)
}

fn wide(value: &str) -> Result<Vec<u16>> {
    if value.encode_utf16().any(|c| c == 0) {
        bail!("wide string contains NUL");
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}

unsafe fn free_blob(blob: *mut FwpByteBlob) {
    if !blob.is_null() {
        let mut memory = blob.cast::<c_void>();
        let _ = FwpmFreeMemory0(&mut memory);
    }
}

unsafe fn readback_matches(engine: Handle, key: &Guid, action: Dword) -> bool {
    let mut filter: *mut FwpmFilter = null_mut();
    let status = FwpmFilterGetByKey0(engine, key, &mut filter);
    let ok = status == ERROR_SUCCESS
        && !filter.is_null()
        && (*filter).filter_key == *key
        && (*filter).action.type_ == action
        && (*filter).num_filter_conditions >= if action == FWP_ACTION_BLOCK { 1 } else { 4 };
    if !filter.is_null() {
        let mut memory = filter.cast::<c_void>();
        let _ = FwpmFreeMemory0(&mut memory);
    }
    ok
}

/// Resolve a process image path without claiming a process-scoped WFP rule.
/// This helper is used by callers that want to present the required explicit
/// image-scope consent in their UI/doctor output.
pub fn process_image_path(process_id: u32) -> Result<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        bail!("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed for {process_id}");
    }
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as Dword;
    let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) };
    let error = unsafe { GetLastError() };
    unsafe {
        let _ = CloseHandle(process);
    }
    if ok == 0 {
        bail!("QueryFullProcessImageNameW failed with {error}");
    }
    String::from_utf16(&buffer[..length as usize]).context("process image path is not UTF-16")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_scope_is_fail_closed() {
        let policy = PinnedPolicy {
            mode: NetworkMode::Strict,
            endpoints: vec![],
            broker_loopback: None,
        };
        assert!(install_for_process(1, &policy).is_err());
    }

    #[test]
    fn endpoints_reject_non_routable_addresses() {
        assert!(PinnedEndpoint::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443).is_err());
        assert!(PinnedEndpoint::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443).is_err());
        assert!(PinnedEndpoint::new(IpAddr::V6("::ffff:10.0.0.1".parse().unwrap()), 443).is_err());
        assert!(PinnedEndpoint::new(IpAddr::V6("::10.0.0.1".parse().unwrap()), 443).is_err());
        assert!(PinnedEndpoint::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443).is_ok());
    }
}
