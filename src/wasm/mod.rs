//! WebAssembly WASI Preview 2 isolation tier module.
//!
//! Provides a portable fallback execution layer when OS-native sandbox mechanisms
//! (such as Linux Landlock or macOS Seatbelt) are unavailable.

pub mod runtime;

pub use runtime::{
    WasiExecutionLimits, WasiMountPoint, WasiSandboxConfig, WasiVersion,
    WasmEngineKind, WasmExecutionResult, WasmModuleMetadata, WasmSandboxError,
    WasmSandboxTier,
};

/// Helper constructor to instantiate a standard WASI Preview 2 sandbox tier.
pub fn create_wasi_sandbox(
    workspace_dir: std::path::PathBuf,
    fuel_limit: u64,
    memory_limit_mb: u64,
) -> WasmSandboxTier {
    let mut config = WasiSandboxConfig::default();
    config.limits.max_fuel = fuel_limit;
    config.limits.max_memory_bytes = memory_limit_mb * 1024 * 1024;
    config.mounts.push(WasiMountPoint {
        guest_path: std::path::PathBuf::from("/workspace"),
        host_path: workspace_dir,
        read_only: false,
    });

    WasmSandboxTier::new(config)
}

/// Validates whether a given byte slice is a valid WASM binary and returns its metadata.
pub fn validate_wasm_binary(wasm_bytes: &[u8]) -> Result<WasmModuleMetadata, WasmSandboxError> {
    WasmSandboxTier::parse_module_metadata(wasm_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_wasi_sandbox_helper() {
        let sandbox = create_wasi_sandbox(std::path::PathBuf::from("/tmp/test_workspace"), 50_000, 32);
        let wasm = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // Header
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00,             // Type
            0x03, 0x02, 0x01, 0x00,                         // Func
            0x07, 0x0a, 0x01, 0x06, b'_', b's', b't', b'a', b'r', b't', 0x00, 0x00, // Export
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,             // Code
        ];

        let meta = validate_wasm_binary(&wasm).unwrap();
        assert_eq!(meta.version, 1);
    }
}
