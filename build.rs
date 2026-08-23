//! Fail-closed platform gate for the native backends.
//!
//! Windows is supported through a target-gated backend.  Unsupported targets
//! still fail during build rather than producing a binary with an accidental
//! unsandboxed path.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("linux") && !target.contains("darwin") && !target.contains("windows") {
        panic!(
            "vetto builds only on Linux, macOS, and Windows. \
             Refusing to produce an unsandboxed or broken build for target {target}."
        );
    }
    println!("cargo:rerun-if-changed=build.rs");
}
