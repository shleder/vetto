//! Fail-closed platform gate: vetto v0.1 supports Linux and macOS only.
//! A Windows build attempt gets an honest error instead of a broken binary.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("linux") && !target.contains("darwin") {
        panic!(
            "vetto v0.1 builds only on Linux and macOS. \
             Windows support is on the v0.3+ roadmap (see README.md); \
             refusing to produce an unsandboxed or broken build."
        );
    }
    println!("cargo:rerun-if-changed=build.rs");
}
