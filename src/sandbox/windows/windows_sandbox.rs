//! Optional Windows Sandbox (`.wsb`) launcher.
//!
//! Windows Sandbox is a disposable VM.  It is not the same boundary as the
//! processmodel/AppContainer backend and this module never claims otherwise.
//! The launcher is opt-in, requires the Windows Sandbox executable and
//! virtualization firmware support, and never requests elevation or enables
//! the optional Windows feature.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use anyhow::{bail, Context, Result};

type Dword = u32;

const PF_VIRT_FIRMWARE_ENABLED: Dword = 21;
const INVALID_FILE_ATTRIBUTES: Dword = u32::MAX;
const FILE_ATTRIBUTE_DIRECTORY: Dword = 0x0000_0010;

#[link(name = "kernel32")]
extern "system" {
    fn IsProcessorFeaturePresent(feature: Dword) -> i32;
    fn GetSystemDirectoryW(buffer: *mut u16, size: Dword) -> Dword;
    fn GetFileAttributesW(path: *const u16) -> Dword;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsSandboxCapabilities {
    pub launcher_present: bool,
    pub virtualization_firmware_enabled: bool,
    pub feature_enabled: bool,
    pub launcher_path: Option<PathBuf>,
    pub note: String,
}

/// Capability probe only.  It never enables `Containers-DisposableClientVM`
/// and never starts `WindowsSandbox.exe`.
pub fn capabilities() -> WindowsSandboxCapabilities {
    let launcher_path = system_directory().map(|directory| directory.join("WindowsSandbox.exe"));
    let launcher_present = launcher_path.as_deref().is_some_and(file_present);
    let virtualization_firmware_enabled =
        unsafe { IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) != 0 };
    // The executable is the observable local signal that the optional feature
    // is installed.  It is still necessary, not sufficient: launch requires
    // both this signal and virtualization firmware support.
    let feature_enabled = launcher_present;
    let note = if launcher_present && virtualization_firmware_enabled {
        "Windows Sandbox launch path is available; this is a disposable VM and requires explicit opt-in".to_string()
    } else {
        "Windows Sandbox unavailable or virtualization firmware disabled; no VM fallback is claimed"
            .to_string()
    };
    WindowsSandboxCapabilities {
        launcher_present,
        virtualization_firmware_enabled,
        feature_enabled,
        launcher_path,
        note,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SandboxSpec {
    pub command: String,
    pub working_directory: Option<PathBuf>,
    pub networking: bool,
    pub mapped_read_only: Vec<(PathBuf, PathBuf)>,
    pub memory_mb: Option<u32>,
}

impl SandboxSpec {
    pub fn validate(&self) -> Result<()> {
        if self.command.trim().is_empty() || self.command.contains('\0') {
            bail!("Windows Sandbox command is empty or contains NUL");
        }
        if let Some(memory) = self.memory_mb {
            if !(128..=65_536).contains(&memory) {
                bail!("Windows Sandbox memory must be between 128 and 65536 MiB");
            }
        }
        for (host, guest) in &self.mapped_read_only {
            if !host.is_absolute() || !guest.is_absolute() {
                bail!("Windows Sandbox mapped folders must use absolute paths");
            }
            if host.to_string_lossy().contains('\0') || guest.to_string_lossy().contains('\0') {
                bail!("Windows Sandbox mapped folder contains NUL");
            }
        }
        if let Some(directory) = &self.working_directory {
            if !directory.is_absolute() || directory.to_string_lossy().contains('\0') {
                bail!("Windows Sandbox working directory must be absolute and NUL-free");
            }
        }
        Ok(())
    }
}

/// Render a `.wsb` document.  Rendering itself has no host side effect.
pub fn render(spec: &SandboxSpec) -> Result<String> {
    spec.validate()?;
    let networking = if spec.networking { "Enable" } else { "Disable" };
    let mut xml = String::from("<Configuration>\n  <VGpu>Disable</VGpu>\n");
    xml.push_str(&format!("  <Networking>{networking}</Networking>\n"));
    if let Some(memory) = spec.memory_mb {
        xml.push_str(&format!("  <MemoryInMB>{memory}</MemoryInMB>\n"));
    }
    if !spec.mapped_read_only.is_empty() {
        xml.push_str("  <MappedFolders>\n");
        for (host, guest) in &spec.mapped_read_only {
            xml.push_str("    <MappedFolder>\n      <HostFolder>");
            xml.push_str(&escape_xml(&host.to_string_lossy()));
            xml.push_str("</HostFolder>\n      <SandboxFolder>");
            xml.push_str(&escape_xml(&guest.to_string_lossy()));
            xml.push_str(
                "</SandboxFolder>\n      <ReadOnly>true</ReadOnly>\n    </MappedFolder>\n",
            );
        }
        xml.push_str("  </MappedFolders>\n");
    }
    if let Some(directory) = &spec.working_directory {
        xml.push_str("  <LogonCommand><Command>cmd.exe /c cd /d ");
        xml.push_str(&escape_xml(&quote_cmd_path(&directory.to_string_lossy())));
        xml.push_str(" && ");
        xml.push_str(&escape_xml(&spec.command));
        xml.push_str("</Command></LogonCommand>\n");
    } else {
        xml.push_str("  <LogonCommand><Command>");
        xml.push_str(&escape_xml(&spec.command));
        xml.push_str("</Command></LogonCommand>\n");
    }
    xml.push_str("</Configuration>\n");
    Ok(xml)
}

/// Create a new `.wsb` file without overwriting an existing file.  Enabling
/// or installing the Windows Sandbox optional feature remains the operator's
/// responsibility and is never attempted here.
pub fn write_config(path: &Path, spec: &SandboxSpec) -> Result<()> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("wsb") {
        bail!("Windows Sandbox configuration must use a .wsb extension");
    }
    let rendered = render(spec)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create Windows Sandbox config {}", path.display()))?;
    file.write_all(rendered.as_bytes())?;
    Ok(())
}

/// Launch an already-written `.wsb` configuration only after explicit
/// caller opt-in.  The process is a VM launcher and is returned to the caller
/// for lifecycle management; this function does not claim a process sandbox
/// or a host-network guarantee.
pub fn launch_config(path: &Path, explicit_opt_in: bool) -> Result<Child> {
    if !explicit_opt_in {
        bail!("Windows Sandbox launch requires explicit opt-in");
    }
    if path.extension().and_then(|extension| extension.to_str()) != Some("wsb") {
        bail!("Windows Sandbox launcher accepts only .wsb files");
    }
    let caps = capabilities();
    if !caps.launcher_present || !caps.feature_enabled || !caps.virtualization_firmware_enabled {
        bail!("Windows Sandbox capability gate failed: {}", caps.note);
    }
    let launcher = caps
        .launcher_path
        .context("Windows Sandbox launcher path unavailable")?;
    Command::new(launcher)
        .arg(path)
        .spawn()
        .context("start WindowsSandbox.exe; no elevation was requested")
}

fn system_directory() -> Option<PathBuf> {
    let mut buffer = vec![0u16; 260];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as Dword) };
    if length == 0 {
        return None;
    }
    if length as usize >= buffer.len() {
        buffer.resize(length as usize + 1, 0);
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as Dword) };
        if length == 0 || length as usize >= buffer.len() {
            return None;
        }
        return String::from_utf16(&buffer[..length as usize])
            .ok()
            .map(PathBuf::from);
    }
    String::from_utf16(&buffer[..length as usize])
        .ok()
        .map(PathBuf::from)
}

fn file_present(path: &Path) -> bool {
    let value = path.to_string_lossy();
    if value.encode_utf16().any(|c| c == 0) {
        return false;
    }
    let wide: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_DIRECTORY == 0
}

fn escape_xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn quote_cmd_path(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendering_disables_network_by_default() {
        let xml = render(&SandboxSpec {
            command: "echo <safe>".to_string(),
            ..SandboxSpec::default()
        })
        .expect("render");
        assert!(xml.contains("<Networking>Disable</Networking>"));
        assert!(xml.contains("echo &lt;safe&gt;"));
    }

    #[test]
    fn rendering_uses_documented_enable_value_when_requested() {
        let xml = render(&SandboxSpec {
            command: "echo safe".to_string(),
            networking: true,
            ..SandboxSpec::default()
        })
        .expect("render");
        assert!(xml.contains("<Networking>Enable</Networking>"));
    }

    #[test]
    fn launch_requires_opt_in() {
        assert!(launch_config(Path::new("sandbox.wsb"), false).is_err());
    }
}
