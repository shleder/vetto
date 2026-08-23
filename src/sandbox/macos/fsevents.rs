//! macOS FSEvents change feed.
//!
//! FSEvents reports filesystem *changes* (create/remove/rename/metadata), not
//! reads and not Seatbelt denials. Consequently this module publishes
//! `Event::Notice` entries with an explicit `fsevents change` label instead of
//! pretending that they are `FileObserved` read events. The feed is
//! inherently delayed/coalesced and remains observation-only; Seatbelt is the
//! enforcement boundary.

use std::ffi::{c_char, c_void, CStr, CString};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr::null;

use crate::events::bus::EventBus;
use crate::events::types::{now, Event};

type CFIndex = isize;
type CFAllocatorRef = *const c_void;
type CFStringRef = *const c_void;
type CFArrayRef = *const c_void;
type CFRunLoopRef = *mut c_void;
type FSEventStreamRef = *mut c_void;

const K_FSEVENT_STREAM_CREATE_FLAG_NO_DEFER: u32 = 0x0000_0002;
const K_FSEVENT_STREAM_CREATE_FLAG_WATCH_ROOT: u32 = 0x0000_0004;
const K_FSEVENT_STREAM_CREATE_FLAG_FILE_EVENTS: u32 = 0x0000_0010;
const K_FSEVENT_STREAM_EVENT_ID_SINCE_NOW: u64 = 0xffff_ffff_ffff_ffff;
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

// Event flags from FSEvents.h. They are kept local so this backend can be
// built with the minimum Rust/macOS SDK without an Objective-C dependency.
const MUST_SCAN_SUB_DIRS: u32 = 0x0000_0001;
const USER_DROPPED: u32 = 0x0000_0002;
const KERNEL_DROPPED: u32 = 0x0000_0004;
const EVENT_IDS_WRAPPED: u32 = 0x0000_0008;
const HISTORY_DONE: u32 = 0x0000_0010;
const ROOT_CHANGED: u32 = 0x0000_0020;
const MOUNT: u32 = 0x0000_0040;
const UNMOUNT: u32 = 0x0000_0080;
const ITEM_CREATED: u32 = 0x0000_0100;
const ITEM_REMOVED: u32 = 0x0000_0200;
const INODE_META_MOD: u32 = 0x0000_0400;
const ITEM_RENAMED: u32 = 0x0000_0800;
const ITEM_MODIFIED: u32 = 0x0000_1000;
const FINDER_INFO_MOD: u32 = 0x0000_2000;
const ITEM_CHANGE_OWNER: u32 = 0x0000_4000;
const ITEM_XATTR_MOD: u32 = 0x0000_8000;
const ITEM_IS_FILE: u32 = 0x0001_0000;
const ITEM_IS_DIR: u32 = 0x0002_0000;
const ITEM_IS_SYMLINK: u32 = 0x0004_0000;
const OWN_EVENT: u32 = 0x0008_0000;
const ITEM_IS_HARDLINK: u32 = 0x0010_0000;
const ITEM_IS_LAST_HARDLINK: u32 = 0x0020_0000;
const ITEM_CLONED: u32 = 0x0040_0000;

type FSEventStreamCallback = unsafe extern "C" fn(
    stream: FSEventStreamRef,
    client_info: *mut c_void,
    num_events: usize,
    event_paths: *const c_void,
    event_flags: *const u32,
    event_ids: *const u64,
);

#[repr(C)]
struct FSEventStreamContext {
    version: CFIndex,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<unsafe extern "C" fn(*const c_void)>,
    copy_description: Option<unsafe extern "C" fn(*const c_void) -> CFStringRef>,
}

#[allow(non_snake_case)]
#[link(name = "CoreServices", kind = "framework")]
extern "C" {
    fn FSEventStreamCreate(
        allocator: CFAllocatorRef,
        callback: FSEventStreamCallback,
        context: *mut FSEventStreamContext,
        paths_to_watch: CFArrayRef,
        since_when: u64,
        latency: f64,
        flags: u32,
    ) -> FSEventStreamRef;
    fn FSEventStreamScheduleWithRunLoop(
        stream: FSEventStreamRef,
        run_loop: CFRunLoopRef,
        run_loop_mode: CFStringRef,
    );
    fn FSEventStreamStart(stream: FSEventStreamRef) -> u8;
    fn FSEventStreamInvalidate(stream: FSEventStreamRef);
    fn FSEventStreamRelease(stream: FSEventStreamRef);
}

#[allow(non_snake_case)]
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFStringCreateWithCString(
        allocator: CFAllocatorRef,
        c_str: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFArrayCreate(
        allocator: CFAllocatorRef,
        values: *const *const c_void,
        num_values: CFIndex,
        callbacks: *const c_void,
    ) -> CFArrayRef;
    fn CFRelease(value: *const c_void);
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopRun();
    #[link_name = "kCFRunLoopDefaultMode"]
    static K_CF_RUN_LOOP_DEFAULT_MODE: CFStringRef;
}

/// Start a feed for the current project. `Some` is an explicit notice suitable
/// for publishing to the bus so operators can see that this is a delayed
/// change feed rather than an access log.
pub fn spawn_watcher_if_available(bus: &EventBus) -> Option<String> {
    let root = match std::env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            return Some(format!(
                "FSEvents change feed unavailable: cannot resolve project root: {error}"
            ));
        }
    };
    spawn_watcher(bus, &[root])
}

/// Start an FSEvents stream for the supplied roots.
pub fn spawn_watcher(bus: &EventBus, roots: &[PathBuf]) -> Option<String> {
    if roots.is_empty() {
        return Some("FSEvents change feed not started: no watch roots".to_string());
    }
    let roots = roots.to_vec();
    let bus = bus.clone();
    let thread = std::thread::Builder::new()
        .name("vetto-fsevents".to_string())
        .spawn(move || run_stream(bus, roots));
    match thread {
        Ok(_) => Some(
            "FSEvents change feed active (change labels only; delayed/coalesced; Seatbelt denials are invisible)"
                .to_string(),
        ),
        Err(error) => Some(format!("FSEvents change feed unavailable: {error}")),
    }
}

fn run_stream(bus: EventBus, roots: Vec<PathBuf>) {
    let path_strings: Vec<CString> = roots
        .iter()
        .filter_map(|path| CString::new(path.to_string_lossy().as_bytes()).ok())
        .collect();
    if path_strings.is_empty() {
        bus.publish(Event::Notice {
            ts: now(),
            message: "FSEvents change feed unavailable: watch paths contain NUL bytes".to_string(),
        });
        return;
    }
    let mut path_refs: Vec<CFStringRef> = Vec::with_capacity(path_strings.len());
    for path in &path_strings {
        // SAFETY: `path` is a live NUL-terminated UTF-8 string and the null
        // allocator requests the default CoreFoundation allocator.
        let cf_path =
            unsafe { CFStringCreateWithCString(null(), path.as_ptr(), K_CF_STRING_ENCODING_UTF8) };
        if !cf_path.is_null() {
            path_refs.push(cf_path);
        }
    }
    if path_refs.is_empty() {
        bus.publish(Event::Notice {
            ts: now(),
            message: "FSEvents change feed unavailable: CoreFoundation rejected watch roots"
                .to_string(),
        });
        return;
    }

    // The temporary array uses null callbacks because the CFString references
    // remain alive until FSEventStreamCreate has copied the watch list.
    let values: Vec<*const c_void> = path_refs.to_vec();
    // SAFETY: values points to live CFStringRefs for the duration of this call.
    let paths = unsafe { CFArrayCreate(null(), values.as_ptr(), values.len() as CFIndex, null()) };
    if paths.is_null() {
        for path in path_refs {
            // SAFETY: each reference was returned by CFStringCreateWithCString.
            unsafe { CFRelease(path) };
        }
        bus.publish(Event::Notice {
            ts: now(),
            message: "FSEvents change feed unavailable: CFArrayCreate failed".to_string(),
        });
        return;
    }

    let info = Box::into_raw(Box::new(bus)) as *mut c_void;
    let mut context = FSEventStreamContext {
        version: 0,
        info,
        retain: None,
        release: None,
        copy_description: None,
    };
    // SAFETY: callback/context/paths are valid for stream creation; flags ask
    // for per-file changes and immediate delivery without historical replay.
    let stream = unsafe {
        FSEventStreamCreate(
            null(),
            callback,
            &mut context,
            paths,
            K_FSEVENT_STREAM_EVENT_ID_SINCE_NOW,
            0.20,
            K_FSEVENT_STREAM_CREATE_FLAG_NO_DEFER
                | K_FSEVENT_STREAM_CREATE_FLAG_WATCH_ROOT
                | K_FSEVENT_STREAM_CREATE_FLAG_FILE_EVENTS,
        )
    };
    // SAFETY: stream creation has copied the watch roots; release temporary
    // CoreFoundation ownership now.
    unsafe {
        CFRelease(paths);
        for path in path_refs {
            CFRelease(path);
        }
    }
    if stream.is_null() {
        // SAFETY: info was allocated immediately above and no stream callback
        // can have run when creation returned null.
        unsafe {
            let bus = Box::from_raw(info as *mut EventBus);
            bus.publish(Event::Notice {
                ts: now(),
                message: "FSEvents change feed unavailable: FSEventStreamCreate failed".to_string(),
            });
            drop(bus);
        }
        return;
    }

    // SAFETY: current run loop belongs to this dedicated thread; the mode is
    // the exported CoreFoundation singleton and the stream is live.
    let run_loop = unsafe { CFRunLoopGetCurrent() };
    // SAFETY: all arguments are valid CoreFoundation objects.
    unsafe {
        FSEventStreamScheduleWithRunLoop(stream, run_loop, K_CF_RUN_LOOP_DEFAULT_MODE);
    }
    // SAFETY: stream remains valid until this thread exits (normally process
    // termination because the run loop is intentionally persistent).
    if unsafe { FSEventStreamStart(stream) } == 0 {
        // SAFETY: stream was not started, but invalidate/release remains the
        // documented cleanup path; reclaim the callback context as well.
        unsafe {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            let bus = Box::from_raw(info as *mut EventBus);
            bus.publish(Event::Notice {
                ts: now(),
                message: "FSEvents change feed unavailable: FSEventStreamStart failed".to_string(),
            });
            drop(bus);
        }
        return;
    }
    unsafe { CFRunLoopRun() };
    // SAFETY: this path is only reachable if the run loop is stopped.
    unsafe {
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        drop(Box::from_raw(info as *mut EventBus));
    }
}

unsafe extern "C" fn callback(
    _stream: FSEventStreamRef,
    client_info: *mut c_void,
    num_events: usize,
    event_paths: *const c_void,
    event_flags: *const u32,
    _event_ids: *const u64,
) {
    if client_info.is_null() || event_paths.is_null() || event_flags.is_null() {
        return;
    }
    // FSEventStreamCreate does not set UseCFTypes, so `event_paths` is a
    // `char **` array of UTF-8 paths.
    let paths = event_paths as *const *const c_char;
    // SAFETY: FSEventStream passes the context pointer installed in
    // `FSEventStreamCreate`; it remains alive for the stream lifetime.
    let bus = unsafe { &*(client_info as *const EventBus) };
    for index in 0..num_events {
        // SAFETY: CoreServices provides `num_events` path/flag entries.
        let path_ptr = unsafe { *paths.add(index) };
        if path_ptr.is_null() {
            continue;
        }
        // SAFETY: each path entry is a NUL-terminated UTF-8 C string for a
        // non-CF-types stream.
        let path = unsafe { CStr::from_ptr(path_ptr) }.to_string_lossy();
        // SAFETY: the flags array has one item for each event.
        let flags = unsafe { *event_flags.add(index) };
        let labels = labels(flags);
        bus.publish(Event::Notice {
            ts: now(),
            message: format!("fsevents change [{}] path={}", labels, path),
        });
        if flags & (USER_DROPPED | KERNEL_DROPPED | EVENT_IDS_WRAPPED) != 0 {
            bus.publish(Event::Notice {
                ts: now(),
                message: format!(
                    "fsevents warning: event history was dropped/wrapped near path={}; this feed is incomplete",
                    path
                ),
            });
        }
    }
}

fn labels(flags: u32) -> String {
    let mut labels = Vec::new();
    let pairs = [
        (MUST_SCAN_SUB_DIRS, "must_scan_subdirs"),
        (USER_DROPPED, "user_dropped"),
        (KERNEL_DROPPED, "kernel_dropped"),
        (EVENT_IDS_WRAPPED, "event_ids_wrapped"),
        (HISTORY_DONE, "history_done"),
        (ROOT_CHANGED, "root_changed"),
        (MOUNT, "mount"),
        (UNMOUNT, "unmount"),
        (ITEM_CREATED, "created"),
        (ITEM_REMOVED, "removed"),
        (INODE_META_MOD, "inode_metadata"),
        (ITEM_RENAMED, "renamed"),
        (ITEM_MODIFIED, "modified"),
        (FINDER_INFO_MOD, "finder_info"),
        (ITEM_CHANGE_OWNER, "owner_changed"),
        (ITEM_XATTR_MOD, "xattr_changed"),
        (ITEM_IS_FILE, "file"),
        (ITEM_IS_DIR, "directory"),
        (ITEM_IS_SYMLINK, "symlink"),
        (OWN_EVENT, "own_event"),
        (ITEM_IS_HARDLINK, "hardlink"),
        (ITEM_IS_LAST_HARDLINK, "last_hardlink"),
        (ITEM_CLONED, "cloned"),
    ];
    for (bit, label) in pairs {
        if flags & bit != 0 {
            labels.push(label);
        }
    }
    if labels.is_empty() {
        labels.push("changed");
    }
    labels.join(",")
}

#[allow(dead_code)]
fn _size_assertions() {
    // Keep this function as a compile-time reminder when SDK headers change;
    // FSEventStreamContext is passed directly to the C API above.
    let _ = size_of::<FSEventStreamContext>();
}

#[allow(dead_code)]
fn _path_is_absolute(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(test)]
mod tests {
    use super::{labels, ITEM_CREATED, ITEM_IS_DIR, USER_DROPPED};

    #[test]
    fn labels_describe_changes_and_dropped_history() {
        let text = labels(ITEM_CREATED | ITEM_IS_DIR | USER_DROPPED);
        assert!(text.contains("created"));
        assert!(text.contains("directory"));
        assert!(text.contains("user_dropped"));
    }

    #[test]
    fn empty_flags_are_not_reported_as_reads() {
        assert_eq!(labels(0), "changed");
    }
}
