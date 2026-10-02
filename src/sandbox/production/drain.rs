//! Bounded stdio drain, AsyncPipeReader, PipePair, StreamCollector (INV-25).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::context::SessionEvidenceState;
use super::error::ProductionError;

/// Configuration for nonblocking stream draining.
#[derive(Debug, Clone)]
pub struct DrainConfig {
    pub max_bytes: usize,
    pub drain_budget: Duration,
    pub poll_interval: Duration,
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024, // 1 MB capture buffer per stream
            drain_budget: Duration::from_millis(200),
            poll_interval: Duration::from_millis(10),
        }
    }
}

/// Non-blocking pipe pair for stdout and stderr.
#[cfg(unix)]
pub struct PipePair {
    pub stdout_read: OwnedFd,
    pub stdout_write: OwnedFd,
    pub stderr_read: OwnedFd,
    pub stderr_write: OwnedFd,
}

#[cfg(unix)]
impl PipePair {
    /// Creates nonblocking pipe pairs with O_CLOEXEC and O_NONBLOCK on the read ends.
    pub fn create_nonblocking() -> Result<Self, ProductionError> {
        let make_pipe = || -> Result<(OwnedFd, OwnedFd), ProductionError> {
            let mut fds = [0i32; 2];
            unsafe {
                if libc::pipe(fds.as_mut_ptr()) != 0 {
                    return Err(ProductionError::DrainFailure(format!(
                        "pipe failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                for &fd in &fds {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                        libc::close(fds[0]);
                        libc::close(fds[1]);
                        return Err(ProductionError::DrainFailure(format!(
                            "fcntl FD_CLOEXEC failed: {}",
                            std::io::Error::last_os_error()
                        )));
                    }
                }
                let read_flags = libc::fcntl(fds[0], libc::F_GETFL);
                if read_flags >= 0 {
                    libc::fcntl(fds[0], libc::F_SETFL, read_flags | libc::O_NONBLOCK);
                }
                Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])))
            }
        };

        let (out_r, out_w) = make_pipe()?;
        let (err_r, err_w) = make_pipe()?;
        Ok(Self {
            stdout_read: out_r,
            stdout_write: out_w,
            stderr_read: err_r,
            stderr_write: err_w,
        })
    }
}

#[cfg(not(unix))]
pub struct PipePair;

#[cfg(not(unix))]
impl PipePair {
    pub fn create_nonblocking() -> Result<Self, ProductionError> {
        Err(ProductionError::DrainFailure(
            "Unsupported platform for nonblocking pipes".into(),
        ))
    }
}

#[cfg(not(unix))]
pub fn piped_stdio_fds() -> anyhow::Result<()> {
    anyhow::bail!("piped_stdio_fds is Unix-only")
}

/// Create two cloexec pipes for boundary-owned captured stdio.
/// Returns `((stdout_r, stdout_w), (stderr_r, stderr_w))`.
#[cfg(unix)]
pub fn piped_stdio_fds() -> anyhow::Result<(OwnedFd, OwnedFd, OwnedFd, OwnedFd)> {
    let pair = PipePair::create_nonblocking().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((
        pair.stdout_read,
        pair.stdout_write,
        pair.stderr_read,
        pair.stderr_write,
    ))
}

/// Non-blocking async pipe reader for captured stdio streams.
/// Drains the pipe concurrently while the child is executing, preventing
/// the 64KB kernel buffer deadlock (FS-01, INV-25).
#[cfg(unix)]
pub struct AsyncPipeReader {
    handle: Option<std::thread::JoinHandle<(Vec<u8>, bool)>>,
    child_done: Arc<AtomicBool>,
}

#[cfg(unix)]
impl AsyncPipeReader {
    /// Canonical 3-arg constructor called in main.rs and cli/bench.rs
    pub fn spawn(fd: OwnedFd, max_bytes: usize, drain_deadline: Duration) -> Self {
        let config = DrainConfig {
            max_bytes,
            drain_budget: drain_deadline,
            poll_interval: Duration::from_millis(10),
        };
        let evidence = Arc::new(SessionEvidenceState::default());
        Self::spawn_with_config(fd, config, evidence)
    }

    /// Full constructor supporting session evidence tracking and DrainConfig
    pub fn spawn_with_config(
        fd: OwnedFd,
        config: DrainConfig,
        evidence: Arc<SessionEvidenceState>,
    ) -> Self {
        let child_done = Arc::new(AtomicBool::new(false));
        let child_done_clone = Arc::clone(&child_done);

        let handle = std::thread::spawn(move || {
            let raw_fd = fd.as_raw_fd();
            let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
            if flags >= 0 {
                unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            }

            let mut collected = Vec::with_capacity(16 * 1024);
            let mut discard_buf = [0u8; 4096];
            let mut truncated = false;
            let mut post_exit_start: Option<Instant> = None;

            'drain_loop: loop {
                if child_done_clone.load(Ordering::Relaxed) {
                    let start = *post_exit_start.get_or_insert_with(Instant::now);
                    if start.elapsed() >= config.drain_budget {
                        break;
                    }
                }

                let mut pfd = libc::pollfd {
                    fd: raw_fd,
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                };
                let r = unsafe {
                    libc::poll(
                        &mut pfd,
                        1,
                        config.poll_interval.as_millis().max(1) as libc::c_int,
                    )
                };
                if r > 0 {
                    loop {
                        if !truncated {
                            let remaining = config.max_bytes.saturating_sub(collected.len());
                            if remaining == 0 {
                                truncated = true;
                                evidence.buffer_overflows.fetch_add(1, Ordering::SeqCst);
                                continue;
                            }
                            let chunk_size = remaining.min(8192);
                            let mut chunk = vec![0u8; chunk_size];
                            let n = unsafe {
                                libc::read(raw_fd, chunk.as_mut_ptr().cast(), chunk.len())
                            };
                            if n > 0 {
                                chunk.truncate(n as usize);
                                collected.extend_from_slice(&chunk);
                            } else if n == 0 {
                                break 'drain_loop;
                            } else {
                                let err = std::io::Error::last_os_error();
                                let code = err.raw_os_error().unwrap_or(0);
                                if code == libc::EAGAIN || code == libc::EWOULDBLOCK {
                                    break;
                                }
                                if code != libc::EINTR {
                                    break 'drain_loop;
                                }
                            }
                        } else {
                            // Bounded drain /dev/null discard mode
                            let n = unsafe {
                                libc::read(
                                    raw_fd,
                                    discard_buf.as_mut_ptr().cast(),
                                    discard_buf.len(),
                                )
                            };
                            if n > 0 {
                                // bytes discarded, kernel buffer drained
                            } else if n == 0 {
                                break 'drain_loop;
                            } else {
                                let err = std::io::Error::last_os_error();
                                let code = err.raw_os_error().unwrap_or(0);
                                if code == libc::EAGAIN || code == libc::EWOULDBLOCK {
                                    break;
                                }
                                if code != libc::EINTR {
                                    break 'drain_loop;
                                }
                            }
                        }
                    }
                } else if r == 0 {
                    if child_done_clone.load(Ordering::Relaxed) {
                        let start = *post_exit_start.get_or_insert_with(Instant::now);
                        if start.elapsed() >= config.drain_budget {
                            break;
                        }
                    }
                } else {
                    let err = std::io::Error::last_os_error();
                    let code = err.raw_os_error().unwrap_or(0);
                    if code != libc::EINTR {
                        break;
                    }
                }
            }

            (collected, truncated)
        });

        Self {
            handle: Some(handle),
            child_done,
        }
    }

    pub fn notify_child_exited(&self) {
        self.child_done.store(true, Ordering::SeqCst);
    }

    pub fn join(self) -> Vec<u8> {
        self.join_with_status().0
    }

    pub fn join_with_status(mut self) -> (Vec<u8>, bool) {
        if let Some(h) = self.handle.take() {
            h.join().unwrap_or_else(|_| (Vec::new(), false))
        } else {
            (Vec::new(), false)
        }
    }
}

#[cfg(not(unix))]
pub struct AsyncPipeReader;

#[cfg(not(unix))]
impl AsyncPipeReader {
    pub fn notify_child_exited(&self) {}
    pub fn join(self) -> Vec<u8> {
        Vec::new()
    }
    pub fn join_with_status(self) -> (Vec<u8>, bool) {
        (Vec::new(), false)
    }
}

/// Collector managing concurrent draining of stdout and stderr streams.
pub struct StreamCollector {
    #[cfg(unix)]
    stdout_reader: AsyncPipeReader,
    #[cfg(unix)]
    stderr_reader: AsyncPipeReader,
}

impl StreamCollector {
    #[cfg(unix)]
    pub fn start(
        pipes: &PipePair,
        config: DrainConfig,
        evidence: Arc<SessionEvidenceState>,
    ) -> Result<Self, ProductionError> {
        unsafe {
            let out_fd = libc::fcntl(pipes.stdout_read.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
            if out_fd < 0 {
                return Err(ProductionError::DrainFailure(format!(
                    "fcntl F_DUPFD_CLOEXEC stdout failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let err_fd = libc::fcntl(pipes.stderr_read.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
            if err_fd < 0 {
                libc::close(out_fd);
                return Err(ProductionError::DrainFailure(format!(
                    "fcntl F_DUPFD_CLOEXEC stderr failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(Self {
                stdout_reader: AsyncPipeReader::spawn_with_config(
                    OwnedFd::from_raw_fd(out_fd),
                    config.clone(),
                    Arc::clone(&evidence),
                ),
                stderr_reader: AsyncPipeReader::spawn_with_config(
                    OwnedFd::from_raw_fd(err_fd),
                    config,
                    evidence,
                ),
            })
        }
    }

    #[cfg(not(unix))]
    pub fn start(
        _pipes: &PipePair,
        _config: DrainConfig,
        _evidence: Arc<SessionEvidenceState>,
    ) -> Result<Self, ProductionError> {
        Err(ProductionError::DrainFailure("Unix only".into()))
    }

    pub fn finish(self) -> (Vec<u8>, Vec<u8>, bool, bool) {
        #[cfg(unix)]
        {
            let (out, out_trunc) = self.stdout_reader.join_with_status();
            let (err, err_trunc) = self.stderr_reader.join_with_status();
            (out, err, out_trunc, err_trunc)
        }
        #[cfg(not(unix))]
        {
            (Vec::new(), Vec::new(), false, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_async_pipe_reader_large_payload() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let reader = AsyncPipeReader::spawn(read_fd, 1 << 20, Duration::from_millis(200));

        let payload_size = 128 * 1024; // 128 KB, exceeds 64KB pipe buffer
        let payload = vec![b'A'; payload_size];
        let payload_clone = payload.clone();

        let writer = std::thread::spawn(move || {
            use std::io::Write;
            let mut file = std::fs::File::from(write_fd);
            file.write_all(&payload_clone).expect("write payload");
        });

        writer.join().expect("writer finished");
        reader.notify_child_exited();
        let collected = reader.join();

        assert_eq!(collected.len(), payload_size);
        assert_eq!(collected, payload);
    }

    #[cfg(unix)]
    #[test]
    fn test_async_pipe_reader_drain_deadline() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) }; // Held open

        let start = Instant::now();
        let reader = AsyncPipeReader::spawn(read_fd, 1 << 20, Duration::from_millis(100));
        reader.notify_child_exited();
        let _ = reader.join();
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(80));
        assert!(elapsed < Duration::from_millis(1000));
    }
}
