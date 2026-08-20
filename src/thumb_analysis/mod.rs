// The shared contract is consumed incrementally as sibling pipeline stages migrate.
#[allow(dead_code)]
mod artifact;
mod radare2;
mod rizin;
mod stream;

use crate::analysis_tool::AnalysisTool;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[allow(unused_imports)]
pub(crate) use artifact::{
    AttemptRecord, AttemptStatus, CaptureRecord, FunctionRunRecord, OwnedFunctionRef,
    ParsedThumbArtifact, RegionRecord, THUMB_V1_FORMAT, THUMB_V2_FORMAT, THUMB_V3_FORMAT,
    ThumbFormat, assemble_v3_atomic, assemble_v3_into, parse_thumb_artifact, read_thumb_artifact,
    validate_thumb_inventory_streaming,
};
pub use radare2::discover_radare2;
pub use rizin::discover_rizin;
pub use stream::run_radare2_thumb;

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const VERSION_LINE_MAX_BYTES: usize = 1_024;
const STDERR_DIAGNOSTIC_MAX_BYTES: usize = 4_096;
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThumbProducer {
    Radare2,
    Rizin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerIdentity {
    pub producer: ThumbProducer,
    pub executable: PathBuf,
    pub version: String,
    pub command: &'static str,
}

impl ThumbProducer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Radare2 => "radare2",
            Self::Rizin => "rizin",
        }
    }

    pub const fn command(self) -> &'static str {
        match self {
            Self::Radare2 => "aaa;aflj;pdfj @@f",
            Self::Rizin => "aaa;aflj;pdfj @@F;axlj",
        }
    }
}

impl From<ThumbProducer> for AnalysisTool {
    fn from(value: ThumbProducer) -> Self {
        match value {
            ThumbProducer::Radare2 => Self::Radare2,
            ThumbProducer::Rizin => Self::Rizin,
        }
    }
}

enum VersionOutput {
    Empty,
    InvalidUtf8,
    Oversized,
    Version(String),
}

/// Incrementally trims one UTF-8 line while retaining at most the accepted
/// version bytes. Trailing whitespace is committed only if content follows it.
#[derive(Default)]
struct VersionLine {
    content: Vec<u8>,
    trailing_whitespace: Vec<u8>,
    trailing_whitespace_overflow: bool,
    utf8_tail: Vec<u8>,
    invalid_utf8: bool,
    oversized: bool,
}

impl VersionLine {
    fn push_bytes(&mut self, bytes: &[u8]) {
        if self.invalid_utf8 {
            return;
        }

        let mut input = Vec::with_capacity(self.utf8_tail.len() + bytes.len());
        input.append(&mut self.utf8_tail);
        input.extend_from_slice(bytes);
        match std::str::from_utf8(&input) {
            Ok(text) => self.push_str(text),
            Err(error) => {
                let valid_up_to = error.valid_up_to();
                let incomplete = error.error_len().is_none();
                let valid =
                    std::str::from_utf8(&input[..valid_up_to]).expect("UTF-8 error valid prefix");
                self.push_str(valid);
                if incomplete {
                    self.utf8_tail.extend_from_slice(&input[valid_up_to..]);
                } else {
                    self.invalid_utf8 = true;
                }
            }
        }
    }

    fn push_str(&mut self, text: &str) {
        for character in text.chars() {
            if self.oversized {
                continue;
            }
            let mut encoded = [0u8; 4];
            let bytes = character.encode_utf8(&mut encoded).as_bytes();
            if character.is_whitespace() {
                if self.content.is_empty() || self.trailing_whitespace_overflow {
                    continue;
                }
                let retained = self.content.len() + self.trailing_whitespace.len();
                if bytes.len() <= VERSION_LINE_MAX_BYTES.saturating_sub(retained) {
                    self.trailing_whitespace.extend_from_slice(bytes);
                } else {
                    self.trailing_whitespace.clear();
                    self.trailing_whitespace_overflow = true;
                }
            } else if self.trailing_whitespace_overflow
                || self.content.len() + self.trailing_whitespace.len() + bytes.len()
                    > VERSION_LINE_MAX_BYTES
            {
                self.trailing_whitespace.clear();
                self.oversized = true;
            } else {
                self.content.append(&mut self.trailing_whitespace);
                self.content.extend_from_slice(bytes);
            }
        }
    }

    fn finish(self) -> Option<VersionOutput> {
        if self.invalid_utf8 || !self.utf8_tail.is_empty() {
            Some(VersionOutput::InvalidUtf8)
        } else if self.oversized {
            Some(VersionOutput::Oversized)
        } else if self.content.is_empty() {
            None
        } else {
            Some(VersionOutput::Version(
                String::from_utf8(self.content).expect("validated UTF-8 version line"),
            ))
        }
    }
}

fn read_version_stdout(mut stdout: impl Read) -> std::io::Result<VersionOutput> {
    let mut chunk = [0u8; 8 * 1_024];
    let mut line = VersionLine::default();
    let mut output = None;

    loop {
        let read = stdout.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if output.is_some() {
            continue;
        }
        let mut start = 0;
        for (index, &byte) in chunk[..read].iter().enumerate() {
            if byte == b'\n' {
                line.push_bytes(&chunk[start..index]);
                if let Some(parsed) = std::mem::take(&mut line).finish() {
                    output = Some(parsed);
                    break;
                }
                start = index + 1;
            }
        }
        if output.is_none() {
            line.push_bytes(&chunk[start..read]);
        }
    }

    Ok(output
        .or_else(|| line.finish())
        .unwrap_or(VersionOutput::Empty))
}

fn read_stderr_diagnostic(mut stderr: impl Read) -> std::io::Result<Vec<u8>> {
    let mut chunk = [0u8; 8 * 1_024];
    let mut diagnostic = Vec::with_capacity(STDERR_DIAGNOSTIC_MAX_BYTES);
    loop {
        let read = stderr.read(&mut chunk)?;
        if read == 0 {
            return Ok(diagnostic);
        }
        let keep = read.min(STDERR_DIAGNOSTIC_MAX_BYTES - diagnostic.len());
        diagnostic.extend_from_slice(&chunk[..keep]);
    }
}

struct CancellableReader<R> {
    reader: R,
    cancelled: Arc<AtomicBool>,
}

impl<R> CancellableReader<R> {
    fn new(reader: R, cancelled: Arc<AtomicBool>) -> Self {
        Self { reader, cancelled }
    }
}

impl<R: Read> Read for CancellableReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.cancelled.load(Ordering::Acquire) {
                return Ok(0);
            }
            match self.reader.read(buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(PROBE_POLL_INTERVAL);
                }
                result => return result,
            }
        }
    }
}

#[cfg(unix)]
fn make_pipe_cancellable(pipe: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    let file_descriptor = pipe.as_raw_fd();
    // SAFETY: `file_descriptor` is borrowed from a live child pipe. `F_GETFL`
    // and `F_SETFL` do not retain the descriptor or access Rust-managed memory.
    let flags = unsafe { libc::fcntl(file_descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same live descriptor and no retained pointers; this only adds
    // `O_NONBLOCK` to the existing file-status flags.
    if unsafe { libc::fcntl(file_descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_pipe_cancellable<T>(_pipe: &T) -> std::io::Result<()> {
    Ok(())
}

fn reap_after_kill(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn timeout_error(producer: ThumbProducer, timeout: Duration) -> Error {
    Error::ToolNotFound(format!(
        "{} version probe timed out after {} ms",
        producer.as_str(),
        timeout.as_millis()
    ))
}

fn wait_with_deadline(
    child: &mut std::process::Child,
    producer: ThumbProducer,
    started: Instant,
    timeout: Duration,
) -> Result<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() >= timeout => {
                reap_after_kill(child);
                return Err(timeout_error(producer, timeout));
            }
            Ok(None) => {
                thread::sleep(PROBE_POLL_INTERVAL.min(timeout.saturating_sub(started.elapsed())))
            }
            Err(error) => {
                reap_after_kill(child);
                return Err(error.into());
            }
        }
    }
}

fn join_reader<T>(reader: JoinHandle<std::io::Result<T>>) -> Result<T> {
    reader
        .join()
        .map_err(|_| Error::ToolNotFound("version probe output reader panicked".into()))?
        .map_err(Into::into)
}

#[derive(Clone, Default)]
struct ReaderTracker(Option<Arc<AtomicUsize>>);

struct ReaderActivity(Option<Arc<AtomicUsize>>);

impl ReaderTracker {
    fn start(self) -> ReaderActivity {
        if let Some(active) = &self.0 {
            active.fetch_add(1, Ordering::SeqCst);
        }
        ReaderActivity(self.0)
    }
}

impl Drop for ReaderActivity {
    fn drop(&mut self) {
        if let Some(active) = &self.0 {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn spawn_probe_reader<T, F>(
    tracker: ReaderTracker,
    read: F,
) -> std::io::Result<JoinHandle<std::io::Result<T>>>
where
    T: Send + 'static,
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
{
    let activity = tracker.start();
    std::thread::Builder::new().spawn(move || {
        let _activity = activity;
        read()
    })
}

#[cfg(windows)]
fn interrupt_reader<T>(reader: &JoinHandle<T>) {
    use std::os::windows::io::AsRawHandle;

    // SAFETY: `reader` owns a live Windows thread handle. Cancellation is
    // retried until the thread observes the shared flag and exits, covering
    // the race where no synchronous read is pending during one call.
    unsafe {
        let _ = windows_sys::Win32::System::IO::CancelSynchronousIo(
            reader.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE
        );
    }
}

#[cfg(not(windows))]
fn interrupt_reader<T>(_reader: &JoinHandle<T>) {}

struct ProbeReaders {
    stdout: Option<JoinHandle<std::io::Result<VersionOutput>>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    cancelled: Arc<AtomicBool>,
}

impl ProbeReaders {
    fn spawn(
        stdout: std::process::ChildStdout,
        stderr: std::process::ChildStderr,
        tracker: ReaderTracker,
    ) -> std::io::Result<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let stdout_cancelled = Arc::clone(&cancelled);
        let stderr_cancelled = Arc::clone(&cancelled);
        let mut readers = Self {
            stdout: None,
            stderr: None,
            cancelled,
        };
        readers.stdout = Some(spawn_probe_reader(tracker.clone(), move || {
            read_version_stdout(CancellableReader::new(stdout, stdout_cancelled))
        })?);
        readers.stderr = Some(spawn_probe_reader(tracker, move || {
            read_stderr_diagnostic(CancellableReader::new(stderr, stderr_cancelled))
        })?);
        Ok(readers)
    }

    fn is_finished(&self) -> bool {
        self.stdout.as_ref().is_none_or(JoinHandle::is_finished)
            && self.stderr.as_ref().is_none_or(JoinHandle::is_finished)
    }

    fn finish(
        mut self,
        producer: ThumbProducer,
        started: Instant,
        timeout: Duration,
    ) -> Result<(VersionOutput, Vec<u8>)> {
        while !self.is_finished() {
            if started.elapsed() >= timeout {
                return Err(timeout_error(producer, timeout));
            }
            thread::sleep(PROBE_POLL_INTERVAL.min(timeout.saturating_sub(started.elapsed())));
        }
        self.join()
    }

    fn join(&mut self) -> Result<(VersionOutput, Vec<u8>)> {
        let stdout = join_reader(self.stdout.take().expect("stdout reader present"));
        let stderr = join_reader(self.stderr.take().expect("stderr reader present"));
        Ok((stdout?, stderr?))
    }

    fn cancel_and_join(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        while !self.is_finished() {
            if let Some(reader) = &self.stdout {
                interrupt_reader(reader);
            }
            if let Some(reader) = &self.stderr {
                interrupt_reader(reader);
            }
            thread::sleep(PROBE_POLL_INTERVAL);
        }
        if let Some(reader) = self.stdout.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for ProbeReaders {
    fn drop(&mut self) {
        self.cancel_and_join();
    }
}

fn probe_identity_inner(
    path: &Path,
    producer: ThumbProducer,
    command: &'static str,
    timeout: Duration,
    tracker: ReaderTracker,
) -> Result<ProducerIdentity> {
    let executable = std::fs::canonicalize(path)?;
    let started = Instant::now();
    let mut child = Command::new(&executable)
        .arg("-v")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    if let Err(error) = make_pipe_cancellable(&stdout).and_then(|()| make_pipe_cancellable(&stderr))
    {
        reap_after_kill(&mut child);
        return Err(error.into());
    }
    let readers = match ProbeReaders::spawn(stdout, stderr, tracker) {
        Ok(readers) => readers,
        Err(error) => {
            reap_after_kill(&mut child);
            return Err(error.into());
        }
    };

    let status = wait_with_deadline(&mut child, producer, started, timeout)?;
    let (output, diagnostic) = readers.finish(producer, started, timeout)?;

    if !status.success() {
        let status = status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "terminated by signal".into());
        let diagnostic = String::from_utf8_lossy(&diagnostic);
        let diagnostic = diagnostic.trim();
        let detail = if diagnostic.is_empty() {
            String::new()
        } else {
            format!(": {diagnostic}")
        };
        return Err(Error::ToolNotFound(format!(
            "{} version probe exited with status {status}{detail}",
            producer.as_str()
        )));
    }

    let version = match output {
        VersionOutput::Version(version) => version,
        VersionOutput::Empty => {
            return Err(Error::ToolNotFound(format!(
                "{} version probe returned empty stdout",
                producer.as_str()
            )));
        }
        VersionOutput::InvalidUtf8 => {
            return Err(Error::ToolNotFound(format!(
                "{} version probe returned invalid UTF-8 stdout",
                producer.as_str()
            )));
        }
        VersionOutput::Oversized => {
            return Err(Error::ToolNotFound(format!(
                "{} version probe first non-empty stdout line exceeds 1,024 bytes",
                producer.as_str()
            )));
        }
    };

    Ok(ProducerIdentity {
        producer,
        executable,
        version,
        command,
    })
}

fn probe_identity(
    path: &Path,
    producer: ThumbProducer,
    command: &'static str,
    timeout: Duration,
) -> Result<ProducerIdentity> {
    probe_identity_inner(path, producer, command, timeout, ReaderTracker::default())
}

#[cfg(test)]
fn probe_identity_with_reader_tracking(
    path: &Path,
    producer: ThumbProducer,
    command: &'static str,
    timeout: Duration,
    active_readers: Arc<AtomicUsize>,
) -> Result<ProducerIdentity> {
    probe_identity_inner(
        path,
        producer,
        command,
        timeout,
        ReaderTracker(Some(active_readers)),
    )
}

fn discover(executable: &str, producer: ThumbProducer) -> Result<ProducerIdentity> {
    let path = find_executable(executable).ok_or_else(|| {
        Error::ToolNotFound(format!(
            "{} ({executable}) not found on PATH",
            producer.as_str()
        ))
    })?;
    probe_identity(&path, producer, producer.command(), VERSION_PROBE_TIMEOUT)
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = directory.join(format!("{name}.exe"));
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        ProducerIdentity, ThumbProducer, probe_identity as probe_identity_once,
        probe_identity_with_reader_tracking as probe_identity_with_reader_tracking_once,
    };
    use crate::analysis_tool::AnalysisTool;
    use crate::error::{Error, Result};
    use std::fs;
    use std::io;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn retry_executable_busy<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
        for attempt in 1..=5 {
            match operation() {
                Err(Error::Io(error))
                    if error.kind() == io::ErrorKind::ExecutableFileBusy && attempt < 5 =>
                {
                    std::thread::sleep(Duration::from_millis(5 * attempt));
                }
                result => return result,
            }
        }
        unreachable!()
    }

    fn probe_identity(
        executable: &Path,
        producer: ThumbProducer,
        command: &'static str,
        timeout: Duration,
    ) -> Result<ProducerIdentity> {
        retry_executable_busy(|| probe_identity_once(executable, producer, command, timeout))
    }

    fn probe_identity_with_reader_tracking(
        executable: &Path,
        producer: ThumbProducer,
        command: &'static str,
        timeout: Duration,
        active_readers: Arc<AtomicUsize>,
    ) -> Result<ProducerIdentity> {
        retry_executable_busy(|| {
            probe_identity_with_reader_tracking_once(
                executable,
                producer,
                command,
                timeout,
                Arc::clone(&active_readers),
            )
        })
    }

    fn tool_script(body: &str) -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nset -eu\n\
                 if [ \"$#\" -ne 1 ] || [ \"$1\" != \"-v\" ]; then\n\
                   exit 97\n\
                 fi\n\
                 {body}\n"
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        (dir, path)
    }

    #[test]
    fn executable_busy_retry_retries_the_transient_failure() {
        let mut attempts = 0;
        let value = retry_executable_busy(|| {
            attempts += 1;
            if attempts < 3 {
                Err(Error::Io(io::Error::from(
                    io::ErrorKind::ExecutableFileBusy,
                )))
            } else {
                Ok("ready")
            }
        })
        .unwrap();

        assert_eq!(value, "ready");
        assert_eq!(attempts, 3);
    }

    #[test]
    fn thumb_producer_exposes_exact_ids_commands_and_analysis_tools() {
        assert_eq!(ThumbProducer::Radare2.as_str(), "radare2");
        assert_eq!(ThumbProducer::Rizin.as_str(), "rizin");
        assert_eq!(ThumbProducer::Radare2.command(), "aaa;aflj;pdfj @@f");
        assert_eq!(ThumbProducer::Rizin.command(), "aaa;aflj;pdfj @@F;axlj");
        assert_eq!(
            serde_json::to_string(&ThumbProducer::Radare2).unwrap(),
            "\"radare2\""
        );
        assert_eq!(
            serde_json::to_string(&ThumbProducer::Rizin).unwrap(),
            "\"rizin\""
        );
        assert_eq!(
            AnalysisTool::from(ThumbProducer::Radare2),
            AnalysisTool::Radare2
        );
        assert_eq!(
            AnalysisTool::from(ThumbProducer::Rizin),
            AnalysisTool::Rizin
        );
    }

    #[test]
    fn probe_version_uses_first_trimmed_stdout_line_and_canonical_path() {
        let (dir, script) = tool_script("printf '\\n  rizin 0.8.2  \\nignored\\n'");
        let alias = dir.path().join("tool-alias");
        symlink(&script, &alias).unwrap();

        let identity = probe_identity(
            &alias,
            ThumbProducer::Rizin,
            ThumbProducer::Rizin.command(),
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(identity.producer, ThumbProducer::Rizin);
        assert_eq!(identity.executable, fs::canonicalize(script).unwrap());
        assert_eq!(identity.version, "rizin 0.8.2");
        assert_eq!(identity.command, "aaa;aflj;pdfj @@F;axlj");
    }

    #[test]
    fn probe_version_rejects_empty_stdout_even_with_stderr() {
        let (_dir, script) = tool_script(
            "printf 'radare2 5.9.0\\n' >&2\n\
             printf '\\n   \\n'",
        );

        let error = probe_identity(
            &script,
            ThumbProducer::Radare2,
            ThumbProducer::Radare2.command(),
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(error.to_string().contains("empty stdout"), "{error}");
    }

    #[test]
    fn probe_version_rejects_invalid_utf8() {
        let (_dir, script) = tool_script("printf '\\377\\n'");

        let error = probe_identity(
            &script,
            ThumbProducer::Radare2,
            ThumbProducer::Radare2.command(),
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(error.to_string().contains("UTF-8"), "{error}");
    }

    #[test]
    fn probe_version_accepts_a_1024_byte_first_line() {
        let version = "v".repeat(1_024);
        let (_dir, script) = tool_script(&format!("printf '%s\\n' '{version}'"));

        let identity = probe_identity(
            &script,
            ThumbProducer::Radare2,
            ThumbProducer::Radare2.command(),
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(identity.version, version);
    }

    #[test]
    fn probe_version_applies_the_size_limit_after_trimming() {
        let version = "v".repeat(1_024);
        let line = format!("{}{version}{}", " ".repeat(1_500), " ".repeat(1_500));
        let (_dir, script) = tool_script(&format!("printf '%s\\n' '{line}'"));

        let identity = probe_identity(
            &script,
            ThumbProducer::Radare2,
            ThumbProducer::Radare2.command(),
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(identity.version, version);
    }

    #[test]
    fn probe_version_skips_an_oversized_whitespace_only_line() {
        let whitespace = " ".repeat(2_048);
        let (_dir, script) = tool_script(&format!("printf '%s\\nradare2 5.9.0\\n' '{whitespace}'"));

        let identity = probe_identity(
            &script,
            ThumbProducer::Radare2,
            ThumbProducer::Radare2.command(),
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(identity.version, "radare2 5.9.0");
    }

    #[test]
    fn probe_version_rejects_a_1025_byte_first_line() {
        let version = "v".repeat(1_025);
        let (_dir, script) = tool_script(&format!("printf '%s\\n' '{version}'"));

        let error = probe_identity(
            &script,
            ThumbProducer::Radare2,
            ThumbProducer::Radare2.command(),
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(error.to_string().contains("1,024 bytes"), "{error}");
    }

    #[test]
    fn probe_version_rejects_nonzero_exit_and_reports_stderr() {
        let (_dir, script) = tool_script(
            "printf 'radare2 5.9.0\\n'\n\
             printf 'probe diagnostic\\n' >&2\n\
             exit 7",
        );

        let error = probe_identity(
            &script,
            ThumbProducer::Radare2,
            ThumbProducer::Radare2.command(),
            Duration::from_secs(1),
        )
        .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("status 7"), "{message}");
        assert!(message.contains("probe diagnostic"), "{message}");
    }

    #[test]
    fn probe_version_honors_an_injected_short_timeout() {
        let (_dir, script) = tool_script("while :; do :; done");
        let started = Instant::now();

        let error = probe_identity(
            &script,
            ThumbProducer::Radare2,
            ThumbProducer::Radare2.command(),
            Duration::from_millis(20),
        )
        .unwrap_err();

        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn probe_version_timeout_joins_readers_with_inherited_pipes() {
        let (_dir, script) = tool_script("sleep 1 &\nexit 0");
        let active_readers = Arc::new(AtomicUsize::new(0));

        let error = probe_identity_with_reader_tracking(
            &script,
            ThumbProducer::Radare2,
            ThumbProducer::Radare2.command(),
            Duration::from_millis(20),
            Arc::clone(&active_readers),
        )
        .unwrap_err();

        assert!(error.to_string().contains("timed out"), "{error}");
        assert_eq!(
            active_readers.load(Ordering::SeqCst),
            0,
            "probe detached reader threads"
        );
    }
}
