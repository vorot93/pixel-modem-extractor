//! Analyzer discovery, canonical identity, version probing, and probe-process handling.

use super::{ProducerIdentity, ThumbProducer};
use crate::error::{Error, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use typed_path::{
    Utf8Component, Utf8UnixComponent, Utf8UnixPath, Utf8WindowsComponent, Utf8WindowsPath,
    Utf8WindowsPrefix,
};

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const VERSION_LINE_MAX_BYTES: usize = 1_024;
const STDERR_DIAGNOSTIC_MAX_BYTES: usize = 4_096;
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(5);
/// Bound probe-child termination, reaping, and forced reader cancellation.
/// Without it the declared 10-second probe deadline would only bound when
/// cleanup starts, not when the probe returns.
const PROBE_CLEANUP_LIMIT: Duration = Duration::from_secs(1);

/// How a producer identity is being checked.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum IdentityMode {
    /// A retained artifact records the host that produced it, which may be a
    /// different OS family with paths this host cannot resolve. Only the
    /// lexical spelling can be verified.
    Artifact,
    /// A runtime identity is what the coordinator will spawn and what v3 will
    /// record as the executable actually used, so it must additionally name an
    /// executable file on *this* host that resolves to exactly that spelling.
    Runtime,
}

/// The single producer-identity check shared by the coordinator and every
/// artifact reader. Returns the reason the identity is unusable, so each caller
/// can wrap it in its own error vocabulary.
pub(super) fn producer_identity_error(
    identity: &ProducerIdentity,
    expected: ThumbProducer,
    mode: IdentityMode,
) -> Option<String> {
    let producer = expected.as_str();
    if identity.producer != expected {
        return Some(format!(
            "Thumb {producer} producer identity has the wrong backend"
        ));
    }
    if identity.command != expected.command() {
        return Some(format!(
            "{producer} producer command does not match the v3 schema"
        ));
    }
    if identity.version.is_empty()
        || identity.version.trim() != identity.version
        || identity.version.contains(['\r', '\n'])
    {
        return Some(format!("{producer} producer version is not normalized"));
    }
    // Discovery cannot produce a longer version, so a longer one did not come
    // from a version probe.
    if identity.version.len() > VERSION_LINE_MAX_BYTES {
        return Some(format!(
            "{producer} producer version exceeds the {VERSION_LINE_MAX_BYTES}-byte discovery bound"
        ));
    }
    if !is_canonical_executable_path(&identity.executable) {
        return Some(format!(
            "{producer} producer executable must be a canonical absolute path"
        ));
    }
    match mode {
        IdentityMode::Artifact => None,
        IdentityMode::Runtime => runtime_executable_error(&identity.executable, producer),
    }
}

fn runtime_executable_error(executable: &Path, producer: &str) -> Option<String> {
    if !is_canonical_native_executable_path(executable) {
        return Some(format!(
            "{producer} producer executable {} is not a canonical path for this host",
            executable.display()
        ));
    }
    let resolved = match std::fs::canonicalize(executable) {
        Ok(resolved) => resolved,
        Err(error) => {
            return Some(format!(
                "{producer} producer executable {} cannot be resolved: {error}",
                executable.display()
            ));
        }
    };
    if resolved != executable {
        return Some(format!(
            "{producer} producer executable {} is not the canonical path of {}",
            executable.display(),
            resolved.display()
        ));
    }
    if !is_executable(executable) {
        return Some(format!(
            "{producer} producer executable {} is not an executable file",
            executable.display()
        ));
    }
    None
}

pub(super) fn is_canonical_executable_path(path: &Path) -> bool {
    let Some(spelling) = path.to_str() else {
        return false;
    };
    is_canonical_unix_executable_path(spelling) || is_canonical_windows_executable_path(spelling)
}

/// Canonical spelling for *this* host's path family. A runtime identity in the
/// other family cannot name a file the coordinator will spawn.
fn is_canonical_native_executable_path(path: &Path) -> bool {
    let Some(spelling) = path.to_str() else {
        return false;
    };
    if cfg!(windows) {
        is_canonical_windows_executable_path(spelling)
    } else {
        is_canonical_unix_executable_path(spelling)
    }
}

fn is_canonical_unix_executable_path(spelling: &str) -> bool {
    if !spelling.starts_with('/')
        || spelling.ends_with('/')
        || spelling.contains("//")
        || spelling.contains('\0')
    {
        return false;
    }
    let mut components = Utf8UnixPath::new(spelling).components();
    if !matches!(components.next(), Some(Utf8UnixComponent::RootDir)) {
        return false;
    }
    let mut saw_name = false;
    components.all(|component| match component {
        Utf8UnixComponent::Normal(name) if name != "." && name != ".." => {
            saw_name = true;
            true
        }
        _ => false,
    }) && saw_name
}

fn is_canonical_windows_executable_path(spelling: &str) -> bool {
    if !spelling.starts_with(r"\\?\")
        || spelling.ends_with('\\')
        || spelling.contains('/')
        || spelling.contains('\0')
    {
        return false;
    }
    let path = Utf8WindowsPath::new(spelling);
    if !path.is_absolute() {
        return false;
    }
    let mut components = path.components();
    let prefix = match components.next() {
        Some(Utf8WindowsComponent::Prefix(prefix)) => prefix,
        _ => return false,
    };
    match prefix.kind() {
        Utf8WindowsPrefix::Verbatim(name) if is_valid_windows_component(name) => {}
        Utf8WindowsPrefix::VerbatimDisk(letter) if letter.is_ascii_alphabetic() => {}
        Utf8WindowsPrefix::VerbatimUNC(server, share)
            if is_valid_windows_component(server) && is_valid_windows_component(share) => {}
        _ => return false,
    }
    if !matches!(components.next(), Some(Utf8WindowsComponent::RootDir)) {
        return false;
    }
    // The raw split is authoritative: the component iterator normalizes `.`
    // away, so a non-canonical spelling would otherwise survive.
    let Some(tail) = spelling
        .get(prefix.as_str().len()..)
        .and_then(|suffix| suffix.strip_prefix('\\'))
    else {
        return false;
    };
    if !tail.split('\\').all(is_valid_windows_component) {
        return false;
    }
    let mut saw_name = false;
    components.all(|component| match component {
        Utf8WindowsComponent::Normal(_) if component.is_valid() => {
            saw_name = true;
            true
        }
        _ => false,
    }) && saw_name
}

/// Windows names that address a character device rather than a file, in any
/// directory and with any extension. Discovery resolves a real executable, so
/// an identity naming one of these did not come from discovery.
const WINDOWS_RESERVED_DEVICE_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// One canonical Windows path component. `Utf8Component::is_valid` rejects NUL
/// and separators but accepts reserved device names, trailing spaces/dots, and
/// the characters Win32 reserves — none of which discovery can produce.
fn is_valid_windows_component(component: &str) -> bool {
    if component.is_empty() || component == "." || component == ".." {
        return false;
    }
    if component.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
    }) {
        return false;
    }
    if component.ends_with(' ') || component.ends_with('.') {
        return false;
    }
    let stem = component.split('.').next().unwrap_or(component);
    !WINDOWS_RESERVED_DEVICE_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

#[cfg(test)]
mod path_validation_tests {
    use super::{
        IdentityMode, ProducerIdentity, ThumbProducer, is_canonical_executable_path,
        producer_identity_error,
    };
    use std::path::{Path, PathBuf};

    fn artifact_identity(executable: &str, version: &str) -> ProducerIdentity {
        ProducerIdentity {
            producer: ThumbProducer::Radare2,
            executable: PathBuf::from(executable),
            version: version.to_owned(),
            command: ThumbProducer::Radare2.command(),
        }
    }

    /// Discovery canonicalizes a real executable, so it can never yield a
    /// reserved device name, a Win32-reserved character, or an unusable
    /// verbatim prefix. Accepting those admits identities no probe produced.
    #[test]
    fn canonical_windows_paths_reject_reserved_names_and_prefixes() {
        for accepted in [
            r"\\?\C:\Program Files\radare2\r2.exe",
            r"\\?\UNC\server\share\r2.exe",
            r"\\?\cat_pics\r2.exe",
        ] {
            assert!(
                is_canonical_executable_path(Path::new(accepted)),
                "{accepted}"
            );
        }

        for rejected in [
            r"\\?\C:\bin\CON",
            r"\\?\C:\bin\nul.exe",
            r"\\?\C:\bin\LPT9.exe",
            r"\\?\C:\bin\r2 ",
            r"\\?\C:\bin\r2.",
            r"\\?\C:\bin\r*2.exe",
            r"\\?\C:\bin\r|2.exe",
            r"\\?\CON\r2.exe",
            r"\\?\UNC\CON\share\r2.exe",
            r"\\?\UNC\server\PRN\r2.exe",
            r"\\?\UNC\\share\r2.exe",
            r"\\?\1:\bin\r2.exe",
        ] {
            assert!(
                !is_canonical_executable_path(Path::new(rejected)),
                "{rejected}"
            );
        }
    }

    #[test]
    fn producer_identity_rejects_versions_beyond_the_discovery_bound() {
        let accepted = artifact_identity("/usr/bin/r2", &"v".repeat(1_024));
        assert_eq!(
            producer_identity_error(&accepted, ThumbProducer::Radare2, IdentityMode::Artifact),
            None
        );

        let oversized = artifact_identity("/usr/bin/r2", &"v".repeat(1_025));
        let reason =
            producer_identity_error(&oversized, ThumbProducer::Radare2, IdentityMode::Artifact)
                .expect("an oversized version cannot come from discovery");

        assert!(reason.contains("1024-byte discovery bound"), "{reason}");
    }
}

enum VersionOutput {
    Empty,
    InvalidUtf8,
    Oversized,
    Version(String),
}

/// Incremental UTF-8 decoder: hands each complete prefix to a sink and carries
/// a sequence split across reads into the next chunk.
#[derive(Default)]
struct Utf8Decoder {
    tail: Vec<u8>,
    invalid: bool,
}

impl Utf8Decoder {
    fn push(&mut self, bytes: &[u8], on_text: impl FnOnce(&str)) {
        if self.invalid {
            return;
        }
        let mut input = Vec::with_capacity(self.tail.len() + bytes.len());
        input.append(&mut self.tail);
        input.extend_from_slice(bytes);
        match std::str::from_utf8(&input) {
            Ok(text) => on_text(text),
            Err(error) => {
                let valid_up_to = error.valid_up_to();
                let valid =
                    std::str::from_utf8(&input[..valid_up_to]).expect("UTF-8 error valid prefix");
                on_text(valid);
                if error.error_len().is_none() {
                    self.tail.extend_from_slice(&input[valid_up_to..]);
                } else {
                    self.invalid = true;
                }
            }
        }
    }

    /// Input is valid UTF-8 only when nothing was rejected and no sequence is
    /// left incomplete at end of stream.
    fn is_complete(&self) -> bool {
        !self.invalid && self.tail.is_empty()
    }
}

/// Incrementally trims one UTF-8 line while retaining at most the accepted
/// version bytes. Trailing whitespace is committed only if content follows it.
#[derive(Default)]
struct VersionLine {
    content: Vec<u8>,
    trailing_whitespace: Vec<u8>,
    trailing_whitespace_overflow: bool,
    decoder: Utf8Decoder,
    oversized: bool,
}

impl VersionLine {
    fn push_bytes(&mut self, bytes: &[u8]) {
        let mut decoder = std::mem::take(&mut self.decoder);
        decoder.push(bytes, |text| self.push_str(text));
        self.decoder = decoder;
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
        if !self.decoder.is_complete() {
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
    // Preflight requires successful stdout to be UTF-8, so the bytes drained
    // after the selected line are validated too — they are just not retained.
    let mut drained = Utf8Decoder::default();

    loop {
        let read = stdout.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let mut start = 0;
        if output.is_none() {
            for (index, &byte) in chunk[..read].iter().enumerate() {
                if byte == b'\n' {
                    line.push_bytes(&chunk[start..index]);
                    start = index + 1;
                    if let Some(parsed) = std::mem::take(&mut line).finish() {
                        output = Some(parsed);
                        break;
                    }
                }
            }
            if output.is_none() {
                line.push_bytes(&chunk[start..read]);
                start = read;
            }
        }
        drained.push(&chunk[start..read], |_| {});
    }

    let output = output.or_else(|| line.finish());
    if !drained.is_complete() {
        return Ok(VersionOutput::InvalidUtf8);
    }
    Ok(output.unwrap_or(VersionOutput::Empty))
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

/// Terminate a probe child and reap it, reporting both outcomes. Silently
/// discarding them would leave an unverified probe process behind while the
/// probe reports only its own failure.
fn kill_and_reap(child: &mut std::process::Child) -> std::io::Result<()> {
    kill_and_reap_within(child, PROBE_CLEANUP_LIMIT)
}

fn kill_and_reap_within(child: &mut std::process::Child, limit: Duration) -> std::io::Result<()> {
    let mut first_error = None;
    // An already-reaped child cannot be signalled; that is not a failure.
    if let Err(error) = child.kill()
        && error.kind() != std::io::ErrorKind::InvalidInput
    {
        first_error = Some(error);
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return first_error.map_or(Ok(()), Err),
            Ok(None) if started.elapsed() >= limit => {
                return Err(first_error.unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "version probe child was not reaped before the cleanup deadline",
                    )
                }));
            }
            Ok(None) => thread::sleep(PROBE_POLL_INTERVAL),
            Err(error) => return Err(first_error.unwrap_or(error)),
        }
    }
}

/// Fold a probe-cleanup failure into the probe's own error so an unverified
/// probe child or reader is never reported as a bare timeout or I/O failure.
fn with_probe_cleanup(primary: Error, cleanup: std::io::Result<()>) -> Error {
    match cleanup {
        Ok(()) => primary,
        Err(error) => {
            Error::ToolNotFound(format!("{primary}; version probe cleanup failed: {error}"))
        }
    }
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
                return Err(with_probe_cleanup(
                    timeout_error(producer, timeout),
                    kill_and_reap(child),
                ));
            }
            Ok(None) => {
                thread::sleep(PROBE_POLL_INTERVAL.min(timeout.saturating_sub(started.elapsed())))
            }
            Err(error) => {
                return Err(with_probe_cleanup(error.into(), kill_and_reap(child)));
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
fn interrupt_reader<T>(reader: &JoinHandle<T>) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    // SAFETY: `reader` owns a live Windows thread handle. Cancellation is
    // retried until the thread observes the shared flag and exits, covering
    // the race where no synchronous read is pending during one call.
    let cancelled = unsafe {
        windows_sys::Win32::System::IO::CancelSynchronousIo(
            reader.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE
        )
    };
    if cancelled != 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    // No synchronous read was pending, so the shared flag alone stops the
    // reader on its next poll. Every other failure is real and reportable.
    if error.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_NOT_FOUND as i32) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(not(windows))]
fn interrupt_reader<T>(_reader: &JoinHandle<T>) -> std::io::Result<()> {
    Ok(())
}

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
                let cleanup = self.cancel_and_join();
                return Err(with_probe_cleanup(
                    timeout_error(producer, timeout),
                    cleanup,
                ));
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

    fn cancel_and_join(&mut self) -> std::io::Result<()> {
        self.cancel_and_join_within(PROBE_CLEANUP_LIMIT)
    }

    /// Cancel both readers and join them within `limit`. A reader that never
    /// observes cancellation is detached and reported: joining it would hang
    /// the probe past its declared deadline.
    fn cancel_and_join_within(&mut self, limit: Duration) -> std::io::Result<()> {
        self.cancelled.store(true, Ordering::Release);
        let started = Instant::now();
        let mut first_error = None;
        while !self.is_finished() {
            let interrupted = self
                .stdout
                .as_ref()
                .map_or(Ok(()), interrupt_reader)
                .and_then(|()| self.stderr.as_ref().map_or(Ok(()), interrupt_reader));
            if let Err(error) = interrupted
                && first_error.is_none()
            {
                first_error = Some(error);
            }
            if started.elapsed() >= limit {
                // Detach rather than join: a reader that ignores cancellation
                // would otherwise block the probe past its declared deadline.
                self.stdout = None;
                self.stderr = None;
                return Err(first_error.unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "version probe output readers did not stop before the cleanup deadline",
                    )
                }));
            }
            thread::sleep(PROBE_POLL_INTERVAL);
        }
        let panicked = self
            .stdout
            .take()
            .is_some_and(|reader| reader.join().is_err())
            | self
                .stderr
                .take()
                .is_some_and(|reader| reader.join().is_err());
        if panicked && first_error.is_none() {
            first_error = Some(std::io::Error::other(
                "version probe output reader panicked",
            ));
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for ProbeReaders {
    fn drop(&mut self) {
        if let Err(error) = self.cancel_and_join() {
            tracing::error!("version probe output readers could not be stopped: {error}");
        }
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
        return Err(with_probe_cleanup(error.into(), kill_and_reap(&mut child)));
    }
    let readers = match ProbeReaders::spawn(stdout, stderr, tracker) {
        Ok(readers) => readers,
        Err(error) => {
            return Err(with_probe_cleanup(error.into(), kill_and_reap(&mut child)));
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

#[cfg(all(test, unix))]
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

pub(super) fn discover(executable: &str, producer: ThumbProducer) -> Result<ProducerIdentity> {
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
        assert!(super::is_canonical_executable_path(&identity.executable));
        assert_eq!(identity.version, "rizin 0.8.2");
        assert_eq!(identity.command, "aaa;aflj;pdfj @@F;axlj");
    }

    fn runtime_identity(executable: PathBuf) -> ProducerIdentity {
        ProducerIdentity {
            producer: ThumbProducer::Radare2,
            executable,
            version: "radare2 5.9.0".into(),
            command: ThumbProducer::Radare2.command(),
        }
    }

    fn runtime_reason(identity: &ProducerIdentity) -> Option<String> {
        super::producer_identity_error(
            identity,
            ThumbProducer::Radare2,
            super::IdentityMode::Runtime,
        )
    }

    /// A runtime identity is spawned and then recorded as the executable
    /// actually used, so a lexically canonical spelling is not enough: it must
    /// resolve to itself on this host and name an executable file.
    #[test]
    fn runtime_identity_requires_a_resolved_native_executable() {
        let (dir, script) = tool_script("printf 'radare2 5.9.0\\n'");
        let root = fs::canonicalize(dir.path()).unwrap();
        let alias = root.join("tool-alias");
        symlink(&script, &alias).unwrap();
        let data = root.join("not-a-tool");
        fs::write(&data, b"data").unwrap();

        let canonical = runtime_identity(fs::canonicalize(&script).unwrap());
        assert_eq!(runtime_reason(&canonical), None);

        for (case, executable, expected) in [
            ("symlink spelling", alias, "is not the canonical path of"),
            ("non-executable file", data, "is not an executable file"),
            ("missing file", root.join("absent"), "cannot be resolved"),
            (
                "other host family",
                PathBuf::from(r"\\?\C:\bin\r2.exe"),
                "is not a canonical path for this host",
            ),
        ] {
            let identity = runtime_identity(executable);
            // The same spelling is acceptable when read back from a retained
            // artifact produced on another host.
            assert_eq!(
                super::producer_identity_error(
                    &identity,
                    ThumbProducer::Radare2,
                    super::IdentityMode::Artifact,
                ),
                None,
                "{case} must stay readable as artifact provenance"
            );
            let reason = runtime_reason(&identity).unwrap_or_else(|| panic!("{case} was accepted"));
            assert!(reason.contains(expected), "{case}: {reason}");
        }
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

    /// Preflight requires successful stdout to be UTF-8, not merely its first
    /// non-empty line: bytes drained after the version line are still checked.
    #[test]
    fn probe_version_rejects_invalid_utf8_after_the_selected_line() {
        for (case, body) in [
            ("invalid sequence", "printf 'radare2 5.9.0\\n\\377\\n'"),
            ("truncated sequence", "printf 'radare2 5.9.0\\n\\303'"),
        ] {
            let (_dir, script) = tool_script(body);

            let error = probe_identity(
                &script,
                ThumbProducer::Radare2,
                ThumbProducer::Radare2.command(),
                Duration::from_secs(1),
            )
            .unwrap_err();

            assert!(error.to_string().contains("UTF-8"), "{case}: {error}");
        }
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

    /// The declared probe deadline must bound when the API returns, not only
    /// when cancellation starts. A reader that never observes cancellation is
    /// detached and reported instead of looping forever.
    #[test]
    fn stuck_probe_readers_are_detached_within_the_cancellation_bound() {
        let mut readers = super::ProbeReaders {
            stdout: Some(std::thread::spawn(|| {
                std::thread::sleep(Duration::from_secs(5));
                Ok(super::VersionOutput::Empty)
            })),
            stderr: Some(std::thread::spawn(|| {
                std::thread::sleep(Duration::from_secs(5));
                Ok(Vec::new())
            })),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let started = Instant::now();

        let error = readers
            .cancel_and_join_within(Duration::from_millis(50))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(readers.stdout.is_none() && readers.stderr.is_none());
    }

    #[test]
    fn probe_cleanup_kills_reaps_and_reports_its_outcome() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();

        super::kill_and_reap(&mut child).unwrap();

        assert!(child.try_wait().unwrap().is_some(), "child was not reaped");
        // A second cleanup of the same reaped child is still verified, not an
        // error: the kill can only report that the process is already gone.
        super::kill_and_reap(&mut child).unwrap();
    }

    #[test]
    fn probe_cleanup_failure_is_folded_into_the_probe_error() {
        let folded = super::with_probe_cleanup(
            super::timeout_error(ThumbProducer::Rizin, Duration::from_millis(10)),
            Err(io::Error::other("child is unreapable")),
        );
        let message = folded.to_string();

        assert!(message.contains("timed out"), "{message}");
        assert!(message.contains("child is unreapable"), "{message}");
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
