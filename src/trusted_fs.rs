use crate::error::{Error, Result};
#[cfg(unix)]
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as _;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(windows)]
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
#[cfg(windows)]
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0, FILE_SYNCHRONOUS_IO_NONALERT,
    FileDispositionInformation, FileRenameInformation, NtCreateFile, NtSetInformationFile,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
    UNICODE_STRING,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, GetFileInformationByHandle, SYNCHRONIZE,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const MAX_TEMP_ATTEMPTS: usize = 128;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
#[cfg(windows)]
const WINDOWS_DIRECTORY_ACCESS: FILE_ACCESS_RIGHTS =
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

#[cfg(all(test, unix))]
type ContainedOpenHook = Option<(String, Box<dyn FnOnce()>)>;

#[cfg(all(test, unix))]
thread_local! {
    static BEFORE_CONTAINED_OPEN: std::cell::RefCell<ContainedOpenHook> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, unix))]
pub(crate) fn set_before_contained_open(context: &str, hook: impl FnOnce() + 'static) {
    BEFORE_CONTAINED_OPEN.with(|slot| {
        assert!(
            slot.borrow_mut()
                .replace((context.to_owned(), Box::new(hook)))
                .is_none()
        );
    });
}

#[cfg(all(test, unix))]
fn run_before_contained_open(context: &str) {
    BEFORE_CONTAINED_OPEN.with(|slot| {
        let should_run = slot
            .borrow()
            .as_ref()
            .is_some_and(|(target, _)| target == context);
        if should_run {
            let (_, hook) = slot.borrow_mut().take().unwrap();
            hook();
        }
    });
}

#[cfg(not(all(test, unix)))]
fn run_before_contained_open(_context: &str) {}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    file: u64,
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct TrustedDirectory {
    // Every descendant lookup and mutation is relative to this retained capability.
    file: File,
}

#[cfg(unix)]
impl TrustedDirectory {
    pub(crate) fn open_existing(path: &Path, context: &str) -> Result<Option<Self>> {
        let file = match open_unix_root(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(bad(format!(
                    "{context} cannot be opened without following its final component: {error}"
                )));
            }
        };
        let metadata = file
            .metadata()
            .map_err(|error| bad(format!("{context} metadata is unavailable: {error}")))?;
        if !metadata.is_dir() {
            return Err(bad(format!("{context} is not a directory")));
        }
        Ok(Some(Self { file }))
    }

    pub(crate) fn new(path: &Path, context: &str) -> Result<Self> {
        Self::open_existing(path, context)?.ok_or_else(|| bad(format!("{context} does not exist")))
    }

    pub(crate) fn open_regular_file_with_parent(
        &self,
        relative: &Path,
        context: &str,
    ) -> Result<(File, Self)> {
        validate_relative_path(relative, context)?;
        run_before_contained_open(context);
        let file_name = relative
            .file_name()
            .ok_or_else(|| bad(format!("{context} path has no file name")))?;
        let parent =
            self.open_directory(relative.parent().unwrap_or_else(|| Path::new("")), context)?;
        let file = open_unix_regular_component(&parent.file, file_name, context)?;
        Ok((file, parent))
    }

    pub(crate) fn open_regular_file(&self, relative: &Path, context: &str) -> Result<File> {
        self.open_regular_file_with_parent(relative, context)
            .map(|(file, _)| file)
    }

    pub(crate) fn open_directory_child(&self, name: &str, context: &str) -> Result<Option<Self>> {
        let name = unix_component(name, context)?;
        match open_unix_component_io(
            &self.file,
            &name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        ) {
            Ok(file) => Ok(Some(Self { file })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(bad(format!(
                "{context} directory component cannot be opened without following links: {error}"
            ))),
        }
    }

    pub(crate) fn open_or_create_directory_child(&self, name: &str, context: &str) -> Result<Self> {
        let component = unix_component(name, context)?;
        // SAFETY: `self.file` is a live directory and `component` is one NUL-terminated name.
        let created = unsafe { libc::mkdirat(self.file.as_raw_fd(), component.as_ptr(), 0o777) };
        if created != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(bad(format!("{context} cannot be created: {error}")));
            }
        }
        self.open_directory_child(name, context)?
            .ok_or_else(|| bad(format!("{context} disappeared after creation")))
    }

    pub(crate) fn require_regular_file_or_absent(&self, name: &str, context: &str) -> Result<()> {
        match unix_entry_kind(&self.file, name, context)? {
            None | Some(UnixEntryKind::Regular) => Ok(()),
            Some(UnixEntryKind::Symlink) => Err(bad(format!("{context} is a symlink"))),
            Some(_) => Err(bad(format!("{context} is not a regular file"))),
        }
    }

    pub(crate) fn unlink_regular_file_if_exists(&self, name: &str, context: &str) -> Result<bool> {
        match unix_entry_kind(&self.file, name, context)? {
            None => return Ok(false),
            Some(UnixEntryKind::Regular) => {}
            Some(UnixEntryKind::Symlink) => return Err(bad(format!("{context} is a symlink"))),
            Some(_) => return Err(bad(format!("{context} is not a regular file"))),
        }
        let component = unix_component(name, context)?;
        // SAFETY: `self.file` is a live directory and `component` is one NUL-terminated name.
        let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), component.as_ptr(), 0) };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(bad(format!("{context} cannot be removed: {error}")))
        }
    }

    pub(crate) fn remove_child_directory_if_empty(
        &self,
        name: &str,
        child: &Self,
        context: &str,
    ) -> Result<()> {
        let Some(current) = self.open_directory_child(name, context)? else {
            return Ok(());
        };
        let current_metadata = current
            .file
            .metadata()
            .map_err(|error| bad(format!("{context} metadata is unavailable: {error}")))?;
        let child_metadata = child.file.metadata().map_err(|error| {
            bad(format!(
                "{context} retained metadata is unavailable: {error}"
            ))
        })?;
        if (current_metadata.dev(), current_metadata.ino())
            != (child_metadata.dev(), child_metadata.ino())
        {
            return Ok(());
        }
        let component = unix_component(name, context)?;
        // The identity check prevents an already-replaced name from being removed. This cleanup
        // is non-authoritative and callers must ignore a concurrent rename or non-empty result.
        // SAFETY: `self.file` is a live directory and `component` is one NUL-terminated name.
        let result = unsafe {
            libc::unlinkat(
                self.file.as_raw_fd(),
                component.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(bad(format!(
                "{context} cannot be removed: {}",
                io::Error::last_os_error()
            )))
        }
    }

    pub(crate) fn atomic_write_file(
        &self,
        target: &str,
        context: &str,
    ) -> Result<TrustedAtomicFile> {
        self.require_regular_file_or_absent(target, context)?;
        let destination_metadata = unix_entry_metadata(&self.file, target, context)?;
        match destination_metadata.as_ref().map(unix_entry_kind_from_stat) {
            None | Some(UnixEntryKind::Regular) => {}
            Some(UnixEntryKind::Symlink) => return Err(bad(format!("{context} is a symlink"))),
            Some(_) => return Err(bad(format!("{context} is not a regular file"))),
        }
        let target = unix_component(target, context)?;
        let parent = self.file.try_clone().map_err(|error| {
            bad(format!(
                "{context} parent handle cannot be retained: {error}"
            ))
        })?;
        for _ in 0..MAX_TEMP_ATTEMPTS {
            let temporary_name = temporary_name(target.to_string_lossy().as_ref());
            let temporary = unix_component(&temporary_name, context)?;
            let descriptor = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    temporary.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o666,
                )
            };
            if descriptor >= 0 {
                // SAFETY: `openat` returned a new owned descriptor on success.
                let file = unsafe { File::from_raw_fd(descriptor) };
                let atomic = TrustedAtomicFile {
                    file,
                    parent,
                    target,
                    temporary,
                    finalized: false,
                };
                if let Some(metadata) = destination_metadata.as_ref() {
                    atomic.preserve_metadata(metadata).map_err(|error| {
                        bad(format!(
                            "{context} existing metadata cannot be preserved: {error}"
                        ))
                    })?;
                }
                return Ok(atomic);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(bad(format!(
                    "{context} temporary file cannot be created: {error}"
                )));
            }
        }
        Err(bad(format!(
            "{context} temporary name allocation exhausted"
        )))
    }

    fn open_directory(&self, relative: &Path, context: &str) -> Result<Self> {
        let mut current = self.file.try_clone().map_err(|error| {
            bad(format!(
                "{context} directory handle cannot be retained: {error}"
            ))
        })?;
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(bad(format!(
                    "{context} path is not canonical relative form"
                )));
            };
            current = open_unix_directory_component(&current, name, context)?;
        }
        Ok(Self { file: current })
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct TrustedAtomicFile {
    file: File,
    parent: File,
    target: CString,
    temporary: CString,
    finalized: bool,
}

#[cfg(unix)]
impl TrustedAtomicFile {
    fn preserve_metadata(&self, metadata: &libc::stat) -> io::Result<()> {
        #[allow(clippy::unnecessary_cast)]
        let mode = metadata.st_mode as libc::mode_t;
        // SAFETY: `file` is live and `mode` came from the existing regular file's `stat`.
        if unsafe { libc::fchmod(self.file.as_raw_fd(), mode) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Match atomic-write-file's best-effort owner preservation for unprivileged users.
        // SAFETY: `file` is live and the uid/gid came from the existing file's `stat`.
        if unsafe { libc::fchown(self.file.as_raw_fd(), metadata.st_uid, metadata.st_gid) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EPERM) || unsafe { libc::geteuid() } == 0 {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn commit(mut self) -> io::Result<()> {
        self.file.sync_all()?;
        // SAFETY: both names are NUL-terminated components and `parent` is a live directory.
        let result = unsafe {
            libc::renameat(
                self.parent.as_raw_fd(),
                self.temporary.as_ptr(),
                self.parent.as_raw_fd(),
                self.target.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        self.finalized = true;
        self.parent.sync_all()
    }
}

#[cfg(unix)]
impl Write for TrustedAtomicFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(unix)]
impl Drop for TrustedAtomicFile {
    fn drop(&mut self) {
        if !self.finalized {
            // SAFETY: `parent` remains live and `temporary` is a NUL-terminated component.
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), self.temporary.as_ptr(), 0);
            }
            let _ = self.parent.sync_all();
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixEntryKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[cfg(unix)]
fn open_unix_root(path: &Path) -> io::Result<File> {
    let Some(name) = path.file_name() else {
        return OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path);
    };
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(parent_path)?;
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "root component contains NUL"))?;
    open_unix_component_io(
        &parent,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
}

#[cfg(unix)]
fn unix_component(name: &str, context: &str) -> Result<CString> {
    let path = Path::new(name);
    let mut components = path.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(component)) if component == OsStr::new(name))
        || components.next().is_some()
    {
        return Err(bad(format!("{context} path is not one normal component")));
    }
    CString::new(name.as_bytes()).map_err(|_| bad(format!("{context} path component contains NUL")))
}

#[cfg(unix)]
fn unix_os_component(name: &OsStr, context: &str) -> Result<CString> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(component)) if component == name)
        || components.next().is_some()
    {
        return Err(bad(format!("{context} path is not one normal component")));
    }
    CString::new(name.as_bytes()).map_err(|_| bad(format!("{context} path component contains NUL")))
}

#[cfg(unix)]
fn open_unix_component_io(parent: &File, name: &CString, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: `parent` is a live directory handle and `name` is a NUL-terminated component.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new owned descriptor on success.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn open_unix_directory_component(parent: &File, name: &OsStr, context: &str) -> Result<File> {
    let name = unix_os_component(name, context)?;
    open_unix_component_io(
        parent,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
    .map_err(|error| {
        bad(format!(
            "{context} directory component cannot be opened without following links: {error}"
        ))
    })
}

#[cfg(unix)]
fn open_unix_regular_component(parent: &File, name: &OsStr, context: &str) -> Result<File> {
    let name = unix_os_component(name, context)?;
    let file = open_unix_component_io(
        parent,
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .map_err(|error| {
        if error.raw_os_error() == Some(libc::ELOOP) {
            bad(format!("{context} is a symlink"))
        } else {
            bad(format!(
                "{context} file cannot be opened without following links: {error}"
            ))
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| bad(format!("{context} metadata is unavailable: {error}")))?;
    require_regular_file(&metadata, context)?;
    Ok(file)
}

#[cfg(unix)]
fn unix_entry_kind(parent: &File, name: &str, context: &str) -> Result<Option<UnixEntryKind>> {
    Ok(unix_entry_metadata(parent, name, context)?
        .as_ref()
        .map(unix_entry_kind_from_stat))
}

#[cfg(unix)]
fn unix_entry_metadata(parent: &File, name: &str, context: &str) -> Result<Option<libc::stat>> {
    let name = unix_component(name, context)?;
    // SAFETY: a zeroed `stat` is a valid output buffer for `fstatat`.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `parent` is live, `name` is NUL-terminated, and `metadata` is writable.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            std::ptr::addr_of_mut!(metadata),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(bad(format!("{context} metadata is unavailable: {error}")));
    }
    Ok(Some(metadata))
}

#[cfg(unix)]
fn unix_entry_kind_from_stat(metadata: &libc::stat) -> UnixEntryKind {
    let file_type = metadata.st_mode & libc::S_IFMT;
    if file_type == libc::S_IFREG {
        UnixEntryKind::Regular
    } else if file_type == libc::S_IFDIR {
        UnixEntryKind::Directory
    } else if file_type == libc::S_IFLNK {
        UnixEntryKind::Symlink
    } else {
        UnixEntryKind::Other
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsDirectoryHandle {
    file: File,
    identity: FileIdentity,
}

#[cfg(windows)]
impl WindowsDirectoryHandle {
    fn from_root(file: File, context: &str) -> Result<Self> {
        let information = windows_file_information(&file, context)?;
        require_windows_directory(&information, context)?;
        let identity = windows_file_identity(&information, context)?;
        validate_windows_root_binding(identity, context)?;
        Ok(Self { file, identity })
    }

    fn try_clone(&self, context: &str) -> Result<Self> {
        Ok(Self {
            file: self.file.try_clone().map_err(|error| {
                bad(format!(
                    "{context} directory handle cannot be retained: {error}"
                ))
            })?,
            identity: self.identity,
        })
    }

    fn open_directory_with_access(
        &self,
        name: &OsStr,
        access: FILE_ACCESS_RIGHTS,
        disposition: u32,
        context: &str,
    ) -> Result<Self> {
        self.open_optional_directory_with_access(name, access, disposition, context)?
            .ok_or_else(|| bad(format!("{context} directory component does not exist")))
    }

    fn open_optional_directory_with_access(
        &self,
        name: &OsStr,
        access: FILE_ACCESS_RIGHTS,
        disposition: u32,
        context: &str,
    ) -> Result<Option<Self>> {
        let file = match open_windows_component(&self.file, name, true, access, disposition) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(bad(format!(
                    "{context} directory component cannot be opened relative to its retained parent: {error}"
                )));
            }
        };
        let information = windows_file_information(&file, context)?;
        require_windows_directory(&information, context)?;
        let identity = windows_file_identity(&information, context)?;
        validate_windows_child_binding(self.identity, self.identity, identity, context)?;
        Ok(Some(Self { file, identity }))
    }

    fn open_regular_with_access(
        &self,
        name: &OsStr,
        access: FILE_ACCESS_RIGHTS,
        context: &str,
    ) -> Result<File> {
        self.open_optional_regular_with_access(name, access, context)?
            .ok_or_else(|| bad(format!("{context} does not exist")))
    }

    fn open_optional_regular_with_access(
        &self,
        name: &OsStr,
        access: FILE_ACCESS_RIGHTS,
        context: &str,
    ) -> Result<Option<File>> {
        let file = match open_windows_component(&self.file, name, false, access, FILE_OPEN) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(bad(format!(
                    "{context} cannot be opened relative to its retained parent: {error}"
                )));
            }
        };
        let information = windows_file_information(&file, context)?;
        require_windows_regular_file(&file, &information, context)?;
        let identity = windows_file_identity(&information, context)?;
        validate_windows_child_binding(self.identity, self.identity, identity, context)?;
        Ok(Some(file))
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct TrustedDirectory {
    directory: WindowsDirectoryHandle,
}

#[cfg(windows)]
impl TrustedDirectory {
    pub(crate) fn open_existing(path: &Path, context: &str) -> Result<Option<Self>> {
        let file = match open_windows_root(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(bad(format!(
                    "{context} cannot be opened without following its final component: {error}"
                )));
            }
        };
        Ok(Some(Self {
            directory: WindowsDirectoryHandle::from_root(file, context)?,
        }))
    }

    pub(crate) fn new(path: &Path, context: &str) -> Result<Self> {
        Self::open_existing(path, context)?.ok_or_else(|| bad(format!("{context} does not exist")))
    }

    pub(crate) fn open_regular_file_with_parent(
        &self,
        relative: &Path,
        context: &str,
    ) -> Result<(File, Self)> {
        validate_relative_path(relative, context)?;
        run_before_contained_open(context);
        let file_name = relative
            .file_name()
            .ok_or_else(|| bad(format!("{context} path has no file name")))?;
        let parent =
            self.open_directory(relative.parent().unwrap_or_else(|| Path::new("")), context)?;
        let file = parent.directory.open_regular_with_access(
            file_name,
            GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            context,
        )?;
        Ok((file, parent))
    }

    pub(crate) fn open_regular_file(&self, relative: &Path, context: &str) -> Result<File> {
        self.open_regular_file_with_parent(relative, context)
            .map(|(file, _)| file)
    }

    pub(crate) fn open_directory_child(&self, name: &str, context: &str) -> Result<Option<Self>> {
        self.directory
            .open_optional_directory_with_access(
                OsStr::new(name),
                WINDOWS_DIRECTORY_ACCESS,
                FILE_OPEN,
                context,
            )
            .map(|directory| directory.map(|directory| Self { directory }))
    }

    pub(crate) fn open_or_create_directory_child(&self, name: &str, context: &str) -> Result<Self> {
        self.directory
            .open_directory_with_access(
                OsStr::new(name),
                WINDOWS_DIRECTORY_ACCESS,
                FILE_OPEN_IF,
                context,
            )
            .map(|directory| Self { directory })
    }

    pub(crate) fn require_regular_file_or_absent(&self, name: &str, context: &str) -> Result<()> {
        self.directory
            .open_optional_regular_with_access(
                OsStr::new(name),
                SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                context,
            )
            .map(|_| ())
    }

    pub(crate) fn unlink_regular_file_if_exists(&self, name: &str, context: &str) -> Result<bool> {
        let Some(file) = self.directory.open_optional_regular_with_access(
            OsStr::new(name),
            DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            context,
        )?
        else {
            return Ok(false);
        };
        windows_set_delete(&file)
            .map_err(|error| bad(format!("{context} cannot be removed: {error}")))?;
        drop(file);
        Ok(true)
    }

    pub(crate) fn remove_child_directory_if_empty(
        &self,
        name: &str,
        child: &Self,
        context: &str,
    ) -> Result<()> {
        let Some(current) = self.directory.open_optional_directory_with_access(
            OsStr::new(name),
            WINDOWS_DIRECTORY_ACCESS | DELETE,
            FILE_OPEN,
            context,
        )?
        else {
            return Ok(());
        };
        if current.identity != child.directory.identity {
            return Ok(());
        }
        windows_set_delete(&current.file)
            .map_err(|error| bad(format!("{context} cannot be removed: {error}")))
    }

    pub(crate) fn atomic_write_file(
        &self,
        target: &str,
        context: &str,
    ) -> Result<TrustedAtomicFile> {
        self.require_regular_file_or_absent(target, context)?;
        let target = windows_component(OsStr::new(target))?;
        let parent = self.directory.file.try_clone().map_err(|error| {
            bad(format!(
                "{context} parent handle cannot be retained: {error}"
            ))
        })?;
        for _ in 0..MAX_TEMP_ATTEMPTS {
            let temporary_name = temporary_name(target_string(&target).as_str());
            let temporary = windows_component(OsStr::new(&temporary_name))?;
            match open_windows_component_wide(
                &self.directory.file,
                &temporary,
                false,
                GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                FILE_CREATE,
            ) {
                Ok(file) => {
                    return Ok(TrustedAtomicFile {
                        file,
                        parent,
                        target,
                        finalized: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(bad(format!(
                        "{context} temporary file cannot be created: {error}"
                    )));
                }
            }
        }
        Err(bad(format!(
            "{context} temporary name allocation exhausted"
        )))
    }

    fn open_directory(&self, relative: &Path, context: &str) -> Result<Self> {
        let mut directory = self.directory.try_clone(context)?;
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(bad(format!(
                    "{context} path is not canonical relative form"
                )));
            };
            directory = directory.open_directory_with_access(
                name,
                WINDOWS_DIRECTORY_ACCESS,
                FILE_OPEN,
                context,
            )?;
        }
        Ok(Self { directory })
    }
}

#[cfg(windows)]
const MAX_WINDOWS_RENAME_UNITS: usize = 1024;

#[cfg(windows)]
#[repr(C)]
struct WindowsRenameInformation {
    anonymous: FILE_RENAME_INFORMATION_0,
    root_directory: windows_sys::Win32::Foundation::HANDLE,
    file_name_length: u32,
    file_name: [u16; MAX_WINDOWS_RENAME_UNITS],
}

#[cfg(windows)]
const _: () = {
    assert!(
        std::mem::offset_of!(WindowsRenameInformation, anonymous)
            == std::mem::offset_of!(FILE_RENAME_INFORMATION, Anonymous)
    );
    assert!(
        std::mem::offset_of!(WindowsRenameInformation, root_directory)
            == std::mem::offset_of!(FILE_RENAME_INFORMATION, RootDirectory)
    );
    assert!(
        std::mem::offset_of!(WindowsRenameInformation, file_name_length)
            == std::mem::offset_of!(FILE_RENAME_INFORMATION, FileNameLength)
    );
    assert!(
        std::mem::offset_of!(WindowsRenameInformation, file_name)
            == std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName)
    );
};

#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct TrustedAtomicFile {
    file: File,
    parent: File,
    target: Vec<u16>,
    finalized: bool,
}

#[cfg(windows)]
impl TrustedAtomicFile {
    pub(crate) fn commit(mut self) -> io::Result<()> {
        self.file.sync_all()?;
        windows_rename(&self.file, &self.parent, &self.target)?;
        self.finalized = true;
        Ok(())
    }
}

#[cfg(windows)]
impl Write for TrustedAtomicFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(windows)]
impl Drop for TrustedAtomicFile {
    fn drop(&mut self) {
        if !self.finalized {
            let _ = windows_set_delete(&self.file);
        }
    }
}

#[cfg(windows)]
fn open_windows_root(path: &Path) -> io::Result<File> {
    let Some(name) = path.file_name() else {
        return OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path);
    };
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent_path)?;
    open_windows_component(&parent, name, true, WINDOWS_DIRECTORY_ACCESS, FILE_OPEN)
}

#[cfg(windows)]
fn open_windows_component(
    parent: &File,
    name: &OsStr,
    directory: bool,
    desired_access: FILE_ACCESS_RIGHTS,
    disposition: u32,
) -> io::Result<File> {
    let wide = windows_component(name).map_err(io_from_trusted_error)?;
    open_windows_component_wide(parent, &wide, directory, desired_access, disposition)
}

#[cfg(windows)]
fn open_windows_component_wide(
    parent: &File,
    wide: &[u16],
    directory: bool,
    desired_access: FILE_ACCESS_RIGHTS,
    disposition: u32,
) -> io::Result<File> {
    let byte_length = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path component is too long"))?;
    let mut wide = wide.to_vec();
    let name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())
            .expect("OBJECT_ATTRIBUTES size fits u32"),
        RootDirectory: parent.as_raw_handle(),
        ObjectName: std::ptr::addr_of!(name),
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = INVALID_HANDLE_VALUE;
    let create_options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if directory {
            FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT
        } else {
            FILE_NON_DIRECTORY_FILE
        };

    // One counted component plus `RootDirectory` binds the operation to the retained parent.
    // Reparse objects are exposed for rejection, and delete sharing permits the retained object
    // to remain authoritative if its namespace entry is renamed concurrently.
    // SAFETY: all pointers outlive the call, `parent` is live, and a returned handle is owned.
    let status = unsafe {
        NtCreateFile(
            std::ptr::addr_of_mut!(handle),
            desired_access,
            std::ptr::addr_of!(attributes),
            std::ptr::addr_of_mut!(status_block),
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            create_options,
            std::ptr::null(),
            0,
        )
    };
    ntstatus_result(status)?;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            "NtCreateFile succeeded without returning a valid handle",
        ));
    }
    // SAFETY: successful `NtCreateFile` returned a new owned handle, checked above.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn windows_component(name: &OsStr) -> Result<Vec<u16>> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(component)) if component == name)
        || components.next().is_some()
    {
        return Err(bad("path is not one normal component"));
    }
    let wide: Vec<u16> = name.encode_wide().collect();
    if wide.contains(&0) {
        return Err(bad("path component contains NUL"));
    }
    if wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .is_none()
    {
        return Err(bad("path component is too long"));
    }
    Ok(wide)
}

#[cfg(windows)]
fn windows_file_information(file: &File, context: &str) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a live handle and `information` is writable for the call.
    let result = unsafe {
        GetFileInformationByHandle(file.as_raw_handle(), std::ptr::addr_of_mut!(information))
    };
    if result == 0 {
        return Err(bad(format!(
            "{context} identity is unavailable: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(information)
}

#[cfg(windows)]
fn windows_file_identity(
    information: &BY_HANDLE_FILE_INFORMATION,
    context: &str,
) -> Result<FileIdentity> {
    let file = (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    let identity = FileIdentity {
        volume: u64::from(information.dwVolumeSerialNumber),
        file,
    };
    validate_windows_root_binding(identity, context)?;
    Ok(identity)
}

#[cfg(any(windows, test))]
fn validate_windows_root_binding(identity: FileIdentity, context: &str) -> Result<()> {
    if identity.file == 0 {
        Err(bad(format!("{context} identity is unavailable")))
    } else {
        Ok(())
    }
}

#[cfg(any(windows, test))]
fn validate_windows_child_binding(
    retained_parent: FileIdentity,
    opened_from: FileIdentity,
    opened: FileIdentity,
    context: &str,
) -> Result<()> {
    if opened_from != retained_parent {
        return Err(bad(format!(
            "{context} was not opened from the retained parent"
        )));
    }
    if opened.file == 0 || opened.volume != retained_parent.volume {
        return Err(bad(format!(
            "{context} identity is unavailable or outside the parent volume"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn require_windows_directory(
    information: &BY_HANDLE_FILE_INFORMATION,
    context: &str,
) -> Result<()> {
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(bad(format!("{context} directory is a reparse point")));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(bad(format!("{context} is not a directory")));
    }
    Ok(())
}

#[cfg(windows)]
fn require_windows_regular_file(
    file: &File,
    information: &BY_HANDLE_FILE_INFORMATION,
    context: &str,
) -> Result<()> {
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(bad(format!("{context} is a reparse point")));
    }
    let metadata = file
        .metadata()
        .map_err(|error| bad(format!("{context} metadata is unavailable: {error}")))?;
    require_regular_file(&metadata, context)
}

#[cfg(windows)]
fn windows_rename(file: &File, parent: &File, target: &[u16]) -> io::Result<()> {
    if target.len() > MAX_WINDOWS_RENAME_UNITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rename target is too long",
        ));
    }
    let mut information = WindowsRenameInformation {
        anonymous: FILE_RENAME_INFORMATION_0 {
            ReplaceIfExists: true,
        },
        root_directory: parent.as_raw_handle(),
        file_name_length: u32::try_from(std::mem::size_of_val(target))
            .expect("validated rename target length fits u32"),
        file_name: [0; MAX_WINDOWS_RENAME_UNITS],
    };
    information.file_name[..target.len()].copy_from_slice(target);
    // Microsoft requires at least `sizeof(FILE_RENAME_INFORMATION) + FileNameLength` bytes.
    let length = std::mem::size_of::<FILE_RENAME_INFORMATION>() + std::mem::size_of_val(target);
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `information` has the documented C layout and remains live for the call.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            std::ptr::addr_of_mut!(status_block),
            std::ptr::addr_of!(information).cast(),
            u32::try_from(length).expect("rename information length fits u32"),
            FileRenameInformation,
        )
    };
    ntstatus_result(status)
}

#[cfg(windows)]
fn windows_set_delete(file: &File) -> io::Result<()> {
    let information = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: `information` is a valid fixed-size input and remains live for the call.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            std::ptr::addr_of_mut!(status_block),
            std::ptr::addr_of!(information).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFORMATION>())
                .expect("disposition information size fits u32"),
            FileDispositionInformation,
        )
    };
    ntstatus_result(status)
}

#[cfg(windows)]
fn ntstatus_result(status: i32) -> io::Result<()> {
    if status >= 0 {
        return Ok(());
    }
    // SAFETY: translating an NTSTATUS has no pointer or lifetime requirements.
    let error = unsafe { RtlNtStatusToDosError(status) };
    Err(io::Error::from_raw_os_error(error as i32))
}

#[cfg(windows)]
fn io_from_trusted_error(error: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

#[cfg(windows)]
fn target_string(wide: &[u16]) -> String {
    String::from_utf16_lossy(wide)
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug)]
pub(crate) struct TrustedDirectory;

#[cfg(not(any(unix, windows)))]
impl TrustedDirectory {
    pub(crate) fn open_existing(_path: &Path, context: &str) -> Result<Option<Self>> {
        Err(unsupported(context))
    }

    pub(crate) fn new(_path: &Path, context: &str) -> Result<Self> {
        Err(unsupported(context))
    }

    pub(crate) fn open_regular_file_with_parent(
        &self,
        _relative: &Path,
        context: &str,
    ) -> Result<(File, Self)> {
        Err(unsupported(context))
    }

    pub(crate) fn open_regular_file(&self, _relative: &Path, context: &str) -> Result<File> {
        Err(unsupported(context))
    }

    pub(crate) fn open_directory_child(&self, _name: &str, context: &str) -> Result<Option<Self>> {
        Err(unsupported(context))
    }

    pub(crate) fn open_or_create_directory_child(
        &self,
        _name: &str,
        context: &str,
    ) -> Result<Self> {
        Err(unsupported(context))
    }

    pub(crate) fn require_regular_file_or_absent(&self, _name: &str, context: &str) -> Result<()> {
        Err(unsupported(context))
    }

    pub(crate) fn unlink_regular_file_if_exists(&self, _name: &str, context: &str) -> Result<bool> {
        Err(unsupported(context))
    }

    pub(crate) fn remove_child_directory_if_empty(
        &self,
        _name: &str,
        _child: &Self,
        context: &str,
    ) -> Result<()> {
        Err(unsupported(context))
    }

    pub(crate) fn atomic_write_file(
        &self,
        _target: &str,
        context: &str,
    ) -> Result<TrustedAtomicFile> {
        Err(unsupported(context))
    }
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug)]
pub(crate) struct TrustedAtomicFile;

#[cfg(not(any(unix, windows)))]
impl TrustedAtomicFile {
    pub(crate) fn commit(self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "trusted atomic publication is unsupported on this platform",
        ))
    }
}

#[cfg(not(any(unix, windows)))]
impl Write for TrustedAtomicFile {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "trusted atomic publication is unsupported on this platform",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "trusted atomic publication is unsupported on this platform",
        ))
    }
}

fn temporary_name(target: &str) -> String {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{target}.tmp-{}-{counter:016x}", std::process::id())
}

fn require_regular_file(metadata: &Metadata, context: &str) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(bad(format!("{context} is a symlink")));
    }
    if !metadata.file_type().is_file() {
        return Err(bad(format!("{context} is not a regular file")));
    }
    Ok(())
}

pub(crate) fn validate_relative_path(path: &Path, context: &str) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(bad(format!(
            "{context} path is not canonical relative form"
        )));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn unsupported(context: &str) -> Error {
    bad(format!(
        "{context} trusted-directory validation is unsupported on this platform"
    ))
}

fn bad(reason: impl Into<String>) -> Error {
    Error::BadScatter(reason.into())
}

#[cfg(test)]
mod tests {
    use super::FileIdentity;
    use crate::error::{Error, Result};
    #[cfg(unix)]
    use std::path::Path;
    #[cfg(unix)]
    use tempfile::tempdir;

    fn assert_bad<T>(result: Result<T>, expected: &str) {
        match result {
            Err(Error::BadScatter(reason)) => assert!(
                reason.contains(expected),
                "expected {expected:?} in {reason:?}"
            ),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("expected trusted-filesystem rejection"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn trusted_directory_rejects_final_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let path = root.path().join("payload.bin");
        std::fs::write(&path, b"same bytes").unwrap();
        let trusted = super::TrustedDirectory::new(root.path(), "test root").unwrap();
        std::fs::rename(&path, root.path().join("authenticated.bin")).unwrap();
        symlink(root.path().join("authenticated.bin"), &path).unwrap();

        assert_bad(
            trusted.open_regular_file(Path::new("payload.bin"), "test payload"),
            "is a symlink",
        );
    }

    #[cfg(unix)]
    #[test]
    fn trusted_directory_rejects_final_symlink_with_trailing_separator() {
        use std::os::unix::fs::symlink;

        let holder = tempdir().unwrap();
        let target = holder.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let linked = holder.path().join("linked");
        symlink(&target, &linked).unwrap();
        let with_separator = std::path::PathBuf::from(format!("{}/", linked.display()));

        assert_bad(
            super::TrustedDirectory::new(&with_separator, "test root"),
            "without following its final component",
        );
    }

    #[test]
    fn windows_root_binding_rejects_missing_identity() {
        assert_bad(
            super::validate_windows_root_binding(FileIdentity { volume: 7, file: 0 }, "test root"),
            "identity is unavailable",
        );
    }

    #[test]
    fn windows_child_binding_rejects_replaced_parent_authority() {
        let retained_parent = FileIdentity { volume: 7, file: 9 };

        assert_bad(
            super::validate_windows_child_binding(
                retained_parent,
                FileIdentity {
                    volume: 7,
                    file: 99,
                },
                FileIdentity {
                    volume: 7,
                    file: 10,
                },
                "test child",
            ),
            "was not opened from the retained parent",
        );
    }

    #[test]
    fn windows_binding_accepts_exact_handle_bound_identities() {
        let root = FileIdentity { volume: 7, file: 9 };
        let child = FileIdentity {
            volume: 7,
            file: 10,
        };

        super::validate_windows_root_binding(root, "test root").unwrap();
        super::validate_windows_child_binding(root, root, child, "test child").unwrap();
    }
}
