use crate::error::{Error, Result};
#[cfg(unix)]
use std::ffi::CString;
#[cfg(windows)]
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::Path;
#[cfg(any(windows, test))]
use std::path::PathBuf;
#[cfg(windows)]
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
#[cfg(windows)]
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    GENERIC_READ, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, GetFinalPathNameByHandleW, SYNCHRONIZE, VOLUME_NAME_DOS,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

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

#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsObjectProof {
    resolved_path: PathBuf,
    identity: FileIdentity,
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct TrustedDirectory {
    // Descendant traversal is always relative to this retained capability.
    file: File,
}

#[cfg(unix)]
impl TrustedDirectory {
    pub(crate) fn new(path: &Path, context: &str) -> Result<Self> {
        let canonical = fs::canonicalize(path)
            .map_err(|error| bad(format!("{context} cannot be canonicalized: {error}")))?;
        open_unix_absolute_directory(&canonical, context)
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
        let metadata = file
            .metadata()
            .map_err(|error| bad(format!("{context} metadata is unavailable: {error}")))?;
        require_regular_file(&metadata, context)?;
        Ok((file, parent))
    }

    pub(crate) fn open_regular_file(&self, relative: &Path, context: &str) -> Result<File> {
        self.open_regular_file_with_parent(relative, context)
            .map(|(file, _)| file)
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

#[cfg(windows)]
#[derive(Debug)]
struct WindowsDirectoryHandle {
    file: File,
    proof: WindowsObjectProof,
}

#[cfg(windows)]
impl WindowsDirectoryHandle {
    fn from_namespace_root(file: File, expected_path: &Path, context: &str) -> Result<Self> {
        let metadata = file
            .metadata()
            .map_err(|error| bad(format!("{context} metadata is unavailable: {error}")))?;
        if !metadata.is_dir() {
            return Err(bad(format!("{context} is not a directory")));
        }
        let information = windows_file_information(&file, context)?;
        require_windows_directory(&information, context)?;
        let proof = windows_object_proof(&file, &information, context)?;
        validate_windows_root_binding(expected_path, &proof, context)?;
        Ok(Self { file, proof })
    }

    fn try_clone(&self, context: &str) -> Result<Self> {
        Ok(Self {
            file: self.file.try_clone().map_err(|error| {
                bad(format!(
                    "{context} directory handle cannot be retained: {error}"
                ))
            })?,
            proof: self.proof.clone(),
        })
    }

    fn open_directory(&self, name: &std::ffi::OsStr, context: &str) -> Result<Self> {
        let file = open_windows_component(&self.file, name, true).map_err(|error| {
            bad(format!(
                "{context} directory component cannot be opened relative to its retained parent: {error}"
            ))
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| bad(format!("{context} metadata is unavailable: {error}")))?;
        if !metadata.is_dir() {
            return Err(bad(format!("{context} is not a directory")));
        }
        let information = windows_file_information(&file, context)?;
        require_windows_directory(&information, context)?;
        let proof = windows_object_proof(&file, &information, context)?;
        let expected_path = self.proof.resolved_path.join(name);
        validate_windows_child_binding(
            &self.proof,
            &expected_path,
            self.proof.identity,
            &proof,
            context,
        )?;
        Ok(Self { file, proof })
    }

    fn open_regular_file(&self, name: &std::ffi::OsStr, context: &str) -> Result<File> {
        let file = open_windows_component(&self.file, name, false).map_err(|error| {
            bad(format!(
                "{context} cannot be opened relative to its retained parent: {error}"
            ))
        })?;
        let information = windows_file_information(&file, context)?;
        require_windows_regular_file(&file, &information, context)?;
        let proof = windows_object_proof(&file, &information, context)?;
        let expected_path = self.proof.resolved_path.join(name);
        validate_windows_child_binding(
            &self.proof,
            &expected_path,
            self.proof.identity,
            &proof,
            context,
        )?;
        Ok(file)
    }
}

#[cfg(windows)]
fn open_windows_component(
    parent: &File,
    name: &std::ffi::OsStr,
    directory: bool,
) -> std::io::Result<File> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(component)) if component == name)
        || components.next().is_some()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not one normal component",
        ));
    }

    let mut wide: Vec<u16> = name.encode_wide().collect();
    if wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        ));
    }
    let byte_length = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path component is too long",
            )
        })?;
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

    // One counted component plus `RootDirectory` binds lookup to the retained parent.
    // Reparse objects are exposed for rejection, and no delete sharing pins the opened name.
    // SAFETY: every pointer refers to storage that outlives the call, `parent` is a live
    // directory handle, and the returned owned handle is converted into `File` exactly once.
    let status = unsafe {
        NtCreateFile(
            std::ptr::addr_of_mut!(handle),
            GENERIC_READ | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            std::ptr::addr_of!(attributes),
            std::ptr::addr_of_mut!(status_block),
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            create_options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: translating an NTSTATUS has no pointer or lifetime requirements.
        let error = unsafe { RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(error as i32));
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other(
            "NtCreateFile succeeded without returning a valid handle",
        ));
    }

    // SAFETY: successful `NtCreateFile` returned a new owned handle, checked above.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct TrustedDirectory {
    directory: WindowsDirectoryHandle,
}

#[cfg(windows)]
impl TrustedDirectory {
    pub(crate) fn new(path: &Path, context: &str) -> Result<Self> {
        let canonical = fs::canonicalize(path)
            .map_err(|error| bad(format!("{context} cannot be canonicalized: {error}")))?;
        let (namespace_root, components) =
            windows_namespace_root_and_components(&canonical, context)?;
        let file = open_windows_namespace_root(&namespace_root, context)?;
        let mut directory =
            WindowsDirectoryHandle::from_namespace_root(file, &namespace_root, context)?;
        for component in components {
            directory = directory.open_directory(&component, context)?;
        }
        validate_windows_root_binding(&canonical, &directory.proof, context)?;
        Ok(Self { directory })
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
        let file = parent.directory.open_regular_file(file_name, context)?;
        Ok((file, parent))
    }

    pub(crate) fn open_regular_file(&self, relative: &Path, context: &str) -> Result<File> {
        self.open_regular_file_with_parent(relative, context)
            .map(|(file, _)| file)
    }

    fn open_directory(&self, relative: &Path, context: &str) -> Result<Self> {
        let mut directory = self.directory.try_clone(context)?;
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(bad(format!(
                    "{context} path is not canonical relative form"
                )));
            };
            directory = directory.open_directory(name, context)?;
        }
        Ok(Self { directory })
    }
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

#[cfg(any(windows, test))]
fn validate_windows_root_binding(
    expected_path: &Path,
    opened: &WindowsObjectProof,
    context: &str,
) -> Result<()> {
    if opened.identity.file == 0 {
        return Err(bad(format!("{context} identity is unavailable")));
    }
    if opened.resolved_path != expected_path {
        return Err(bad(format!(
            "{context} resolved handle does not match the requested canonical path"
        )));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn validate_windows_child_binding(
    retained_parent: &WindowsObjectProof,
    expected_path: &Path,
    opened_from: FileIdentity,
    opened: &WindowsObjectProof,
    context: &str,
) -> Result<()> {
    if opened_from != retained_parent.identity {
        return Err(bad(format!(
            "{context} was not opened from the retained parent"
        )));
    }
    if expected_path.parent() != Some(retained_parent.resolved_path.as_path())
        || opened.resolved_path != expected_path
    {
        return Err(bad(format!(
            "{context} resolved handle is not the expected direct child"
        )));
    }
    if opened.identity.file == 0 || opened.identity.volume != retained_parent.identity.volume {
        return Err(bad(format!(
            "{context} identity is unavailable or outside the parent volume"
        )));
    }
    Ok(())
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
            std::io::Error::last_os_error()
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
    if file == 0 {
        return Err(bad(format!("{context} identity is unavailable")));
    }
    Ok(FileIdentity {
        volume: u64::from(information.dwVolumeSerialNumber),
        file,
    })
}

#[cfg(windows)]
fn windows_object_proof(
    file: &File,
    information: &BY_HANDLE_FILE_INFORMATION,
    context: &str,
) -> Result<WindowsObjectProof> {
    Ok(WindowsObjectProof {
        resolved_path: windows_resolved_path(file, context)?,
        identity: windows_file_identity(information, context)?,
    })
}

#[cfg(windows)]
fn windows_namespace_root_and_components(
    canonical: &Path,
    context: &str,
) -> Result<(PathBuf, Vec<OsString>)> {
    let mut components = canonical.components();
    let prefix = match components.next() {
        Some(std::path::Component::Prefix(prefix)) => prefix,
        _ => {
            return Err(bad(format!(
                "{context} canonical path has no Windows prefix"
            )));
        }
    };
    if !matches!(
        prefix.kind(),
        std::path::Prefix::Disk(_)
            | std::path::Prefix::UNC(_, _)
            | std::path::Prefix::VerbatimDisk(_)
            | std::path::Prefix::VerbatimUNC(_, _)
    ) {
        return Err(bad(format!(
            "{context} canonical path has an unsupported Windows prefix"
        )));
    }
    let root = match components.next() {
        Some(component @ std::path::Component::RootDir) => component,
        _ => {
            return Err(bad(format!(
                "{context} canonical path has no namespace root"
            )));
        }
    };
    let mut namespace_root = PathBuf::from(prefix.as_os_str());
    namespace_root.push(root.as_os_str());
    let mut relative = Vec::new();
    for component in components {
        let std::path::Component::Normal(name) = component else {
            return Err(bad(format!(
                "{context} canonical path has an ambiguous component"
            )));
        };
        relative.push(name.to_os_string());
    }
    Ok((namespace_root, relative))
}

#[cfg(unix)]
fn open_unix_absolute_directory(path: &Path, context: &str) -> Result<TrustedDirectory> {
    if !path.is_absolute() {
        return Err(bad(format!("{context} path is not absolute")));
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(Path::new("/"))
        .map_err(|error| {
            bad(format!(
                "{context} filesystem root cannot be opened securely: {error}"
            ))
        })?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                current = open_unix_directory_component(&current, name, context)?;
            }
            _ => {
                return Err(bad(format!(
                    "{context} path is not canonical absolute form"
                )));
            }
        }
    }
    Ok(TrustedDirectory { file: current })
}

#[cfg(unix)]
fn open_unix_directory_component(
    parent: &File,
    name: &std::ffi::OsStr,
    context: &str,
) -> Result<File> {
    open_unix_component(
        parent,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        context,
        true,
    )
}

#[cfg(unix)]
fn open_unix_regular_component(
    parent: &File,
    name: &std::ffi::OsStr,
    context: &str,
) -> Result<File> {
    open_unix_component(
        parent,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        context,
        false,
    )
}

#[cfg(unix)]
fn open_unix_component(
    parent: &File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
    context: &str,
    directory: bool,
) -> Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| bad(format!("{context} path component contains NUL")))?;
    // SAFETY: `parent` is a live directory handle and `name` is a NUL-terminated component.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if !directory && error.raw_os_error() == Some(libc::ELOOP) {
            return Err(bad(format!("{context} is a symlink")));
        }
        let target = if directory {
            "directory component"
        } else {
            "file"
        };
        return Err(bad(format!(
            "{context} {target} cannot be opened without following links: {error}"
        )));
    }
    // SAFETY: `openat` returned a new owned descriptor on success.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(windows)]
fn open_windows_namespace_root(path: &Path, context: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| {
            bad(format!(
                "{context} Windows namespace root cannot be opened without rename sharing or reparse traversal: {error}"
            ))
        })
}

#[cfg(windows)]
fn windows_resolved_path(file: &File, context: &str) -> Result<PathBuf> {
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    // SAFETY: a null buffer with zero length requests the required UTF-16 buffer size.
    let required =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), std::ptr::null_mut(), 0, flags) };
    if required == 0 {
        return Err(bad(format!(
            "{context} resolved path is unavailable: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(required as usize)
        .map_err(|_| bad(format!("{context} resolved-path allocation failed")))?;
    buffer.resize(required as usize, 0u16);
    loop {
        let capacity = u32::try_from(buffer.len())
            .map_err(|_| bad(format!("{context} resolved path is too long")))?;
        // SAFETY: `buffer` is writable for `capacity` UTF-16 code units and the handle is live.
        let length = unsafe {
            GetFinalPathNameByHandleW(file.as_raw_handle(), buffer.as_mut_ptr(), capacity, flags)
        };
        if length == 0 {
            return Err(bad(format!(
                "{context} resolved path is unavailable: {}",
                std::io::Error::last_os_error()
            )));
        }
        if length < capacity {
            buffer.truncate(length as usize);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        let required = usize::try_from(length)
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| bad(format!("{context} resolved path is too long")))?;
        buffer
            .try_reserve(required.saturating_sub(buffer.len()))
            .map_err(|_| bad(format!("{context} resolved-path allocation failed")))?;
        buffer.resize(required, 0);
    }
}

#[cfg(windows)]
fn require_windows_directory(
    information: &BY_HANDLE_FILE_INFORMATION,
    context: &str,
) -> Result<()> {
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(bad(format!(
            "{context} directory component is a reparse point"
        )));
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

#[cfg(not(any(unix, windows)))]
#[derive(Debug)]
pub(crate) struct TrustedDirectory;

#[cfg(not(any(unix, windows)))]
impl TrustedDirectory {
    pub(crate) fn new(_path: &Path, context: &str) -> Result<Self> {
        Err(bad(format!(
            "{context} trusted-directory validation is unsupported on this platform"
        )))
    }

    pub(crate) fn open_regular_file_with_parent(
        &self,
        _relative: &Path,
        context: &str,
    ) -> Result<(File, Self)> {
        Err(bad(format!(
            "{context} trusted-directory validation is unsupported on this platform"
        )))
    }

    pub(crate) fn open_regular_file(&self, _relative: &Path, context: &str) -> Result<File> {
        Err(bad(format!(
            "{context} trusted-directory validation is unsupported on this platform"
        )))
    }
}

fn bad(reason: impl Into<String>) -> Error {
    Error::BadScatter(reason.into())
}

#[cfg(test)]
mod tests {
    use super::{FileIdentity, WindowsObjectProof};
    use crate::error::{Error, Result};
    use std::path::{Path, PathBuf};
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

    #[test]
    fn windows_root_binding_rejects_redirected_handle_proof() {
        let opened = WindowsObjectProof {
            resolved_path: PathBuf::from("/outside/root"),
            identity: FileIdentity { volume: 7, file: 9 },
        };

        assert_bad(
            super::validate_windows_root_binding(Path::new("/trusted/root"), &opened, "test root"),
            "does not match the requested canonical path",
        );
    }

    #[test]
    fn windows_child_binding_rejects_replaced_parent_authority() {
        let retained_parent = WindowsObjectProof {
            resolved_path: PathBuf::from("/trusted/root"),
            identity: FileIdentity { volume: 7, file: 9 },
        };
        let opened = WindowsObjectProof {
            resolved_path: PathBuf::from("/trusted/root/child"),
            identity: FileIdentity {
                volume: 7,
                file: 10,
            },
        };

        assert_bad(
            super::validate_windows_child_binding(
                &retained_parent,
                Path::new("/trusted/root/child"),
                FileIdentity {
                    volume: 7,
                    file: 99,
                },
                &opened,
                "test child",
            ),
            "was not opened from the retained parent",
        );
    }

    #[test]
    fn windows_binding_accepts_exact_handle_bound_proofs() {
        let root = WindowsObjectProof {
            resolved_path: PathBuf::from("/trusted/root"),
            identity: FileIdentity { volume: 7, file: 9 },
        };
        let child = WindowsObjectProof {
            resolved_path: PathBuf::from("/trusted/root/child"),
            identity: FileIdentity {
                volume: 7,
                file: 10,
            },
        };

        super::validate_windows_root_binding(Path::new("/trusted/root"), &root, "test root")
            .unwrap();
        super::validate_windows_child_binding(
            &root,
            Path::new("/trusted/root/child"),
            root.identity,
            &child,
            "test child",
        )
        .unwrap();
    }
}
