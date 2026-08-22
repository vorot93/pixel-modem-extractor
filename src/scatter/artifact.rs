use super::{LoadPlan, Operation, PlannedEntry, PlannedOutput, PlannedStorage};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[cfg(unix)]
use std::ffi::CString;
#[cfg(windows)]
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
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
use std::path::{Path, PathBuf};
use std::sync::Mutex;
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

pub const LOAD_MAP_FORMAT: &str = "pixel-modem-extractor-scatter-load-v1";

const SCHEMA_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
static ZERO_CHUNK: [u8; 64 * 1024] = [0; 64 * 1024];

#[cfg(all(test, unix))]
type ContainedOpenHook = Option<(String, Box<dyn FnOnce()>)>;

#[cfg(all(test, unix))]
thread_local! {
    static BEFORE_CONTAINED_OPEN: std::cell::RefCell<ContainedOpenHook> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, unix))]
fn set_before_contained_open(context: &str, hook: impl FnOnce() + 'static) {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedLoadMap {
    pub relative_path: String,
    pub blake3: String,
}

#[derive(Debug)]
pub(crate) struct MaterializedScatter {
    pub image_label: String,
    pub image_base: u32,
    pub image_size: u32,
    pub image_blake3: [u8; 32],
    pub manifest_blake3: [u8; 32],
    pub(crate) segments: Vec<ArtifactSegment>,
}

#[derive(Debug)]
pub(crate) struct ArtifactSegment {
    address: u32,
    size: u32,
    scatter_entry: usize,
    backing: ArtifactBacking,
}

#[derive(Debug)]
enum ArtifactBacking {
    File(Mutex<File>),
    Zero,
}

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

    fn open_regular_file(&self, relative: &Path, context: &str) -> Result<File> {
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

    fn open_regular_file(&self, relative: &Path, context: &str) -> Result<File> {
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

fn validate_relative_path(path: &Path, context: &str) -> Result<()> {
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
struct TrustedDirectory;

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

    fn open_regular_file(&self, _relative: &Path, context: &str) -> Result<File> {
        Err(bad(format!(
            "{context} trusted-directory validation is unsupported on this platform"
        )))
    }
}

impl ArtifactSegment {
    pub(crate) fn address(&self) -> u32 {
        self.address
    }

    pub(crate) fn size(&self) -> u32 {
        self.size
    }

    pub(crate) fn scatter_entry(&self) -> usize {
        self.scatter_entry
    }

    pub(crate) fn is_zero_fill(&self) -> bool {
        matches!(self.backing, ArtifactBacking::Zero)
    }

    pub(crate) fn read_exact(&self, offset: u32, output: &mut [u8]) -> Result<()> {
        if output.len() > ZERO_CHUNK.len() {
            return Err(bad("artifact read exceeds 64 KiB"));
        }
        let length = u32::try_from(output.len())
            .map_err(|_| bad("artifact read length does not fit u32"))?;
        offset
            .checked_add(length)
            .filter(|&end| end <= self.size)
            .ok_or_else(|| bad("artifact read escapes its authenticated segment"))?;
        match &self.backing {
            ArtifactBacking::File(file) => {
                let mut file = file
                    .lock()
                    .map_err(|_| bad("authenticated scatter payload lock is poisoned"))?;
                file.seek(SeekFrom::Start(u64::from(offset)))
                    .map_err(|error| {
                        bad(format!(
                            "authenticated scatter payload seek failed: {error}"
                        ))
                    })?;
                file.read_exact(output).map_err(|error| {
                    bad(format!(
                        "authenticated scatter payload read failed: {error}"
                    ))
                })?;
            }
            ArtifactBacking::Zero => output.fill(0),
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct LoadMap<'a> {
    format: &'static str,
    schema_version: u32,
    tool_version: &'static str,
    image: Image<'a>,
    loader: Loader,
    table: Table,
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct Image<'a> {
    label: &'a str,
    base_addr: String,
    size: u32,
    blake3: String,
}

#[derive(Serialize)]
struct Loader {
    address: String,
    literal_pair: String,
}

#[derive(Serialize)]
struct Table {
    start: String,
    end: String,
    entry_count: usize,
    handlers: Handlers,
}

#[derive(Serialize)]
struct Handlers {
    null: String,
    copy: String,
    decompress1: String,
    zero: String,
}

#[derive(Serialize)]
struct Entry {
    index: usize,
    source: String,
    destination: String,
    size: u32,
    handler: String,
    operation: Operation,
    #[serde(skip_serializing_if = "Option::is_none")]
    compressed_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_blake3: Option<String>,
    materialization: Materialization,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Materialization {
    None,
    ZeroFill,
    File { path: String, size: u32 },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadMapWire {
    format: String,
    schema_version: u32,
    tool_version: String,
    image: ImageWire,
    loader: LoaderWire,
    table: TableWire,
    entries: Vec<EntryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageWire {
    label: String,
    base_addr: String,
    size: u32,
    blake3: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoaderWire {
    address: String,
    literal_pair: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableWire {
    start: String,
    end: String,
    entry_count: usize,
    handlers: HandlersWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandlersWire {
    null: String,
    copy: String,
    decompress1: String,
    zero: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryWire {
    index: usize,
    source: String,
    destination: String,
    size: u32,
    handler: String,
    operation: Operation,
    #[serde(default)]
    compressed_size: OptionalField<u32>,
    #[serde(default)]
    output_blake3: OptionalField<String>,
    materialization: MaterializationWire,
}

#[derive(Default)]
enum OptionalField<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T> Deserialize<'de> for OptionalField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum MaterializationWire {
    None,
    ZeroFill,
    File { path: String, size: u32 },
}

struct ParsedHandlers {
    null: u32,
    copy: u32,
    decompress1: u32,
    zero: u32,
}

struct ValidatedEntry {
    index: usize,
    source: u32,
    destination: u32,
    size: u32,
    operation: Operation,
    output_blake3: Option<[u8; 32]>,
    materialization: MaterializationWire,
}

#[derive(Clone, Copy)]
struct DestinationRange {
    start: u32,
    end: u32,
    entry: usize,
}

pub fn clear_materialized(root: &Path, label: &str) -> Result<()> {
    validate_label(label)?;
    let Some(scatter_root) = scatter_directory(root, false)? else {
        return Ok(());
    };
    remove_owned_path(&scatter_root.join(label))
}

pub fn materialize(
    plan: &LoadPlan,
    image: &[u8],
    label: &str,
    root: &Path,
) -> Result<MaterializedLoadMap> {
    validate_label(label)?;

    let Some(scatter_root) = scatter_directory(root, true)? else {
        return Err(bad("failed to create the artifact scatter directory"));
    };
    let final_dir = scatter_root.join(label);
    remove_owned_path(&final_dir)?;

    let staging_dir = scatter_root.join(format!("{label}.staging+{}", std::process::id()));
    remove_owned_path(&staging_dir)?;
    let manifest_blake3 = match stage_and_publish(plan, image, label, &staging_dir, &final_dir) {
        Ok(blake3) => blake3,
        Err(error) => {
            let _ = remove_owned_path(&staging_dir);
            return Err(error);
        }
    };

    Ok(MaterializedLoadMap {
        relative_path: format!("scatter/{label}/load_map.json"),
        blake3: manifest_blake3,
    })
}

pub(crate) fn read_materialized(
    root: &Path,
    manifest_path: &Path,
    raw_image: &[u8],
    base: u32,
) -> Result<MaterializedScatter> {
    let (manifest, manifest_parent) = open_manifest(root, manifest_path)?;
    let (wire, manifest_blake3) = read_manifest(manifest)?;

    if wire.format != LOAD_MAP_FORMAT {
        return Err(bad("unexpected scatter load-map format"));
    }
    if wire.schema_version != SCHEMA_VERSION {
        return Err(bad("unsupported scatter load-map schema version"));
    }
    if wire.tool_version.is_empty() {
        return Err(bad("scatter load-map tool_version is empty"));
    }
    validate_label(&wire.image.label)?;

    let raw_size =
        u32::try_from(raw_image.len()).map_err(|_| bad("raw image size does not fit u32"))?;
    if raw_size == 0 {
        return Err(bad("raw image is empty"));
    }
    let raw_end = checked_end(base, raw_size, "raw image")?;
    let image_base = parse_address(&wire.image.base_addr, "image base_addr")?;
    if image_base != base || wire.image.size != raw_size {
        return Err(bad("raw image base or size does not match the load map"));
    }
    let image_blake3 = parse_blake3(&wire.image.blake3, "image blake3")?;
    if image_blake3 != *hash_bytes(raw_image).as_bytes() {
        return Err(bad("raw image BLAKE3 does not match the load map"));
    }

    require_within_raw(
        parse_address(&wire.loader.address, "loader address")?,
        16,
        base,
        raw_end,
        "loader instruction window",
    )?;
    require_within_raw(
        parse_address(&wire.loader.literal_pair, "loader literal_pair")?,
        8,
        base,
        raw_end,
        "loader literal pair",
    )?;

    if wire.table.entry_count == 0
        || wire.table.entry_count > super::MAX_ENTRIES
        || wire.table.entry_count != wire.entries.len()
    {
        return Err(bad(
            "scatter table entry_count does not match the bounded non-empty entry array",
        ));
    }
    let table_length = wire
        .table
        .entry_count
        .checked_mul(16)
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| bad("scatter table length overflows u32"))?;
    let table_start = parse_address(&wire.table.start, "table start")?;
    let table_end = parse_address(&wire.table.end, "table end")?;
    if checked_end(table_start, table_length, "scatter table")? != table_end {
        return Err(bad(
            "scatter table range does not exactly match entry_count descriptors",
        ));
    }
    require_within_raw(table_start, table_length, base, raw_end, "scatter table")?;

    let handlers = ParsedHandlers {
        null: parse_address(&wire.table.handlers.null, "null handler")?,
        copy: parse_address(&wire.table.handlers.copy, "copy handler")?,
        decompress1: parse_address(&wire.table.handlers.decompress1, "decompress1 handler")?,
        zero: parse_address(&wire.table.handlers.zero, "zero handler")?,
    };
    let distinct_handlers = BTreeSet::from([
        handlers.null,
        handlers.copy,
        handlers.decompress1,
        handlers.zero,
    ]);
    if distinct_handlers.len() != 4 {
        return Err(bad(
            "scatter table handlers are not four distinct addresses",
        ));
    }
    for handler in distinct_handlers {
        require_within_raw(handler & !1, 1, base, raw_end, "scatter table handler")?;
    }

    let mut logical_output_size = 0u64;
    let mut destinations = Vec::with_capacity(wire.entries.len());
    let mut entries = Vec::with_capacity(wire.entries.len());
    for (position, entry) in wire.entries.into_iter().enumerate() {
        let context = format!("scatter entry {position}");
        if entry.index != position {
            return Err(bad(format!(
                "{context} index does not match its array position"
            )));
        }
        let source = parse_address(&entry.source, &format!("{context} source"))?;
        let destination = parse_address(&entry.destination, &format!("{context} destination"))?;
        let handler = parse_address(&entry.handler, &format!("{context} handler"))?;
        if handler != handler_for(entry.operation, &handlers) {
            return Err(bad(format!(
                "{context} handler does not match its operation"
            )));
        }

        if entry.operation == Operation::Decompress1 {
            let OptionalField::Present(compressed_size) = &entry.compressed_size else {
                return Err(bad(format!("{context} compressed_size is absent or zero")));
            };
            if *compressed_size == 0 {
                return Err(bad(format!("{context} compressed_size is absent or zero")));
            }
            require_within_raw(
                source,
                *compressed_size,
                base,
                raw_end,
                &format!("{context} compressed source"),
            )?;
        } else if matches!(&entry.compressed_size, OptionalField::Present(_)) {
            return Err(bad(format!(
                "{context} has compressed_size for a non-decompress entry"
            )));
        }

        let output_blake3 = match (entry.operation, &entry.output_blake3) {
            (Operation::Null, OptionalField::Missing) => None,
            (Operation::Null, OptionalField::Present(_)) => {
                return Err(bad(format!("{context} null operation has output_blake3")));
            }
            (_, OptionalField::Present(hash)) => {
                Some(parse_blake3(hash, &format!("{context} output_blake3"))?)
            }
            (_, OptionalField::Missing) => {
                return Err(bad(format!("{context} has no output_blake3")));
            }
        };

        if entry.operation == Operation::Null {
            if entry.size != 0 || !matches!(entry.materialization, MaterializationWire::None) {
                return Err(bad(format!(
                    "{context} null operation must be a zero-size none entry"
                )));
            }
        } else {
            if entry.size == 0 || destination == 0 {
                return Err(bad(format!("{context} has a zero size or destination")));
            }
            let destination_end =
                checked_end(destination, entry.size, &format!("{context} destination"))?;
            logical_output_size = logical_output_size
                .checked_add(u64::from(entry.size))
                .ok_or_else(|| bad("scatter logical output size overflows u64"))?;
            if logical_output_size > super::MAX_LOGICAL_OUTPUT {
                return Err(bad("scatter logical output exceeds the supported limit"));
            }
            destinations.push(DestinationRange {
                start: destination,
                end: destination_end,
                entry: position,
            });

            if entry.operation == Operation::Copy {
                require_within_raw(
                    source,
                    entry.size,
                    base,
                    raw_end,
                    &format!("{context} copy source"),
                )?;
            }

            match (&entry.operation, &entry.materialization) {
                (Operation::Copy, MaterializationWire::None) if source == destination => {}
                (Operation::Copy, MaterializationWire::File { size, .. })
                    if source != destination && *size == entry.size => {}
                (Operation::Decompress1, MaterializationWire::File { size, .. })
                    if *size == entry.size => {}
                (Operation::Decompress1 | Operation::Zero, MaterializationWire::ZeroFill) => {}
                _ => {
                    return Err(bad(format!(
                        "{context} materialization does not match its operation and size"
                    )));
                }
            }

            if !matches!(entry.materialization, MaterializationWire::None)
                && ranges_overlap(destination, destination_end, base, raw_end)
            {
                return Err(bad(format!(
                    "{context} materialized destination overlaps the raw image"
                )));
            }
        }

        entries.push(ValidatedEntry {
            index: position,
            source,
            destination,
            size: entry.size,
            operation: entry.operation,
            output_blake3,
            materialization: entry.materialization,
        });
    }

    destinations.sort_unstable_by_key(|range| (range.start, range.end, range.entry));
    for adjacent in destinations.windows(2) {
        let [first, second] = adjacent else {
            continue;
        };
        if ranges_overlap(first.start, first.end, second.start, second.end) {
            return Err(bad(format!(
                "scatter entry {} destination overlaps scatter entry {}",
                second.entry, first.entry
            )));
        }
    }

    let mut segments = Vec::with_capacity(entries.len());
    for entry in entries {
        let context = format!("scatter entry {}", entry.index);
        let Some(expected_hash) = entry.output_blake3 else {
            continue;
        };
        match entry.materialization {
            MaterializationWire::None => {
                let bytes = raw_slice(raw_image, base, entry.source, entry.size, &context)?;
                if *hash_bytes(bytes).as_bytes() != expected_hash {
                    return Err(bad(format!(
                        "{context} self-copy output BLAKE3 does not match the raw image"
                    )));
                }
            }
            MaterializationWire::ZeroFill => {
                if *hash_zeros(entry.size).as_bytes() != expected_hash {
                    return Err(bad(format!(
                        "{context} zero-fill output BLAKE3 does not match the load map"
                    )));
                }
                segments.push(ArtifactSegment {
                    address: entry.destination,
                    size: entry.size,
                    scatter_entry: entry.index,
                    backing: ArtifactBacking::Zero,
                });
            }
            MaterializationWire::File { path, .. } => {
                let copy_source = if entry.operation == Operation::Copy {
                    Some(raw_slice(
                        raw_image,
                        base,
                        entry.source,
                        entry.size,
                        &context,
                    )?)
                } else {
                    None
                };
                let file = open_authenticated_payload(
                    &manifest_parent,
                    &path,
                    entry.size,
                    expected_hash,
                    copy_source,
                    &context,
                )?;
                segments.push(ArtifactSegment {
                    address: entry.destination,
                    size: entry.size,
                    scatter_entry: entry.index,
                    backing: ArtifactBacking::File(Mutex::new(file)),
                });
            }
        }
    }

    Ok(MaterializedScatter {
        image_label: wire.image.label,
        image_base,
        image_size: raw_size,
        image_blake3,
        manifest_blake3,
        segments,
    })
}

fn open_manifest(root: &Path, manifest_path: &Path) -> Result<(File, TrustedDirectory)> {
    if !root.is_absolute() || !manifest_path.is_absolute() {
        return Err(bad("scatter root and load-map path must be absolute"));
    }
    let relative = manifest_path
        .strip_prefix(root)
        .map_err(|_| bad("scatter load map escapes the scatter root"))?;
    validate_relative_path(relative, "scatter load map")?;
    if relative.file_name().and_then(|name| name.to_str()) != Some("load_map.json") {
        return Err(bad("scatter load-map filename is not load_map.json"));
    }
    let trusted_root = TrustedDirectory::new(root, "scatter root")?;
    trusted_root.open_regular_file_with_parent(relative, "scatter load map")
}

fn read_manifest(mut file: File) -> Result<(LoadMapWire, [u8; 32])> {
    let length = file
        .metadata()
        .map_err(|error| bad(format!("scatter load-map metadata is unavailable: {error}")))?
        .len();
    if length > MAX_MANIFEST_BYTES {
        return Err(bad("scatter load map exceeds the manifest size limit"));
    }
    let length =
        usize::try_from(length).map_err(|_| bad("scatter load-map size does not fit the host"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| bad("scatter load-map allocation failed"))?;
    bytes.resize(length, 0);
    for chunk in bytes.chunks_mut(ZERO_CHUNK.len()) {
        file.read_exact(chunk).map_err(|error| {
            bad(format!(
                "scatter load map ended before its declared size: {error}"
            ))
        })?;
    }
    let mut trailing = [0; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| bad(format!("scatter load-map trailing read failed: {error}")))?
        != 0
    {
        return Err(bad(
            "scatter load map grew while it was being authenticated",
        ));
    }
    let manifest_blake3 = *hash_bytes(&bytes).as_bytes();
    let wire = serde_json::from_slice(&bytes)
        .map_err(|error| bad(format!("scatter load map is not strict v1 JSON: {error}")))?;
    Ok((wire, manifest_blake3))
}

fn open_authenticated_payload(
    manifest_parent: &TrustedDirectory,
    relative_path: &str,
    size: u32,
    expected_hash: [u8; 32],
    copy_source: Option<&[u8]>,
    context: &str,
) -> Result<File> {
    let payload_context = format!("{context} payload");
    let relative = Path::new(relative_path);
    let mut file = manifest_parent.open_regular_file(relative, &payload_context)?;
    let metadata = file.metadata().map_err(|error| {
        bad(format!(
            "{context} payload metadata is unavailable: {error}"
        ))
    })?;
    if metadata.len() != u64::from(size) {
        return Err(bad(format!(
            "{context} payload does not have its declared size"
        )));
    }

    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; 64 * 1024];
    let mut offset = 0u32;
    let mut copy_matches = true;
    while offset < size {
        let length = (size - offset).min(buffer.len() as u32) as usize;
        file.read_exact(&mut buffer[..length])
            .map_err(|error| bad(format!("{context} payload read failed: {error}")))?;
        hasher.update(&buffer[..length]);
        if let Some(source) = copy_source {
            let start = usize::try_from(offset)
                .map_err(|_| bad(format!("{context} copy offset does not fit the host")))?;
            let end = start
                .checked_add(length)
                .ok_or_else(|| bad(format!("{context} copy range overflows the host")))?;
            copy_matches &= source.get(start..end) == Some(&buffer[..length]);
        }
        offset = offset
            .checked_add(length as u32)
            .ok_or_else(|| bad(format!("{context} payload offset overflows u32")))?;
    }
    let mut trailing = [0; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| bad(format!("{context} payload trailing read failed: {error}")))?
        != 0
    {
        return Err(bad(format!("{context} payload exceeds its declared size")));
    }
    if *hasher.finalize().as_bytes() != expected_hash {
        return Err(bad(format!(
            "{context} payload BLAKE3 does not match the load map"
        )));
    }
    if !copy_matches {
        return Err(bad(format!(
            "{context} payload bytes do not match the raw copy source"
        )));
    }
    if file
        .metadata()
        .map_err(|error| {
            bad(format!(
                "{context} payload metadata is unavailable: {error}"
            ))
        })?
        .len()
        != u64::from(size)
    {
        return Err(bad(format!(
            "{context} payload size changed during authentication"
        )));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| bad(format!("{context} payload rewind failed: {error}")))?;
    Ok(file)
}

fn handler_for(operation: Operation, handlers: &ParsedHandlers) -> u32 {
    match operation {
        Operation::Null => handlers.null,
        Operation::Copy => handlers.copy,
        Operation::Decompress1 => handlers.decompress1,
        Operation::Zero => handlers.zero,
    }
}

fn parse_address(value: &str, context: &str) -> Result<u32> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || !value.starts_with("0x")
        || !bytes[2..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(bad(format!("{context} is not a canonical address")));
    }
    u32::from_str_radix(&value[2..], 16)
        .map_err(|_| bad(format!("{context} is outside the u32 address domain")))
}

fn parse_blake3(value: &str, context: &str) -> Result<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(bad(format!("{context} is not canonical lowercase BLAKE3")));
    }
    let mut output = [0; 32];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("parse_blake3 validates every hexadecimal digit"),
    }
}

fn raw_slice<'a>(
    raw: &'a [u8],
    base: u32,
    address: u32,
    size: u32,
    context: &str,
) -> Result<&'a [u8]> {
    let start = address
        .checked_sub(base)
        .ok_or_else(|| bad(format!("{context} raw range begins below the image")))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| bad(format!("{context} raw range overflows u32")))?;
    let start = usize::try_from(start)
        .map_err(|_| bad(format!("{context} raw offset does not fit the host")))?;
    let end = usize::try_from(end)
        .map_err(|_| bad(format!("{context} raw end does not fit the host")))?;
    raw.get(start..end)
        .ok_or_else(|| bad(format!("{context} raw range escapes the image")))
}

fn checked_end(start: u32, size: u32, context: &str) -> Result<u32> {
    start
        .checked_add(size)
        .ok_or_else(|| bad(format!("{context} range wraps the 32-bit address space")))
}

fn require_within_raw(
    start: u32,
    size: u32,
    raw_start: u32,
    raw_end: u32,
    context: &str,
) -> Result<()> {
    let end = checked_end(start, size, context)?;
    if size == 0 || start < raw_start || end > raw_end {
        return Err(bad(format!("{context} range escapes the raw image")));
    }
    Ok(())
}

fn ranges_overlap(first_start: u32, first_end: u32, second_start: u32, second_end: u32) -> bool {
    first_start < second_end && second_start < first_end
}

fn hash_bytes(bytes: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    for chunk in bytes.chunks(ZERO_CHUNK.len()) {
        hasher.update(chunk);
    }
    hasher.finalize()
}

fn hash_zeros(size: u32) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    let mut remaining = size;
    while remaining > 0 {
        let length = remaining.min(ZERO_CHUNK.len() as u32) as usize;
        hasher.update(&ZERO_CHUNK[..length]);
        remaining -= length as u32;
    }
    hasher.finalize()
}

fn stage_and_publish(
    plan: &LoadPlan,
    image: &[u8],
    label: &str,
    staging_dir: &Path,
    final_dir: &Path,
) -> Result<String> {
    let blocks_dir = staging_dir.join("blocks");
    fs::create_dir_all(&blocks_dir)?;

    let image_size = u32::try_from(image.len())
        .map_err(|_| bad("source image size does not fit the load-map schema"))?;
    if image_size != plan.image_size {
        return Err(bad(format!(
            "source image size {image_size} does not match planned size {}",
            plan.image_size
        )));
    }

    let mut entries = Vec::with_capacity(plan.entries.len());
    for entry in &plan.entries {
        entries.push(stage_entry(plan, image, entry, &blocks_dir)?);
    }
    let map = LoadMap {
        format: LOAD_MAP_FORMAT,
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION"),
        image: Image {
            label,
            base_addr: address(plan.image_base),
            size: plan.image_size,
            blake3: hash_bytes(image).to_hex().to_string(),
        },
        loader: Loader {
            address: address(plan.loader_address),
            literal_pair: address(plan.literal_pair_address),
        },
        table: Table {
            start: address(plan.table_start),
            end: address(plan.table_end),
            entry_count: plan.entries.len(),
            handlers: Handlers {
                null: address(plan.handlers.null),
                copy: address(plan.handlers.copy),
                decompress1: address(plan.handlers.decompress1),
                zero: address(plan.handlers.zero),
            },
        },
        entries,
    };
    let mut manifest =
        serde_json::to_vec_pretty(&map).map_err(|error| Error::Serialize(error.to_string()))?;
    manifest.push(b'\n');
    let manifest_blake3 = hash_bytes(&manifest).to_hex().to_string();
    fs::write(staging_dir.join("load_map.json"), manifest)?;
    fs::rename(staging_dir, final_dir)?;
    Ok(manifest_blake3)
}

fn stage_entry(
    plan: &LoadPlan,
    image: &[u8],
    entry: &PlannedEntry,
    blocks_dir: &Path,
) -> Result<Entry> {
    validate_operation_metadata(plan, entry)?;
    let (output_blake3, materialization) = match (&entry.operation, &entry.output) {
        (Operation::Null, PlannedOutput::None) => (None, Materialization::None),
        (Operation::Copy, PlannedOutput::SelfCopy) => {
            if entry.descriptor.source != entry.descriptor.destination {
                return Err(entry_error(
                    entry,
                    "self-copy source and destination differ",
                ));
            }
            let bytes = source_slice(plan, image, entry)?;
            (
                Some(hash_bytes(bytes).to_hex().to_string()),
                Materialization::None,
            )
        }
        (Operation::Copy, PlannedOutput::Bytes(bytes))
        | (Operation::Decompress1, PlannedOutput::Bytes(bytes)) => {
            validate_output_size(entry, bytes)?;
            let hash = hash_bytes(bytes).to_hex().to_string();
            match entry.storage() {
                PlannedStorage::ZeroFill => (Some(hash), Materialization::ZeroFill),
                PlannedStorage::Bytes(bytes) => {
                    let operation = operation_name(entry.operation);
                    let file_name = format!("{:02}-{operation}.bin", entry.index);
                    fs::write(blocks_dir.join(&file_name), bytes)?;
                    (
                        Some(hash),
                        Materialization::File {
                            path: format!("blocks/{file_name}"),
                            size: entry.descriptor.size,
                        },
                    )
                }
                _ => {
                    return Err(entry_error(
                        entry,
                        "byte output has an invalid storage classification",
                    ));
                }
            }
        }
        (Operation::Zero, PlannedOutput::ZeroFill) => (
            Some(blake3_zeros(entry.descriptor.size)),
            Materialization::ZeroFill,
        ),
        _ => {
            return Err(entry_error(
                entry,
                "planned output does not match the classified operation",
            ));
        }
    };

    Ok(Entry {
        index: entry.index,
        source: address(entry.descriptor.source),
        destination: address(entry.descriptor.destination),
        size: entry.descriptor.size,
        handler: address(entry.descriptor.handler),
        operation: entry.operation,
        compressed_size: entry.compressed_size,
        output_blake3,
        materialization,
    })
}

fn validate_operation_metadata(plan: &LoadPlan, entry: &PlannedEntry) -> Result<()> {
    let expected_handler = match entry.operation {
        Operation::Null => plan.handlers.null,
        Operation::Copy => plan.handlers.copy,
        Operation::Decompress1 => plan.handlers.decompress1,
        Operation::Zero => plan.handlers.zero,
    };
    if entry.descriptor.handler != expected_handler {
        return Err(entry_error(
            entry,
            "handler does not match the classified operation",
        ));
    }
    if (entry.operation == Operation::Decompress1) != entry.compressed_size.is_some() {
        return Err(entry_error(
            entry,
            "compressed size presence does not match the classified operation",
        ));
    }
    Ok(())
}

fn validate_output_size(entry: &PlannedEntry, bytes: &[u8]) -> Result<()> {
    let size = usize::try_from(entry.descriptor.size)
        .map_err(|_| entry_error(entry, "output size does not fit the host"))?;
    if bytes.len() != size {
        return Err(entry_error(
            entry,
            format!(
                "output byte length {} does not match declared size {}",
                bytes.len(),
                entry.descriptor.size
            ),
        ));
    }
    Ok(())
}

fn source_slice<'a>(plan: &LoadPlan, image: &'a [u8], entry: &PlannedEntry) -> Result<&'a [u8]> {
    let start = entry
        .descriptor
        .source
        .checked_sub(plan.image_base)
        .ok_or_else(|| entry_error(entry, "self-copy source begins below the source image"))?;
    let end = start
        .checked_add(entry.descriptor.size)
        .filter(|&end| end <= plan.image_size)
        .ok_or_else(|| entry_error(entry, "self-copy source range escapes the source image"))?;
    let start = usize::try_from(start)
        .map_err(|_| entry_error(entry, "self-copy source offset does not fit the host"))?;
    let end = usize::try_from(end)
        .map_err(|_| entry_error(entry, "self-copy source end does not fit the host"))?;
    image
        .get(start..end)
        .ok_or_else(|| entry_error(entry, "self-copy source range escapes the source image"))
}

fn blake3_zeros(size: u32) -> String {
    hash_zeros(size).to_hex().to_string()
}

fn validate_label(label: &str) -> Result<()> {
    let valid = !label.is_empty()
        && label != "."
        && label != ".."
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(bad(format!("invalid artifact label {label:?}")))
    }
}

fn scatter_directory(root: &Path, create: bool) -> Result<Option<PathBuf>> {
    let path = root.join("scatter");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root)?;
            match fs::create_dir(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            fs::symlink_metadata(&path)?
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(bad("artifact scatter path is not an owned real directory"));
    }
    Ok(Some(path))
}

fn remove_owned_path(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Null => "null",
        Operation::Copy => "copy",
        Operation::Decompress1 => "decompress1",
        Operation::Zero => "zero",
    }
}

fn address(value: u32) -> String {
    format!("{value:#010x}")
}

fn entry_error(entry: &PlannedEntry, reason: impl Into<String>) -> Error {
    bad(format!("entry {}: {}", entry.index, reason.into()))
}

fn bad(reason: impl Into<String>) -> Error {
    Error::BadScatter(reason.into())
}

#[cfg(test)]
mod tests {
    use super::{LOAD_MAP_FORMAT, clear_materialized, materialize, read_materialized};
    use crate::error::Error;
    use crate::runtime_image::{RuntimeImage, StorageKind, StorageSpan};
    use crate::scatter::{
        Descriptor, HandlerMap, LoadPlan, Operation, PlannedEntry, PlannedOutput,
    };
    use serde_json::json;
    #[cfg(unix)]
    use std::ffi::CString;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, symlink};
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::time::{Duration, Instant};
    use tempfile::{TempDir, tempdir};

    const BASE: u32 = 0x1000_0000;
    const IMAGE_LEN: usize = 0x1000;
    const NULL_HANDLER: u32 = BASE + 0x600;
    const COPY_HANDLER: u32 = BASE + 0x601;
    const DECOMPRESS1_HANDLER: u32 = BASE + 0x604;
    const ZERO_HANDLER: u32 = BASE + 0x609;
    const SENTINEL_SOURCE: u32 = BASE + 0x680;
    const SELF_COPY_SOURCE: u32 = BASE + 0x700;
    const COPY_SOURCE: u32 = BASE + 0x710;
    const DECOMPRESS1_SOURCE: u32 = BASE + 0x720;
    const ZERO_SOURCE: u32 = BASE + 0x730;

    struct Fixture {
        image: Vec<u8>,
        plan: LoadPlan,
    }

    fn fixture() -> Fixture {
        let mut image = vec![0; IMAGE_LEN];
        image[0x700..0x704].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        image[0x710..0x714].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        image[0x720..0x722].copy_from_slice(&[0x22, 0xaa]);

        let entries = vec![
            planned_entry(
                0,
                SENTINEL_SOURCE,
                0,
                0,
                NULL_HANDLER,
                Operation::Null,
                None,
                PlannedOutput::None,
            ),
            planned_entry(
                1,
                0,
                SENTINEL_SOURCE,
                0,
                NULL_HANDLER,
                Operation::Null,
                None,
                PlannedOutput::None,
            ),
            planned_entry(
                2,
                SELF_COPY_SOURCE,
                SELF_COPY_SOURCE,
                4,
                COPY_HANDLER,
                Operation::Copy,
                None,
                PlannedOutput::SelfCopy,
            ),
            planned_entry(
                3,
                COPY_SOURCE,
                0x2000_0100,
                4,
                COPY_HANDLER,
                Operation::Copy,
                None,
                PlannedOutput::Bytes(vec![0x11, 0x22, 0x33, 0x44]),
            ),
            planned_entry(
                4,
                DECOMPRESS1_SOURCE,
                0x2000_0200,
                3,
                DECOMPRESS1_HANDLER,
                Operation::Decompress1,
                Some(2),
                PlannedOutput::Bytes(vec![0xaa, 0, 0]),
            ),
            planned_entry(
                5,
                ZERO_SOURCE,
                0x2000_0300,
                5,
                ZERO_HANDLER,
                Operation::Zero,
                None,
                PlannedOutput::ZeroFill,
            ),
        ];
        let plan = LoadPlan {
            image_base: BASE,
            image_size: IMAGE_LEN as u32,
            loader_address: BASE + 0x40,
            literal_pair_address: BASE + 0x80,
            table_start: BASE + 0x200,
            table_end: BASE + 0x260,
            handlers: HandlerMap {
                null: NULL_HANDLER,
                copy: COPY_HANDLER,
                decompress1: DECOMPRESS1_HANDLER,
                zero: ZERO_HANDLER,
            },
            entries,
            logical_output_size: 16,
        };
        Fixture { image, plan }
    }

    #[allow(clippy::too_many_arguments)]
    fn planned_entry(
        index: usize,
        source: u32,
        destination: u32,
        size: u32,
        handler: u32,
        operation: Operation,
        compressed_size: Option<u32>,
        output: PlannedOutput,
    ) -> PlannedEntry {
        PlannedEntry {
            index,
            descriptor: Descriptor {
                source,
                destination,
                size,
                handler,
            },
            operation,
            compressed_size,
            output,
        }
    }

    fn strict_case() -> (Fixture, TempDir, PathBuf) {
        let fixture = fixture();
        let root = tempdir().unwrap();
        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        let manifest = root.path().join(artifact.relative_path);
        (fixture, root, manifest)
    }

    fn mutate_manifest(path: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
        let mut document = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        mutate(&mut document);
        let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
    }

    fn assert_bad_reader<T>(result: crate::error::Result<T>, expected: &str) {
        match result {
            Err(Error::BadScatter(reason)) => assert!(
                reason.contains(expected),
                "expected {expected:?} in reader failure, got {reason:?}"
            ),
            Err(other) => panic!("expected bad scatter reader failure, got {other:?}"),
            Ok(_) => panic!("strict reader accepted invalid input"),
        }
    }

    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
    }

    #[cfg(unix)]
    fn delayed_fifo_writer(path: PathBuf, delay: Duration) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            let _ = fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path);
        })
    }

    #[test]
    fn materializes_exact_pretty_schema_hashes_and_payloads() {
        let fixture = fixture();
        let root = tempdir().unwrap();

        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        assert_eq!(LOAD_MAP_FORMAT, "pixel-modem-extractor-scatter-load-v1");
        assert_eq!(artifact.relative_path, "scatter/02_MAIN/load_map.json");

        let manifest_path = root.path().join(&artifact.relative_path);
        let bytes = fs::read(&manifest_path).unwrap();
        let expected = r#"{
  "format": "pixel-modem-extractor-scatter-load-v1",
  "schema_version": 1,
  "tool_version": "2.0.0",
  "image": {
    "label": "02_MAIN",
    "base_addr": "0x10000000",
    "size": 4096,
    "blake3": "e6e58cd8b4cdf2a04a31d39aea29579eecda4d8f58147c10a9e478c279092e8a"
  },
  "loader": {
    "address": "0x10000040",
    "literal_pair": "0x10000080"
  },
  "table": {
    "start": "0x10000200",
    "end": "0x10000260",
    "entry_count": 6,
    "handlers": {
      "null": "0x10000600",
      "copy": "0x10000601",
      "decompress1": "0x10000604",
      "zero": "0x10000609"
    }
  },
  "entries": [
    {
      "index": 0,
      "source": "0x10000680",
      "destination": "0x00000000",
      "size": 0,
      "handler": "0x10000600",
      "operation": "null",
      "materialization": {
        "kind": "none"
      }
    },
    {
      "index": 1,
      "source": "0x00000000",
      "destination": "0x10000680",
      "size": 0,
      "handler": "0x10000600",
      "operation": "null",
      "materialization": {
        "kind": "none"
      }
    },
    {
      "index": 2,
      "source": "0x10000700",
      "destination": "0x10000700",
      "size": 4,
      "handler": "0x10000601",
      "operation": "copy",
      "output_blake3": "650e93bacca01942a5a787f2f3ec4ce560998eb7c250733601a880d7f0c11178",
      "materialization": {
        "kind": "none"
      }
    },
    {
      "index": 3,
      "source": "0x10000710",
      "destination": "0x20000100",
      "size": 4,
      "handler": "0x10000601",
      "operation": "copy",
      "output_blake3": "a7c8ca54b7a30c966b22e012bdef6cbda17a47047f323f482d62c2b999e9e275",
      "materialization": {
        "kind": "file",
        "path": "blocks/03-copy.bin",
        "size": 4
      }
    },
    {
      "index": 4,
      "source": "0x10000720",
      "destination": "0x20000200",
      "size": 3,
      "handler": "0x10000604",
      "operation": "decompress1",
      "compressed_size": 2,
      "output_blake3": "f15560edad7f63b7ff8df07a8222f6246941621ad8db903b047972ccc5a4ab9b",
      "materialization": {
        "kind": "file",
        "path": "blocks/04-decompress1.bin",
        "size": 3
      }
    },
    {
      "index": 5,
      "source": "0x10000730",
      "destination": "0x20000300",
      "size": 5,
      "handler": "0x10000609",
      "operation": "zero",
      "output_blake3": "cdc96eca844d7912acdbb3dca677757d0db5747a1df61166339cfc7156d4880f",
      "materialization": {
        "kind": "zero_fill"
      }
    }
  ]
}
"#;
        assert_eq!(bytes, expected.as_bytes());
        assert_eq!(
            artifact.blake3,
            blake3::hash(expected.as_bytes()).to_hex().to_string()
        );
        assert_eq!(
            fs::read(root.path().join("scatter/02_MAIN/blocks/03-copy.bin")).unwrap(),
            [0x11, 0x22, 0x33, 0x44]
        );
        assert_eq!(
            fs::read(
                root.path()
                    .join("scatter/02_MAIN/blocks/04-decompress1.bin")
            )
            .unwrap(),
            [0xaa, 0, 0]
        );
        let mut names = fs::read_dir(root.path().join("scatter/02_MAIN/blocks"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["03-copy.bin", "04-decompress1.bin"]);
    }

    #[test]
    fn all_zero_decompression_uses_zero_fill_without_a_payload_file() {
        let mut fixture = fixture();
        fixture.plan.entries[4].output = PlannedOutput::Bytes(vec![0; 3]);
        let root = tempdir().unwrap();

        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join(artifact.relative_path)).unwrap())
                .unwrap();

        assert_eq!(
            manifest["entries"][4]["output_blake3"],
            "91525ff00a3755a8df93c626b59f6e36cf021d85ebccecdedc38f3f1890a15fc"
        );
        assert_eq!(
            manifest["entries"][4]["materialization"],
            json!({"kind": "zero_fill"})
        );
        assert!(
            !root
                .path()
                .join("scatter/02_MAIN/blocks/04-decompress1.bin")
                .exists()
        );
    }

    #[test]
    fn all_zero_copy_remains_file_backed() {
        let mut fixture = fixture();
        fixture.image[0x710..0x714].fill(0);
        fixture.plan.entries[3].output = PlannedOutput::Bytes(vec![0; 4]);
        let root = tempdir().unwrap();

        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join(artifact.relative_path)).unwrap())
                .unwrap();

        assert_eq!(
            manifest["entries"][3]["output_blake3"],
            "ec2bd03bf86b935fa34d71ad7ebb049f1f10f87d343e521511d8f9e6625620cd"
        );
        assert_eq!(
            manifest["entries"][3]["materialization"],
            json!({"kind": "file", "path": "blocks/03-copy.bin", "size": 4})
        );
        assert_eq!(
            fs::read(root.path().join("scatter/02_MAIN/blocks/03-copy.bin")).unwrap(),
            [0, 0, 0, 0]
        );
    }

    #[test]
    fn zero_fill_hash_crosses_the_chunk_boundary() {
        let size = 64 * 1024 + 1;
        let expected = blake3::hash(&vec![0; size as usize]).to_hex().to_string();

        assert_eq!(super::blake3_zeros(size), expected);
    }

    #[test]
    fn rerun_is_byte_identical_and_replaces_stale_owned_output() {
        let fixture = fixture();
        let root = tempdir().unwrap();
        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        let manifest_path = root.path().join(&artifact.relative_path);
        let first = fs::read(&manifest_path).unwrap();
        let final_dir = root.path().join("scatter/02_MAIN");
        fs::write(final_dir.join("stale.bin"), b"stale").unwrap();
        fs::write(&manifest_path, b"stale manifest").unwrap();
        let staging = root
            .path()
            .join(format!("scatter/02_MAIN.staging+{}", std::process::id()));
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("stale.bin"), b"stale staging").unwrap();

        let rerun = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();

        assert_eq!(rerun, artifact);
        assert_eq!(fs::read(&manifest_path).unwrap(), first);
        assert!(!final_dir.join("stale.bin").exists());
        assert!(!staging.exists());
    }

    #[test]
    fn failed_staging_exposes_no_manifest_and_cleans_staging() {
        let mut fixture = fixture();
        let root = tempdir().unwrap();
        materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        fixture.plan.entries[2].descriptor.source = BASE + IMAGE_LEN as u32 - 2;
        fixture.plan.entries[2].descriptor.destination = BASE + IMAGE_LEN as u32 - 2;
        let final_dir = root.path().join("scatter/02_MAIN");
        let staging = root
            .path()
            .join(format!("scatter/02_MAIN.staging+{}", std::process::id()));

        let error = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap_err();

        assert!(
            matches!(error, Error::BadScatter(reason) if reason.contains("entry 2") && reason.contains("source"))
        );
        assert!(!final_dir.join("load_map.json").exists());
        assert!(!final_dir.exists());
        assert!(!staging.exists());
    }

    #[cfg(unix)]
    #[test]
    fn clear_rejects_intermediate_scatter_symlink_without_touching_target() {
        let root = tempdir().unwrap();
        let external = tempdir().unwrap();
        let external_label = external.path().join("02_MAIN");
        fs::create_dir(&external_label).unwrap();
        let sentinel = external_label.join("keep.bin");
        fs::write(&sentinel, b"external").unwrap();
        symlink(external.path(), root.path().join("scatter")).unwrap();

        let result = clear_materialized(root.path(), "02_MAIN");
        let sentinel_after = fs::read(&sentinel);

        assert!(matches!(result, Err(Error::BadScatter(_))));
        assert_eq!(sentinel_after.unwrap(), b"external");
        assert!(
            fs::symlink_metadata(root.path().join("scatter"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn materialize_rejects_intermediate_scatter_symlink_without_touching_target() {
        let fixture = fixture();
        let root = tempdir().unwrap();
        let external = tempdir().unwrap();
        let external_label = external.path().join("02_MAIN");
        fs::create_dir(&external_label).unwrap();
        let sentinel = external_label.join("keep.bin");
        fs::write(&sentinel, b"external").unwrap();
        symlink(external.path(), root.path().join("scatter")).unwrap();

        let result = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path());
        let sentinel_after = fs::read(&sentinel);
        let external_manifest = external_label.join("load_map.json").exists();

        assert!(matches!(result, Err(Error::BadScatter(_))));
        assert_eq!(sentinel_after.unwrap(), b"external");
        assert!(!external_manifest);
        assert!(
            fs::symlink_metadata(root.path().join("scatter"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn materializing_short_label_preserves_valid_legacy_staging_name_label() {
        let fixture = fixture();
        let root = tempdir().unwrap();
        let colliding_label = format!("A.staging-{}", std::process::id());
        let colliding =
            materialize(&fixture.plan, &fixture.image, &colliding_label, root.path()).unwrap();
        let colliding_dir = root.path().join("scatter").join(&colliding_label);
        let manifest_before = fs::read(root.path().join(colliding.relative_path)).unwrap();
        fs::write(colliding_dir.join("keep.bin"), b"owned by colliding label").unwrap();

        materialize(&fixture.plan, &fixture.image, "A", root.path()).unwrap();

        assert_eq!(
            fs::read(colliding_dir.join("load_map.json")).unwrap(),
            manifest_before
        );
        assert_eq!(
            fs::read(colliding_dir.join("keep.bin")).unwrap(),
            b"owned by colliding label"
        );
        assert!(root.path().join("scatter/A/load_map.json").exists());
    }

    #[test]
    fn clear_removes_only_the_owned_label_directory_and_absence_succeeds() {
        let root = tempdir().unwrap();
        let owned = root.path().join("scatter/02_MAIN");
        let sibling = root.path().join("scatter/03_DSP");
        let similarly_named = root.path().join("scatter/02_MAIN.staging-foreign");
        let unrelated = root.path().join("outside");
        for path in [&owned, &sibling, &similarly_named, &unrelated] {
            fs::create_dir_all(path).unwrap();
            fs::write(path.join("keep.bin"), b"keep").unwrap();
        }

        clear_materialized(root.path(), "02_MAIN").unwrap();

        assert!(!owned.exists());
        assert!(sibling.join("keep.bin").exists());
        assert!(similarly_named.join("keep.bin").exists());
        assert!(unrelated.join("keep.bin").exists());
        clear_materialized(root.path(), "02_MAIN").unwrap();
        assert!(sibling.join("keep.bin").exists());
    }

    #[test]
    fn labels_accept_only_safe_ascii_components() {
        let fixture = fixture();
        let root = tempdir().unwrap();
        for label in ["A", "02_MAIN", "a.b-c_9", "a..b", "-", "_"] {
            let artifact = materialize(&fixture.plan, &fixture.image, label, root.path()).unwrap();
            assert_eq!(
                artifact.relative_path,
                format!("scatter/{label}/load_map.json")
            );
            clear_materialized(root.path(), label).unwrap();
        }

        let invalid_root = tempdir().unwrap();
        for label in [
            "", ".", "..", "a/b", "a\\b", "a b", "a\tb", "a\nb", "a;b", "$(id)", "`id`", "a&b",
            "a|b", "a*b", "a?b", "a>b", "a<b", "a'b", "a\"b", "[ab]", "{a,b}", "!a", "é",
        ] {
            let clear_error = clear_materialized(invalid_root.path(), label).unwrap_err();
            assert!(
                matches!(clear_error, Error::BadScatter(_)),
                "clear accepted {label:?}"
            );
            let write_error =
                materialize(&fixture.plan, &fixture.image, label, invalid_root.path()).unwrap_err();
            assert!(
                matches!(write_error, Error::BadScatter(_)),
                "materialize accepted {label:?}"
            );
        }
        assert!(!invalid_root.path().join("scatter").exists());
    }

    #[test]
    fn strict_reader_accepts_canonical_materialization() {
        let fixture = fixture();
        let root = tempdir().unwrap();
        let artifact = materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        let manifest = root.path().join(&artifact.relative_path);
        let manifest_bytes = fs::read(&manifest).unwrap();

        let scatter = read_materialized(root.path(), &manifest, &fixture.image, BASE).unwrap();

        assert_eq!(scatter.image_label, "02_MAIN");
        assert_eq!(scatter.image_base, BASE);
        assert_eq!(scatter.image_size, IMAGE_LEN as u32);
        assert_eq!(
            scatter.image_blake3,
            *blake3::hash(&fixture.image).as_bytes()
        );
        assert_eq!(
            scatter.manifest_blake3,
            *blake3::hash(&manifest_bytes).as_bytes()
        );
        assert_eq!(
            artifact.blake3,
            blake3::hash(&manifest_bytes).to_hex().to_string()
        );
        let runtime =
            RuntimeImage::from_artifact(&fixture.image, BASE, root.path(), Some(&manifest))
                .unwrap();
        assert_eq!(
            runtime.read_exact(0x2000_0100, 4).unwrap().as_ref(),
            [0x11, 0x22, 0x33, 0x44]
        );
        assert_eq!(
            runtime.read_exact(0x2000_0300, 5).unwrap().as_ref(),
            [0, 0, 0, 0, 0]
        );
        assert_eq!(
            scatter
                .segments
                .iter()
                .map(|segment| (
                    segment.scatter_entry(),
                    segment.address(),
                    segment.size(),
                    segment.is_zero_fill(),
                ))
                .collect::<Vec<_>>(),
            [
                (3, 0x2000_0100, 4, false),
                (4, 0x2000_0200, 3, false),
                (5, 0x2000_0300, 5, true),
            ]
        );

        #[cfg(unix)]
        {
            let payload = manifest.parent().unwrap().join("blocks/03-copy.bin");
            let authenticated = payload.with_extension("authenticated");
            fs::rename(&payload, &authenticated).unwrap();
            fs::write(&payload, [0xde, 0xad, 0xbe, 0xef]).unwrap();
            let segment = scatter
                .segments
                .iter()
                .find(|segment| segment.scatter_entry() == 3)
                .unwrap();
            let mut bytes = [0; 4];
            segment.read_exact(0, &mut bytes).unwrap();
            assert_eq!(bytes, [0x11, 0x22, 0x33, 0x44]);
        }
    }

    #[test]
    fn plan_and_artifact_use_identical_zero_and_byte_backed_provenance() {
        let mut fixture = fixture();
        fixture.image[0x710..0x714].fill(0);
        fixture.plan.entries[3].output = PlannedOutput::Bytes(vec![0; 4]);
        fixture.plan.entries[4].output = PlannedOutput::Bytes(vec![0; 3]);
        let root = tempdir().unwrap();
        let materialized =
            materialize(&fixture.plan, &fixture.image, "02_MAIN", root.path()).unwrap();
        let manifest = root.path().join(materialized.relative_path);
        let planned = RuntimeImage::from_plan(&fixture.image, BASE, Some(&fixture.plan)).unwrap();
        let retained =
            RuntimeImage::from_artifact(&fixture.image, BASE, root.path(), Some(&manifest))
                .unwrap();

        let copy_storage = vec![StorageSpan {
            kind: StorageKind::ScatterBytes,
            address: 0x2000_0100,
            size: 4,
            scatter_entry: Some(3),
        }];
        assert_eq!(planned.storage_spans(0x2000_0100, 4).unwrap(), copy_storage);
        assert_eq!(
            retained.storage_spans(0x2000_0100, 4).unwrap(),
            copy_storage
        );
        assert!(planned.is_byte_backed(0x2000_0100, 4).unwrap());
        assert!(retained.is_byte_backed(0x2000_0100, 4).unwrap());

        let zero_storage = vec![StorageSpan {
            kind: StorageKind::ScatterZero,
            address: 0x2000_0200,
            size: 3,
            scatter_entry: Some(4),
        }];
        assert_eq!(planned.storage_spans(0x2000_0200, 3).unwrap(), zero_storage);
        assert_eq!(
            retained.storage_spans(0x2000_0200, 3).unwrap(),
            zero_storage
        );
        assert!(!planned.is_byte_backed(0x2000_0200, 3).unwrap());
        assert!(!retained.is_byte_backed(0x2000_0200, 3).unwrap());
        assert_eq!(planned.read_exact(0x2000_0200, 3).unwrap().as_ref(), [0; 3]);
        assert_eq!(
            retained.read_exact(0x2000_0200, 3).unwrap().as_ref(),
            [0; 3]
        );
    }

    #[cfg(unix)]
    #[test]
    fn strict_reader_rejects_non_regular_files_before_opening() {
        const WRITER_DELAY: Duration = Duration::from_millis(400);
        const MAX_PREOPEN_REJECTION: Duration = Duration::from_millis(200);

        let (fixture, root, manifest) = strict_case();
        fs::remove_file(&manifest).unwrap();
        make_fifo(&manifest);
        let writer = delayed_fifo_writer(manifest.clone(), WRITER_DELAY);
        let started = Instant::now();
        let result = read_materialized(root.path(), &manifest, &fixture.image, BASE);
        let elapsed = started.elapsed();
        writer.join().unwrap();
        assert_bad_reader(result, "regular file");
        assert!(
            elapsed < MAX_PREOPEN_REJECTION,
            "manifest FIFO was opened before rejection: {elapsed:?}"
        );

        let (fixture, root, manifest) = strict_case();
        let payload = manifest.parent().unwrap().join("blocks/03-copy.bin");
        fs::remove_file(&payload).unwrap();
        make_fifo(&payload);
        let writer = delayed_fifo_writer(payload, WRITER_DELAY);
        let started = Instant::now();
        let result = read_materialized(root.path(), &manifest, &fixture.image, BASE);
        let elapsed = started.elapsed();
        writer.join().unwrap();
        assert_bad_reader(result, "regular file");
        assert!(
            elapsed < MAX_PREOPEN_REJECTION,
            "payload FIFO was opened before rejection: {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn trusted_directory_rejects_final_symlink_replacement() {
        let root = tempdir().unwrap();
        let path = root.path().join("payload.bin");
        fs::write(&path, b"same bytes").unwrap();
        let trusted = super::TrustedDirectory::new(root.path(), "test root").unwrap();
        fs::rename(&path, root.path().join("authenticated.bin")).unwrap();
        symlink(root.path().join("authenticated.bin"), &path).unwrap();

        assert_bad_reader(
            trusted.open_regular_file(Path::new("payload.bin"), "test payload"),
            "is a symlink",
        );
    }

    #[test]
    fn windows_root_binding_rejects_redirected_handle_proof() {
        let opened = super::WindowsObjectProof {
            resolved_path: PathBuf::from("/outside/root"),
            identity: super::FileIdentity { volume: 7, file: 9 },
        };

        assert_bad_reader(
            super::validate_windows_root_binding(Path::new("/trusted/root"), &opened, "test root"),
            "does not match the requested canonical path",
        );
    }

    #[test]
    fn windows_child_binding_rejects_replaced_parent_authority() {
        let retained_parent = super::WindowsObjectProof {
            resolved_path: PathBuf::from("/trusted/root"),
            identity: super::FileIdentity { volume: 7, file: 9 },
        };
        let opened = super::WindowsObjectProof {
            resolved_path: PathBuf::from("/trusted/root/child"),
            identity: super::FileIdentity {
                volume: 7,
                file: 10,
            },
        };

        assert_bad_reader(
            super::validate_windows_child_binding(
                &retained_parent,
                Path::new("/trusted/root/child"),
                super::FileIdentity {
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
        let root = super::WindowsObjectProof {
            resolved_path: PathBuf::from("/trusted/root"),
            identity: super::FileIdentity { volume: 7, file: 9 },
        };
        let child = super::WindowsObjectProof {
            resolved_path: PathBuf::from("/trusted/root/child"),
            identity: super::FileIdentity {
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

    #[cfg(unix)]
    #[test]
    fn strict_reader_rejects_intermediate_directory_replacement() {
        let (_fixture, root, manifest) = strict_case();
        let outside = tempdir().unwrap();
        let trusted_scatter = root.path().join("scatter");
        let outside_scatter = outside.path().join("outside-scatter");
        let replacement = trusted_scatter.clone();
        let target = outside_scatter.clone();
        super::set_before_contained_open("scatter load map", move || {
            fs::rename(&replacement, &target).unwrap();
            symlink(&target, &replacement).unwrap();
        });

        let result = super::open_manifest(root.path(), &manifest).map(|_| ());

        assert_bad_reader(result, "directory component");
        assert!(outside_scatter.join("02_MAIN/load_map.json").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn strict_reader_rejects_payload_intermediate_directory_replacement() {
        let (fixture, root, manifest) = strict_case();
        let outside = tempdir().unwrap();
        let trusted_blocks = manifest.parent().unwrap().join("blocks");
        let outside_blocks = outside.path().join("outside-blocks");
        let replacement = trusted_blocks.clone();
        let target = outside_blocks.clone();
        super::set_before_contained_open("scatter entry 4 payload", move || {
            fs::rename(&replacement, &target).unwrap();
            symlink(&target, &replacement).unwrap();
        });

        let result = read_materialized(root.path(), &manifest, &fixture.image, BASE);

        assert_bad_reader(result, "directory component");
        assert!(outside_blocks.join("03-copy.bin").is_file());
    }

    #[test]
    fn strict_reader_rejects_changed_or_unsafe_inputs() {
        let (fixture, root, manifest) = strict_case();
        mutate_manifest(&manifest, |document| {
            document["image"]["blake3"] =
                json!("0000000000000000000000000000000000000000000000000000000000000000");
        });
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "raw image BLAKE3",
        );

        let (fixture, root, manifest) = strict_case();
        mutate_manifest(&manifest, |document| {
            document["entries"][3]["materialization"]["path"] = json!("../outside.bin");
        });
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "payload path",
        );

        #[cfg(unix)]
        {
            let (fixture, root, manifest) = strict_case();
            let payload = manifest.parent().unwrap().join("blocks/03-copy.bin");
            let target = payload.with_extension("target");
            fs::rename(&payload, &target).unwrap();
            symlink(&target, &payload).unwrap();
            assert_bad_reader(
                read_materialized(root.path(), &manifest, &fixture.image, BASE),
                "payload is a symlink",
            );
        }

        let (fixture, root, manifest) = strict_case();
        fs::write(
            manifest.parent().unwrap().join("blocks/03-copy.bin"),
            [0x11, 0x22, 0x33],
        )
        .unwrap();
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "declared size",
        );

        let (fixture, root, manifest) = strict_case();
        fs::write(
            manifest.parent().unwrap().join("blocks/03-copy.bin"),
            [0xde, 0xad, 0xbe, 0xef],
        )
        .unwrap();
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "BLAKE3",
        );

        let (mut fixture, root, manifest) = strict_case();
        fixture.image[0] ^= 0xff;
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "raw image BLAKE3",
        );

        let (fixture, root, manifest) = strict_case();
        mutate_manifest(&manifest, |document| {
            document["entries"][4]["destination"] = json!("0x20000102");
        });
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "overlaps",
        );

        let (fixture, root, manifest) = strict_case();
        mutate_manifest(&manifest, |document| {
            document["unexpected"] = json!(true);
        });
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "unknown field",
        );

        let (fixture, root, manifest) = strict_case();
        mutate_manifest(&manifest, |document| {
            document["entries"][0]["output_blake3"] = serde_json::Value::Null;
        });
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "strict v1 JSON",
        );

        let (fixture, root, manifest) = strict_case();
        mutate_manifest(&manifest, |document| {
            document["entries"][2]["compressed_size"] = serde_json::Value::Null;
        });
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "strict v1 JSON",
        );

        let (fixture, root, manifest) = strict_case();
        mutate_manifest(&manifest, |document| {
            document["entries"][5]["destination"] = json!("0x60000000");
            document["entries"][5]["size"] = json!(512 * 1024 * 1024u32);
        });
        assert_bad_reader(
            read_materialized(root.path(), &manifest, &fixture.image, BASE),
            "logical output",
        );
    }
}
