use crate::error::{Error, Result};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

/// The versioned whole-tree hash scheme: `pme-paq-v1`. blake3 leaf-set of
/// (root-relative path, file bytes) over the entire tree — hidden entries
/// included, no exclusion list. Fail-closed: a missing, unreadable, symlink-
/// bearing, or non-UTF-8-path tree yields a typed error and no hash.
pub fn pme_paq_v1(dir: &Path) -> Result<String> {
    validate_hashable_tree(dir)?;
    let dir = dir.to_path_buf();
    let hash = catch_unwind(AssertUnwindSafe(|| {
        paq::hash_source(&dir, /* ignore_hidden = */ false)
    }))
    .map_err(|_| Error::BadTree("pme-paq-v1 hashing failed (traversal or IO)".into()))?;
    Ok(hash.as_str().to_ascii_lowercase())
}

/// Reject before hashing anything the leaf-set walk cannot faithfully represent:
/// a nonexistent root, any symlink, or a non-UTF-8 path component.
fn validate_hashable_tree(dir: &Path) -> Result<()> {
    if dir.to_str().is_none() {
        return Err(Error::BadTree(
            "tree-hash target path is not valid UTF-8".into(),
        ));
    }
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|_| Error::BadTree("tree-hash target does not exist".into()))?;
    if !meta.is_dir() {
        return Err(Error::BadTree("tree-hash target is not a directory".into()));
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)
            .map_err(|_| Error::BadTree("tree-hash target is unreadable".into()))?
        {
            let entry =
                entry.map_err(|_| Error::BadTree("tree-hash entry is unreadable".into()))?;
            if entry.file_name().to_str().is_none() {
                return Err(Error::BadTree("tree-hash path is not valid UTF-8".into()));
            }
            let file_type = entry
                .file_type()
                .map_err(|_| Error::BadTree("tree-hash entry type is unreadable".into()))?;
            if file_type.is_symlink() {
                return Err(Error::BadTree("tree-hash tree contains a symlink".into()));
            }
            if file_type.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::pme_paq_v1;
    use std::fs;

    fn tree(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tree");
        for (rel, bytes) in files {
            let path = dir.path().join(rel);
            fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
            fs::write(path, bytes).expect("write");
        }
        dir
    }

    #[test]
    fn content_name_hidden_and_membership_all_change_the_hash() {
        let base = tree(&[("a.txt", b"one"), ("sub/b.txt", b"two"), (".hidden", b"h")]);
        let h = pme_paq_v1(base.path()).expect("hash");
        assert_eq!(h.len(), 64);
        assert!(
            h.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        let content = tree(&[("a.txt", b"ONE"), ("sub/b.txt", b"two"), (".hidden", b"h")]);
        let name = tree(&[("a.txt", b"one"), ("sub/c.txt", b"two"), (".hidden", b"h")]);
        let no_hidden = tree(&[("a.txt", b"one"), ("sub/b.txt", b"two")]);
        let added = tree(&[
            ("a.txt", b"one"),
            ("sub/b.txt", b"two"),
            (".hidden", b"h"),
            ("c.txt", b"x"),
        ]);
        for other in [&content, &name, &no_hidden, &added] {
            assert_ne!(h, pme_paq_v1(other.path()).expect("hash"));
        }
    }

    #[test]
    fn missing_non_directory_symlinked_and_unreadable_trees_fail_closed() {
        assert!(pme_paq_v1(std::path::Path::new("/no/such/tree")).is_err());
        let file_dir = tempfile::tempdir().expect("file_dir");
        let plain_file = file_dir.path().join("not-a-tree.txt");
        fs::write(&plain_file, b"x").expect("plain file");
        assert!(pme_paq_v1(&plain_file).is_err());
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().expect("t");
            fs::write(dir.path().join("real"), b"r").expect("real");
            std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link"))
                .expect("symlink");
            assert!(pme_paq_v1(dir.path()).is_err());
            use std::os::unix::fs::PermissionsExt;
            let locked_dir = tempfile::tempdir().expect("locked_dir");
            let locked = locked_dir.path().join("locked");
            fs::create_dir(&locked).expect("locked subdir");
            fs::write(locked.join("inside.txt"), b"inside").expect("inside file");
            fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("lock");
            let result = pme_paq_v1(locked_dir.path());
            fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("restore");
            assert!(result.is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_root_path_fails_closed() {
        // paq strips the root prefix before .to_str(), so a non-UTF-8 ROOT
        // basename never panics inside paq — only the explicit root check
        // catches it. Regression ported from pe-decompose.
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let parent = tempfile::tempdir().expect("parent");
        let bad_name = OsString::from_vec(b"ro\x80ot".to_vec());
        let root = parent.path().join(&bad_name);
        fs::create_dir(&root).expect("root");
        fs::write(root.join("a.txt"), b"one").expect("a.txt");
        assert!(pme_paq_v1(&root).is_err());
    }

    #[test]
    fn pinned_pme_paq_v1_vector() {
        // Locks the scheme against a paq behaviour change. Compute once on the
        // first green run and paste the 64-hex constant here; a later paq bump
        // that moves it forces a named pme-paq-v2 revision + fresh goldens.
        let fixture = tree(&[("a.txt", b"one"), ("sub/b.txt", b"two"), (".hidden", b"h")]);
        assert_eq!(pme_paq_v1(fixture.path()).expect("hash"), PIN);
    }
    const PIN: &str = "1ee2df54d76c421981a80ae45e4ce43376a442ae9c33fabc5c320cc9702c01b4";
}
