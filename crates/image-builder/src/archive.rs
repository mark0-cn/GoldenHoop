use crate::{MAX_ENTRIES, invalid};
use std::{
    fs::File,
    io::{self, Read, Seek},
    path::{Component, Path},
    sync::atomic::{AtomicBool, Ordering},
};

struct Guarded<'a> {
    file: &'a mut File,
    cancel: &'a AtomicBool,
}
impl Read for Guarded<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(invalid("image preparation interrupted"));
        }
        self.file.read(bytes)
    }
}
impl Seek for Guarded<'_> {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(invalid("image preparation interrupted"));
        }
        self.file.seek(position)
    }
}

fn path_allowed(path: &Path, root_directory: bool) -> io::Result<()> {
    if path.as_os_str().as_encoded_bytes().len() > 4096
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
        || !root_directory
            && !path
                .components()
                .any(|part| matches!(part, Component::Normal(_)))
    {
        return Err(invalid("archive path is outside the private image root"));
    }
    Ok(())
}

/// Raw preflight bounds extended headers before tar-rs normal iteration can
/// allocate them. Reject sparse/PAX-size interpretations and special nodes.
pub(crate) fn preflight(file: &mut File, maximum: u64, cancel: &AtomicBool) -> io::Result<()> {
    file.rewind()?;
    let mut archive = tar::Archive::new(Guarded {
        file: &mut *file,
        cancel,
    });
    let mut total = 0u64;
    for (index, entry) in archive.entries_with_seek()?.raw(true).enumerate() {
        if cancel.load(Ordering::Acquire) {
            return Err(invalid("image preparation interrupted"));
        }
        if index >= MAX_ENTRIES {
            return Err(invalid("archive entry limit exceeded"));
        }
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        let size = entry.size();
        if kind.is_gnu_longname() || kind.is_gnu_longlink() || kind.is_pax_local_extensions() {
            if size > 65536 {
                return Err(invalid("archive extended header exceeds limit"));
            }
            if kind.is_pax_local_extensions() {
                let extensions = entry
                    .pax_extensions()?
                    .ok_or_else(|| invalid("missing PAX extensions"))?;
                for extension in extensions {
                    let extension = extension?;
                    let key = extension.key_bytes();
                    if key == b"size"
                        || key.starts_with(b"GNU.sparse")
                        || key.len() > 256
                        || extension.value_bytes().len() > 4096
                    {
                        return Err(invalid("unsupported or oversized PAX metadata"));
                    }
                }
            }
        } else if kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link() {
            if size > maximum {
                return Err(invalid("archive file exceeds disk limit"));
            }
            if kind.is_file() {
                total = total
                    .checked_add(size)
                    .ok_or_else(|| invalid("archive size overflow"))?;
            }
            if total > maximum {
                return Err(invalid("archive payload exceeds disk limit"));
            }
        } else {
            return Err(invalid(
                "archive special nodes and sparse/global extensions are forbidden",
            ));
        }
    }
    file.rewind()?;
    Ok(())
}

/// The OS-isolated builder exclusively owns this tree. tar-rs explicitly does
/// not protect against a second process mutating its destination concurrently.
pub(crate) fn unpack(file: &mut File, root: &Path, cancel: &AtomicBool) -> io::Result<()> {
    file.rewind()?;
    let mut archive = tar::Archive::new(Guarded { file, cancel });
    archive.set_preserve_ownerships(true);
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    for entry in archive.entries()? {
        if cancel.load(Ordering::Acquire) {
            return Err(invalid("image preparation interrupted"));
        }
        let mut entry = entry?;
        let directory = entry.header().entry_type().is_dir();
        path_allowed(&entry.path()?, directory)?;
        if entry.header().entry_type().is_hard_link() {
            path_allowed(
                &entry
                    .link_name()?
                    .ok_or_else(|| invalid("missing hardlink target"))?,
                false,
            )?;
        }
        if directory
            && !entry
                .path()?
                .components()
                .any(|part| matches!(part, Component::Normal(_)))
        {
            continue;
        }
        if !entry.unpack_in(root)? {
            return Err(invalid("archive entry was not safely extracted"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn archive(kind: tar::EntryType, path: &str, target: Option<&str>) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(0);
        header.set_mode(0o755);
        if let Some(target) = target {
            header.set_link_name(target).unwrap();
        }
        header.set_cksum();
        builder.append_data(&mut header, path, io::empty()).unwrap();
        builder.into_inner().unwrap()
    }
    #[test]
    fn special_nodes_sparse_and_oversized_metadata_are_refused_before_unpack() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_owned();
        for kind in [
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
            tar::EntryType::GNUSparse,
            tar::EntryType::XGlobalHeader,
        ] {
            let file = path.join("input.tar");
            std::fs::write(&file, archive(kind, "node", None)).unwrap();
            assert!(
                preflight(
                    &mut File::open(file).unwrap(),
                    1024 * 1024,
                    &AtomicBool::new(false)
                )
                .is_err()
            );
        }
        let file = path.join("oversized.tar");
        let mut output = File::create(&file).unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNULongName);
        header.set_size(65537);
        header.set_cksum();
        output.write_all(header.as_bytes()).unwrap();
        drop(output);
        assert!(
            preflight(
                &mut File::open(file).unwrap(),
                1024 * 1024,
                &AtomicBool::new(false)
            )
            .is_err()
        );
        directory.close().unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn symlink_escape_cannot_write_the_sibling_and_cancellation_refuses() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_owned();
        let root = path.join("root");
        std::fs::create_dir(&root).unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        link.set_link_name("..").unwrap();
        link.set_cksum();
        builder
            .append_data(&mut link, "escape", io::empty())
            .unwrap();
        let mut file = tar::Header::new_gnu();
        file.set_size(6);
        file.set_mode(0o644);
        file.set_cksum();
        builder
            .append_data(&mut file, "escape/canary", &b"unsafe"[..])
            .unwrap();
        let input = path.join("input.tar");
        std::fs::write(&input, builder.into_inner().unwrap()).unwrap();
        let mut file = File::open(&input).unwrap();
        preflight(&mut file, 1024 * 1024, &AtomicBool::new(false)).unwrap();
        assert!(unpack(&mut file, &root, &AtomicBool::new(false)).is_err());
        assert!(!path.join("canary").exists());
        assert!(preflight(&mut file, 1024 * 1024, &AtomicBool::new(true)).is_err());
        directory.close().unwrap();
        assert!(!path.exists());
    }
}
