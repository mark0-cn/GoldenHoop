//! A complete, synced manifest is the commit point. Shared gVisor gofer
//! mounts reject RENAME_NOREPLACE; hard-link creation still cannot clobber.
use super::{invalid, trusted};
use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(super) fn publish(source: &Path, destination: &Path) -> io::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("publication has no parent"))?;
    if source == destination || source.parent() != Some(parent) {
        return Err(invalid("publication requires sibling directories"));
    }
    let names = ["owner.json", "rootfs.ext4", "manifest.json"];
    let mut files = Vec::new();
    for name in names {
        let file = trusted(&source.join(name))?;
        let metadata = file.metadata()?;
        if metadata.nlink() != 1 || metadata.mode() & 0o7777 != 0o400 {
            return Err(invalid("publication input ownership or links differ"));
        }
        file.sync_all()?;
        files.push(file);
    }
    // mkdir is the no-replace claim. A pre-existing directory grants no
    // authority, even if empty. Only this exclusive converter writes its stage.
    fs::DirBuilder::new().mode(0o700).create(destination)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    for (index, name) in names.into_iter().enumerate() {
        if name == "manifest.json" {
            // Data names and the new directory persist before the complete
            // manifest becomes visible. Directory presence alone is not Ready.
            directory.sync_all()?;
            parent.sync_all()?;
        }
        fs::hard_link(source.join(name), destination.join(name))?;
        let expected = files[index].metadata()?;
        let observed = trusted(&destination.join(name))?.metadata()?;
        if observed.dev() != expected.dev()
            || observed.ino() != expected.ino()
            || observed.nlink() != 2
            || observed.len() != expected.len()
        {
            return Err(invalid("publication inode readback differs"));
        }
    }
    directory.sync_all()?;
    parent.sync_all()?;
    // Unlike tempfile's best-effort unlink, stage collection and its directory
    // sync are required for success. A later failure cannot accept an image.
    fs::remove_dir_all(source)?;
    parent.sync_all()?;
    for name in names {
        if trusted(&destination.join(name))?.metadata()?.nlink() != 1 {
            return Err(invalid("published file still has another link"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn stage(root: &Path) -> std::path::PathBuf {
        let path = root.join("generation.writing");
        fs::create_dir(&path).unwrap();
        for (name, bytes) in [
            ("owner.json", b"owned-generation".as_slice()),
            ("rootfs.ext4", b"verified-disk".as_slice()),
            ("manifest.json", b"complete-manifest".as_slice()),
        ] {
            fs::write(path.join(name), bytes).unwrap();
            fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o400)).unwrap();
        }
        path
    }

    #[test]
    fn complete_publication_preserves_content_inodes_and_collects_staging() {
        let root = tempfile::tempdir().unwrap();
        let source = stage(root.path());
        let ready = root.path().join("generation");
        if unsafe { libc::geteuid() } != 0 {
            assert!(publish(&source, &ready).is_err());
            assert!(!ready.exists());
            return;
        }
        let inode = fs::metadata(source.join("rootfs.ext4")).unwrap().ino();
        publish(&source, &ready).unwrap();
        assert!(!source.exists());
        assert_eq!(
            fs::read(ready.join("manifest.json")).unwrap(),
            b"complete-manifest"
        );
        assert_eq!(
            fs::read(ready.join("rootfs.ext4")).unwrap(),
            b"verified-disk"
        );
        let metadata = fs::metadata(ready.join("rootfs.ext4")).unwrap();
        assert_eq!(metadata.ino(), inode);
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn existing_generation_and_foreign_source_links_are_never_adopted_or_unlinked() {
        let root = tempfile::tempdir().unwrap();
        let source = stage(root.path());
        let ready = root.path().join("generation");
        fs::create_dir(&ready).unwrap();
        fs::write(ready.join("foreign"), b"keep").unwrap();
        assert!(publish(&source, &ready).is_err());
        assert_eq!(fs::read(ready.join("foreign")).unwrap(), b"keep");
        assert!(source.join("rootfs.ext4").exists());
        fs::remove_file(ready.join("foreign")).unwrap();
        fs::remove_dir(&ready).unwrap();
        let foreign = root.path().join("foreign-disk");
        fs::hard_link(source.join("rootfs.ext4"), &foreign).unwrap();
        assert!(publish(&source, &ready).is_err());
        assert!(!ready.exists());
        assert_eq!(fs::read(&foreign).unwrap(), b"verified-disk");
        assert!(source.join("rootfs.ext4").exists());
    }
}
