//! Trusted, isolated bootstrap utility for public, immutable resolver files.
use goldenhoop_core::resolver::ResolverConfig;
use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

fn invalid() -> io::Error {
    io::Error::other("owned resolver configuration differs")
}

pub fn configure(gateway: Ipv4Addr) -> io::Result<()> {
    // This utility is invoked only in the trusted, network-none bundle helper.
    if unsafe { libc::geteuid() } != 0
        || std::env::var("GOLDENHOOP_ISOLATED_AGENT").as_deref() != Ok("1")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "isolated root helper required",
        ));
    }
    write_in(Path::new("/bundle"), &ResolverConfig::new(gateway))
}

fn verify(path: &Path, config: &ResolverConfig) -> io::Result<bool> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o444
        || metadata.len() != config.contents().len() as u64
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(128).read_to_end(&mut bytes)?;
    if bytes != config.contents().as_bytes() {
        return Err(invalid());
    }
    Ok(true)
}

fn write_in(directory: &Path, config: &ResolverConfig) -> io::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(invalid());
    }
    let path = directory.join(config.file_name());
    if verify(&path, config)? {
        return Ok(());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(config.contents().as_bytes())?;
    temporary
        .as_file()
        .set_permissions(Permissions::from_mode(0o444))?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(&path) {
        Ok(file) => file.sync_all()?,
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => drop(error),
        Err(error) => return Err(error.error),
    }
    File::open(directory)?.sync_all()?;
    if !verify(&path, config)? {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn resolver_cache_is_atomic_immutable_and_rejects_links_or_changed_content() {
        let directory = tempfile::tempdir().unwrap();
        let config = ResolverConfig::new("192.0.2.1".parse().unwrap());
        write_in(directory.path(), &config).unwrap();
        write_in(directory.path(), &config).unwrap();
        let path = directory.path().join(config.file_name());
        assert_eq!(fs::read(&path).unwrap(), config.contents().as_bytes());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o444);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);

        fs::remove_file(&path).unwrap();
        let foreign = directory.path().join("foreign");
        fs::write(&foreign, config.contents()).unwrap();
        symlink(&foreign, &path).unwrap();
        assert!(write_in(directory.path(), &config).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), config.contents().as_bytes());
        fs::remove_file(&path).unwrap();
        fs::write(&path, "nameserver 127.0.0.11\n").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o444)).unwrap();
        assert!(write_in(directory.path(), &config).is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "nameserver 127.0.0.11\n"
        );
        fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
    }
}
