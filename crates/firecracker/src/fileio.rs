//! Descriptor-bound, verified file transfer with bounded cache windows. A
//! small userspace buffer alone does not bound cgroup-charged dirty/file cache.
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

const WINDOW: u64 = 1024 * 1024;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn advise(file: &File, offset: u64, length: u64, advice: libc::c_int) -> io::Result<()> {
    let offset = offset
        .try_into()
        .map_err(|_| invalid("file advice offset exceeds ABI"))?;
    let length = length
        .try_into()
        .map_err(|_| invalid("file advice length exceeds ABI"))?;
    let error = unsafe { libc::posix_fadvise(file.as_raw_fd(), offset, length, advice) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    Ok(())
}
fn discard(file: &File, offset: u64, length: u64) -> io::Result<()> {
    if length != 0 {
        advise(file, offset, length, libc::POSIX_FADV_DONTNEED)?;
    }
    Ok(())
}

pub(crate) fn digest(input: File) -> io::Result<(String, u64)> {
    digest_inner(input, None)
}

pub(crate) fn digest_exact(input: File, expected_size: u64) -> io::Result<(String, u64)> {
    digest_inner(input, Some(expected_size))
}

fn digest_inner(mut input: File, expected_size: Option<u64>) -> io::Result<(String, u64)> {
    // Disable speculative readahead on this descriptor. DONTNEED remains a
    // kernel hint; the actual memory boundary still needs the native gate.
    advise(&input, 0, 0, libc::POSIX_FADV_RANDOM)?;
    let start = input.stream_position()?;
    let mut window = 0u64;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| invalid("file hash length overflow"))?;
        if expected_size.is_some_and(|size| count > size) {
            return Err(invalid("file exceeds its reserved hash length"));
        }
        hash.update(&buffer[..read]);
        if count - window >= WINDOW {
            discard(&input, start + window, count - window)?;
            window = count;
        }
    }
    discard(&input, start + window, count - window)?;
    if expected_size.is_some_and(|size| count != size) {
        return Err(invalid("file hash length differs"));
    }
    Ok((format!("{:x}", hash.finalize()), count))
}

pub(crate) fn copy(
    input: File,
    destination: &Path,
    expected_sha: &str,
    expected_size: u64,
    mode: u32,
) -> io::Result<()> {
    if input.metadata()?.len() != expected_size {
        return Err(invalid("artifact length mismatch"));
    }
    let output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(destination)?;
    copy_to(input, output, expected_sha, expected_size)?;
    Ok(())
}

/// The caller owns the destination descriptor and its publication/collection.
/// A fresh unnamed output can be dropped on failure without a named partial.
pub(crate) fn copy_to(
    mut input: File,
    mut output: File,
    expected_sha: &str,
    expected_size: u64,
) -> io::Result<File> {
    if input.metadata()?.len() != expected_size || output.metadata()?.len() != 0 {
        return Err(invalid("artifact input length or fresh output differs"));
    }
    input.rewind()?;
    output.rewind()?;
    advise(&input, 0, 0, libc::POSIX_FADV_RANDOM)?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut window = 0u64;
    let mut dirty = false;
    let mut buffer = [0u8; 65536];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| invalid("artifact size overflow"))?;
        if count > expected_size {
            return Err(invalid("artifact changed while copying"));
        }
        hash.update(&buffer[..read]);
        if buffer[..read].iter().all(|byte| *byte == 0) {
            // Preserve zero regions as independent sparse holes, including the
            // trailing hole, whose logical size is set explicitly below.
            output.seek(SeekFrom::Current(read as i64))?;
        } else {
            output.write_all(&buffer[..read])?;
            dirty = true;
        }
        if count - window >= WINDOW {
            if dirty {
                output.sync_data()?;
                discard(&output, window, count - window)?;
                dirty = false;
            }
            discard(&input, window, count - window)?;
            window = count;
        }
    }
    if count != expected_size || format!("{:x}", hash.finalize()) != expected_sha {
        return Err(invalid("artifact digest mismatch"));
    }
    output.set_len(count)?;
    output.sync_all()?;
    discard(&output, window, count - window)?;
    discard(&input, window, count - window)?;
    output.rewind()?;
    if digest(output.try_clone()?)? != (expected_sha.to_owned(), expected_size) {
        return Err(invalid("copied artifact digest mismatch"));
    }
    output.rewind()?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    #[test]
    fn sparse_copy_has_exact_bytes_length_independent_mutation_and_no_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_owned();
        let source = root.join("source");
        let target = root.join("target");
        let size = 16 * WINDOW + 17;
        let mut file = File::create(&source).unwrap();
        file.set_len(size).unwrap();
        file.write_all(b"start").unwrap();
        file.seek(SeekFrom::Start(8 * WINDOW + 7)).unwrap();
        file.write_all(b"middle").unwrap();
        file.seek(SeekFrom::Start(size - 3)).unwrap();
        file.write_all(b"end").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let expected = format!("{:x}", Sha256::digest(std::fs::read(&source).unwrap()));
        assert_eq!(
            digest_exact(File::open(&source).unwrap(), size).unwrap(),
            (expected.clone(), size)
        );
        assert!(digest_exact(File::open(&source).unwrap(), size - 1).is_err());
        assert!(digest_exact(File::open(&source).unwrap(), size + 1).is_err());
        copy(
            File::open(&source).unwrap(),
            &target,
            &expected,
            size,
            0o600,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&source).unwrap(),
            std::fs::read(&target).unwrap()
        );
        assert_eq!(target.metadata().unwrap().len(), size);
        assert!(target.metadata().unwrap().blocks() * 512 < size / 2);
        {
            let mut changed = OpenOptions::new().write(true).open(&target).unwrap();
            changed.write_all(b"local").unwrap();
            changed.sync_all().unwrap();
        }
        assert_eq!(
            digest(File::open(&source).unwrap()).unwrap(),
            (expected.clone(), size)
        );
        let changed = std::fs::read(&target).unwrap();
        assert!(
            copy(
                File::open(&source).unwrap(),
                &target,
                &expected,
                size,
                0o600
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&target).unwrap(), changed);
        let bad = root.join("bad");
        assert!(
            copy(
                File::open(&source).unwrap(),
                &bad,
                &"0".repeat(64),
                size,
                0o600
            )
            .is_err()
        );
        let short = root.join("short");
        assert!(
            copy(
                File::open(&source).unwrap(),
                &short,
                &expected,
                size - 1,
                0o600
            )
            .is_err()
        );
        assert!(!short.exists());
        directory.close().unwrap();
        assert!(!root.exists());
    }
}
