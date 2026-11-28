//! Controlled real-kernel I/O regression, not a sandbox/runtime probe.
#[cfg(target_os = "linux")]
#[path = "../src/fileio.rs"]
mod fileio;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::unix::fs::{DirBuilderExt, MetadataExt},
        path::Path,
    };
    fn require(condition: bool, message: &str) -> std::io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(std::io::Error::other(message))
        }
    }
    let limit: u64 = fs::read_to_string("/sys/fs/cgroup/memory.max")?
        .trim()
        .parse()?;
    require(
        limit == 128 * 1024 * 1024,
        "regression requires the actual128MiB cgroup",
    )?;
    let root = Path::new("/work").join(format!("copy-{}", uuid::Uuid::new_v4()));
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let result = (|| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let source = root.join("source");
        let destination = root.join("destination");
        let size = 1024 * 1024 * 1024 + 17;
        let mut file = File::create(&source)?;
        file.set_len(size)?;
        file.write_all(b"immutable-source")?;
        file.seek(SeekFrom::Start(size - 4))?;
        file.write_all(b"tail")?;
        file.sync_all()?;
        drop(file);
        let expected = fileio::digest_exact(File::open(&source)?, size)?;
        require(expected.1 == size, "source logical length mismatch")?;
        fileio::copy(File::open(&source)?, &destination, &expected.0, size, 0o600)?;
        let metadata = destination.metadata()?;
        require(
            metadata.len() == size,
            "destination logical length mismatch",
        )?;
        require(
            metadata.blocks() * 512 < 16 * 1024 * 1024,
            "sparse copy unexpectedly allocated dense storage",
        )?;
        {
            let mut copied = File::open(&destination)?;
            copied.seek(SeekFrom::Start(size - 4))?;
            let mut last = [0; 4];
            copied.read_exact(&mut last)?;
            require(&last == b"tail", "trailing payload mismatch")?;
        }
        {
            let mut changed = OpenOptions::new().write(true).open(&destination)?;
            changed.write_all(b"private-change")?;
            changed.sync_all()?;
        }
        require(
            fileio::digest(File::open(&source)?)? == expected,
            "private destination mutation changed source",
        )?;
        let executable = fileio::digest(File::open(std::env::current_exe()?)?)?.0;
        let peak: u64 = fs::read_to_string("/sys/fs/cgroup/memory.peak")?
            .trim()
            .parse()?;
        let events = fs::read_to_string("/sys/fs/cgroup/memory.events.local")?;
        let kills = events
            .lines()
            .find_map(|line| line.strip_prefix("oom_kill "))
            .ok_or("missing OOM counter")?
            .parse::<u64>()?;
        require(
            peak <= limit && kills == 0,
            "actual cgroup OOM or boundary violation",
        )?;
        Ok(
            serde_json::json!({"size_bytes":size,"source_sha256":expected.0,"allocated_destination_bytes":metadata.blocks()*512,
            "memory_max_bytes":limit,"memory_peak_bytes":peak,"memory_events_local":events,"binary_sha256":executable,
            "scope":"controlled file copy only; no guest or runtime capability acceptance"}),
        )
    })();
    fs::remove_dir_all(&root)?;
    require(
        !root.try_exists()?,
        "owned copy directory collection unconfirmed",
    )?;
    require(
        fs::read_dir("/work")?.next().is_none(),
        "owned fixture volume is not empty",
    )?;
    let observations = result?;
    println!(
        "{}",
        serde_json::json!({"suite":"actual128MiB-sparse-file-copy","result":"passed","cleanup":"complete","observations":observations})
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("controlled memory copy regression requires Linux cgroupv2".into())
}
