//! Inspect a read-only, clean ext4 disk in the existing isolated builder.
//! Only fixed guest paths/inodes are read. No filesystem mount, recursive dump,
//! journal repair, guest executable or caller-supplied debugfs command is used.
use super::*;
use crate::{
    InspectedFile, RootfsGuestConfig, RootfsInspection, RootfsInspectionInventory,
    RootfsInspectionReport, RootfsInspectionRequest,
};
use std::io::{Seek, SeekFrom};

const DISK: &str = "/input/rootfs.ext4";
const DEBUGFS: &str = "/usr/sbin/debugfs";

pub fn inventory() -> io::Result<RootfsInspectionInventory> {
    let cancel = AtomicBool::new(false);
    let result = RootfsInspectionInventory {
        format: 1,
        builder_version: env!("CARGO_PKG_VERSION").into(),
        agent: content(trusted(Path::new(AGENT))?, &cancel)?,
        init: content(trusted(Path::new(INIT))?, &cancel)?,
        e2fsck: content(trusted(Path::new(FSCK))?, &cancel)?,
        debugfs: content(trusted(Path::new(DEBUGFS))?, &cancel)?,
    };
    result.validate()?;
    Ok(result)
}

pub fn read_request() -> io::Result<RootfsInspectionRequest> {
    let file = trusted(Path::new("/input/inspect-rootfs.json"))?;
    if file.metadata()?.len() > 65536 {
        return Err(invalid("rootfs inspection request exceeds limit"));
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(invalid("rootfs inspection request exceeds limit"));
    }
    let request: RootfsInspectionRequest = serde_json::from_slice(&bytes)?;
    request.validate()?;
    Ok(request)
}

fn clean_superblock(bytes: &[u8; 1024], disk_bytes: u64) -> io::Result<()> {
    let short = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let word = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let flags = word(0x60);
    let shift = word(0x18);
    let blocks = u64::from(word(4))
        | if flags & 0x80 != 0 {
            u64::from(word(0x150)) << 32
        } else {
            0
        };
    if short(0x38) != 0xef53
        || short(0x3a) != 1
        || flags & (0x4 | 0x8) != 0
        || flags & 0x40 == 0
        || shift > 2
        || blocks.checked_mul(1024u64 << shift) != Some(disk_bytes)
    {
        return Err(invalid(
            "rootfs requires a clean, full-length ext4 filesystem without pending journal recovery",
        ));
    }
    Ok(())
}

fn verify_disk(request: &RootfsInspectionRequest, cancel: &AtomicBool) -> io::Result<()> {
    let mut file = trusted(Path::new(DISK))?;
    let metadata = file.metadata()?;
    if metadata.nlink() != 1 || metadata.len() != request.disk.size_bytes {
        return Err(invalid(
            "rootfs input has another link or a different length",
        ));
    }
    file.seek(SeekFrom::Start(1024))?;
    let mut block = [0; 1024];
    file.read_exact(&mut block)?;
    clean_superblock(&block, request.disk.size_bytes)?;
    file.rewind()?;
    if content(file, cancel)? != request.disk {
        return Err(invalid("rootfs disk content digest differs"));
    }
    Ok(())
}

#[derive(Debug)]
struct Inode {
    number: u32,
    kind: String,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    links: u32,
    target: Option<String>,
}
fn one_line<'a>(text: &'a str, prefix: &str) -> io::Result<&'a str> {
    let mut lines = text.lines().filter_map(|line| line.strip_prefix(prefix));
    let first = lines
        .next()
        .ok_or_else(|| invalid("rootfs inode observation is incomplete"))?;
    if lines.next().is_some() {
        return Err(invalid("rootfs inode observation is ambiguous"));
    }
    Ok(first)
}
fn number(text: &str, field: &str) -> io::Result<u64> {
    let fields: Vec<_> = text.split_whitespace().collect();
    let indexes: Vec<_> = fields
        .iter()
        .enumerate()
        .filter_map(|(i, s)| (*s == field).then_some(i))
        .collect();
    if indexes.len() != 1 {
        return Err(invalid("rootfs inode numeric field is ambiguous"));
    }
    fields
        .get(indexes[0] + 1)
        .ok_or_else(|| invalid("rootfs inode numeric field is missing"))?
        .parse()
        .map_err(|_| invalid("invalid rootfs inode numeric field"))
}
fn parse_stat(text: &str) -> io::Result<Inode> {
    let header = one_line(text, "Inode:")?;
    let (inode, rest) = header
        .split_once("Type:")
        .ok_or_else(|| invalid("rootfs inode type missing"))?;
    let (kind, rest) = rest
        .split_once("Mode:")
        .ok_or_else(|| invalid("rootfs inode mode missing"))?;
    let (mode, _) = rest
        .split_once("Flags:")
        .ok_or_else(|| invalid("rootfs inode flags missing"))?;
    let owner = one_line(text, "User:")?;
    let owners = format!("User: {owner}");
    let links = format!("Links: {}", one_line(text, "Links:")?);
    let target = if kind.trim() == "symlink" {
        Some(
            one_line(text, "Fast link dest: ")?
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .ok_or_else(|| invalid("rootfs symlink target is not a bounded fast link"))?
                .to_owned(),
        )
    } else {
        None
    };
    let result = Inode {
        number: inode
            .trim()
            .parse()
            .map_err(|_| invalid("invalid rootfs inode number"))?,
        kind: kind.trim().into(),
        mode: u32::from_str_radix(mode.trim(), 8)
            .map_err(|_| invalid("invalid rootfs inode mode"))?,
        uid: number(&owners, "User:")?
            .try_into()
            .map_err(|_| invalid("rootfs inode UID overflows"))?,
        gid: number(&owners, "Group:")?
            .try_into()
            .map_err(|_| invalid("rootfs inode GID overflows"))?,
        size: number(&owners, "Size:")?,
        links: number(&links, "Links:")?
            .try_into()
            .map_err(|_| invalid("rootfs inode links overflow"))?,
        target,
    };
    if result.number == 0 || result.mode > 0o7777 || result.links == 0 {
        return Err(invalid("invalid rootfs inode metadata"));
    }
    Ok(result)
}
async fn stat(path: &str, cancel: Arc<AtomicBool>, collected: &mut bool) -> io::Result<Inode> {
    let (count, bytes) = tool_output(
        DEBUGFS,
        &["-R".into(), format!("stat {path}").into(), DISK.into()],
        cancel,
        collected,
    )
    .await?;
    if count != bytes.len() {
        return Err(invalid("rootfs inode observation exceeds retained bound"));
    }
    parse_stat(
        std::str::from_utf8(&bytes)
            .map_err(|_| invalid("rootfs inode observation is not UTF-8"))?,
    )
}
async fn directory(path: &str, cancel: Arc<AtomicBool>, collected: &mut bool) -> io::Result<()> {
    let value = stat(path, cancel, collected).await?;
    if value.kind != "directory"
        || value.uid != 0
        || value.gid != 0
        || value.mode & 0o022 != 0
        || value.mode & 0o700 != 0o700
    {
        return Err(invalid(
            "rootfs protected parent is not a root-owned protected directory",
        ));
    }
    Ok(())
}
async fn read_asset(
    path: &str,
    destination: &Path,
    expected: Option<&Content>,
    mode: u32,
    maximum: u64,
    cancel: Arc<AtomicBool>,
    collected: &mut bool,
) -> io::Result<InspectedFile> {
    let value = stat(path, cancel.clone(), collected).await?;
    if value.kind != "regular"
        || value.uid != 0
        || value.gid != 0
        || value.mode != mode
        || value.links != 1
        || value.size == 0
        || value.size > maximum
        || expected.is_some_and(|e| e.size_bytes != value.size)
        || !absent(destination)?
    {
        return Err(invalid("rootfs protected asset metadata differs"));
    }
    tool(
        DEBUGFS,
        &[
            "-R".into(),
            format!("dump <{}> {}", value.number, destination.display()).into(),
            DISK.into(),
        ],
        cancel.clone(),
        collected,
    )
    .await?;
    let file = trusted(destination)?;
    if file.metadata()?.nlink() != 1 || file.metadata()?.len() != value.size {
        return Err(invalid(
            "rootfs protected asset dump length or links differ",
        ));
    }
    let found = content(file, &cancel)?;
    if expected.is_some_and(|e| *e != found) {
        return Err(invalid("rootfs protected asset content digest differs"));
    }
    Ok(InspectedFile {
        path: path.into(),
        inode: value.number,
        uid: value.uid,
        gid: value.gid,
        mode: value.mode,
        links: value.links,
        content: found,
    })
}

pub async fn inspect(
    request: RootfsInspectionRequest,
    cancel: Arc<AtomicBool>,
) -> RootfsInspectionReport {
    inspect_inner(request, cancel, None).await
}
pub async fn inspect_authorized(
    request: RootfsInspectionRequest,
    permit: HostPermit,
    cancel: Arc<AtomicBool>,
) -> RootfsInspectionReport {
    inspect_inner(request, cancel, Some(permit)).await
}
async fn inspect_inner(
    request: RootfsInspectionRequest,
    cancel: Arc<AtomicBool>,
    permit: Option<HostPermit>,
) -> RootfsInspectionReport {
    let mut report = RootfsInspectionReport {
        passed: false,
        staging_absent: false,
        tools_collected: true,
        inspection: None,
        error: None,
    };
    let stage = Path::new("/output").join(format!("{}.checking", request.generation));
    let mut owned = false;
    let timer = {
        let flag = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(600)).await;
            flag.store(true, Ordering::Release);
        })
    };
    let result: io::Result<()> = async {
        request.validate()?;
        verify_isolation()?;
        if let Some(permit) = &permit {
            permit.validate_rootfs(&request)?;
            if fs::read_to_string("/proc/sys/kernel/hostname")?.trim()
                != request.generation.simple().to_string()
            {
                return Err(invalid("rootfs permit hostname/generation binding differs"));
            }
            if permit.runtime == BuilderRuntime::RuncDevelopment {
                verify_context()?;
            }
        } else {
            verify_context()?;
        }
        let metadata = fs::symlink_metadata("/output")?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || !absent(&stage)?
        {
            return Err(invalid(
                "rootfs inspection stage is not an absent owned generation",
            ));
        }
        let pinned = inventory()?;
        if request.agent != pinned.agent || request.init != pinned.init {
            return Err(invalid(
                "rootfs expected guest assets differ from the pinned inspector",
            ));
        }
        let first = request.clone();
        let flag = cancel.clone();
        tokio::task::spawn_blocking(move || verify_disk(&first, &flag))
            .await
            .map_err(io::Error::other)??;
        fs::DirBuilder::new().mode(0o700).create(&stage)?;
        owned = true;
        let mut owner = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(stage.join("owner.json"))?;
        owner.write_all(&serde_json::to_vec(&request)?)?;
        owner.sync_all()?;
        drop(owner);
        tool(
            FSCK,
            &["-f".into(), "-n".into(), DISK.into()],
            cancel.clone(),
            &mut report.tools_collected,
        )
        .await?;
        for path in [
            "/",
            "/usr",
            "/usr/local",
            "/usr/local/bin",
            "/etc",
            "/etc/goldenhoop",
            "/proc",
            "/sys",
            "/dev",
            "/run",
        ] {
            directory(path, cancel.clone(), &mut report.tools_collected).await?;
        }
        let sbin = stat("/sbin", cancel.clone(), &mut report.tools_collected).await?;
        let init_path = if sbin.kind == "symlink"
            && sbin.links == 1
            && matches!(sbin.target.as_deref(), Some("usr/sbin" | "/usr/sbin"))
        {
            directory("/usr/sbin", cancel.clone(), &mut report.tools_collected).await?;
            "/usr/sbin/goldenhoop-init"
        } else {
            directory("/sbin", cancel.clone(), &mut report.tools_collected).await?;
            "/sbin/goldenhoop-init"
        };
        let workspace = stat("/workspace", cancel.clone(), &mut report.tools_collected).await?;
        if workspace.kind != "directory" || workspace.uid != 1000 || workspace.gid != 1000 {
            return Err(invalid(
                "rootfs workspace type or workload ownership differs",
            ));
        }
        let agent = read_asset(
            "/usr/local/bin/goldenhoop-agent",
            &stage.join("agent"),
            Some(&request.agent),
            0o755,
            64 * 1024 * 1024,
            cancel.clone(),
            &mut report.tools_collected,
        )
        .await?;
        let init = read_asset(
            init_path,
            &stage.join("init"),
            Some(&request.init),
            0o755,
            64 * 1024 * 1024,
            cancel.clone(),
            &mut report.tools_collected,
        )
        .await?;
        let config_path = stage.join("guest.json");
        let guest_config = read_asset(
            "/etc/goldenhoop/guest.json",
            &config_path,
            None,
            0o644,
            4096,
            cancel.clone(),
            &mut report.tools_collected,
        )
        .await?;
        let guest: RootfsGuestConfig = serde_json::from_reader(trusted(&config_path)?)?;
        guest.validate()?;
        if guest != request.guest {
            return Err(invalid(
                "rootfs guest configuration differs from the trusted request",
            ));
        }
        let last = request.clone();
        let flag = cancel.clone();
        tokio::task::spawn_blocking(move || verify_disk(&last, &flag))
            .await
            .map_err(io::Error::other)??;
        if inventory()? != pinned || cancel.load(Ordering::Acquire) {
            return Err(invalid(
                "rootfs inspector changed or inspection was interrupted",
            ));
        }
        let found = RootfsInspection {
            format: 1,
            generation: request.generation,
            disk: request.disk.clone(),
            agent,
            init,
            guest_config,
            guest,
            inventory: pinned,
        };
        found.validate_for(&request, &found.inventory)?;
        report.inspection = Some(found);
        Ok(())
    }
    .await;
    timer.abort();
    if owned
        && report.tools_collected
        && let Err(error) = fs::remove_dir_all(&stage)
    {
        report.error = Some(format!(
            "rootfs inspection stage collection failed: {error}"
        ));
    }
    report.staging_absent = absent(&stage).unwrap_or(false);
    match result {
        Ok(()) if report.staging_absent && report.tools_collected && report.error.is_none() => {
            report.passed = true
        }
        Ok(()) => report.error = Some("rootfs inspection collection is unconfirmed".into()),
        Err(error) => {
            report.error = Some(format!(
                "{error}{}",
                report
                    .error
                    .as_ref()
                    .map(|e| format!("; {e}"))
                    .unwrap_or_default()
            ))
        }
    }
    if !report.passed {
        report.inspection = None;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inode_observations_require_unambiguous_type_owner_size_and_link_fields() {
        let text = "Inode: 18   Type: regular    Mode:  0755   Flags: 0x80000\nGeneration: 0\nUser: 0 Group: 0 Project: 0 Size: 123\nLinks: 1 Blockcount: 8\nFragment: Address: 0 Number: 0 Size: 0\n";
        let inode = parse_stat(text).unwrap();
        assert_eq!(inode.number, 18);
        assert_eq!(inode.mode, 0o755);
        assert_eq!(inode.size, 123);
        assert!(parse_stat(&text.replace("Group: 0", "Group: invalid")).is_err());
        assert!(parse_stat(&format!("{text}User: 0 Group: 0 Size: 123\n")).is_err());
        assert!(parse_stat(&text.replace("Links: 1", "Links: 0")).is_err());
        assert!(parse_stat("").is_err());
    }
    #[test]
    fn cold_disk_refuses_pending_journal_errors_trailing_bytes_and_wrong_magic() {
        let mut block = [0; 1024];
        block[0x38..0x3a].copy_from_slice(&0xef53u16.to_le_bytes());
        block[0x3a..0x3c].copy_from_slice(&1u16.to_le_bytes());
        block[0x60..0x64].copy_from_slice(&0x40u32.to_le_bytes());
        block[0x18..0x1c].copy_from_slice(&2u32.to_le_bytes());
        block[4..8].copy_from_slice(&16384u32.to_le_bytes());
        clean_superblock(&block, 64 * 1024 * 1024).unwrap();
        assert!(clean_superblock(&block, 64 * 1024 * 1024 + 4096).is_err());
        block[0x60..0x64].copy_from_slice(&0x44u32.to_le_bytes());
        assert!(clean_superblock(&block, 64 * 1024 * 1024).is_err());
        block[0x60..0x64].copy_from_slice(&0x40u32.to_le_bytes());
        block[0x3a..0x3c].copy_from_slice(&3u16.to_le_bytes());
        assert!(clean_superblock(&block, 64 * 1024 * 1024).is_err());
        block[0x38] = 0;
        assert!(clean_superblock(&block, 64 * 1024 * 1024).is_err());
    }
}
