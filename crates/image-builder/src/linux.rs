use crate::{
    BuilderInventory, BuilderLimits, BuilderRuntime, Content, HostPermit, PrepareReport,
    PrepareRequest, PreparedImage, archive, invalid,
};
mod publication;
pub mod rootfs;
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapOptions},
};
use publication::publish;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

const SOURCE: &str = "/input/source.tar";
const AGENT: &str = "/opt/goldenhoop/agent";
const INIT: &str = "/opt/goldenhoop/init";
const MKFS: &str = "/usr/sbin/mke2fs";
const FSCK: &str = "/usr/sbin/e2fsck";

fn trusted(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(invalid("builder input is not a trusted regular file"));
    }
    Ok(file)
}
fn content(mut file: impl Read, cancel: &AtomicBool) -> io::Result<Content> {
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(invalid("image preparation interrupted"));
        }
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| invalid("content length overflow"))?;
    }
    Ok(Content {
        sha256: format!("{:x}", hash.finalize()),
        size_bytes: size,
    })
}
fn verify_file(path: &Path, expected: &Content, cancel: &AtomicBool) -> io::Result<()> {
    let input = trusted(path)?;
    if input.metadata()?.len() != expected.size_bytes
        || content(input.take(expected.size_bytes + 1), cancel)? != *expected
    {
        return Err(invalid("image input content digest or length mismatch"));
    }
    Ok(())
}
async fn verified_input(
    path: &'static str,
    expected: Content,
    cancel: Arc<AtomicBool>,
) -> io::Result<()> {
    tokio::task::spawn_blocking(move || verify_file(Path::new(path), &expected, &cancel))
        .await
        .map_err(io::Error::other)?
}
fn absent(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}
pub fn inventory() -> io::Result<BuilderInventory> {
    let cancel = AtomicBool::new(false);
    let value = BuilderInventory {
        format: 1,
        builder_version: env!("CARGO_PKG_VERSION").into(),
        agent: content(trusted(Path::new(AGENT))?, &cancel)?,
        init: content(trusted(Path::new(INIT))?, &cancel)?,
        mke2fs: content(trusted(Path::new(MKFS))?, &cancel)?,
        e2fsck: content(trusted(Path::new(FSCK))?, &cancel)?,
    };
    value.validate()?;
    Ok(value)
}

pub fn read_request() -> io::Result<PrepareRequest> {
    let mut file = trusted(Path::new("/input/prepare.json"))?;
    if file.metadata()?.len() > 65536 {
        return Err(invalid("image preparation request exceeds limit"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(invalid("image preparation request exceeds limit"));
    }
    let request: PrepareRequest = serde_json::from_slice(&bytes)?;
    request.validate()?;
    Ok(request)
}

/// Cancellable private-pipe read. Tokio's blocking stdin adapter can outlive a
/// timeout while waiting for a writer; nonblocking fd readiness keeps both the
/// authorization deadline and TERM handling effective even if the host stalls.
pub async fn read_host_permit() -> io::Result<HostPermit> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let raw = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    read_permit_fd(fd).await
}

fn network_interface_names() -> io::Result<std::collections::BTreeSet<String>> {
    struct Names(*mut libc::if_nameindex);
    impl Drop for Names {
        fn drop(&mut self) {
            // SAFETY: This is the unchanged allocation returned by the one
            // successful if_nameindex call below, released exactly once.
            unsafe { libc::if_freenameindex(self.0) };
        }
    }
    let pointer = unsafe { libc::if_nameindex() };
    if pointer.is_null() {
        return Err(io::Error::last_os_error());
    }
    let owned = Names(pointer);
    let mut result = std::collections::BTreeSet::new();
    let mut indexes = std::collections::BTreeSet::new();
    for offset in 0..64 {
        // SAFETY: libc returns a terminated array whose names remain valid
        // until if_freenameindex. Stop at its documented zero/NULL terminator.
        let item = unsafe { &*owned.0.add(offset) };
        if item.if_index == 0 && item.if_name.is_null() {
            return Ok(result);
        }
        if item.if_index == 0 || item.if_name.is_null() || !indexes.insert(item.if_index) {
            return Err(invalid("invalid network interface observation"));
        }
        let name = unsafe { std::ffi::CStr::from_ptr(item.if_name) };
        if name.to_bytes().is_empty() || name.to_bytes().len() >= libc::IF_NAMESIZE {
            return Err(invalid("invalid network interface name"));
        }
        let name = name
            .to_str()
            .map_err(|_| invalid("invalid network interface name"))?;
        if !result.insert(name.to_owned()) {
            return Err(invalid("duplicate network interface observation"));
        }
    }
    Err(invalid("network interface observation exceeds limit"))
}

async fn read_permit_fd(fd: std::os::fd::OwnedFd) -> io::Result<HostPermit> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OwnedFd retains this descriptor without replacement; only the
    // readiness callback reads it, and AsyncFd drops before the descriptor.
    let input = unsafe { tokio::io::unix::AsyncFd::register(fd) }.map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    loop {
        let mut ready = input.readable().await?;
        let mut chunk = [0u8; 1024];
        let count = match ready.try_io(|fd| {
            let count =
                unsafe { libc::read(fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
            if count < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(count as usize)
            }
        }) {
            Ok(value) => value?,
            Err(_) => continue,
        };
        if count == 0 {
            return Err(invalid(
                "host preparation decision ended before its delimiter",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > 65536 {
            return Err(invalid("host preparation decision exceeds limit"));
        }
        if let Some(end) = bytes.iter().position(|b| *b == b'\n') {
            if end + 1 != bytes.len() {
                return Err(invalid("multiple host preparation decisions"));
            }
            return serde_json::from_slice(&bytes[..end]).map_err(Into::into);
        }
    }
}

/// Refuse ordinary host invocation before creating files. The trusted parent
/// additionally verifies private namespaces, its exact image and owned volume.
pub fn verify_isolation() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getpid() } != 1 {
        return Err(invalid(
            "image conversion requires root PID1 in an isolated builder",
        ));
    }
    let status = fs::read_to_string("/proc/self/status")?;
    let field = |name: &str| {
        status.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| *key == name)
                .map(|(_, value)| value.trim())
        })
    };
    if field("NoNewPrivs") != Some("1")
        || field("CapEff").and_then(|v| u64::from_str_radix(v, 16).ok()) != Some(0x1b)
    {
        return Err(invalid(
            "builder requires no-new-privileges and only CHOWN/DAC_OVERRIDE/FOWNER/FSETID",
        ));
    }
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c"/".as_ptr(), &mut info) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if info.f_flag & libc::ST_RDONLY as libc::c_ulong == 0 {
        return Err(invalid("builder root must be read-only"));
    }
    // gVisor exposes RTM_GETLINK without /sys/class/net. Enumerate names,
    // including unaddressed links, rather than interpreting missing sysfs as
    // an empty network or filtering by configured IP addresses/statistics.
    if network_interface_names()? != std::collections::BTreeSet::from(["lo".to_owned()]) {
        return Err(invalid(
            "builder must have no network interface except loopback",
        ));
    }
    for (key, _) in std::env::vars_os() {
        if !["PATH", "LANG", "HOME", "HOSTNAME", "TERM", "TZ"]
            .iter()
            .any(|allowed| key == *allowed)
        {
            return Err(invalid(
                "builder environment contains an unexpected variable",
            ));
        }
    }
    Ok(())
}

pub fn verify_context() -> io::Result<()> {
    verify_isolation()?;
    let limit = |name: &str| -> io::Result<u64> {
        fs::read_to_string(Path::new("/sys/fs/cgroup").join(name))?
            .trim()
            .parse()
            .map_err(|_| invalid("builder cgroup limit is unavailable"))
    };
    let cpu = fs::read_to_string("/sys/fs/cgroup/cpu.max")?;
    let values = cpu
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("builder CPU limit is unavailable"))?;
    if values.len() != 2 {
        return Err(invalid("builder CPU limit is unavailable"));
    }
    BuilderLimits {
        memory_max: limit("memory.max")?,
        swap_max: limit("memory.swap.max")?,
        pids_max: limit("pids.max")?,
        cpu_quota: values[0],
        cpu_period: values[1],
    }
    .validate()?;
    Ok(())
}

fn permitted_context(request: &PrepareRequest, permit: &HostPermit) -> io::Result<()> {
    verify_isolation()?;
    permit.validate_for(request)?;
    if fs::read_to_string("/proc/sys/kernel/hostname")?.trim()
        != request.generation.simple().to_string()
    {
        return Err(invalid("host permit hostname/generation binding differs"));
    }
    if permit.runtime == BuilderRuntime::RuncDevelopment {
        verify_context()?;
    }
    Ok(())
}

fn verify_owner_mode(
    fd: std::os::fd::RawFd,
    uid: u32,
    gid: u32,
    mode: u32,
    directory: bool,
) -> io::Result<()> {
    let mut actual: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut actual) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let kind = if directory {
        libc::S_IFDIR
    } else {
        libc::S_IFREG
    };
    if actual.st_uid != uid
        || actual.st_gid != gid
        || actual.st_mode & 0o7777 != mode
        || actual.st_mode & libc::S_IFMT != kind
        || (!directory && actual.st_nlink != 1)
    {
        return Err(invalid(
            "installed owner, mode, type or link count readback mismatch",
        ));
    }
    Ok(())
}
fn own_directory(directory: &Dir, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    if unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) } != 0
        || unsafe { libc::fchmod(directory.as_raw_fd(), mode) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // Linux may silently clear SGID when FSETID is absent. A successful chmod
    // is insufficient evidence for the final guest access boundary.
    verify_owner_mode(directory.as_raw_fd(), uid, gid, mode, true)
}
fn protected_parent(root: &Dir, path: &str) -> io::Result<()> {
    let parent = Path::new(path)
        .parent()
        .ok_or_else(|| invalid("asset has no parent"))?;
    root.create_dir_all(parent)?;
    // Resolve through legitimate relative usr-merge links, then protect every
    // physical ancestor. A workload must not replace a trusted agent directory.
    let physical = root.canonicalize(parent)?;
    let mut prefix = PathBuf::new();
    for part in physical.components() {
        prefix.push(part);
        own_directory(&root.open_dir(&prefix)?, 0, 0, 0o755)?;
    }
    Ok(())
}
fn install(root: &Dir, path: &str, mut input: impl Read, mode: u32) -> io::Result<()> {
    protected_parent(root, path)?;
    match root.remove_file(path) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let mut options = CapOptions::new();
    options.write(true).create_new(true);
    let mut file = root.open_with(path, &options)?;
    io::copy(&mut input, &mut file)?;
    if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    file.set_permissions(cap_std::fs::Permissions::from_std(
        fs::Permissions::from_mode(mode),
    ))?;
    verify_owner_mode(file.as_raw_fd(), 0, 0, mode, false)?;
    file.sync_all()?;
    Ok(())
}
fn overlay_assets(
    root_path: &Path,
    request: &PrepareRequest,
    cancel: &AtomicBool,
) -> io::Result<()> {
    let root = Dir::open_ambient_dir(root_path, ambient_authority())?;
    own_directory(&root, 0, 0, 0o755)?;
    for name in ["proc", "sys", "dev", "run", "tmp", "workspace"] {
        match root.symlink_metadata(name) {
            Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
                return Err(invalid(
                    "guest mount/workspace path must be a real directory",
                ));
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => root.create_dir(name)?,
            Err(error) => return Err(error),
        }
        let (uid, gid, mode) = match name {
            "workspace" => (1000, 1000, 0o2770),
            "tmp" => (0, 0, 0o1777),
            _ => (0, 0, 0o755),
        };
        own_directory(&root.open_dir(name)?, uid, gid, mode)?;
    }
    for (source, destination, expected) in [
        (AGENT, "usr/local/bin/goldenhoop-agent", &request.agent),
        (INIT, "sbin/goldenhoop-init", &request.init),
    ] {
        verify_file(Path::new(source), expected, cancel)?;
        install(&root, destination, trusted(Path::new(source))?, 0o755)?;
        if content(root.open(destination)?, cancel)? != *expected {
            return Err(invalid("installed guest asset readback mismatch"));
        }
    }
    install(
        &root,
        "etc/goldenhoop/guest.json",
        &b"{\"control_port\":52,\"pids\":256}\n"[..],
        0o644,
    )?;
    install(&root, "etc/machine-id", io::empty(), 0o644)?;
    install(&root, "etc/hostname", &b"goldenhoop\n"[..], 0o644)?;
    install(
        &root,
        "etc/hosts",
        &b"127.0.0.1 localhost goldenhoop\n::1 localhost\n"[..],
        0o644,
    )?;
    install(
        &root,
        "etc/resolv.conf",
        &b"nameserver 127.0.0.1\n"[..],
        0o644,
    )?;
    Ok(())
}

async fn drain(mut input: impl AsyncRead + Unpin) -> io::Result<(usize, Vec<u8>)> {
    let mut total = 0usize;
    let mut tail = Vec::new();
    let mut bytes = [0; 4096];
    loop {
        let count = input.read(&mut bytes).await?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count);
        tail.extend_from_slice(&bytes[..count]);
        if tail.len() > 8192 {
            tail.drain(..tail.len() - 8192);
        }
    }
    Ok((total, tail))
}
async fn cancelled(flag: Arc<AtomicBool>) {
    while !flag.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
async fn tool(
    program: &str,
    args: &[std::ffi::OsString],
    cancel: Arc<AtomicBool>,
    collected: &mut bool,
) -> io::Result<()> {
    tool_output(program, args, cancel, collected)
        .await
        .map(|_| ())
}

async fn tool_output(
    program: &str,
    args: &[std::ffi::OsString],
    cancel: Arc<AtomicBool>,
    collected: &mut bool,
) -> io::Result<(usize, Vec<u8>)> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    *collected = false;
    let mut stdout = tokio::spawn(drain(
        child
            .stdout
            .take()
            .ok_or_else(|| invalid("tool stdout missing"))?,
    ));
    let mut stderr = tokio::spawn(drain(
        child
            .stderr
            .take()
            .ok_or_else(|| invalid("tool stderr missing"))?,
    ));
    let result = tokio::select! {
        status=child.wait()=>status,
        _=tokio::time::sleep(Duration::from_secs(180))=>Err(io::Error::new(io::ErrorKind::TimedOut,"image tool deadline")),
        _=cancelled(cancel)=>Err(invalid("image preparation interrupted")),
    };
    if result.is_err() {
        let _ = child.start_kill();
        if !matches!(
            tokio::time::timeout(Duration::from_secs(10), child.wait()).await,
            Ok(Ok(_))
        ) {
            stdout.abort();
            stderr.abort();
            return Err(invalid("image tool collection is unconfirmed"));
        }
    }
    // A confirmed Child wait and completed pipe drains are separate evidence.
    let pipes = tokio::time::timeout(Duration::from_secs(5), async {
        Ok::<_, io::Error>((
            (&mut stdout).await.map_err(io::Error::other)??,
            (&mut stderr).await.map_err(io::Error::other)??,
        ))
    })
    .await;
    let (out, err) = match pipes {
        Ok(Ok(value)) => value,
        _ => {
            stdout.abort();
            stderr.abort();
            return Err(invalid("image tool pipe collection is unconfirmed"));
        }
    };
    *collected = true;
    let status = result?;
    if !status.success() || out.0 > 65536 || err.0 > 65536 {
        return Err(invalid(format!(
            "image tool failed: {status}; {}",
            String::from_utf8_lossy(&err.1)
        )));
    }
    Ok(out)
}

pub async fn prepare(request: PrepareRequest, cancel: Arc<AtomicBool>) -> PrepareReport {
    prepare_inner(request, cancel, None).await
}

pub async fn prepare_authorized(
    request: PrepareRequest,
    permit: HostPermit,
    cancel: Arc<AtomicBool>,
) -> PrepareReport {
    prepare_inner(request, cancel, Some(permit)).await
}

async fn prepare_inner(
    request: PrepareRequest,
    cancel: Arc<AtomicBool>,
    permit: Option<HostPermit>,
) -> PrepareReport {
    let mut report = PrepareReport {
        passed: false,
        staging_absent: false,
        tools_collected: true,
        manifest: None,
        error: None,
    };
    let stage = Path::new("/output").join(format!("{}.writing", request.generation));
    let ready = Path::new("/output").join(request.generation.to_string());
    let mut owned = false;
    let timer = {
        let flag = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(600)).await;
            flag.store(true, Ordering::Release);
        })
    };
    let result = async {
        request.validate()?;
        if let Some(permit) = &permit {
            permitted_context(&request, permit)?;
        } else {
            verify_context()?;
        }
        let metadata = fs::symlink_metadata("/output")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
            return Err(invalid("builder output must be an owned real directory"));
        }
        if !absent(&ready)? || !absent(&stage)? {
            return Err(invalid(
                "image generation already exists; reconcile its owner",
            ));
        }
        verified_input(SOURCE, request.archive.clone(), cancel.clone()).await?;
        for (path, expected) in [(AGENT, &request.agent), (INIT, &request.init)] {
            verified_input(path, expected.clone(), cancel.clone()).await?;
        }
        let mke2fs = content(trusted(Path::new(MKFS))?, &cancel)?;
        let e2fsck = content(trusted(Path::new(FSCK))?, &cancel)?;
        fs::DirBuilder::new().mode(0o700).create(&stage)?;
        owned = true;
        report.staging_absent = false;
        let mut owner = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(stage.join("owner.json"))?;
        owner.write_all(&serde_json::to_vec(&request)?)?;
        owner.sync_all()?;
        let root = stage.join("rootfs");
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let extract_root = root.clone();
        let extract_request = request.clone();
        let flag = cancel.clone();
        tokio::task::spawn_blocking(move || {
            let mut input = trusted(Path::new(SOURCE))?;
            archive::preflight(&mut input, extract_request.disk_bytes, &flag)?;
            archive::unpack(&mut input, &extract_root, &flag)?;
            overlay_assets(&extract_root, &extract_request, &flag)
        })
        .await
        .map_err(io::Error::other)??;
        verified_input(SOURCE, request.archive.clone(), cancel.clone()).await?;
        let disk = stage.join("rootfs.ext4");
        let args = [
            "-t".into(),
            "ext4".into(),
            "-q".into(),
            "-F".into(),
            "-b".into(),
            "4096".into(),
            "-m".into(),
            "0".into(),
            "-U".into(),
            request.generation.to_string().into(),
            "-d".into(),
            root.as_os_str().to_owned(),
            disk.as_os_str().to_owned(),
            (request.disk_bytes / 4096).to_string().into(),
        ];
        tool(MKFS, &args, cancel.clone(), &mut report.tools_collected).await?;
        tool(
            FSCK,
            &["-f".into(), "-n".into(), disk.as_os_str().to_owned()],
            cancel.clone(),
            &mut report.tools_collected,
        )
        .await?;
        let final_disk = disk.clone();
        let final_root = root.clone();
        let flag = cancel.clone();
        let disk_bytes = request.disk_bytes;
        // Keep the signal/timer loop responsive through full-disk hashing and
        // large-tree collection. The blocking reader checks the shared fence.
        let disk_content = tokio::task::spawn_blocking(move || {
            let output = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&final_disk)?;
            if output.metadata()?.len() != disk_bytes {
                return Err(invalid("ext4 image length mismatch"));
            }
            output.sync_all()?;
            let disk_content = content(&output, &flag)?;
            output.set_permissions(fs::Permissions::from_mode(0o400))?;
            drop(output);
            if content(File::open(&final_disk)?, &flag)? != disk_content {
                return Err(invalid("ext4 image readback mismatch"));
            }
            fs::remove_dir_all(&final_root)?;
            if !absent(&final_root)? {
                return Err(invalid("extracted staging collection unconfirmed"));
            }
            Ok::<_, io::Error>(disk_content)
        })
        .await
        .map_err(io::Error::other)??;
        let manifest = PreparedImage {
            format: 1,
            generation: request.generation,
            archive: request.archive.clone(),
            agent: request.agent.clone(),
            init: request.init.clone(),
            disk: disk_content,
            mke2fs,
            e2fsck,
            created_at: chrono::Utc::now(),
            builder_version: env!("CARGO_PKG_VERSION").into(),
        };
        let bytes = serde_json::to_vec(&manifest)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(stage.join("manifest.json"))?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        drop(output);
        File::open(&stage)?.sync_all()?;
        if cancel.load(Ordering::Acquire) {
            return Err(invalid("image preparation interrupted before publication"));
        }
        publish(&stage, &ready).map_err(|error| {
            io::Error::new(error.kind(), format!("publish prepared image: {error}"))
        })?;
        report.staging_absent = !stage.try_exists()?;
        report.manifest = Some(manifest);
        Ok::<_, io::Error>(())
    }
    .await;
    timer.abort();
    if let Err(error) = result {
        report.error = Some(error.to_string());
        if owned && report.tools_collected {
            match fs::remove_dir_all(&stage) {
                Ok(()) => (),
                Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => (),
                Err(cleanup) => {
                    report.error = Some(format!("{error}; staging collection failed: {cleanup}"))
                }
            }
        }
    } else {
        report.passed = true;
    }
    report.staging_absent = absent(&stage).unwrap_or(false);
    if report.passed && !report.staging_absent {
        report.passed = false;
        report.error = Some("image staging absence is unconfirmed".into());
    }
    report
}

#[cfg(test)]
mod permit_io_tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    #[test]
    fn actual_name_enumeration_matches_all_kernel_links() {
        let observed = network_interface_names().unwrap();
        let expected = fs::read_dir("/sys/class/net")
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(observed, expected);
    }
    #[tokio::test]
    async fn stalled_private_writer_does_not_prevent_authorization_cancellation() {
        let (reader, writer) = UnixStream::pair().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), read_permit_fd(reader.into()))
                .await
                .is_err()
        );
        // The timed-out reader owns no blocking task; its descriptor is gone
        // even though the parent still holds its side of the authorization pipe.
        let mut writer = writer;
        assert!(writer.write_all(b"late decision\n").is_err());
    }
    #[tokio::test]
    async fn decisions_require_one_bounded_complete_json_line() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"{}\n{}\n").unwrap();
        assert!(read_permit_fd(reader.into()).await.is_err());
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&vec![b'x'; 65537]).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), read_permit_fd(reader.into()))
                .await
                .unwrap()
                .is_err()
        );
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"{}").unwrap();
        drop(writer);
        assert!(read_permit_fd(reader.into()).await.is_err());
    }
}
