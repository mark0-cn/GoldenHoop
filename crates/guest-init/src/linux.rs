use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

use goldenhoop_firecracker::control::{
    GUEST_CONTROL_VERSION, GuestBootIdentity, GuestControlInfo, GuestControlRequest,
    GuestRpcRequest,
};
use goldenhoop_firecracker::vsock::{
    GuestControlListener, MAX_AGENT_FRAME, SocketStream, read_frame,
};
use goldenhoop_protocol::{AgentReply, AgentRequest, AgentResponse};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::Semaphore,
};

use crate::GuestConfig;

const AGENT: &str = "/usr/local/bin/goldenhoop-agent";
const SOCKET: &str = "/run/goldenhoop/agent.sock";
const WORKSPACE: &str = "/workspace";
const CGROUP: &str = "/sys/fs/cgroup/goldenhoop";
const WORKLOAD_GROUP: &str = "/sys/fs/cgroup/goldenhoop/workloads";

mod barrier;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn mount(
    source: &str,
    target: &str,
    kind: &str,
    flags: libc::c_ulong,
    options: &str,
) -> io::Result<()> {
    std::fs::create_dir_all(target)?;
    let source = CString::new(source)?;
    let target = CString::new(target)?;
    let kind = CString::new(kind)?;
    let options = CString::new(options)?;
    // SAFETY: all C strings are NUL-terminated and remain alive for the syscall.
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            kind.as_ptr(),
            flags,
            options.as_ptr().cast(),
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "mount {} on {}: {error}",
                kind.to_string_lossy(),
                target.to_string_lossy()
            ),
        ));
    }
    Ok(())
}

fn dev_mount_options(information: &str) -> io::Result<Option<&str>> {
    let mut found = None;
    for line in information.lines() {
        let (mount, filesystem) = line
            .split_once(" - ")
            .ok_or_else(|| invalid("invalid guest mount observation"))?;
        let fields: Vec<_> = mount.split_whitespace().collect();
        if fields.len() < 6 {
            return Err(invalid("incomplete guest mount observation"));
        }
        if fields[4] != "/dev" {
            continue;
        }
        if filesystem.split_whitespace().next() != Some("devtmpfs") || found.is_some() {
            return Err(invalid("guest /dev is not one unambiguous devtmpfs mount"));
        }
        found = Some(fields[5]);
    }
    Ok(found)
}

fn mount_information() -> io::Result<String> {
    let file = File::open("/proc/self/mountinfo")?;
    let mut information = String::new();
    file.take(65537).read_to_string(&mut information)?;
    if information.len() > 65536 {
        return Err(invalid("guest mount observation exceeds limit"));
    }
    Ok(information)
}

fn prepare_devices() -> io::Result<()> {
    // The pinned kernel has CONFIG_DEVTMPFS_MOUNT=y. Like OpenRC's devfs,
    // inspect an existing kernel mount and remount it with required flags.
    // An arbitrary EBUSY never substitutes for an observed, constrained mount.
    let information = mount_information()?;
    let remount = if dev_mount_options(&information)?.is_some() {
        libc::MS_REMOUNT
    } else {
        0
    };
    mount(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        remount | libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755",
    )?;
    let information = mount_information()?;
    let options = dev_mount_options(&information)?
        .ok_or_else(|| invalid("guest /dev mount was not observed"))?;
    if !["rw", "nosuid", "noexec"]
        .iter()
        .all(|required| options.split(',').any(|option| option == *required))
    {
        return Err(invalid("guest /dev mount constraints were not applied"));
    }
    Ok(())
}

fn configure_filesystems() -> io::Result<()> {
    mount(
        "proc",
        "/proc",
        "proc",
        libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
        "hidepid=2",
    )?;
    prepare_devices()?;
    mount(
        "sysfs",
        "/sys",
        "sysfs",
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
        "",
    )?;
    mount(
        "tmpfs",
        "/run",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        "mode=0755,size=33554432",
    )?;
    mount(
        "tmpfs",
        "/tmp",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        "mode=1777,size=67108864",
    )?;
    mount(
        "devpts",
        "/dev/pts",
        "devpts",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "newinstance,ptmxmode=0666,mode=0620,gid=5",
    )?;
    match std::fs::remove_file("/dev/ptmx") {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    std::os::unix::fs::symlink("pts/ptmx", "/dev/ptmx")?;
    mount(
        "cgroup2",
        "/sys/fs/cgroup",
        "cgroup2",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )?;
    if Path::new("/proc/sys/user/max_user_namespaces").exists() {
        std::fs::write("/proc/sys/user/max_user_namespaces", b"0")?;
        if std::fs::read_to_string("/proc/sys/user/max_user_namespaces")?.trim() != "0" {
            return Err(invalid("guest user namespace restriction was not applied"));
        }
    }
    Ok(())
}

fn configure_loopback() -> io::Result<()> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    // SAFETY: ifreq is a C POD structure, zero initialization is valid. Both
    // ioctl calls receive its live, correctly sized pointer and the fixed lo name.
    unsafe {
        let mut interface: libc::ifreq = std::mem::zeroed();
        interface.ifr_name[0] = b'l' as libc::c_char;
        interface.ifr_name[1] = b'o' as libc::c_char;
        // These fixed request numbers fit both musl's int and glibc's ulong.
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut interface) != 0 {
            return Err(io::Error::last_os_error());
        }
        interface.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS as _, &interface) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn read_config() -> io::Result<GuestConfig> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/etc/goldenhoop/guest.json")?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 4096
    {
        return Err(invalid(
            "guest configuration must be a trusted bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(invalid("guest configuration exceeds limit"));
    }
    let config: GuestConfig =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid guest configuration"))?;
    config.validate().map_err(invalid)?;
    Ok(config)
}

fn prepare_tasks(config: &GuestConfig) -> io::Result<File> {
    let controllers = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")?;
    if !controllers.split_whitespace().any(|value| value == "pids") {
        return Err(invalid("guest kernel lacks task accounting"));
    }
    std::fs::write("/sys/fs/cgroup/cgroup.subtree_control", b"+pids")?;
    std::fs::create_dir(CGROUP)?;
    std::fs::write(format!("{CGROUP}/pids.max"), config.pids.to_string())?;
    if std::fs::read_to_string(format!("{CGROUP}/pids.max"))?.trim() != config.pids.to_string() {
        return Err(invalid("guest task budget was not applied"));
    }
    std::fs::create_dir(format!("{CGROUP}/control"))?;
    std::fs::write(format!("{CGROUP}/control/cgroup.procs"), b"0")?;
    // The aggregate parent remains empty. Its task ceiling includes PID1,
    // trusted control and the agent's entire workload subtree.
    std::fs::write(format!("{CGROUP}/cgroup.subtree_control"), b"+pids")?;
    std::fs::create_dir(WORKLOAD_GROUP)?;
    OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(format!("{WORKLOAD_GROUP}/cgroup.procs"))
}

fn spawn_agent(tasks: &File) -> io::Result<Child> {
    let descriptor = tasks.as_raw_fd();
    let mut command = Command::new(AGENT);
    command
        .args(["serve", "--socket", SOCKET, "--workspace", WORKSPACE])
        .env_clear()
        .env("GOLDENHOOP_ISOLATED_AGENT", "1")
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C.UTF-8")
        .env("HOME", "/root")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // SAFETY: the child hook only performs async-signal-safe syscalls and reads
    // static bytes. The inherited fd stays alive until exec, then closes via CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            if libc::write(descriptor, b"0".as_ptr().cast(), 1) != 1 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

async fn agent_connection(pid: u32) -> io::Result<UnixStream> {
    use std::os::unix::fs::FileTypeExt;
    let metadata = std::fs::symlink_metadata(SOCKET)?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(invalid("agent socket ownership mismatch"));
    }
    let stream = UnixStream::connect(SOCKET).await?;
    let peer = stream.peer_cred()?;
    if peer.uid() != 0 || peer.pid() != Some(pid as i32) {
        return Err(invalid("agent peer identity mismatch"));
    }
    Ok(stream)
}

async fn wait_agent(child: &mut Child) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait()?.is_some() {
            return Err(invalid("guest agent exited during startup"));
        }
        let probe = async {
            let stream = agent_connection(child.id()).await?;
            let mut stream = BufReader::new(stream);
            let mut request = serde_json::to_vec(&AgentRequest::Ping)?;
            request.push(b'\n');
            stream.get_mut().write_all(&request).await?;
            let reply = read_frame(&mut stream, MAX_AGENT_FRAME).await?;
            match serde_json::from_slice::<AgentReply>(&reply)? {
                AgentReply::Success(AgentResponse::Pong { version })
                    if version == env!("CARGO_PKG_VERSION") =>
                {
                    Ok(())
                }
                _ => Err(invalid("guest agent readiness reply mismatch")),
            }
        };
        if tokio::time::timeout_at(deadline, probe)
            .await
            .is_ok_and(|result: io::Result<()>| result.is_ok())
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guest agent readiness deadline",
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn proxy(
    stream: SocketStream,
    pid: u32,
    identity: GuestBootIdentity,
    barrier: Arc<barrier::Barrier>,
) -> io::Result<()> {
    let mut host = BufReader::new(stream);
    let request = read_frame(&mut host, MAX_AGENT_FRAME).await?;
    if serde_json::from_slice::<serde_json::Value>(&request)?
        .get("guest_control")
        .is_some()
    {
        let control: GuestControlRequest = serde_json::from_slice(&request)?;
        if let GuestControlRequest::TransferAuthority { transfer } = control {
            let info = barrier.transfer(transfer).await?;
            let mut reply = serde_json::to_vec(&info)?;
            reply.push(b'\n');
            host.get_mut().write_all(&reply).await?;
            return host.get_mut().shutdown().await;
        }
        if !matches!(control, GuestControlRequest::Info) {
            let info = barrier.request(control).await?;
            let mut reply = serde_json::to_vec(&info)?;
            reply.push(b'\n');
            host.get_mut().write_all(&reply).await?;
            return host.get_mut().shutdown().await;
        }
        let observed: u32 = std::fs::read_to_string(format!("{CGROUP}/pids.max"))?
            .trim()
            .parse()
            .map_err(|_| invalid("invalid observed guest task limit"))?;
        if observed != identity.pids {
            return Err(invalid("guest task budget drifted"));
        }
        let info = GuestControlInfo {
            protocol: GUEST_CONTROL_VERSION,
            generation: barrier.generation().await,
            pids: observed,
            agent_pid: pid,
            host_cid: 2,
            no_new_privileges: unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1,
            version: env!("CARGO_PKG_VERSION").into(),
        };
        let mut reply = serde_json::to_vec(&info)?;
        reply.push(b'\n');
        host.get_mut().write_all(&reply).await?;
        return host.get_mut().shutdown().await;
    }
    let envelope: GuestRpcRequest<AgentRequest> = serde_json::from_slice(&request)?;
    let mut effect = match barrier.admission.enter(envelope.guest_rpc.generation).await {
        Ok(effect) => effect,
        Err(_) => {
            let reply = AgentReply::Error(goldenhoop_protocol::ApiError::new(
                goldenhoop_protocol::ErrorCode::InvalidState,
                "guest workload admission or generation differs",
            ));
            let mut reply = serde_json::to_vec(&reply)?;
            reply.push(b'\n');
            host.get_mut().write_all(&reply).await?;
            return host.get_mut().shutdown().await;
        }
    };
    let mut request = serde_json::to_vec(&envelope.guest_rpc.request)?;
    request.push(b'\n');
    let mut agent = BufReader::new(agent_connection(pid).await?);
    effect.dispatched();
    agent.get_mut().write_all(&request).await?;
    let reply = read_frame(&mut agent, MAX_AGENT_FRAME).await?;
    let _: AgentReply = serde_json::from_slice(&reply)?;
    effect.confirmed();
    drop(effect);
    host.get_mut().write_all(&reply).await?;
    host.get_mut().shutdown().await
}

pub async fn run() -> io::Result<()> {
    if !crate::is_guest_init_context() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "guest boot requires root PID1",
        ));
    }
    configure_filesystems()
        .map_err(|error| io::Error::new(error.kind(), format!("guest filesystems: {error}")))?;
    configure_loopback()
        .map_err(|error| io::Error::new(error.kind(), format!("guest loopback: {error}")))?;
    let mut config = read_config()
        .map_err(|error| io::Error::new(error.kind(), format!("guest configuration: {error}")))?;
    let mut cmdline = String::new();
    File::open("/proc/cmdline")?
        .take(4097)
        .read_to_string(&mut cmdline)?;
    let identity = GuestBootIdentity::from_cmdline(&cmdline, config.pids).map_err(invalid)?;
    config.pids = identity.pids;
    // SAFETY: the requested process-local setting has integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    std::fs::create_dir_all(WORKSPACE)?;
    let tasks = prepare_tasks(&config)
        .map_err(|error| io::Error::new(error.kind(), format!("guest task accounting: {error}")))?;
    let mut child = spawn_agent(&tasks)
        .map_err(|error| io::Error::new(error.kind(), format!("guest agent spawn: {error}")))?;
    wait_agent(&mut child)
        .await
        .map_err(|error| io::Error::new(error.kind(), format!("guest agent readiness: {error}")))?;
    let pid = child.id();
    let barrier = Arc::new(barrier::Barrier::new(identity.generation, pid)?);
    let listener = GuestControlListener::bind(config.control_port)?;
    let permits = Arc::new(Semaphore::new(8));
    let mut reap = tokio::time::interval(Duration::from_millis(100));
    println!(
        "{}",
        serde_json::json!({"event":"guest_control_ready","agent_pid":pid,"pids":config.pids,"host_cid":2})
    );
    loop {
        tokio::select! {
            stream=listener.accept_host()=> {
                let stream=stream?;
                if let Ok(permit)=permits.clone().try_acquire_owned() {
                    let identity=identity.clone();
                    let barrier=barrier.clone();
                    tokio::spawn(async move { let _permit=permit;let _=tokio::time::timeout(Duration::from_secs(120),proxy(stream,pid,identity,barrier)).await; });
                }
            },
            _=reap.tick()=>loop {
                let mut status=0;
                // SAFETY: PID1 collects only its own exited/adopted children, without blocking.
                let reaped=unsafe { libc::waitpid(-1,&mut status,libc::WNOHANG) };
                if reaped==pid as i32 { return Err(invalid("guest agent exited; refusing to replay its processes")); }
                if reaped==0 { break; }
                if reaped<0 {
                    let error=io::Error::last_os_error();
                    if error.kind()==io::ErrorKind::Interrupted { continue; }
                    return Err(error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_kernel_devtmpfs_is_identified_before_remount() {
        let information = "1 0 254:0 / / rw,relatime - ext4 /dev/vda rw\n2 1 0:2 / /dev rw,relatime - devtmpfs devtmpfs rw,size=1000k\n";
        assert_eq!(dev_mount_options(information).unwrap(), Some("rw,relatime"));
        let constrained = information.replace(
            "rw,relatime - devtmpfs",
            "rw,nosuid,noexec,relatime - devtmpfs",
        );
        assert_eq!(
            dev_mount_options(&constrained).unwrap(),
            Some("rw,nosuid,noexec,relatime")
        );
    }

    #[test]
    fn absence_is_distinct_from_foreign_or_ambiguous_mounts() {
        assert!(
            dev_mount_options("1 0 254:0 / / rw - ext4 /dev/vda rw\n")
                .unwrap()
                .is_none()
        );
        let foreign = "2 1 0:2 / /dev rw - tmpfs tmpfs rw\n";
        assert!(dev_mount_options(foreign).is_err());
        let valid = foreign.replace("tmpfs tmpfs", "devtmpfs devtmpfs");
        assert!(dev_mount_options(&format!("{valid}{valid}")).is_err());
    }

    #[test]
    fn malformed_observations_cannot_be_treated_as_missing_mounts() {
        for information in ["invalid", "1 0 /dev - devtmpfs devtmpfs rw"] {
            assert!(dev_mount_options(information).is_err());
        }
    }
}
