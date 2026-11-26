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
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn configure_filesystems() -> io::Result<()> {
    mount(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "mode=0755",
    )?;
    mount(
        "proc",
        "/proc",
        "proc",
        libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
        "hidepid=2",
    )?;
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
    OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(format!("{CGROUP}/cgroup.procs"))
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

async fn proxy(stream: SocketStream, pid: u32) -> io::Result<()> {
    let mut host = BufReader::new(stream);
    let mut agent = BufReader::new(agent_connection(pid).await?);
    let request = read_frame(&mut host, MAX_AGENT_FRAME).await?;
    agent.get_mut().write_all(&request).await?;
    let reply = read_frame(&mut agent, MAX_AGENT_FRAME).await?;
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
    configure_filesystems()?;
    configure_loopback()?;
    let config = read_config()?;
    // SAFETY: the requested process-local setting has integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    std::fs::create_dir_all(WORKSPACE)?;
    let tasks = prepare_tasks(&config)?;
    let mut child = spawn_agent(&tasks)?;
    wait_agent(&mut child).await?;
    let pid = child.id();
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
                    tokio::spawn(async move { let _permit=permit;let _=tokio::time::timeout(Duration::from_secs(120),proxy(stream,pid)).await; });
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
