use goldenhoop_jupyter::peer::Peer;
use serde_json::{Value, json};
use std::{
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    time::Instant,
};
use uuid::Uuid;

use super::{Agent, Context};

fn owned(file: &std::fs::File, uid: u32, mode: u32) -> std::io::Result<()> {
    // SAFETY: file is an owned open descriptor in the generated private tree.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, 1000) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

pub(super) async fn start(
    agent: &Agent,
    context: &Context,
    directory: &Path,
    child: &mut Option<Child>,
) -> Result<(Peer, Value), String> {
    let result = async {
        std::fs::create_dir(directory)?;
        let private = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(directory)?;
        owned(&private, context.uid, 0o700)?;
        let prefix = directory.join("kernel");
        let connection = directory.join("connection.json");
        let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let config = json!({"transport":"ipc","ip":prefix,"shell_port":1,"iopub_port":2,"stdin_port":3,"control_port":4,"hb_port":5,
            "signature_scheme":"hmac-sha256","key":key});
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&connection)?;
        file.write_all(&serde_json::to_vec(&config)?)?;
        file.sync_all()?;
        owned(&file, context.uid, 0o600)?;
        drop(file);
        let cwd_path = context.record.lock().await.spec.cwd.clone();
        let cwd = agent.workspace.cwd_handle(&cwd_path)?;
        let mut command = Command::new("python3");
        command.args(["-I", "-m", "ipykernel_launcher", "-f"]).arg(&connection)
            .current_dir(format!("/proc/self/fd/{}", cwd.as_raw_fd()))
            .env_clear().env("PATH", "/usr/local/bin:/usr/bin:/bin").env("HOME", directory).env("USER", "workload-context").env("LANG", "C.UTF-8")
            .env("IPYTHONDIR", directory.join("ipython")).env("JUPYTER_CONFIG_DIR", directory.join("config")).env("JUPYTER_RUNTIME_DIR", directory.join("runtime"))
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0).kill_on_drop(true);
        let uid = context.uid;
        // SAFETY: the child hook only calls async-signal-safe libc operations.
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(1000) != 0 || libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::umask(0o002);
                Ok(())
            });
        }
        *child = Some(command.spawn()?);
        drop(command);
        drop(cwd);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if [1, 2].iter().all(|port| Path::new(&format!("{}-{port}", prefix.display())).exists()) { break; }
            if child.as_mut().expect("spawned kernel").try_wait()?.is_some() {
                return Err("kernel exited before establishing IPC".into());
            }
            if Instant::now() >= deadline { return Err("kernel did not establish IPC before deadline".into()); }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut peer = Peer::connect(&prefix, uid, key.into_bytes()).await?;
        let info = peer.ready().await?;
        if info["language_info"]["name"] != "python" { return Err("image did not provide a Python kernel".into()); }
        let mut retained = serde_json::Map::new();
        for field in ["protocol_version", "implementation", "implementation_version"] {
            let value = info[field].as_str().filter(|value| value.len() <= 128).ok_or("invalid kernel-info field")?;
            retained.insert(field.into(), json!(value));
        }
        retained.insert("language_info".into(), json!({"name":"python","version":info["language_info"]["version"].as_str().filter(|value| value.len() <= 128)}));
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((peer, Value::Object(retained)))
    }.await;
    result.map_err(|error| format!("kernel startup failed: {error}"))
}

pub(super) fn remove_private(directory: &Path) -> bool {
    match std::fs::symlink_metadata(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => return false,
        _ => {}
    }
    // The parent is root-owned and not writable by any workload. Reclaim the
    // fixed child before removing its contents; never follow a final symlink.
    let Ok(private) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)
    else {
        return false;
    };
    if owned(&private, 0, 0o700).is_err() {
        return false;
    }
    if std::fs::remove_dir_all(directory).is_err() {
        return false;
    }
    matches!(std::fs::symlink_metadata(directory), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}
