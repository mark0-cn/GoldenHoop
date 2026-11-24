use goldenhoop_jupyter::peer::Peer;
use serde_json::{Value, json};
use std::sync::Arc;
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
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::Mutex,
    task::JoinHandle,
    time::Instant,
};
use uuid::Uuid;

use super::{Agent, Context, launch::Launch};

pub(super) struct StartupLog {
    bytes: Arc<Mutex<Option<Vec<u8>>>>,
    task: Option<JoinHandle<()>>,
}
impl StartupLog {
    fn capture(mut input: impl AsyncRead + Unpin + Send + 'static) -> Self {
        let bytes = Arc::new(Mutex::new(Some(Vec::new())));
        let retained = bytes.clone();
        let task = tokio::spawn(async move {
            let mut chunk = [0u8; 4096];
            loop {
                match input.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(size) => {
                        if let Some(bytes) = retained.lock().await.as_mut() {
                            let count = size.min(2048usize.saturating_sub(bytes.len()));
                            bytes.extend_from_slice(&chunk[..count]);
                        }
                    }
                }
            }
        });
        Self {
            bytes,
            task: Some(task),
        }
    }
    async fn message(&self) -> String {
        let guard = self.bytes.lock().await;
        let mut text = String::from_utf8_lossy(guard.as_deref().unwrap_or_default()).into_owned();
        truncate(&mut text, 2048);
        text
    }
    async fn discard(&self) {
        // Keep draining after readiness so raw fd-2 writes cannot block or grow
        // an unbounded spool. Only startup diagnostics are retained.
        *self.bytes.lock().await = None;
    }
    pub(super) async fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for StartupLog {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
fn truncate(text: &mut String, maximum: usize) {
    if text.len() > maximum {
        let mut end = maximum;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
}

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
    startup_log: &mut Option<StartupLog>,
) -> Result<(Peer, Value), String> {
    let result = async {
        let spec = context.record.lock().await.spec.clone();
        let plan = Launch::load(spec.language)?;
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
        let cwd = agent.workspace.cwd_handle(&spec.cwd)?;
        let mut command = Command::new(&plan.program);
        command.args(plan.args.iter().map(|arg| arg.replace("{connection_file}", &connection.to_string_lossy())))
            .current_dir(format!("/proc/self/fd/{}", cwd.as_raw_fd()))
            .env_clear().envs(&plan.env).env("PATH", "/usr/local/bin:/usr/bin:/bin").env("HOME", directory).env("USER", "workload-context").env("LANG", "C.UTF-8")
            .env("TMPDIR", directory).env("IPYTHONDIR", directory.join("ipython")).env("JUPYTER_CONFIG_DIR", directory.join("config")).env("JUPYTER_RUNTIME_DIR", directory.join("runtime"))
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).process_group(0).kill_on_drop(true);
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
        *startup_log=Some(StartupLog::capture(child.as_mut().expect("spawned kernel").stderr.take().expect("piped kernel stderr")));
        drop(command);
        drop(cwd);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if [1, 2].iter().all(|port| plan.naming.path(&prefix, *port).exists()) { break; }
            if child.as_mut().expect("spawned kernel").try_wait()?.is_some() {
                return Err("kernel exited before establishing IPC".into());
            }
            if Instant::now() >= deadline { return Err("kernel did not establish IPC before deadline".into()); }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut peer = Peer::connect_named(&prefix, uid, key.into_bytes(), plan.naming).await?;
        let info = peer.ready().await?;
        if !info["language_info"]["name"].as_str().is_some_and(|name| name.eq_ignore_ascii_case(spec.language.as_str())) {
            return Err("image kernel-info language does not match the requested language".into());
        }
        let mut retained = serde_json::Map::new();
        for field in ["protocol_version", "implementation", "implementation_version"] {
            let value = info[field].as_str().filter(|value| value.len() <= 128).ok_or("invalid kernel-info field")?;
            retained.insert(field.into(), json!(value));
        }
        retained.insert("language_info".into(), json!({"name":spec.language.as_str(),"version":info["language_info"]["version"].as_str().filter(|value| value.len() <= 128)}));
        if let Some(log)=startup_log.as_ref() {log.discard().await;}
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((peer, Value::Object(retained)))
    }.await;
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            let mut reason = format!("kernel startup failed: {error}");
            if let Some(child) = child.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                reason.push_str(&format!("; child={status}"));
            }
            if let Some(log) = startup_log.as_ref() {
                let stderr = log.message().await;
                if !stderr.trim().is_empty() {
                    reason.push_str("; kernel stderr: ");
                    reason.push_str(stderr.trim());
                }
            }
            truncate(&mut reason, 4096);
            Err(reason)
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn startup_stderr_is_bounded_then_discarded_and_its_reader_is_collected() {
        let (input, mut output) = tokio::io::duplex(64);
        let log = StartupLog::capture(input);
        output.write_all(&vec![b'x'; 32 * 1024]).await.unwrap();
        assert!(log.message().await.len() <= 2048);
        log.discard().await;
        output.write_all(&vec![b'y'; 32 * 1024]).await.unwrap();
        assert!(log.message().await.is_empty());
        log.stop().await;
        assert!(output.write_all(b"reader must be closed").await.is_err());
    }
}
