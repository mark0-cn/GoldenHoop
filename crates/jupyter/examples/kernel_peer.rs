//! Actual kernel interoperability experiment, restricted to a disposable Linux guest.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("kernel_peer requires an isolated Linux guest");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run().await
}

#[cfg(target_os = "linux")]
mod linux {
    use bytes::Bytes;
    use goldenhoop_jupyter::{Codec, Message};
    use serde_json::{Value, json};
    use std::{process::Stdio, time::Duration};
    use tokio::time::Instant;
    use uuid::Uuid;
    use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, SubSocket, ZmqMessage};

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    struct Peer {
        codec: Codec,
        shell: DealerSocket,
        publish: SubSocket,
        control: DealerSocket,
    }
    impl Peer {
        fn frame(&self, id: Uuid, kind: &str, content: Value) -> Result<ZmqMessage> {
            Ok(self
                .codec
                .request(id, kind, content)?
                .into_iter()
                .map(Bytes::from)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| "empty kernel request")?)
        }
        async fn next(&mut self, deadline: Instant) -> Result<Message> {
            let raw=tokio::time::timeout_at(deadline,async {
                tokio::select! {message=self.shell.recv()=>message,message=self.publish.recv()=>message}
            }).await??;
            Ok(self.codec.decode(&raw.into_vec())?)
        }
        async fn ready(&mut self) -> Result<Value> {
            // Kernel-info is safe to retry while establishing real subscription readiness.
            // A delay or a socket file alone never establishes readiness.
            for _ in 0..10 {
                let id = Uuid::new_v4();
                let parent = id.to_string();
                self.shell
                    .send(self.frame(id, "kernel_info_request", json!({}))?)
                    .await?;
                let deadline = Instant::now() + Duration::from_millis(500);
                let (mut reply, mut idle) = (None, false);
                while Instant::now() < deadline {
                    let message = match self.next(deadline).await {
                        Ok(message) => message,
                        Err(error) if error.is::<tokio::time::error::Elapsed>() => break,
                        Err(error) => return Err(error),
                    };
                    if message.parent_id() != Some(parent.as_str()) {
                        continue;
                    }
                    if message.message_type() == "kernel_info_reply" {
                        reply = Some(message.content().clone());
                    }
                    if message.message_type() == "status"
                        && message.content()["execution_state"] == "idle"
                    {
                        idle = true;
                    }
                    if idle && let Some(reply) = reply {
                        return Ok(reply);
                    }
                }
            }
            Err("authenticated kernel-info and output-idle readiness were not observed".into())
        }
        async fn execute(&mut self, code: &str) -> Result<Value> {
            let id = Uuid::new_v4();
            let parent = id.to_string();
            let content = json!({"code":code,"silent":false,"store_history":true,"user_expressions":{},"allow_stdin":false,"stop_on_error":true});
            self.shell
                .send(self.frame(id, "execute_request", content)?)
                .await?;
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut reply, mut idle) = (None, false);
            let mut output = String::new();
            let mut result = None;
            let mut exception = None;
            loop {
                let message = self.next(deadline).await?;
                if message.parent_id() != Some(parent.as_str()) {
                    continue;
                }
                match message.message_type() {
                    "execute_reply" => reply = Some(message.content().clone()),
                    "status" if message.content()["execution_state"] == "idle" => idle = true,
                    "stream" => {
                        let text = message.content()["text"]
                            .as_str()
                            .ok_or("invalid kernel stream")?;
                        if output.len() + text.len() > 65536 {
                            return Err("experiment output exceeds limit".into());
                        }
                        output.push_str(text);
                    }
                    "execute_result" => result = Some(message.content()["data"].clone()),
                    "error" => exception = Some(message.content()["ename"].clone()),
                    _ => {}
                }
                if idle && let Some(reply) = reply {
                    return Ok(
                        json!({"oracle":"kernel_reply_and_iopub_idle","request_id":id,"reply":reply,"stream":output,"result":result,"exception":exception}),
                    );
                }
            }
        }
        async fn shutdown(&mut self) -> Result<()> {
            let id = Uuid::new_v4();
            let parent = id.to_string();
            self.control
                .send(self.frame(id, "shutdown_request", json!({"restart":false}))?)
                .await?;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let raw = tokio::time::timeout_at(deadline, self.control.recv()).await??;
                let reply = self.codec.decode(&raw.into_vec())?;
                if reply.message_type() == "shutdown_reply"
                    && reply.parent_id() == Some(parent.as_str())
                {
                    return Ok(());
                }
            }
        }
    }

    pub async fn run() -> Result<()> {
        if std::env::var("GOLDENHOOP_ISOLATED_AGENT").as_deref() != Ok("1") {
            return Err("experiment requires the isolated fixture marker".into());
        }
        let private = tempfile::Builder::new()
            .prefix("gh-kernel-")
            .tempdir_in("/tmp")?;
        let directory = private.path().to_owned();
        let prefix = directory.join("kernel");
        let connection = directory.join("connection.json");
        let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let config = json!({"transport":"ipc","ip":prefix,"shell_port":1,"iopub_port":2,"stdin_port":3,"control_port":4,"hb_port":5,"signature_scheme":"hmac-sha256","key":key});
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&connection)?;
            file.write_all(&serde_json::to_vec(&config)?)?;
            file.sync_all()?;
        }
        let mut child = tokio::process::Command::new("python3")
            .args(["-m", "ipykernel_launcher", "-f"])
            .arg(&connection)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/workspace")
            .env("USER", "workload")
            .env("LANG", "C.UTF-8")
            .env("IPYTHONDIR", directory.join("ipython"))
            .env("JUPYTER_CONFIG_DIR", directory.join("config"))
            .env("JUPYTER_RUNTIME_DIR", directory.join("runtime"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let operation = async {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if [1, 2, 4].iter().all(|port| {
                    std::path::Path::new(&format!("{}-{port}", prefix.display())).exists()
                }) {
                    break;
                }
                if child.try_wait()?.is_some() {
                    return Err("kernel process exited before creating its sockets".into());
                }
                if Instant::now() >= deadline {
                    return Err("kernel socket creation timed out".into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut peer = Peer {
                codec: Codec::new(key.as_bytes().to_vec(), Uuid::new_v4())?,
                shell: DealerSocket::new(),
                publish: SubSocket::new(),
                control: DealerSocket::new(),
            };
            peer.publish.subscribe("").await?;
            tokio::time::timeout(
                Duration::from_secs(5),
                peer.publish
                    .connect(&format!("ipc://{}-2", prefix.display())),
            )
            .await??;
            tokio::time::timeout(
                Duration::from_secs(5),
                peer.shell.connect(&format!("ipc://{}-1", prefix.display())),
            )
            .await??;
            tokio::time::timeout(
                Duration::from_secs(5),
                peer.control
                    .connect(&format!("ipc://{}-4", prefix.display())),
            )
            .await??;
            let info = peer.ready().await?;
            let first = peer.execute("value = 40\nprint('first')").await?;
            let second = peer.execute("print(value + 2)\nvalue + 2").await?;
            let third = peer
                .execute("raise ValueError('goldenhoop expected')")
                .await?;
            if first["reply"]["status"] != "ok"
                || second["reply"]["status"] != "ok"
                || second["stream"] != "42\n"
                || second["result"]["text/plain"] != "42"
                || third["reply"]["status"] != "error"
                || third["exception"] != "ValueError"
            {
                return Err("actual interpreter state/result/error contract failed".into());
            }
            peer.shutdown().await?;
            drop(peer);
            let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
            if !status.success() {
                return Err("kernel did not exit successfully after shutdown".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                json!({"suite":"jupyter-ipc-interoperability","result":"passed","kernel_info":info,"runs":[first,second,third],"kernel_exit_code":status.code()}),
            )
        };
        let result = tokio::time::timeout(Duration::from_secs(40), operation).await;
        if child.try_wait()?.is_none() {
            child.start_kill()?;
            tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        }
        private.close()?;
        if directory.exists() {
            return Err("private kernel files remain".into());
        }
        let mut result = result??;
        result["private_files_removed"] = json!(true);
        println!("{result}");
        Ok(())
    }
}
