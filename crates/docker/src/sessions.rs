use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

impl DockerDriver {
    pub(super) async fn probe_session(
        &self,
        handle: &RuntimeHandle,
        terminal: bool,
    ) -> Result<bool, ApiError> {
        let id = Uuid::new_v4();
        let run = async {
            let mut session = SessionSpec::shell();
            session.command.timeout_seconds = 15;
            if terminal {
                session.terminal = Some(TerminalSize {
                    rows: 24,
                    columns: 80,
                });
                session.command.argv=vec!["python3".into(),"-c".into(),"import os,sys,termios,tty; assert all(os.isatty(fd) for fd in (0,1,2)); assert os.getsid(0)==os.getpid(); open('/dev/tty').close(); tty.setraw(0); print('READY',flush=True); data=sys.stdin.buffer.readline(); assert data==b'probe\\n'; assert termios.tcgetwinsize(0)==(40,100); print('PTY_OK',flush=True)".into()];
            }
            if !matches!(
                self.bridge(handle, &AgentRequest::StartSession { id, session })
                    .await?,
                AgentResponse::Execution(_)
            ) {
                return Err(unavailable("session probe returned an unexpected response"));
            }
            self.wait_session_running(handle, id).await?;
            if terminal {
                self.wait_session_output(handle, id, b"READY\n").await?;
                self.probe_control(
                    handle,
                    id,
                    1,
                    SessionAction::Resize {
                        size: TerminalSize {
                            rows: 40,
                            columns: 100,
                        },
                    },
                )
                .await?;
                self.probe_control(
                    handle,
                    id,
                    2,
                    SessionAction::Write {
                        data_base64: STANDARD.encode(b"probe\n"),
                    },
                )
                .await?;
            } else {
                self.probe_control(
                    handle,
                    id,
                    1,
                    SessionAction::Write {
                        data_base64: STANDARD.encode(b"value=golden; printf 'READY\\n'\n"),
                    },
                )
                .await?;
                self.wait_session_output(handle, id, b"READY\n").await?;
                self.probe_control(
                    handle,
                    id,
                    2,
                    SessionAction::Write {
                        data_base64: STANDARD.encode(b"printf 'retained:%s\\n' \"$value\"\n"),
                    },
                )
                .await?;
                self.probe_control(handle, id, 3, SessionAction::CloseInput)
                    .await?;
            }
            let record = self.wait_session_finished(handle, id).await?;
            if record.state != ExecutionState::Succeeded || record.exit_code != Some(0) {
                return Err(unavailable("session process probe failed"));
            }
            let output = self.session_output(handle, id).await?;
            let expected = if terminal {
                b"PTY_OK\n".as_slice()
            } else {
                b"retained:golden\n".as_slice()
            };
            if !output
                .windows(expected.len())
                .any(|bytes| bytes == expected)
            {
                return Err(unavailable("session output probe failed"));
            }
            Ok::<_, ApiError>(())
        };
        let success = matches!(
            tokio::time::timeout(Duration::from_secs(20), run).await,
            Ok(Ok(()))
        );
        // Optional capability failure still requires confirmed collection before reuse.
        match self.bridge(handle, &AgentRequest::Inspect { id }).await {
            Ok(AgentResponse::Execution(record))
                if record.state.is_terminal() && record.cleanup == CleanupState::Complete => {}
            Err(error) if error.code == ErrorCode::NotFound => {}
            _ => {
                self.bridge(handle, &AgentRequest::Cancel { id }).await?;
                self.wait_session_finished(handle, id).await?;
            }
        }
        Ok(success)
    }
    async fn probe_control(
        &self,
        handle: &RuntimeHandle,
        id: Uuid,
        sequence: u64,
        action: SessionAction,
    ) -> Result<(), ApiError> {
        let request = AgentRequest::SessionControl {
            id,
            control: SessionControl { sequence, action },
        };
        let AgentResponse::SessionControl(first) = self.bridge(handle, &request).await? else {
            return Err(unavailable(
                "session control probe returned an unexpected response",
            ));
        };
        let AgentResponse::SessionControl(replay) = self.bridge(handle, &request).await? else {
            return Err(unavailable(
                "session control replay returned an unexpected response",
            ));
        };
        if first.execution_id != id
            || first.sequence != sequence
            || first.state != SessionControlState::Applied
            || serde_json::to_value(&first).ok() != serde_json::to_value(&replay).ok()
        {
            return Err(unavailable("session control or replay probe failed"));
        }
        Ok(())
    }
    async fn session_output(&self, handle: &RuntimeHandle, id: Uuid) -> Result<Vec<u8>, ApiError> {
        let AgentResponse::Events(events) = self
            .bridge(handle, &AgentRequest::Events { id, after: 0 })
            .await?
        else {
            return Err(unavailable("session events probe failed"));
        };
        let mut bytes = Vec::new();
        for event in events {
            if event.kind == EventKind::Stdout {
                let data = event
                    .data
                    .get("data")
                    .and_then(|data| data.as_str())
                    .ok_or_else(|| unavailable("invalid session probe output"))?;
                bytes.extend(
                    STANDARD
                        .decode(data)
                        .map_err(|_| unavailable("invalid session probe encoding"))?,
                );
            }
        }
        Ok(bytes)
    }
    async fn wait_session_output(
        &self,
        handle: &RuntimeHandle,
        id: Uuid,
        expected: &[u8],
    ) -> Result<(), ApiError> {
        for _ in 0..50 {
            if self
                .session_output(handle, id)
                .await?
                .windows(expected.len())
                .any(|bytes| bytes == expected)
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(unavailable("session probe output was not observed"))
    }
    async fn wait_session_running(&self, handle: &RuntimeHandle, id: Uuid) -> Result<(), ApiError> {
        for _ in 0..50 {
            if let AgentResponse::Execution(record) =
                self.bridge(handle, &AgentRequest::Inspect { id }).await?
            {
                if record.state == ExecutionState::Running {
                    return Ok(());
                }
                if record.state.is_terminal() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(unavailable("session probe did not start"))
    }
    async fn wait_session_finished(
        &self,
        handle: &RuntimeHandle,
        id: Uuid,
    ) -> Result<Execution, ApiError> {
        for _ in 0..50 {
            if let AgentResponse::Execution(record) =
                self.bridge(handle, &AgentRequest::Inspect { id }).await?
                && record.state.is_terminal()
                && record.cleanup == CleanupState::Complete
            {
                return Ok(record);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(unavailable("session probe cleanup was not confirmed"))
    }
}
