use std::pin::Pin;

use futures_util::{Stream, StreamExt};

use super::*;

pub type EventStream = Pin<Box<dyn Stream<Item = Result<ExecutionEvent>> + Send>>;
pub struct RunOutput {
    pub execution: Execution,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Client {
    pub async fn events(&self, id: Uuid, after: Option<u64>) -> Result<EventStream> {
        let mut request = self
            .0
            .http
            .get(self.url(&format!("v1/executions/{id}/events"))?)
            .header("accept", "text/event-stream");
        if let Some(after) = after {
            request = request.header("last-event-id", format!("{id}:{after}"));
        }
        let response = Self::checked(request.send().await.map_err(|_| Error::Transport)?).await?;
        if !response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"))
        {
            return Err(Error::Protocol("expected an SSE response"));
        }
        let stream = async_stream::try_stream! {
            let mut incoming=response.bytes_stream();let mut buffer=Vec::new();
            let mut data=String::new();let mut event_id=String::new();let mut kind=String::new();let mut cursor=after.unwrap_or(0);
            while let Some(packet)=incoming.next().await {
                buffer.extend_from_slice(&packet.map_err(|_|Error::Transport)?);
                let mut consumed=0;
                while let Some(end)=buffer[consumed..].iter().position(|byte|*byte==b'\n') {
                    let end=consumed+end;
                    if end-consumed>2*1024*1024 {Err(Error::Protocol("SSE line exceeds limit"))?;}
                    let line=std::str::from_utf8(&buffer[consumed..end]).map_err(|_|Error::Protocol("invalid UTF-8 SSE frame"))?.trim_end_matches('\r');
                    consumed=end+1;
                    if line.is_empty() {
                        if !data.is_empty() {
                            if kind=="error" {Err(Error::Api(serde_json::from_str(&data).map_err(|_|Error::Protocol("invalid stream error"))?))?;}
                            if kind!="execution" {Err(Error::Protocol("unexpected SSE event type"))?;}
                            let event:ExecutionEvent=serde_json::from_str(&data).map_err(|_|Error::Protocol("invalid execution event"))?;
                            if event.execution_id!=id || Some(event.sequence)!=cursor.checked_add(1) || event_id!=format!("{id}:{}",event.sequence){Err(Error::Protocol("event identity or sequence mismatch"))?;}
                            cursor=event.sequence;yield event;
                        }
                        data.clear();event_id.clear();kind.clear();
                    }else if let Some(value)=line.strip_prefix("data:") {
                        if !data.is_empty(){data.push('\n');}data.push_str(value.strip_prefix(' ').unwrap_or(value));
                    }else if let Some(value)=line.strip_prefix("id:") {event_id=value.trim_start().into();}
                    else if let Some(value)=line.strip_prefix("event:") {kind=value.trim_start().into();}
                    if data.len()>2*1024*1024 {Err(Error::Protocol("SSE frame exceeds limit"))?;}
                }
                buffer.drain(..consumed);
                if buffer.len()+data.len()>2*1024*1024 {Err(Error::Protocol("SSE frame exceeds limit"))?;}
            }
            if !buffer.is_empty() || !data.is_empty(){Err(Error::Transport)?;}
        };
        Ok(Box::pin(stream))
    }

    pub async fn run(&self, sandbox: Uuid, command: &CommandSpec) -> Result<RunOutput> {
        let key = Uuid::new_v4().to_string();
        self.run_with_key(sandbox, command, &key).await
    }

    pub async fn run_with_key(
        &self,
        sandbox: Uuid,
        command: &CommandSpec,
        key: &str,
    ) -> Result<RunOutput> {
        let execution = match self.start(sandbox, command, key).await {
            Ok(execution) => execution,
            Err(Error::Transport) => return Err(Error::UncertainRequest(key.into())),
            Err(Error::Api(error)) if error.code == ErrorCode::BackendUnavailable => {
                return Err(Error::UncertainRequest(key.into()));
            }
            Err(error) => return Err(error),
        };
        let deadline = Duration::from_secs(command.timeout_seconds.saturating_add(60));
        let output = tokio::time::timeout(
            deadline,
            self.collect(sandbox, execution.id, command.max_output_bytes),
        )
        .await
        .map_err(|_| Error::Timeout(execution.id))?;
        output.map_err(|error| Error::Observation(execution.id, Box::new(error)))
    }

    async fn collect(&self, sandbox: Uuid, id: Uuid, limit: u64) -> Result<RunOutput> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut cursor = 0;
        for _ in 0..3 {
            let mut stream = match self.events(id, Some(cursor)).await {
                Ok(stream) => stream,
                Err(Error::Transport) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            while let Some(event) = stream.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(Error::Transport) => break,
                    Err(error) => return Err(error),
                };
                cursor = event.sequence;
                match event.kind {
                    EventKind::Stdout | EventKind::Stderr => {
                        if event.data["encoding"] != "base64" {
                            return Err(Error::Protocol("unsupported output encoding"));
                        }
                        let bytes = STANDARD
                            .decode(
                                event.data["data"]
                                    .as_str()
                                    .ok_or(Error::Protocol("missing output data"))?,
                            )
                            .map_err(|_| Error::Protocol("invalid output encoding"))?;
                        if (stdout.len() + stderr.len() + bytes.len()) as u64 > limit {
                            return Err(Error::Protocol("output exceeds requested limit"));
                        }
                        if event.kind == EventKind::Stdout {
                            stdout.extend(bytes);
                        } else {
                            stderr.extend(bytes);
                        }
                    }
                    EventKind::Completed => {
                        let execution: Execution = serde_json::from_value(event.data)
                            .map_err(|_| Error::Protocol("invalid completion result"))?;
                        if execution.id != id
                            || execution.sandbox_id != sandbox
                            || !execution.state.is_terminal()
                            || execution.cleanup != CleanupState::Complete
                            || execution.state == ExecutionState::Succeeded
                                && execution.exit_code != Some(0)
                        {
                            return Err(Error::Protocol(
                                "completion lacks a matching terminal result and cleanup",
                            ));
                        }
                        return Ok(RunOutput {
                            execution,
                            stdout,
                            stderr,
                        });
                    }
                    _ => {}
                }
            }
            // EOF is not success. Reconnect to the persisted cursor before giving up.
        }
        Err(Error::Protocol(
            "event stream ended before an explicit terminal result",
        ))
    }
}
