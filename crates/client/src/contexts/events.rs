use super::*;
use futures_util::Stream;
use std::pin::Pin;

pub type CodeContextEventStream = Pin<Box<dyn Stream<Item = Result<CodeContextEvent>> + Send>>;
const FRAME_LIMIT: usize = 2 * 1024 * 1024 + 16384;

impl Client {
    /// Dropping this observer never closes or cancels its context.
    pub async fn code_context_events(
        &self,
        id: Uuid,
        after: u64,
    ) -> Result<CodeContextEventStream> {
        let initial = self.code_context(id).await?;
        let response = Self::checked(
            self.0
                .http
                .get(self.url(&format!("v1/code-contexts/{id}/events"))?)
                .header("accept", "text/event-stream")
                .header("last-event-id", format!("{id}:{after}"))
                .send()
                .await
                .map_err(|_| Error::Transport)?,
        )
        .await?;
        if !response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"))
        {
            return Err(Error::Protocol("expected a context SSE response"));
        }
        let stream = async_stream::try_stream! {
            let mut incoming=response.bytes_stream();
            let mut buffer=Vec::new();
            let (mut data,mut event_id,mut kind)=(String::new(),String::new(),String::new());
            let mut cursor=after;
            while let Some(packet)=incoming.next().await {
                let packet=packet.map_err(|_|Error::Transport)?;
                for chunk in packet.chunks(64*1024) {
                    buffer.extend_from_slice(chunk);
                    let mut consumed=0;
                    while let Some(end)=buffer[consumed..].iter().position(|byte|*byte==b'\n') {
                        let end=consumed+end;
                        if end-consumed>FRAME_LIMIT {Err(Error::Protocol("context SSE line exceeds limit"))?;}
                        let line=std::str::from_utf8(&buffer[consumed..end]).map_err(|_|Error::Protocol("invalid context SSE UTF-8"))?.trim_end_matches('\r');
                        consumed=end+1;
                        if line.is_empty() {
                            if !data.is_empty() {
                                if kind=="error" {Err(Error::Api(serde_json::from_str(&data).map_err(|_|Error::Protocol("invalid context stream error"))?))?;}
                                if kind!="code_context" {Err(Error::Protocol("unexpected context SSE type"))?;}
                                let event:CodeContextEvent=serde_json::from_str(&data).map_err(|_|Error::Protocol("invalid context event"))?;
                                if event.context_id!=id || Some(event.sequence)!=cursor.checked_add(1) || event_id!=format!("{id}:{}",event.sequence) {Err(Error::Protocol("context event identity or cursor mismatch"))?;}
                                let closed=if event.kind==CodeContextEventKind::Closed {
                                    let value:CodeContext=serde_json::from_value(event.data.clone()).map_err(|_|Error::Protocol("invalid context collection event"))?;
                                    if value.id!=id || value.sandbox_id!=initial.sandbox_id || !collected(&value) {Err(Error::Protocol("context closure lacks matching collection"))?;}
                                    true
                                } else {false};
                                cursor=event.sequence;
                                yield event;
                                if closed {return;}
                            }
                            data.clear();event_id.clear();kind.clear();
                        } else if let Some(value)=line.strip_prefix("data:") {
                            if !data.is_empty() {data.push('\n');}
                            data.push_str(value.strip_prefix(' ').unwrap_or(value));
                        } else if let Some(value)=line.strip_prefix("id:") {if value.len()>128 {Err(Error::Protocol("context event id exceeds limit"))?;}event_id=value.trim_start().into();}
                        else if let Some(value)=line.strip_prefix("event:") {if value.len()>128 {Err(Error::Protocol("context event type exceeds limit"))?;}kind=value.trim_start().into();}
                        if data.len()>FRAME_LIMIT {Err(Error::Protocol("context SSE data exceeds limit"))?;}
                    }
                    buffer.drain(..consumed);
                    if buffer.len()+data.len()>FRAME_LIMIT {Err(Error::Protocol("context SSE frame exceeds limit"))?;}
                }
            }
            if !buffer.is_empty() || !data.is_empty() || !collected(&initial) {Err(Error::Transport)?;}
        };
        Ok(Box::pin(stream))
    }
}
