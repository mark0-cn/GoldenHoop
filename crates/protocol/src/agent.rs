use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    ApiError, CodeContext, CodeContextEvent, CodeContextSpec, CodeRun, CodeRunSpec, CommandSpec,
    Execution, ExecutionEvent, SessionControl, SessionControlReceipt, SessionSpec,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentRequest {
    Ping,
    Start {
        id: Uuid,
        command: CommandSpec,
    },
    StartSession {
        id: Uuid,
        session: SessionSpec,
    },
    SessionControl {
        id: Uuid,
        control: SessionControl,
    },
    SessionControlStatus {
        id: Uuid,
        sequence: u64,
    },
    Inspect {
        id: Uuid,
    },
    Events {
        id: Uuid,
        after: u64,
    },
    Cancel {
        id: Uuid,
    },
    CodeContextCreate {
        id: Uuid,
        spec: CodeContextSpec,
    },
    CodeContextGet {
        id: Uuid,
    },
    CodeContextClose {
        id: Uuid,
    },
    CodeContextEvents {
        id: Uuid,
        after: u64,
    },
    CodeRunStart {
        context_id: Uuid,
        id: Uuid,
        spec: CodeRunSpec,
    },
    CodeRunGet {
        context_id: Uuid,
        id: Uuid,
    },
    CodeRunCancel {
        context_id: Uuid,
        id: Uuid,
    },
    WriteFile {
        path: String,
        data_base64: String,
    },
    ReadFile {
        path: String,
        max_bytes: u64,
    },
    ListFiles {
        path: String,
    },
    RemoveFile {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AgentResponse {
    Pong { version: String },
    Execution(Execution),
    Events(Vec<ExecutionEvent>),
    SessionControl(SessionControlReceipt),
    CodeContext(CodeContext),
    CodeRun(CodeRun),
    CodeContextEvents(Vec<CodeContextEvent>),
    File { data_base64: String },
    Files(Vec<FileInfo>),
    Ok,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum AgentReply {
    Success(AgentResponse),
    Error(ApiError),
}

impl AgentReply {
    pub fn into_result(self) -> Result<AgentResponse, ApiError> {
        match self {
            Self::Success(value) => Ok(value),
            Self::Error(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FileInfo {
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
}
