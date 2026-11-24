use goldenhoop_protocol::*;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(components(schemas(
    ApiError,
    ErrorCode,
    Capability,
    Placement,
    Isolation,
    Availability,
    ResourceLimits,
    RuntimeProfile,
    NetworkAction,
    NetworkRule,
    NetworkPolicy,
    CreateSandbox,
    Sandbox,
    SandboxState,
    DesiredState,
    SandboxCreated,
    SandboxPage,
    WriteFile,
    FileData,
    ResourceUsage,
    RuntimeDiagnostics,
    SandboxDiagnostics,
    CreateArtifact,
    Artifact,
    ArtifactState,
    ArtifactDesiredState,
    ArtifactCreated,
    ArtifactPage,
    CleanupState,
    CommandSpec,
    Execution,
    ExecutionState,
    EventKind,
    ExecutionEvent,
    FileInfo,
    FileKind,
    SnapshotKind,
    SnapshotManifest,
    Operation,
    OperationState
)))]
struct Contract;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", Contract::openapi().to_pretty_json()?);
    Ok(())
}
