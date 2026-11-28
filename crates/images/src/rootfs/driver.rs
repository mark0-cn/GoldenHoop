//! Private daemon I/O. The caller retains its permanent disk object lease and
//! supplies a synchronous durable journal writer; client lifetimes own neither.
use super::*;
use bollard::{Docker, container::LogOutput, errors::Error as DockerError, query_parameters::*};
use futures_util::{StreamExt, TryStreamExt};
use std::{fs::File, future::Future, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

fn unknown(_: impl std::fmt::Display) -> io::Error {
    io::Error::other(
        "original rootfs inspector effect is unconfirmed; reconcile its durable operation",
    )
}
fn missing(error: &DockerError) -> bool {
    matches!(
        error,
        DockerError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}
async fn bounded<T>(call: impl Future<Output = Result<T, DockerError>>) -> io::Result<T> {
    tokio::time::timeout(Duration::from_secs(15), call)
        .await
        .map_err(unknown)?
        .map_err(unknown)
}
type Save<'a> = &'a mut dyn FnMut(&InspectionState) -> io::Result<()>;
fn phase(state: &mut InspectionState, next: InspectionPhase, save: Save<'_>) -> io::Result<()> {
    state.phase = next;
    save(state)
}
fn dispatch(
    state: &mut InspectionState,
    next: InspectionPhase,
    effect: InspectionEffect,
    save: Save<'_>,
) -> io::Result<()> {
    if state.pending.is_some() {
        return Err(invalid(
            "rootfs inspector earlier effect remains unconfirmed",
        ));
    }
    state.pending = Some(effect);
    phase(state, next, save)
}

pub struct RootfsInspector {
    docker: Docker,
    engine: String,
    boot: Uuid,
}
impl RootfsInspector {
    pub async fn connect() -> io::Result<Self> {
        let docker = Docker::connect_with_local_defaults().map_err(unknown)?;
        let engine = bounded(docker.info())
            .await?
            .id
            .ok_or_else(|| invalid("rootfs inspector provider identity absent"))?;
        let boot =
            Uuid::parse_str(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim())
                .map_err(unknown)?;
        Ok(Self {
            docker,
            engine,
            boot,
        })
    }
    pub fn reserve(&self, intent: InspectionIntent) -> io::Result<InspectionState> {
        InspectionState::reserve(intent, self.engine.clone(), self.boot)
    }
    async fn container(
        &self,
        state: &InspectionState,
        inspector: bool,
    ) -> io::Result<Option<ContainerInspectResponse>> {
        let key = if inspector {
            state.inspector_id.as_deref()
        } else {
            state.seeder_id.as_deref()
        };
        let Some(key) = key else { return Ok(None) };
        match tokio::time::timeout(
            Duration::from_secs(15),
            self.docker.inspect_container(key, None),
        )
        .await
        {
            Ok(Ok(value)) => {
                state
                    .intent
                    .validate_container(&value, inspector, Some(key))?;
                Ok(Some(value))
            }
            Ok(Err(error)) if missing(&error) => Ok(None),
            _ => Err(unknown("container observation")),
        }
    }
    async fn volume(&self, state: &InspectionState, part: InspectionPart) -> io::Result<bool> {
        let value = match tokio::time::timeout(
            Duration::from_secs(15),
            self.docker.inspect_volume(&state.intent.resource(part)),
        )
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error)) if missing(&error) => return Ok(false),
            _ => return Err(unknown("volume observation")),
        };
        if value.name != state.intent.resource(part)
            || value.driver != "local"
            || !value.options.is_empty()
            || !state
                .intent
                .labels(part)?
                .iter()
                .all(|(k, v)| value.labels.get(k) == Some(v))
        {
            return Err(invalid(
                "rootfs inspector volume ownership or placement differs",
            ));
        }
        Ok(true)
    }
    async fn create_volume(&self, state: &InspectionState, part: InspectionPart) -> io::Result<()> {
        let value = bounded(self.docker.create_volume(VolumeCreateRequest {
            name: Some(state.intent.resource(part)),
            driver: Some("local".into()),
            labels: Some(state.intent.labels(part)?),
            ..Default::default()
        }))
        .await?;
        if value.name != state.intent.resource(part) || !self.volume(state, part).await? {
            return Err(invalid("rootfs inspector volume creation unconfirmed"));
        }
        Ok(())
    }
    async fn create_container(
        &self,
        state: &InspectionState,
        inspector: bool,
    ) -> io::Result<String> {
        let part = if inspector {
            InspectionPart::Inspector
        } else {
            InspectionPart::Seeder
        };
        let actual = bounded(self.docker.create_container(
            Some(CreateContainerOptions {
                name: Some(state.intent.resource(part)),
                ..Default::default()
            }),
            state.intent.container(inspector)?,
        ))
        .await?;
        if !hex_id(&actual.id) {
            return Err(invalid("invalid rootfs inspector daemon ID"));
        }
        Ok(actual.id)
    }
    async fn remove_container(&self, state: &InspectionState, inspector: bool) -> io::Result<()> {
        let key = if inspector {
            state.inspector_id.as_deref()
        } else {
            state.seeder_id.as_deref()
        };
        let Some(key) = key else { return Ok(()) };
        if self.container(state, inspector).await?.is_some() {
            bounded(self.docker.remove_container(
                key,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            ))
            .await?;
        }
        if self.container(state, inspector).await?.is_some() {
            return Err(unknown("container removal"));
        }
        Ok(())
    }
    /// Called after the original producer has stopped I/O. Never authorize or
    /// rerun an earlier tool. Unacknowledged create effects retain their fence.
    pub async fn reconcile(
        &self,
        state: &mut InspectionState,
        mut save: impl FnMut(&InspectionState) -> io::Result<()>,
    ) -> io::Result<()> {
        state.validate(&state.intent, &self.engine, self.boot)?;
        if state.phase == InspectionPhase::Collected {
            return Ok(());
        }
        state.require_original_actor_absent()?;
        if state.result.is_none() && state.error.is_none() {
            state.error = Some(
                "original inspection producer stopped before an acknowledged result; no replay"
                    .into(),
            );
            save(state)?;
        }
        self.collect(state, &mut save).await
    }
    async fn collect(&self, state: &mut InspectionState, save: Save<'_>) -> io::Result<()> {
        phase(state, InspectionPhase::Collecting, save)?;
        if state.inspector_id.is_some() && state.host.is_none() {
            let observed = self.container(state, true).await?;
            if observed.is_none() && state.start_dispatched {
                return Err(unknown(
                    "original started inspector has no host collection receipt",
                ));
            }
            if let Some(actual) = observed {
                let runtime = actual
                    .state
                    .as_ref()
                    .ok_or_else(|| invalid("inspector state absent during collection"))?;
                if runtime.running == Some(true) {
                    let live = state.intent.observe(
                        &actual,
                        state.inspector_id.as_deref().expect("recorded inspector"),
                    )?;
                    state.host = Some(live.observation().clone());
                    save(state)?;
                } else if runtime.status != Some(ContainerStateStatusEnum::CREATED)
                    || runtime.pid != Some(0)
                {
                    return Err(unknown(
                        "started inspector has no original host observation",
                    ));
                }
            }
        }
        self.remove_container(state, true).await?;
        self.remove_container(state, false).await?;
        if let Some(host) = &state.host {
            let id = state
                .inspector_id
                .as_deref()
                .ok_or_else(|| invalid("inspector ID absent for host collection"))?;
            let until = tokio::time::Instant::now() + Duration::from_secs(15);
            while !host.collected(id)? {
                if tokio::time::Instant::now() >= until {
                    return Err(unknown("original inspector host process/cgroup collection"));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        for (part, created) in [
            (InspectionPart::Output, state.output_created),
            (InspectionPart::Input, state.input_created),
        ] {
            if created && self.volume(state, part).await? {
                bounded(self.docker.remove_volume(
                    &state.intent.resource(part),
                    Some(RemoveVolumeOptions { force: false }),
                ))
                .await?;
            }
            if created && self.volume(state, part).await? {
                return Err(unknown("original inspection volume absence"));
            }
        }
        if matches!(
            state.pending,
            Some(
                InspectionEffect::CreateInput
                    | InspectionEffect::CreateOutput
                    | InspectionEffect::CreateSeeder
                    | InspectionEffect::CreateInspector
            )
        ) {
            // A late named create can outlive a read-side absence. Keep the
            // exact original dispatch intent rather than reporting collection.
            return Err(unknown("unacknowledged original resource creation"));
        }
        state.pending = None;
        state.input_created = false;
        state.output_created = false;
        if state.result.is_some() {
            // The acknowledged validated result survived. A prior collection
            // error is settled only after all original resources are absent.
            state.error = None;
        }
        phase(state, InspectionPhase::Collected, save)
    }
    pub async fn run(
        &self,
        state: &mut InspectionState,
        disk: File,
        mut save: impl FnMut(&InspectionState) -> io::Result<()>,
    ) -> io::Result<()> {
        state.validate(&state.intent, &self.engine, self.boot)?;
        if state.phase != InspectionPhase::Reserved || state.pending.is_some() {
            return Err(invalid("rootfs inspection is not a new original operation"));
        }
        save(state)?;
        let outcome = self.execute(state, disk, &mut save).await;
        if let Err(error) = &outcome {
            state.error = Some(error.to_string().chars().take(2048).collect());
            save(state)?;
        }
        let collection = self.collect(state, &mut save).await;
        match (outcome, collection) {
            (Ok(()), Ok(())) => {
                state.ready_result()?;
                Ok(())
            }
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => {
                state.error = Some(error.to_string().chars().take(2048).collect());
                phase(state, InspectionPhase::Unconfirmed, &mut save)?;
                Err(error)
            }
        }
    }
    async fn execute(
        &self,
        state: &mut InspectionState,
        disk: File,
        save: Save<'_>,
    ) -> io::Result<()> {
        dispatch(
            state,
            InspectionPhase::VolumesDispatched,
            InspectionEffect::CreateInput,
            save,
        )?;
        self.create_volume(state, InspectionPart::Input).await?;
        state.input_created = true;
        state.pending = None;
        save(state)?;
        dispatch(
            state,
            InspectionPhase::VolumesDispatched,
            InspectionEffect::CreateOutput,
            save,
        )?;
        self.create_volume(state, InspectionPart::Output).await?;
        state.output_created = true;
        state.pending = None;
        phase(state, InspectionPhase::VolumesReady, save)?;
        dispatch(
            state,
            InspectionPhase::SeederDispatched,
            InspectionEffect::CreateSeeder,
            save,
        )?;
        state.seeder_id = Some(self.create_container(state, false).await?);
        state.pending = None;
        phase(state, InspectionPhase::SeederObserved, save)?;
        let actual = self
            .container(state, false)
            .await?
            .ok_or_else(|| unknown("seeder absent"))?;
        if actual.state.as_ref().is_none_or(|v| {
            v.status != Some(ContainerStateStatusEnum::CREATED)
                || v.running == Some(true)
                || v.pid != Some(0)
        }) {
            return Err(invalid("rootfs input seeder was started"));
        }
        dispatch(
            state,
            InspectionPhase::InputUploadDispatched,
            InspectionEffect::UploadInput,
            save,
        )?;
        let (writer, reader) = tokio::io::duplex(128 * 1024);
        let id = state.seeder_id.as_deref().expect("recorded seeder");
        let upload = self.docker.upload_to_container(
            id,
            Some(UploadToContainerOptions {
                path: "/input".into(),
                no_overwrite_dir_non_dir: Some("true".into()),
                copy_uidgid: Some("true".into()),
            }),
            bollard::body_try_stream(ReaderStream::new(reader)),
        );
        let produce = crate::transfer::rootfs_input(writer, disk, &state.intent.request);
        let (uploaded, produced) = tokio::time::timeout(Duration::from_secs(300), async {
            tokio::join!(upload, produce)
        })
        .await
        .map_err(unknown)?;
        state.pending = None;
        save(state)?;
        uploaded.map_err(unknown)?;
        produced?;
        phase(state, InspectionPhase::InputReady, save)?;
        dispatch(
            state,
            InspectionPhase::InputReady,
            InspectionEffect::RemoveSeeder,
            save,
        )?;
        self.remove_container(state, false).await?;
        state.pending = None;
        phase(state, InspectionPhase::SeederRemoved, save)?;
        dispatch(
            state,
            InspectionPhase::InspectorDispatched,
            InspectionEffect::CreateInspector,
            save,
        )?;
        state.inspector_id = Some(self.create_container(state, true).await?);
        state.pending = None;
        phase(state, InspectionPhase::InspectorObserved, save)?;
        let id = state
            .inspector_id
            .as_deref()
            .expect("recorded inspector")
            .to_owned();
        self.container(state, true)
            .await?
            .ok_or_else(|| unknown("inspector absent"))?;
        let mut attached = bounded(self.docker.attach_container(
            &id,
            Some(AttachContainerOptions {
                stdin: true,
                stdout: true,
                stderr: true,
                stream: true,
                ..Default::default()
            }),
        ))
        .await?;
        state.start_dispatched = true;
        dispatch(
            state,
            InspectionPhase::StartDispatched,
            InspectionEffect::StartInspector,
            save,
        )?;
        bounded(self.docker.start_container(&id, None)).await?;
        let actual = self
            .container(state, true)
            .await?
            .ok_or_else(|| unknown("inspector absent after start"))?;
        let live = state.intent.observe(&actual, &id)?;
        state.host = Some(live.observation().clone());
        state.pending = None;
        phase(state, InspectionPhase::RunningObserved, save)?;
        let mut permit = serde_json::to_vec(&state.intent.permit(&live, state.nonce)?)?;
        permit.push(b'\n');
        dispatch(
            state,
            InspectionPhase::AuthorizationDispatched,
            InspectionEffect::AuthorizeInspector,
            save,
        )?;
        live.guard.still_live()?;
        tokio::time::timeout(Duration::from_secs(5), async {
            attached.input.write_all(&permit).await?;
            attached.input.flush().await
        })
        .await
        .map_err(unknown)??;
        state.pending = None;
        save(state)?;
        let output = async {
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            while let Some(item) = attached.output.next().await {
                let (target, bytes) = match item.map_err(unknown)? {
                    LogOutput::StdOut { message } => (&mut stdout, message),
                    LogOutput::StdErr { message } => (&mut stderr, message),
                    _ => return Err(invalid("unexpected inspector output frame")),
                };
                if target.len() + bytes.len() > 65536 {
                    return Err(invalid("rootfs inspector output limit"));
                }
                target.extend_from_slice(&bytes);
            }
            Ok::<_, io::Error>(stdout)
        };
        let wait = async {
            self.docker
                .wait_container(
                    &id,
                    Some(WaitContainerOptions {
                        condition: "not-running".into(),
                    }),
                )
                .try_next()
                .await
                .map_err(unknown)?
                .ok_or_else(|| unknown("inspector exit observation absent"))
        };
        let (exit, stdout) = tokio::time::timeout(Duration::from_secs(240), async {
            tokio::try_join!(wait, output)
        })
        .await
        .map_err(unknown)??;
        let actual = self
            .container(state, true)
            .await?
            .ok_or_else(|| unknown("inspector exit state absent"))?;
        if exit.status_code != 0
            || actual.state.as_ref().is_none_or(|v| {
                v.status != Some(ContainerStateStatusEnum::EXITED)
                    || v.running == Some(true)
                    || v.restarting == Some(true)
                    || v.oom_killed == Some(true)
                    || v.exit_code != Some(0)
            })
        {
            return Err(invalid("rootfs inspector execution did not succeed"));
        }
        let result: RootfsInspectionReport = serde_json::from_slice(&stdout)?;
        state.intent.validate_report(&result)?;
        state.result = Some(result);
        phase(state, InspectionPhase::ResultObserved, save)
    }
}
