//! Trusted parent binding for isolated read-only disk inspection. A tool report
//! alone is never proof of the original host process or cgroup's collection.
use crate::{
    hex_id,
    host::{HostGuard, HostObservation},
    image_id,
};
use bollard::models::*;
use goldenhoop_image_builder::{
    BuilderLimits, BuilderRuntime, Content, HostPermit, RootfsInspectionInventory,
    RootfsInspectionReport, RootfsInspectionRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io};
use uuid::Uuid;

pub mod driver;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionIntent {
    pub installation_id: Uuid,
    pub capture_id: Uuid,
    /// Immutable daemon image ID, never a mutable tag or a disk-provided value.
    pub image: String,
    pub inventory: RootfsInspectionInventory,
    pub request: RootfsInspectionRequest,
    pub guest_config: Content,
}
impl InspectionIntent {
    pub fn validate(&self) -> io::Result<()> {
        self.inventory.validate()?;
        self.request.validate()?;
        self.guest_config.validate(4096)?;
        if self.installation_id.is_nil()
            || self.capture_id.is_nil()
            || !image_id(&self.image)
            || self.request.agent != self.inventory.agent
            || self.request.init != self.inventory.init
        {
            return Err(invalid(
                "rootfs inspector immutable source or pinned assets differ",
            ));
        }
        Ok(())
    }
    pub fn fingerprint(&self) -> io::Result<String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"goldenhoop.rootfs-inspector.parent.v1\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(format!("{:x}", hash.finalize()))
    }
    pub fn resource(&self, part: InspectionPart) -> String {
        format!(
            "ghri-{}-{}-{}",
            self.installation_id.simple(),
            self.request.generation.simple(),
            part.name()
        )
    }
    pub fn labels(&self, part: InspectionPart) -> io::Result<HashMap<String, String>> {
        Ok(HashMap::from([
            (
                "dev.goldenhoop.installation".into(),
                self.installation_id.to_string(),
            ),
            ("dev.goldenhoop.role".into(), "rootfs-inspection".into()),
            ("dev.goldenhoop.capture".into(), self.capture_id.to_string()),
            (
                "dev.goldenhoop.generation".into(),
                self.request.generation.to_string(),
            ),
            ("dev.goldenhoop.request-sha256".into(), self.fingerprint()?),
            ("dev.goldenhoop.part".into(), part.name().into()),
        ]))
    }
    pub fn validate_report(&self, report: &RootfsInspectionReport) -> io::Result<()> {
        if !report.passed
            || !report.staging_absent
            || !report.tools_collected
            || report.error.is_some()
        {
            return Err(invalid(
                "rootfs inspector result or internal tool collection is unconfirmed",
            ));
        }
        let found = report
            .inspection
            .as_ref()
            .ok_or_else(|| invalid("rootfs inspection result absent"))?;
        found.validate_for(&self.request, &self.inventory)?;
        if found.guest_config.content != self.guest_config {
            return Err(invalid("rootfs protected guest configuration bytes differ"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum InspectionPart {
    Input,
    Output,
    Seeder,
    Inspector,
}
pub struct LiveInspection {
    guard: HostGuard,
    intent_sha256: String,
    container_id: String,
}
impl LiveInspection {
    pub fn observation(&self) -> &HostObservation {
        &self.guard.observation
    }
    pub fn container_id(&self) -> &str {
        &self.container_id
    }
}
impl InspectionPart {
    fn name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
            Self::Seeder => "seeder",
            Self::Inspector => "inspector",
        }
    }
}
pub fn limits() -> BuilderLimits {
    BuilderLimits {
        memory_max: 1024 * 1024 * 1024,
        swap_max: 0,
        pids_max: 64,
        cpu_quota: 100000,
        cpu_period: 100000,
    }
}
fn mounts(intent: &InspectionIntent, inspector: bool) -> Vec<Mount> {
    let one = |part, target: &str, readonly| Mount {
        typ: Some(MountType::VOLUME),
        source: Some(intent.resource(part)),
        target: Some(target.into()),
        read_only: Some(readonly),
        volume_options: Some(MountVolumeOptions {
            no_copy: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    if inspector {
        vec![
            one(InspectionPart::Input, "/input", true),
            one(InspectionPart::Output, "/output", false),
        ]
    } else {
        vec![one(InspectionPart::Input, "/input", false)]
    }
}
impl InspectionIntent {
    pub fn container(&self, inspector: bool) -> io::Result<ContainerCreateBody> {
        self.validate()?;
        let maximum = limits();
        Ok(ContainerCreateBody {
            image: Some(self.image.clone()),
            user: Some("0:0".into()),
            hostname: Some(self.request.generation.simple().to_string()),
            entrypoint: Some(vec![
                if inspector {
                    "/usr/local/bin/goldenhoop-image-builder"
                } else {
                    "/goldenhoop-never-executed"
                }
                .into(),
            ]),
            cmd: Some(if inspector {
                vec!["await-inspect-rootfs".into()]
            } else {
                vec![]
            }),
            labels: Some(self.labels(if inspector {
                InspectionPart::Inspector
            } else {
                InspectionPart::Seeder
            })?),
            env: Some(vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
                "LANG=C.UTF-8".into(),
                "HOME=/".into(),
            ]),
            open_stdin: Some(inspector),
            attach_stdin: Some(inspector),
            attach_stdout: Some(inspector),
            attach_stderr: Some(inspector),
            stdin_once: Some(false),
            tty: Some(false),
            host_config: Some(HostConfig {
                runtime: Some(if inspector { "runsc" } else { "runc" }.into()),
                network_mode: Some("none".into()),
                readonly_rootfs: Some(true),
                ipc_mode: Some("private".into()),
                cap_drop: Some(vec!["ALL".into()]),
                cap_add: Some(if inspector {
                    vec![
                        "CHOWN".into(),
                        "DAC_OVERRIDE".into(),
                        "FOWNER".into(),
                        "FSETID".into(),
                    ]
                } else {
                    vec![]
                }),
                security_opt: Some(vec!["no-new-privileges:true".into()]),
                mounts: Some(mounts(self, inspector)),
                memory: Some(maximum.memory_max as i64),
                memory_swap: Some(maximum.memory_max as i64),
                pids_limit: Some(maximum.pids_max as i64),
                cpu_quota: Some(maximum.cpu_quota as i64),
                cpu_period: Some(maximum.cpu_period as i64),
                restart_policy: Some(RestartPolicy {
                    name: Some(RestartPolicyNameEnum::NO),
                    maximum_retry_count: Some(0),
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
    }
    /// Check the actual immutable daemon object before any host permit. The
    /// never-started seeder is the only writable access to the input volume.
    pub fn validate_container(
        &self,
        actual: &ContainerInspectResponse,
        inspector: bool,
        recorded_id: Option<&str>,
    ) -> io::Result<String> {
        self.validate()?;
        let id = actual
            .id
            .as_deref()
            .filter(|id| hex_id(id))
            .ok_or_else(|| invalid("invalid rootfs inspector container ID"))?;
        let config = actual
            .config
            .as_ref()
            .ok_or_else(|| invalid("rootfs inspector configuration absent"))?;
        let host = actual
            .host_config
            .as_ref()
            .ok_or_else(|| invalid("rootfs inspector placement absent"))?;
        let expected = self.container(inspector)?;
        let wanted = expected.host_config.as_ref().expect("fixed host config");
        let part = if inspector {
            InspectionPart::Inspector
        } else {
            InspectionPart::Seeder
        };
        let caps = |values: &Option<Vec<String>>| {
            let mut caps = values
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.strip_prefix("CAP_").unwrap_or(&s).to_owned())
                .collect::<Vec<_>>();
            caps.sort();
            caps
        };
        let actual_mounts = actual.mounts.as_deref().unwrap_or_default();
        let requested = mounts(self, inspector);
        let observed_mounts = host.mounts.as_deref().unwrap_or_default();
        // Moby omits Mount.ReadOnly=false and serializes an empty Cmd as null.
        // Normalize only those defaults; required read-only mounts stay true.
        let checks = [
            ("recorded_id", !recorded_id.is_some_and(|v| v != id)),
            ("image", actual.image.as_deref() == Some(&self.image)),
            (
                "name",
                actual.name.as_deref() == Some(format!("/{}", self.resource(part)).as_str()),
            ),
            ("restart_count", actual.restart_count.unwrap_or(0) == 0),
            ("user", config.user == expected.user),
            ("hostname", config.hostname == expected.hostname),
            ("entrypoint", config.entrypoint == expected.entrypoint),
            (
                "cmd",
                config.cmd.as_deref().unwrap_or_default()
                    == expected.cmd.as_deref().unwrap_or_default(),
            ),
            ("tty", config.tty != Some(true)),
            ("healthcheck", config.healthcheck.is_none()),
            ("open_stdin", config.open_stdin == Some(inspector)),
            ("stdin_once", config.stdin_once != Some(true)),
            (
                "labels",
                config.labels.as_ref().is_some_and(|v| {
                    self.labels(part)
                        .is_ok_and(|wanted| wanted.iter().all(|(k, x)| v.get(k) == Some(x)))
                }),
            ),
            ("runtime", host.runtime == wanted.runtime),
            ("network_mode", host.network_mode == wanted.network_mode),
            ("readonly_rootfs", host.readonly_rootfs == Some(true)),
            ("privileged", host.privileged != Some(true)),
            ("ipc_mode", host.ipc_mode == wanted.ipc_mode),
            (
                "pid_mode",
                !host.pid_mode.as_deref().is_some_and(|v| !v.is_empty()),
            ),
            (
                "uts_mode",
                !host.uts_mode.as_deref().is_some_and(|v| !v.is_empty()),
            ),
            ("binds", !host.binds.as_ref().is_some_and(|v| !v.is_empty())),
            ("tmpfs", !host.tmpfs.as_ref().is_some_and(|v| !v.is_empty())),
            (
                "devices",
                !host.devices.as_ref().is_some_and(|v| !v.is_empty()),
            ),
            (
                "device_requests",
                !host.device_requests.as_ref().is_some_and(|v| !v.is_empty()),
            ),
            ("cap_add", caps(&host.cap_add) == caps(&wanted.cap_add)),
            (
                "cap_drop",
                host.cap_drop.as_deref() == Some(&["ALL".into()]),
            ),
            (
                "security_opt",
                host.security_opt.as_ref().is_some_and(|v| {
                    v.iter()
                        .any(|v| v == "no-new-privileges" || v == "no-new-privileges:true")
                }),
            ),
            ("memory", host.memory == wanted.memory),
            ("memory_swap", host.memory_swap == wanted.memory_swap),
            ("pids_limit", host.pids_limit == wanted.pids_limit),
            ("cpu_quota", host.cpu_quota == wanted.cpu_quota),
            ("cpu_period", host.cpu_period == wanted.cpu_period),
            ("nano_cpus", !host.nano_cpus.is_some_and(|v| v != 0)),
            (
                "mount_count",
                actual_mounts.len() == requested.len() && observed_mounts.len() == requested.len(),
            ),
            (
                "mounted_volumes",
                requested.iter().all(|m| {
                    actual_mounts.iter().any(|v| {
                        v.typ.as_deref() == Some("volume")
                            && v.name == m.source
                            && v.destination == m.target
                            && v.rw == Some(m.read_only != Some(true))
                    })
                }),
            ),
            (
                "requested_mounts",
                requested.iter().all(|m| {
                    observed_mounts
                        .iter()
                        .any(|v| crate::prepare::same_mount(v, m))
                }),
            ),
        ];
        let different = checks
            .into_iter()
            .filter_map(|(field, matches)| (!matches).then_some(field))
            .collect::<Vec<_>>();
        if !different.is_empty() {
            return Err(invalid(&format!(
                "rootfs inspector immutable object or isolated placement differs: {}",
                different.join(", ")
            )));
        }
        Ok(id.into())
    }
    pub fn observe(
        &self,
        actual: &ContainerInspectResponse,
        recorded_id: &str,
    ) -> io::Result<LiveInspection> {
        let id = self.validate_container(actual, true, Some(recorded_id))?;
        let state = actual
            .state
            .as_ref()
            .ok_or_else(|| invalid("rootfs inspector runtime state absent"))?;
        if state.running != Some(true)
            || state.restarting == Some(true)
            || state.oom_killed == Some(true)
        {
            return Err(invalid("original rootfs inspector is not live"));
        }
        let pid = u32::try_from(
            state
                .pid
                .ok_or_else(|| invalid("rootfs inspector host PID absent"))?,
        )
        .map_err(|_| invalid("invalid rootfs inspector host PID"))?;
        Ok(LiveInspection {
            guard: HostGuard::observe(&id, pid, &limits())?,
            intent_sha256: self.fingerprint()?,
            container_id: id,
        })
    }
    pub fn permit(&self, live: &LiveInspection, nonce: Uuid) -> io::Result<HostPermit> {
        self.validate()?;
        if nonce.is_nil() || live.intent_sha256 != self.fingerprint()? {
            return Err(invalid(
                "rootfs inspector permit nonce or original intent differs",
            ));
        }
        live.guard.still_live()?;
        let permit = HostPermit {
            format: 1,
            installation_id: self.installation_id,
            job_id: self.capture_id,
            generation: self.request.generation,
            nonce,
            builder_image: self.image.clone(),
            request_sha256: self.request.fingerprint()?,
            runtime: BuilderRuntime::Runsc,
            limits: live.guard.observation.limits.clone(),
        };
        permit.validate_rootfs(&self.request)?;
        Ok(permit)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InspectionPhase {
    Reserved,
    VolumesDispatched,
    VolumesReady,
    SeederDispatched,
    SeederObserved,
    InputUploadDispatched,
    InputReady,
    SeederRemoved,
    InspectorDispatched,
    InspectorObserved,
    StartDispatched,
    RunningObserved,
    AuthorizationDispatched,
    ResultObserved,
    Collecting,
    Collected,
    Unconfirmed,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InspectionEffect {
    CreateInput,
    CreateOutput,
    CreateSeeder,
    UploadInput,
    RemoveSeeder,
    CreateInspector,
    StartInspector,
    AuthorizeInspector,
    RemoveInspector,
    RemoveInput,
    RemoveOutput,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionState {
    pub format: u32,
    pub intent: InspectionIntent,
    pub engine_id: String,
    pub host_boot_id: Uuid,
    pub nonce: Uuid,
    actor: crate::coordination::Producer,
    pub phase: InspectionPhase,
    /// Persisted before an effect; only an acknowledged provider response can
    /// clear it. A read-side absence cannot settle an uncertain create.
    pub pending: Option<InspectionEffect>,
    pub input_created: bool,
    pub output_created: bool,
    pub seeder_id: Option<String>,
    pub inspector_id: Option<String>,
    pub start_dispatched: bool,
    pub host: Option<HostObservation>,
    pub result: Option<RootfsInspectionReport>,
    pub error: Option<String>,
}
impl InspectionState {
    pub fn same_operation(&self, earlier: &Self) -> io::Result<()> {
        if self.intent.fingerprint()? != earlier.intent.fingerprint()?
            || self.engine_id != earlier.engine_id
            || self.host_boot_id != earlier.host_boot_id
            || self.nonce != earlier.nonce
            || serde_json::to_vec(&self.actor)? != serde_json::to_vec(&earlier.actor)?
            || earlier.seeder_id.is_some() && self.seeder_id != earlier.seeder_id
            || earlier.inspector_id.is_some() && self.inspector_id != earlier.inspector_id
            || earlier.host.is_some()
                && serde_json::to_vec(&self.host)? != serde_json::to_vec(&earlier.host)?
            || earlier.result.is_some()
                && serde_json::to_vec(&self.result)? != serde_json::to_vec(&earlier.result)?
            || earlier.start_dispatched && !self.start_dispatched
        {
            return Err(invalid(
                "rootfs inspector original actor or immutable operation changed",
            ));
        }
        Ok(())
    }
    pub fn reserve(
        intent: InspectionIntent,
        engine_id: String,
        host_boot_id: Uuid,
    ) -> io::Result<Self> {
        intent.validate()?;
        let state = Self {
            format: 1,
            intent,
            engine_id,
            host_boot_id,
            nonce: Uuid::new_v4(),
            actor: crate::coordination::Producer::current()
                .map_err(|_| invalid("rootfs inspector producer identity unavailable"))?,
            phase: InspectionPhase::Reserved,
            pending: None,
            input_created: false,
            output_created: false,
            seeder_id: None,
            inspector_id: None,
            start_dispatched: false,
            host: None,
            result: None,
            error: None,
        };
        state.validate(&state.intent, &state.engine_id, host_boot_id)?;
        Ok(state)
    }
    pub fn validate(&self, intent: &InspectionIntent, engine: &str, boot: Uuid) -> io::Result<()> {
        self.intent.validate()?;
        if self.format != 1
            || self.intent.fingerprint()? != intent.fingerprint()?
            || self.engine_id != engine
            || engine.is_empty()
            || engine.len() > 128
            || !engine.bytes().all(|b| b.is_ascii_graphic())
            || self.host_boot_id != boot
            || boot.is_nil()
            || self.nonce.is_nil()
            || self.seeder_id.as_deref().is_some_and(|v| !hex_id(v))
            || self.inspector_id.as_deref().is_some_and(|v| !hex_id(v))
            || self.host.is_some() && self.inspector_id.is_none()
            || self.result.is_some()
                && (self.host.is_none() || self.inspector_id.is_none() || !self.start_dispatched)
            || self
                .error
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 2048)
            || self.phase == InspectionPhase::Collected
                && (self.pending.is_some() || self.input_created || self.output_created)
        {
            return Err(invalid(
                "rootfs inspector original producer, provider, host or durable intent differs",
            ));
        }
        if let Some(result) = &self.result {
            self.intent.validate_report(result)?;
        }
        Ok(())
    }
    /// The caller also retains the permanent exclusive disk-store object lock.
    /// These observations are deliberately separate from capture's producer.
    pub fn require_original_actor_absent(&self) -> io::Result<()> {
        self.actor
            .require_gone()
            .map_err(|_| invalid("rootfs inspector original producer absence is unconfirmed"))
    }
    pub fn ready_result(&self) -> io::Result<&RootfsInspectionReport> {
        if self.phase != InspectionPhase::Collected
            || self.pending.is_some()
            || self.error.is_some()
        {
            return Err(invalid(
                "rootfs inspector host/provider collection remains unconfirmed",
            ));
        }
        let result = self
            .result
            .as_ref()
            .ok_or_else(|| invalid("rootfs inspector output absent"))?;
        self.intent.validate_report(result)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goldenhoop_image_builder::RootfsGuestConfig;

    fn fixture(inspector: bool) -> (InspectionIntent, ContainerInspectResponse) {
        let asset = Content {
            sha256: "a".repeat(64),
            size_bytes: 512,
        };
        let intent = InspectionIntent {
            installation_id: Uuid::new_v4(),
            capture_id: Uuid::new_v4(),
            image: format!("sha256:{}", "b".repeat(64)),
            inventory: RootfsInspectionInventory {
                format: 1,
                builder_version: env!("CARGO_PKG_VERSION").into(),
                agent: asset.clone(),
                init: asset.clone(),
                e2fsck: asset.clone(),
                debugfs: asset.clone(),
            },
            request: RootfsInspectionRequest {
                generation: Uuid::new_v4(),
                disk: Content {
                    sha256: "d".repeat(64),
                    size_bytes: 64 * 1024 * 1024,
                },
                agent: asset.clone(),
                init: asset.clone(),
                guest: RootfsGuestConfig::default(),
            },
            guest_config: asset,
        };
        let body = intent.container(inspector).unwrap();
        let mut config = serde_json::to_value(&body).unwrap();
        config.as_object_mut().unwrap().remove("HostConfig");
        if !inspector {
            config["Cmd"] = serde_json::Value::Null;
        }
        let mut host = serde_json::to_value(&body.host_config).unwrap();
        for mount in host["Mounts"].as_array_mut().unwrap() {
            if mount["ReadOnly"] == false {
                mount.as_object_mut().unwrap().remove("ReadOnly");
            }
        }
        let mounted = mounts(&intent, inspector)
            .iter()
            .map(|mount| {
                serde_json::json!({
                    "Type": "volume", "Name": mount.source, "Destination": mount.target,
                    "RW": mount.read_only != Some(true),
                })
            })
            .collect::<Vec<_>>();
        let part = if inspector {
            InspectionPart::Inspector
        } else {
            InspectionPart::Seeder
        };
        let actual = serde_json::from_value(serde_json::json!({
            "Id": "c".repeat(64), "Image": intent.image, "Name": format!("/{}", intent.resource(part)),
            "RestartCount": 0, "Config": config, "HostConfig": host, "Mounts": mounted,
        })).unwrap();
        (intent, actual)
    }

    #[test]
    fn rootfs_seeder_accepts_moby_omitted_false_and_null_empty_command() {
        let (intent, mut actual) = fixture(false);
        intent.validate_container(&actual, false, None).unwrap();
        actual.config.as_mut().unwrap().cmd = Some(vec!["injected".into()]);
        assert!(
            intent
                .validate_container(&actual, false, None)
                .unwrap_err()
                .to_string()
                .ends_with(": cmd")
        );
    }

    #[test]
    fn rootfs_inspector_still_requires_readonly_input_and_runsc() {
        let (intent, actual) = fixture(true);
        intent.validate_container(&actual, true, None).unwrap();
        for read_only in [None, Some(false)] {
            let mut bad = actual.clone();
            bad.host_config.as_mut().unwrap().mounts.as_mut().unwrap()[0].read_only = read_only;
            assert!(intent.validate_container(&bad, true, None).is_err());
        }
        let mut bad = actual.clone();
        bad.host_config.as_mut().unwrap().runtime = Some("runc".into());
        assert!(
            intent
                .validate_container(&bad, true, None)
                .unwrap_err()
                .to_string()
                .ends_with(": runtime")
        );
        let mut bad = actual;
        bad.mounts.as_mut().unwrap()[0].rw = Some(true);
        assert!(
            intent
                .validate_container(&bad, true, None)
                .unwrap_err()
                .to_string()
                .ends_with(": mounted_volumes")
        );
    }

    #[test]
    fn rootfs_inspector_refuses_extra_host_mount_options() {
        let (intent, mut actual) = fixture(true);
        actual
            .host_config
            .as_mut()
            .unwrap()
            .mounts
            .as_mut()
            .unwrap()[0]
            .bind_options = Some(MountBindOptions::default());
        assert!(
            intent
                .validate_container(&actual, true, None)
                .unwrap_err()
                .to_string()
                .ends_with(": requested_mounts")
        );
    }
}
