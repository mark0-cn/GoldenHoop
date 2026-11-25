//! Pinned read-only host probes; no native controller or workload is fabricated.
use super::*;
use goldenhoop_egress::{ProbeObservation, ProbePlan, ProbePurpose};

fn request(plan: &ProbePlan, image_labels: &HashMap<String, String>) -> ContainerCreateBody {
    let mut labels = image_labels.clone();
    labels.extend(HashMap::from([
        (
            INSTALL_LABEL.into(),
            plan.identity.installation_id.to_string(),
        ),
        (SANDBOX_LABEL.into(), plan.identity.sandbox_id.to_string()),
        (PROFILE_LABEL.into(), plan.identity.profile.clone()),
        (ROLE_LABEL.into(), "native-probe".into()),
        (EXPIRY_LABEL.into(), plan.dispatch_deadline().to_rfc3339()),
        (
            "dev.goldenhoop.probe-plan".into(),
            serde_json::to_string(plan).expect("probe plan"),
        ),
    ]));
    let collecting = plan.purpose == ProbePurpose::ObserveAbsence;
    ContainerCreateBody {
        image: Some(plan.image_id.clone()),
        user: Some(if collecting { "0:0" } else { "1000:1000" }.into()),
        entrypoint: Some(vec![
            PATH.into(),
            "--probe-native".into(),
            serde_json::to_string(plan).expect("probe plan"),
        ]),
        cmd: Some(vec![]),
        working_dir: Some("/".into()),
        env: Some(vec![ENV.into()]),
        attach_stdin: Some(false),
        attach_stdout: Some(false),
        attach_stderr: Some(false),
        open_stdin: Some(false),
        stdin_once: Some(false),
        tty: Some(false),
        stop_signal: Some("SIGTERM".into()),
        labels: Some(labels),
        host_config: Some(HostConfig {
            runtime: Some("runc".into()),
            network_mode: Some("host".into()),
            ipc_mode: Some("private".into()),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            readonly_rootfs: Some(true),
            privileged: Some(false),
            cap_drop: Some(vec!["ALL".into()]),
            cap_add: collecting.then(|| vec!["NET_ADMIN".into()]),
            security_opt: Some(vec!["no-new-privileges:true".into()]),
            memory: Some(MEMORY),
            memory_swap: Some(MEMORY),
            nano_cpus: Some(250_000_000),
            pids_limit: Some(32),
            auto_remove: Some(false),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::NO),
                maximum_retry_count: Some(0),
            }),
            log_config: Some(HostConfigLogConfig {
                typ: Some("json-file".into()),
                config: Some(HashMap::from([
                    ("max-size".into(), "256k".into()),
                    ("max-file".into(), "1".into()),
                ])),
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

impl DockerControllerProvider {
    fn check_probe(&self, plan: &ProbePlan) -> Result<(), ApiError> {
        plan.validate()?;
        if plan.image_id != self.image_id {
            return Err(conflict());
        }
        Ok(())
    }
    pub async fn lookup_probe(
        &self,
        plan: &ProbePlan,
    ) -> Result<Option<ControllerObservation>, ApiError> {
        self.check_probe(plan)?;
        let rows = self
            .inventory("name", &format!("^/{}$", plan.name()))
            .await?;
        if rows.len() > 1 {
            return Err(conflict());
        }
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let container = row.id.as_deref().filter(|s| id(s)).ok_or_else(unknown)?;
        let value = bounded(self.docker.inspect_container(container, None)).await?;
        let observed = inspection::observe_process(
            &plan.name(),
            &plan.image_id,
            &value,
            &request(plan, &self.image_labels),
        )?;
        if observed.container_id != container {
            return Err(conflict());
        }
        Ok(Some(observed))
    }
    pub async fn create_probe(&self, plan: &ProbePlan) -> Result<ControllerObservation, ApiError> {
        self.check_probe(plan)?;
        plan.validate_dispatch_at(Utc::now())?;
        let mut writes = self.writes.lock().await;
        let key = format!("create:{}", plan.name());
        if writes.contains(&key) || self.lookup_probe(plan).await?.is_some() {
            return Err(conflict());
        }
        plan.validate_dispatch_at(Utc::now())?;
        writes.insert(key);
        let created = bounded(self.docker.create_container(
            Some(CreateContainerOptions {
                name: Some(plan.name()),
                ..Default::default()
            }),
            request(plan, &self.image_labels),
        ))
        .await?;
        if !id(&created.id) || !created.warnings.is_empty() {
            return Err(unknown());
        }
        let actual = self.lookup_probe(plan).await?.ok_or_else(unknown)?;
        if actual.container_id != created.id || actual.running || actual.status != "created" {
            return Err(unknown());
        }
        Ok(actual)
    }
    pub async fn start_probe(
        &self,
        plan: &ProbePlan,
        expected_id: &str,
    ) -> Result<ControllerObservation, ApiError> {
        self.check_probe(plan)?;
        plan.validate_dispatch_at(Utc::now())?;
        if !id(expected_id) {
            return Err(invalid());
        }
        let mut writes = self.writes.lock().await;
        let key = format!("start:{}", plan.name());
        if writes.contains(&key) {
            return Err(conflict());
        }
        let before = self.lookup_probe(plan).await?.ok_or_else(unknown)?;
        if before.container_id != expected_id || before.running || before.status != "created" {
            return Err(conflict());
        }
        plan.validate_dispatch_at(Utc::now())?;
        writes.insert(key);
        bounded(self.docker.start_container(expected_id, None)).await?;
        let actual = self.lookup_probe(plan).await?.ok_or_else(unknown)?;
        if actual.container_id != expected_id
            || !matches!(actual.status.as_str(), "running" | "exited")
            || actual.paused
            || actual.restarting
            || actual.dead
        {
            return Err(unknown());
        }
        Ok(actual)
    }
    pub async fn probe_result(
        &self,
        plan: &ProbePlan,
        expected_id: &str,
    ) -> Result<ProbeObservation, ApiError> {
        self.check_probe(plan)?;
        if !id(expected_id) {
            return Err(invalid());
        }
        let actual = self.lookup_probe(plan).await?.ok_or_else(unknown)?;
        if actual.container_id != expected_id
            || actual.status != "exited"
            || actual.running
            || actual.paused
            || actual.dead
            || actual.restarting
            || actual.exit_code != 0
        {
            return Err(unknown());
        }
        let operation = async {
            let mut stream = self.docker.logs(
                expected_id,
                Some(LogsOptions {
                    stdout: true,
                    stderr: true,
                    follow: false,
                    tail: "all".into(),
                    ..Default::default()
                }),
            );
            let mut bytes = Vec::new();
            while let Some(row) = stream.next().await {
                match row.map_err(backend)? {
                    LogOutput::StdOut { message } => {
                        if bytes.len() + message.len() > MAX_FRAME as usize {
                            return Err(unknown());
                        }
                        bytes.extend_from_slice(&message);
                    }
                    LogOutput::StdErr { message } if message.is_empty() => {}
                    _ => return Err(unknown()),
                }
            }
            let observed: ProbeObservation =
                serde_json::from_slice(&bytes).map_err(|_| unknown())?;
            observed.validate(plan)?;
            let final_state = self.lookup_probe(plan).await?.ok_or_else(unknown)?;
            if final_state.status != "exited"
                || final_state.exit_code != 0
                || final_state.container_id != expected_id
            {
                return Err(unknown());
            }
            Ok(observed)
        };
        tokio::time::timeout(Duration::from_secs(10), operation)
            .await
            .map_err(|_| unknown())?
    }
    pub async fn collect_probe(
        &self,
        plan: &ProbePlan,
        expected_id: &str,
    ) -> Result<ControllerRemoval, ApiError> {
        self.check_probe(plan)?;
        if !id(expected_id) {
            return Err(invalid());
        }
        let _serial = self.writes.lock().await;
        if let Some(actual) = self.lookup_probe(plan).await? {
            if actual.container_id != expected_id {
                return Err(conflict());
            }
            match bounded(self.docker.remove_container(
                expected_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            ))
            .await
            {
                Ok(()) => {}
                Err(e) if e.code == ErrorCode::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if self.lookup_probe(plan).await?.is_some()
            || !self.inventory("id", expected_id).await?.is_empty()
        {
            return Err(unknown());
        }
        match bounded(self.docker.inspect_container(expected_id, None)).await {
            Err(e) if e.code == ErrorCode::NotFound => {}
            _ => return Err(unknown()),
        }
        Ok(ControllerRemoval {
            container_id: expected_id.into(),
            provider_absent: true,
            observed_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests;
