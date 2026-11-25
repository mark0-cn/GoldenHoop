//! Pure admission of a complete actual Docker inspection. No daemon I/O.
use super::*;

fn labels(
    plan: &ControllerPlan,
    image_labels: &HashMap<String, String>,
) -> HashMap<String, String> {
    let identity = &plan.native.identity;
    let mut labels = image_labels.clone();
    labels.extend(HashMap::from([
        (INSTALL_LABEL.into(), identity.installation_id.to_string()),
        (SANDBOX_LABEL.into(), identity.sandbox_id.to_string()),
        (PROFILE_LABEL.into(), identity.profile.clone()),
        (ROLE_LABEL.into(), ROLE.into()),
        (EXPIRY_LABEL.into(), plan.native.expires_at.to_rfc3339()),
        (
            PLAN.into(),
            serde_json::to_string(plan).expect("serializable controller plan"),
        ),
    ]));
    labels
}
pub(super) fn request(
    plan: &ControllerPlan,
    image_labels: &HashMap<String, String>,
) -> ContainerCreateBody {
    ContainerCreateBody {
        image: Some(plan.image_id.clone()),
        user: Some("0:0".into()),
        entrypoint: Some(vec![PATH.into()]),
        cmd: Some(vec![]),
        working_dir: Some("/".into()),
        env: Some(vec![ENV.into()]),
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        open_stdin: Some(true),
        stdin_once: Some(true),
        tty: Some(false),
        stop_signal: Some("SIGTERM".into()),
        labels: Some(labels(plan, image_labels)),
        host_config: Some(HostConfig {
            runtime: Some("runc".into()),
            network_mode: Some("host".into()),
            ipc_mode: Some("private".into()),
            cgroupns_mode: Some(HostConfigCgroupnsModeEnum::PRIVATE),
            readonly_rootfs: Some(true),
            privileged: Some(false),
            cap_drop: Some(vec!["ALL".into()]),
            cap_add: Some(vec!["NET_ADMIN".into()]),
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
                typ: Some("none".into()),
                config: None,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}
pub(super) fn observe(
    plan: &ControllerPlan,
    value: &ContainerInspectResponse,
    expected: &ContainerCreateBody,
) -> Result<ControllerObservation, ApiError> {
    let container = value.id.as_deref().filter(|v| id(v)).ok_or_else(unknown)?;
    let config = value.config.as_ref().ok_or_else(unknown)?;
    let host = value.host_config.as_ref().ok_or_else(unknown)?;
    let state = value.state.as_ref().ok_or_else(unknown)?;
    let wanted = expected.host_config.as_ref().expect("fixed host config");
    if value.name.as_deref() != Some(format!("/{}", plan.name()).as_str())
        || value.image.as_deref() != Some(&plan.image_id)
        || value.path.as_deref() != Some(PATH)
        || value.args.as_ref().is_none_or(|v| !v.is_empty())
        || value.mounts.as_ref().is_none_or(|v| !v.is_empty())
        || config.image.as_deref() != Some(&plan.image_id)
        || config.labels != expected.labels
        || config.user != expected.user
        || config.entrypoint != expected.entrypoint
        || config.cmd.as_ref().is_some_and(|v| !v.is_empty())
        || config.working_dir != expected.working_dir
        || config.env != expected.env
        || config.attach_stdin != Some(true)
        || config.attach_stdout != Some(true)
        || config.attach_stderr != Some(true)
        || config.open_stdin != Some(true)
        || config.stdin_once != Some(true)
        || config.tty != Some(false)
        || config.volumes.as_ref().is_some_and(|v| !v.is_empty())
        || config.exposed_ports.as_ref().is_some_and(|v| !v.is_empty())
        || config.healthcheck.is_some()
        || config.stop_signal != expected.stop_signal
        || host.runtime != wanted.runtime
        || host.network_mode != wanted.network_mode
        || host.ipc_mode != wanted.ipc_mode
        || host.cgroupns_mode != wanted.cgroupns_mode
        || host.readonly_rootfs != Some(true)
        || host.privileged != Some(false)
        || host.cap_drop != wanted.cap_drop
        || host.cap_add != wanted.cap_add
        || host.security_opt != wanted.security_opt
        || host.memory != wanted.memory
        || host.memory_swap != wanted.memory_swap
        || host.nano_cpus != wanted.nano_cpus
        || host.pids_limit != wanted.pids_limit
        || host.auto_remove != Some(false)
        || host.restart_policy != wanted.restart_policy
        || host.log_config.as_ref().and_then(|l| l.typ.as_deref()) != Some("none")
        || host.pid_mode.as_ref().is_some_and(|v| !v.is_empty())
        || host.uts_mode.as_ref().is_some_and(|v| !v.is_empty())
        || host.userns_mode.as_ref().is_some_and(|v| !v.is_empty())
        || host.binds.as_ref().is_some_and(|v| !v.is_empty())
        || host.mounts.as_ref().is_some_and(|v| !v.is_empty())
        || host.volumes_from.as_ref().is_some_and(|v| !v.is_empty())
        || host.devices.as_ref().is_some_and(|v| !v.is_empty())
        || host.device_requests.as_ref().is_some_and(|v| !v.is_empty())
        || host
            .device_cgroup_rules
            .as_ref()
            .is_some_and(|v| !v.is_empty())
        || host.group_add.as_ref().is_some_and(|v| !v.is_empty())
        || host.port_bindings.as_ref().is_some_and(|v| !v.is_empty())
        || host.publish_all_ports == Some(true)
        || host.sysctls.as_ref().is_some_and(|v| !v.is_empty())
        || host.extra_hosts.as_ref().is_some_and(|v| !v.is_empty())
        || host.dns.as_ref().is_some_and(|v| !v.is_empty())
        || host.links.as_ref().is_some_and(|v| !v.is_empty())
        || host.tmpfs.as_ref().is_some_and(|v| !v.is_empty())
        || host.init == Some(true)
        || host.oom_kill_disable == Some(true)
    {
        return Err(conflict());
    }
    let status = state.status.ok_or_else(unknown)?.to_string();
    let running = state.running.ok_or_else(unknown)?;
    if state.paused.is_none() || state.restarting.is_none() || state.dead.is_none() {
        return Err(unknown());
    }
    Ok(ControllerObservation {
        container_id: container.into(),
        image_id: plan.image_id.clone(),
        status,
        running,
        paused: state.paused.ok_or_else(unknown)?,
        restarting: state.restarting.ok_or_else(unknown)?,
        dead: state.dead.ok_or_else(unknown)?,
        exit_code: state.exit_code.ok_or_else(unknown)?,
        observed_at: Utc::now(),
    })
}
