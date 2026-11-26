//! Read-only system DNS configuration for the verified owned gateway.
use super::*;
use goldenhoop_core::resolver::ResolverConfig;
use std::net::Ipv4Addr;

impl DockerDriver {
    pub(super) async fn owned_network_gateway(
        &self,
        network: &WorkloadNetworkPlan,
    ) -> Result<Ipv4Addr, ApiError> {
        network.validate()?;
        let observed = DockerNetworkProvider::connect()
            .await?
            .lookup(&network.provider_plan())
            .await?
            .filter(|observed| observed.network_id == network.network_id)
            .ok_or_else(|| unavailable("owned resolver network is unconfirmed"))?;
        Ok(observed.ipv4_gateway)
    }

    pub(super) async fn configure_resolver(
        &self,
        body: &mut ContainerCreateBody,
        volume: &str,
        network: &WorkloadNetworkPlan,
    ) -> Result<(), ApiError> {
        let gateway = self.owned_network_gateway(network).await?;
        let config = ResolverConfig::new(gateway);
        // The existing installation cache contains only trusted executable and
        // public, content-addressed DNS data. No provider or workload data.
        let cached = self.bundle.lock().await;
        let observed = self.docker.inspect_volume(volume).await.map_err(backend)?;
        if cached.as_deref() != Some(volume)
            || observed.name != volume
            || !self.owns(Some(&observed.labels), "agent-bundle")
        {
            return Err(unavailable("owned resolver bundle is unconfirmed"));
        }
        let image = self
            .docker
            .inspect_image(&self.config.agent_image)
            .await
            .map_err(backend)?;
        let image_id = image
            .id
            .ok_or_else(|| unavailable("resolver helper image has no identity"))?;
        self.run_bundle_helper(
            volume,
            image_id,
            vec!["/usr/local/bin/goldenhoop-agent".into()],
            vec!["resolver-config".into(), gateway.to_string()],
        )
        .await?;
        let host = body
            .host_config
            .as_mut()
            .ok_or_else(|| unavailable("missing workload host config"))?;
        host.dns = Some(vec![gateway.to_string()]);
        host.mounts
            .as_mut()
            .ok_or_else(|| unavailable("missing trusted workload mounts"))?
            .push(Mount {
                target: Some("/etc/resolv.conf".into()),
                source: Some(volume.into()),
                typ: Some(MountType::VOLUME),
                read_only: Some(true),
                volume_options: Some(MountVolumeOptions {
                    no_copy: Some(true),
                    subpath: Some(config.file_name().into()),
                    ..Default::default()
                }),
                ..Default::default()
            });
        Ok(())
    }
}

pub(super) fn admit_mounts(actual: &ContainerInspectResponse, gateway: Ipv4Addr) -> bool {
    let Some(mounts) = actual.mounts.as_ref().filter(|mounts| mounts.len() == 2) else {
        return false;
    };
    let Some(agent) = mounts
        .iter()
        .find(|mount| mount.destination.as_deref() == Some("/opt/goldenhoop"))
    else {
        return false;
    };
    let Some(resolver) = mounts
        .iter()
        .find(|mount| mount.destination.as_deref() == Some("/etc/resolv.conf"))
    else {
        return false;
    };
    let Some(volume) = agent.name.as_deref().filter(|name| !name.is_empty()) else {
        return false;
    };
    let Some(source) = agent
        .source
        .as_deref()
        .filter(|source| source.starts_with('/'))
    else {
        return false;
    };
    let config = ResolverConfig::new(gateway);
    if agent.typ.as_deref() != Some("volume")
        || agent.rw != Some(false)
        || resolver.typ.as_deref() != Some("volume")
        || resolver.rw != Some(false)
        || resolver.name.as_deref() != Some(volume)
        || resolver.source.as_deref() != Some(source)
    {
        return false;
    }
    let Some(host) = actual.host_config.as_ref() else {
        return false;
    };
    if host.dns.as_ref() != Some(&vec![gateway.to_string()]) {
        return false;
    }
    let Some(specs) = host.mounts.as_ref().filter(|mounts| mounts.len() == 2) else {
        return false;
    };
    for (target, subpath) in [
        ("/opt/goldenhoop", None),
        ("/etc/resolv.conf", Some(config.file_name())),
    ] {
        let Some(spec) = specs
            .iter()
            .find(|spec| spec.target.as_deref() == Some(target))
        else {
            return false;
        };
        if spec.typ != Some(MountType::VOLUME)
            || spec.source.as_deref() != Some(volume)
            || spec.read_only != Some(true)
            || spec.volume_options.as_ref().is_none_or(|options| {
                options.no_copy != Some(true)
                    || options.subpath.as_deref().filter(|value| !value.is_empty()) != subpath
            })
        {
            return false;
        }
    }
    true
}
