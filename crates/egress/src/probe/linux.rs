use super::*;
use std::path::Path;

pub async fn observe_probe(plan: ProbePlan) -> Result<ProbeObservation, ApiError> {
    plan.validate_dispatch_at(Utc::now())?;
    let status = std::fs::read_to_string("/proc/self/status").map_err(|_| {
        error(
            ErrorCode::BackendUnavailable,
            "cannot inspect probe credentials",
        )
    })?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|v| v.strip_prefix(name))
            .map(str::trim)
    };
    if plan.purpose == ProbePurpose::Discover {
        if unsafe { libc::geteuid() } != 1000
            || field("CapEff:") != Some("0000000000000000")
            || field("CapPrm:") != Some("0000000000000000")
            || field("NoNewPrivs:") != Some("1")
        {
            return Err(error(
                ErrorCode::Forbidden,
                "discovery requires zero capabilities and workload-free UID",
            ));
        }
    } else {
        crate::host::authority()?;
    }
    let bridge = plan.identity.bridge_name();
    let path = Path::new("/sys/class/net").join(&bridge);
    let result = match plan.purpose {
        ProbePurpose::Discover => {
            let read = || -> Result<(u32, String), ApiError> {
                let index = std::fs::read_to_string(path.join("ifindex"))
                    .ok()
                    .and_then(|v| v.trim().parse::<u32>().ok())
                    .filter(|v| (1..=i32::MAX as u32).contains(v))
                    .ok_or_else(|| {
                        error(ErrorCode::Conflict, "native bridge index is unavailable")
                    })?;
                if !path.join("bridge").is_dir() {
                    return Err(error(
                        ErrorCode::Conflict,
                        "native discovery target is not a bridge",
                    ));
                }
                let alias = std::fs::read_to_string(path.join("ifalias")).map_err(|_| {
                    error(ErrorCode::Conflict, "native bridge alias is unavailable")
                })?;
                Ok((index, alias.strip_suffix('\n').unwrap_or(&alias).to_owned()))
            };
            let (ifindex, alias) = read()?;
            let addresses = crate::frontend::bridge_addresses(&bridge)?;
            let ipv6_gateway = addresses.v6.ok_or_else(|| {
                error(ErrorCode::Conflict, "native bridge lacks its IPv6 gateway")
            })?;
            if read()? != (ifindex, alias.clone()) {
                return Err(error(
                    ErrorCode::Conflict,
                    "native bridge changed during discovery",
                ));
            }
            ProbeObservation::Native(NativeProbe {
                plan_sha256: plan.digest(),
                allocation: Allocation {
                    installation_id: plan.identity.installation_id,
                    sandbox_id: plan.identity.sandbox_id,
                    generation: plan.identity.generation,
                    bridge,
                    ifindex,
                },
                ipv4_gateway: addresses.v4,
                ipv6_gateway,
                alias,
                observed_at: Utc::now(),
            })
        }
        ProbePurpose::ObserveAbsence => {
            let absent = !path.try_exists().map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "cannot inspect bridge absence",
                )
            })?;
            let bytes = crate::manager::nft(&["--json", "list", "tables"], None).await?;
            let inventory: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "invalid probe table inventory",
                )
            })?;
            let names = ["gh_e_", "gh_l_", "gh_s_", "gh_d_"]
                .map(|p| format!("{p}{}", plan.identity.generation.simple()));
            let tables = inventory["nftables"].as_array().ok_or_else(|| {
                error(
                    ErrorCode::BackendUnavailable,
                    "missing probe table inventory",
                )
            })?;
            let mut owned_tables_absent = true;
            for row in tables {
                let object = row.as_object().filter(|v| v.len() == 1).ok_or_else(|| {
                    error(ErrorCode::BackendUnavailable, "malformed probe table row")
                })?;
                if object.contains_key("metainfo") {
                    continue;
                }
                let table = object.get("table").ok_or_else(|| {
                    error(
                        ErrorCode::BackendUnavailable,
                        "unexpected probe inventory object",
                    )
                })?;
                let name = table["name"].as_str().ok_or_else(|| {
                    error(ErrorCode::BackendUnavailable, "missing probe table name")
                })?;
                if !matches!(
                    table["family"].as_str(),
                    Some("inet" | "bridge" | "ip" | "ip6" | "arp" | "netdev")
                ) {
                    return Err(error(
                        ErrorCode::BackendUnavailable,
                        "unknown probe table family",
                    ));
                }
                owned_tables_absent &= !names.iter().any(|v| v == name);
            }
            ProbeObservation::Absence(ProbeAbsence {
                plan_sha256: plan.digest(),
                bridge_absent: absent
                    && !path.try_exists().map_err(|_| {
                        error(
                            ErrorCode::BackendUnavailable,
                            "cannot repeat bridge absence",
                        )
                    })?,
                owned_tables_absent,
                observed_at: Utc::now(),
            })
        }
    };
    plan.validate_dispatch_at(Utc::now())?;
    result.validate(&plan)?;
    Ok(result)
}
