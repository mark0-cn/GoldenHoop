//! Unreferenced timeout-set preparation and conservative kernel readback.
//! Activation must not recreate elements or renew their deadlines.
use super::*;
use crate::Allocation;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct SetNames {
    token: Option<Uuid>,
    names: [String; 4],
}
impl SetNames {
    pub fn bootstrap() -> Self {
        Self {
            token: None,
            names: ["dns_u4", "dns_u6", "dns_o4", "dns_o6"].map(str::to_owned),
        }
    }
    pub fn staged(token: Uuid) -> Result<Self, ApiError> {
        if token.is_nil() {
            return Err(error(ErrorCode::InvalidRequest, "empty DNS staging token"));
        }
        Ok(Self {
            token: Some(token),
            names: ["u4", "u6", "o4", "o6"].map(|kind| format!("d_{}_{kind}", token.simple())),
        })
    }
    pub fn token(&self) -> Option<Uuid> {
        self.token
    }
    pub fn user_v4(&self) -> &str {
        &self.names[0]
    }
    pub fn user_v6(&self) -> &str {
        &self.names[1]
    }
    pub fn operator_v4(&self) -> &str {
        &self.names[2]
    }
    pub fn operator_v6(&self) -> &str {
        &self.names[3]
    }
    pub fn entries(&self) -> impl Iterator<Item = (&str, Authority, bool)> {
        self.names.iter().enumerate().map(|(i, n)| {
            (
                n.as_str(),
                if i < 2 {
                    Authority::User
                } else {
                    Authority::OperatorAllow
                },
                i % 2 == 0,
            )
        })
    }
    pub fn declarations(&self, allocation: &Allocation) -> Result<String, ApiError> {
        allocation.validate()?;
        let table = allocation.table();
        Ok(self
            .entries()
            .map(|(name, _, v4)| {
                format!(
                    "add set inet {table} {name} {{ type {}; flags timeout; }}\n",
                    if v4 { "ipv4_addr" } else { "ipv6_addr" }
                )
            })
            .collect())
    }
}

pub struct StagedSets {
    table: String,
    names: SetNames,
    wanted: BTreeMap<(Authority, IpAddr), (Instant, u64)>,
    script: String,
}

pub struct SetConfirmation {
    lower: BTreeMap<(Authority, IpAddr), Instant>,
}
impl SetConfirmation {
    pub fn confirmed_until(
        &self,
        authority: Authority,
        addresses: &[IpAddr],
    ) -> Result<Instant, ApiError> {
        if addresses.is_empty() {
            return Err(error(
                ErrorCode::InvalidRequest,
                "no DNS address requires confirmation",
            ));
        }
        addresses
            .iter()
            .map(|ip| {
                self.lower
                    .get(&(authority, ip.to_canonical()))
                    .copied()
                    .ok_or_else(|| {
                        error(
                            ErrorCode::BackendUnavailable,
                            "kernel DNS address membership is unconfirmed",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .min()
            .ok_or_else(|| {
                error(
                    ErrorCode::BackendUnavailable,
                    "kernel DNS expiry is unconfirmed",
                )
            })
    }
}

impl StagedSets {
    /// Expected upper bounds for an already committed active set generation.
    /// Missing expired grants are not permission; every actual member must
    /// still have an original, unexpired source credit.
    pub fn observation(
        allocation: &Allocation,
        names: SetNames,
        memberships: &[KernelLease],
    ) -> Result<Self, ApiError> {
        allocation.validate()?;
        let mut wanted = BTreeMap::new();
        for member in memberships {
            if wanted
                .insert((member.authority, member.address), (member.expires_at, 0))
                .is_some()
            {
                return Err(error(
                    ErrorCode::InvalidRequest,
                    "duplicate DNS observation member",
                ));
            }
        }
        Ok(Self {
            table: allocation.table(),
            names,
            wanted,
            script: String::new(),
        })
    }
    pub fn new(
        allocation: &Allocation,
        transaction: &LeaseTransaction,
        now: Instant,
    ) -> Result<Self, ApiError> {
        allocation.validate()?;
        let names = SetNames::staged(transaction.id())?;
        let table = allocation.table();
        let mut script = names.declarations(allocation)?;
        let mut wanted = BTreeMap::new();
        for member in transaction.memberships(now) {
            let Some(remaining) = member.expires_at.checked_duration_since(now) else {
                continue;
            };
            // Leave room for enqueue/readback latency. A set is still not
            // referenced; if the observed upper bound is too late, refuse it.
            let millis = remaining.as_millis().saturating_sub(250);
            if millis == 0 {
                continue;
            } // nft timeout zero can mean permanent.
            if millis > 300_000 {
                return Err(error(
                    ErrorCode::InvalidRequest,
                    "DNS set timeout exceeds source maximum",
                ));
            }
            let name = names
                .entries()
                .find(|(_, authority, v4)| {
                    *authority == member.authority && *v4 == member.address.is_ipv4()
                })
                .expect("four set families")
                .0;
            script.push_str(&format!(
                "add element inet {table} {name} {{ {} timeout {millis}ms }}\n",
                member.address
            ));
            wanted.insert(
                (member.authority, member.address),
                (member.expires_at, millis as u64),
            );
        }
        Ok(Self {
            table,
            names,
            wanted,
            script,
        })
    }
    pub fn names(&self) -> &SetNames {
        &self.names
    }
    pub fn script(&self) -> &str {
        &self.script
    }

    /// nft 1.0.6 JSON reports integer seconds. Native duration fields preserve
    /// milliseconds. Read start/end bracket the kernel sample; the extra ms
    /// covers display truncation. Call only after JSON owner/revision checks.
    pub fn confirm_native(
        &self,
        native: &str,
        started: Instant,
        finished: Instant,
    ) -> Result<SetConfirmation, ApiError> {
        self.confirm_observation(native, started, finished, true)
    }

    /// Periodic readback may observe a conservative subset after early kernel
    /// expiry. This never acknowledges a new grant or publishes a DNS answer.
    pub fn confirm_current_native(
        &self,
        native: &str,
        started: Instant,
        finished: Instant,
    ) -> Result<SetConfirmation, ApiError> {
        self.confirm_observation(native, started, finished, false)
    }

    fn confirm_observation(
        &self,
        native: &str,
        started: Instant,
        finished: Instant,
        require_all: bool,
    ) -> Result<SetConfirmation, ApiError> {
        let bad = || {
            error(
                ErrorCode::BackendUnavailable,
                "DNS kernel set readback differs or has insufficient expiry precision",
            )
        };
        if finished < started
            || native.len() > 4 * 1024 * 1024
            || native.lines().next() != Some(&format!("table inet {} {{", self.table))
        {
            return Err(bad());
        }
        let lines = native.lines().collect::<Vec<_>>();
        let mut lower = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for (name, authority, v4) in self.names.entries() {
            let header = format!("\tset {name} {{");
            let indices = lines
                .iter()
                .enumerate()
                .filter_map(|(i, line)| (*line == header).then_some(i))
                .collect::<Vec<_>>();
            if indices.len() != 1 {
                return Err(bad());
            }
            let start = indices[0] + 1;
            let end = lines[start..]
                .iter()
                .position(|line| *line == "\t}")
                .map(|i| i + start)
                .ok_or_else(bad)?;
            let body = &lines[start..end];
            if body
                .iter()
                .filter(|line| {
                    line.trim() == format!("type {}", if v4 { "ipv4_addr" } else { "ipv6_addr" })
                })
                .count()
                != 1
                || body
                    .iter()
                    .filter(|line| line.trim() == "flags timeout")
                    .count()
                    != 1
            {
                return Err(bad());
            }
            let element_lines = body
                .iter()
                .filter_map(|line| line.trim().strip_prefix("elements = "))
                .collect::<Vec<_>>();
            if element_lines.len() > 1 {
                return Err(bad());
            }
            let mut values = String::new();
            let mut in_elements = false;
            for line in body {
                let line = line.trim();
                if let Some(value) = line.strip_prefix("elements = ") {
                    in_elements = true;
                    values.push_str(value);
                } else if in_elements {
                    values.push(' ');
                    values.push_str(line);
                } else if !line.is_empty() && !line.starts_with("type ") && line != "flags timeout"
                {
                    return Err(bad());
                }
            }
            if values.is_empty() {
                continue;
            }
            let values = values
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .ok_or_else(bad)?
                .trim();
            if values.is_empty() {
                continue;
            }
            for element in values.split(',') {
                let fields = element.split_whitespace().collect::<Vec<_>>();
                if fields.len() != 5 || fields[1] != "timeout" || fields[3] != "expires" {
                    return Err(bad());
                }
                let address = fields[0]
                    .parse::<IpAddr>()
                    .map_err(|_| bad())?
                    .to_canonical();
                if address.is_ipv4() != v4 {
                    return Err(bad());
                }
                let &(expiry, _requested_timeout) =
                    self.wanted.get(&(authority, address)).ok_or_else(bad)?;
                let declared = duration_ms(fields[2]).ok_or_else(bad)?;
                let remaining = duration_ms(fields[4]).ok_or_else(bad)?;
                // Kernels quantize the configured timeout (9749ms may read as
                // 9748ms). The security bound is the observed absolute expiry,
                // not literal equality with the requested duration.
                if declared == 0 || declared > 300_000 || remaining > declared {
                    return Err(bad());
                }
                let upper = finished
                    .checked_add(Duration::from_millis(remaining + 1))
                    .ok_or_else(bad)?;
                // Supported x86 Linux timer choices have HZ >= 100. Reported
                // remaining jiffies can overstate wall time by one tick; allow
                // 10ms plus 1ms native-display quantization on the lower bound.
                let until = started
                    .checked_add(Duration::from_millis(remaining.saturating_sub(11)))
                    .ok_or_else(bad)?;
                if upper > expiry || !seen.insert((authority, address)) {
                    return Err(bad());
                }
                if until <= finished {
                    if require_all {
                        return Err(bad());
                    }
                    // Periodic policy inspection does not acknowledge grants.
                    // An already expiring member is finite and within its
                    // original authority, but supplies no live-source credit.
                    continue;
                }
                lower.insert((authority, address), until);
            }
        }
        // Missing/expired members cannot be treated as a successful grant.
        if require_all && lower.len() != self.wanted.len() {
            return Err(bad());
        }
        Ok(SetConfirmation { lower })
    }
}

pub(crate) fn duration_ms(mut value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut total = 0u64;
    let mut previous = 4;
    while !value.is_empty() {
        let digits = value.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let count = value[..digits].parse::<u64>().ok()?;
        value = &value[digits..];
        let (unit, multiplier, rank) = if value.starts_with("ms") {
            ("ms", 1, 1)
        } else if value.starts_with('s') {
            ("s", 1000, 2)
        } else if value.starts_with('m') {
            ("m", 60000, 3)
        } else {
            return None;
        };
        if rank >= previous {
            return None;
        }
        previous = rank;
        value = &value[unit.len()..];
        total = total.checked_add(count.checked_mul(multiplier)?)?;
        if total > 300_000 {
            return None;
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_duration_precision_is_bounded_and_never_confuses_minutes_with_milliseconds() {
        for (text, expected) in [
            ("10s", 10000),
            ("9s532ms", 9532),
            ("4m59s750ms", 299750),
            ("1ms", 1),
            ("0s", 0),
        ] {
            assert_eq!(duration_ms(text), Some(expected));
        }
        for text in [
            "",
            "1s1m",
            "1s2s",
            "-1s",
            "1.2s",
            "5m1ms",
            "9999999999999999999999999ms",
            "1h",
        ] {
            assert_eq!(duration_ms(text), None);
        }
    }

    #[test]
    fn rounded_timeouts_require_source_bounded_live_readback() {
        let now = Instant::now();
        let names = SetNames::staged(Uuid::new_v4()).unwrap();
        let address = "192.0.2.1".parse::<IpAddr>().unwrap();
        let staged = StagedSets {
            table: "gh_e_test".into(),
            names: names.clone(),
            wanted: BTreeMap::from([(
                (Authority::User, address),
                (now + Duration::from_secs(10), 9749),
            )]),
            script: String::new(),
        };
        let mut native = String::from("table inet gh_e_test {\n");
        for (name, authority, v4) in names.entries() {
            native.push_str(&format!(
                "\tset {name} {{\n\t\ttype {}\n\t\tflags timeout\n",
                if v4 { "ipv4_addr" } else { "ipv6_addr" }
            ));
            if authority == Authority::User && v4 {
                native.push_str("\t\telements = { 192.0.2.1 timeout 9s748ms expires 9s744ms }\n");
            }
            native.push_str("\t}\n");
        }
        native.push_str("}\n");
        let ended = now + Duration::from_millis(2);
        let confirmation = staged.confirm_native(&native, now, ended).unwrap();
        assert_eq!(
            confirmation
                .confirmed_until(Authority::User, &[address])
                .unwrap(),
            now + Duration::from_millis(9733)
        );
        for changed in [
            native.replace("timeout 9s748ms expires 9s744ms", "timeout 15s expires 12s"),
            native.replace("timeout 9s748ms expires 9s744ms", "timeout 0s expires 1s"),
            native.replace(" expires 9s744ms", ""),
            native.replace("192.0.2.1", "192.0.2.2"),
            native.replace("gh_e_test", "gh_e_other"),
        ] {
            assert!(staged.confirm_native(&changed, now, ended).is_err());
        }
        assert!(
            staged
                .confirm_native(&native, now, now + Duration::from_secs(10))
                .is_err()
        );
    }
}
