//! Millisecond native expiry readback, independently bracketed by monotonic time.
use super::*;
use std::time::{Duration, Instant};

pub fn verify_native_lease(
    allocation: &Allocation,
    native: &str,
    started: Instant,
    finished: Instant,
    original_deadline: Option<Instant>,
) -> Result<Instant, ApiError> {
    allocation.validate()?;
    if finished < started
        || native.len() > 4 * 1024 * 1024
        || native.lines().next() != Some(&format!("table inet {} {{", allocation.table()))
    {
        return Err(bad());
    }
    let lines = native.lines().collect::<Vec<_>>();
    let positions = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| (*line == "\tset live {").then_some(i))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(bad());
    }
    let start = positions[0] + 1;
    let end = lines[start..]
        .iter()
        .position(|line| *line == "\t}")
        .map(|n| n + start)
        .ok_or_else(bad)?;
    let body = lines[start..end]
        .iter()
        .map(|line| line.trim())
        .collect::<Vec<_>>();
    // nft omits the redundant native flag with a default timeout; the paired
    // JSON structure readback still requires the exact timeout flag.
    for required in ["type ifname", "timeout 10s"] {
        if body.iter().filter(|line| **line == required).count() != 1 {
            return Err(bad());
        }
    }
    let elements = body
        .iter()
        .filter_map(|line| line.strip_prefix("elements = "))
        .collect::<Vec<_>>();
    let flags = body.iter().filter(|line| **line == "flags timeout").count();
    if elements.len() != 1 || flags > 1 || body.len() != 3 + flags {
        return Err(bad());
    }
    let fields = elements[0]
        .strip_prefix("{ ")
        .and_then(|s| s.strip_suffix(" }"))
        .ok_or_else(bad)?
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.first().copied() != Some(format!("\"{}\"", allocation.bridge).as_str()) {
        return Err(bad());
    }
    let (declared, remaining) = match fields.as_slice() {
        [_, "expires", remaining] => (
            u64::from(LEASE_SECONDS) * 1000,
            crate::dns::duration_ms(remaining).ok_or_else(bad)?,
        ),
        [_, "timeout", declared, "expires", remaining] => (
            crate::dns::duration_ms(declared).ok_or_else(bad)?,
            crate::dns::duration_ms(remaining).ok_or_else(bad)?,
        ),
        _ => return Err(bad()),
    };
    if declared == 0 || declared > u64::from(LEASE_SECONDS) * 1000 || remaining > declared {
        return Err(bad());
    }
    let upper = finished
        .checked_add(Duration::from_millis(remaining + 1))
        .ok_or_else(bad)?;
    let lower = started
        .checked_add(Duration::from_millis(remaining.saturating_sub(11)))
        .ok_or_else(bad)?;
    if lower <= finished || original_deadline.is_some_and(|limit| upper > limit) {
        return Err(bad());
    }
    Ok(lower)
}
