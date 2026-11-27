//! Explicit hardware-gate test, excluded from ordinary workspace test counts.
use super::*;
use crate::lifecycle::{
    VmOwner, boot_id,
    cgroup::{self, Group},
};
use std::os::unix::process::ExitStatusExt;

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    path: PathBuf,
    group: Option<Group>,
    children: Vec<OwnedChild>,
}
impl Fixture {
    fn collect(&mut self) -> Result<()> {
        for mut child in self.children.drain(..) {
            child.0.kill()?;
            child.0.wait()?;
        }
        if let Some(group) = &self.group {
            group.remove_empty()?;
            self.group = None;
        }
        let absent = match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
            Ok(_) => false,
        };
        require(absent, "owned test group remains")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.collect();
    }
}
fn require(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(invalid(message).into())
    }
}

#[test]
#[ignore = "requires root and actual writable cgroup-v2; dedicated release gate only"]
fn actual_owned_cgroup_receipts_and_drop_preserve_replacement_process() {
    let generation = Uuid::new_v4();
    let path = Path::new("/sys/fs/cgroup").join(format!("gh-receipt-{}", generation.simple()));
    let mut fixture = Fixture {
        path: path.clone(),
        group: None,
        children: Vec::new(),
    };
    let mut checks = Vec::new();
    let mut observations = serde_json::json!({"group":path});
    let result = (|| -> Result<()> {
        require(
            unsafe { libc::geteuid() } == 0,
            "actual cgroup test requires root",
        )?;
        std::fs::create_dir(&path)?;
        fixture.group = Some(Group::capture(&path)?);
        let group = fixture
            .group
            .as_ref()
            .ok_or_else(|| invalid("original group unobserved"))?;
        let receipt = group.identity();
        observations["original_identity"] = serde_json::to_value(&receipt)?;
        let owner = VmOwner {
            installation_id: Uuid::new_v4(),
            sandbox_id: Uuid::new_v4(),
            generation,
            request_sha256: "a".repeat(64),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(120),
            host_boot_id: boot_id()?,
            boot_deadline_ns: crate::lifecycle::boottime_ns()? + 120_000_000_000,
        };
        let child = OwnedChild(std::process::Command::new("sleep").arg("600").spawn()?);
        let pid = child.0.id();
        fixture.children.push(child);
        group.write("cgroup.procs", pid.to_string().as_bytes())?;
        require(
            group
                .read("cgroup.procs")?
                .split_whitespace()
                .any(|v| v == pid.to_string()),
            "original child membership unobserved",
        )?;
        let mut changed = serde_json::to_value(&receipt)?;
        changed["inode"] = serde_json::json!(
            changed["inode"]
                .as_u64()
                .ok_or_else(|| invalid("inode missing"))?
                + 1
        );
        let changed = serde_json::from_value(changed)?;
        require(
            cgroup::recorded(&path, None, &owner).is_err(),
            "missing receipt granted authority",
        )?;
        require(
            cgroup::recorded(&path, Some(&changed), &owner).is_err(),
            "changed receipt granted authority",
        )?;
        let mut old_boot = owner.clone();
        old_boot.host_boot_id = Uuid::new_v4().to_string();
        require(
            cgroup::recorded(&path, Some(&receipt), &old_boot).is_err(),
            "old boot granted authority",
        )?;
        require(
            fixture.children[0].0.try_wait()?.is_none(),
            "refusal killed original child",
        )?;
        checks.push("actual_missing_changed_and_old_boot_receipts_refuse_with_child_alive");

        group.write("cgroup.kill", b"1")?;
        let mut child = fixture
            .children
            .pop()
            .ok_or_else(|| invalid("original child missing"))?;
        require(
            child.0.wait()?.signal() == Some(libc::SIGKILL),
            "owned kill not observed",
        )?;
        require(
            !Path::new("/proc").join(pid.to_string()).try_exists()?,
            "original child not reaped",
        )?;
        require(group.empty()?, "original group remains populated")?;
        group.remove_empty()?;
        let original = fixture
            .group
            .take()
            .ok_or_else(|| invalid("original descriptor missing"))?;
        require(!path.try_exists()?, "original group remains")?;
        checks.push("actual_acknowledged_group_kill_parent_reap_and_removal_observed");

        // Keep the removed object's descriptor alive, preventing inode reuse.
        std::fs::create_dir(&path)?;
        fixture.group = Some(Group::capture(&path)?);
        let replacement = fixture
            .group
            .as_ref()
            .ok_or_else(|| invalid("replacement group unobserved"))?;
        observations["replacement_identity"] = serde_json::to_value(replacement.identity())?;
        require(
            observations["original_identity"] != observations["replacement_identity"],
            "replacement inode unchanged",
        )?;
        let child = OwnedChild(std::process::Command::new("sleep").arg("600").spawn()?);
        let replacement_pid = child.0.id();
        fixture.children.push(child);
        replacement.write("cgroup.procs", replacement_pid.to_string().as_bytes())?;
        observations["replacement_process"] =
            serde_json::to_value(crate::lifecycle::process_identity(replacement_pid)?)?;
        require(
            Group::open(&path, &receipt).is_err(),
            "old receipt opened replacement",
        )?;
        require(
            original.read("cgroup.procs").is_err(),
            "stale descriptor read accepted",
        )?;
        require(
            original.write("cgroup.kill", b"1").is_err(),
            "stale descriptor kill accepted",
        )?;
        require(
            original.remove_empty().is_err(),
            "stale descriptor removal accepted",
        )?;
        require(
            fixture.children[0].0.try_wait()?.is_none(),
            "replacement child killed by stale object",
        )?;
        checks.push("actual_replacement_group_refuses_stale_open_read_kill_remove");

        let mut machine = Machine::new();
        machine.cgroup = path.clone();
        machine.cgroup_handle = Some(original);
        drop(machine);
        require(
            fixture.children[0].0.try_wait()?.is_none(),
            "Machine Drop killed replacement child",
        )?;
        require(
            replacement
                .read("cgroup.procs")?
                .split_whitespace()
                .any(|v| v == replacement_pid.to_string()),
            "replacement membership lost",
        )?;
        observations["replacement_alive_after_machine_drop"] = serde_json::json!(true);
        checks.push("actual_machine_drop_preserves_replacement_group_and_process");
        Ok(())
    })();
    let cleanup = fixture.collect();
    let report = serde_json::json!({"suite":"actual owned cgroup receipt fencing", "result":if result.is_ok() && cleanup.is_ok() {"passed"} else {"failed"},
        "cleanup":if cleanup.is_ok() {"complete"} else {"unknown"}, "cases":checks, "observations":observations,
        "error":result.as_ref().err().map(ToString::to_string), "cleanup_error":cleanup.as_ref().err().map(ToString::to_string),
        "scope":"actual cgroup-v2 object/kill/reap/replacement/Drop checks; no KVM, VM-root or earlier unacknowledged allocation claim"});
    println!("GH_CGROUP_RECEIPT_CONTRACT={report}");
    assert!(result.is_ok() && cleanup.is_ok(), "{report}");
}
