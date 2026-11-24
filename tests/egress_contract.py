"""Actual Rust host adapter; still no production DNS/network capability gate."""
import argparse
import hashlib
import json
import os
import queue
import subprocess
import threading
import time
import uuid
from pathlib import Path

from network_contract import Contract, Stream, docker


class Controller:
    def __init__(self, container):
        self.process = subprocess.Popen(["docker", "exec", "--interactive", container,
            "/usr/local/libexec/goldenhoop-egress"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.rows = queue.Queue(maxsize=32)
        self.sequence = 0
        self.errors = bytearray()

        def read():
            while True:
                line = self.process.stdout.readline(256 * 1024 + 1)
                if not line:
                    self.rows.put(None)
                    return
                self.rows.put(line)

        def drain():
            while data := self.process.stderr.read(4096):
                if len(self.errors) < 8192:
                    self.errors.extend(data.encode("utf-8")[:8192-len(self.errors)])

        self.reader = threading.Thread(target=read, daemon=True)
        self.drainer = threading.Thread(target=drain, daemon=True)
        self.reader.start()
        self.drainer.start()

    def request(self, operation, error=False, allow_uncertain=False, **fields):
        self.sequence += 1
        self.process.stdin.write(json.dumps({"id": self.sequence, "command": {"operation": operation, **fields}}) + "\n")
        self.process.stdin.flush()
        line = self.rows.get(timeout=12)
        assert line and len(line) <= 256 * 1024, "controller EOF is not an acknowledgement"
        reply = json.loads(line)
        assert reply["id"] == self.sequence, reply
        if error:
            assert "error" in reply, reply
        else:
            assert "result" in reply and (allow_uncertain or not reply["result"]["uncertain"]), reply
        return reply

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.drainer.join(timeout=2)
        assert not self.reader.is_alive() and not self.drainer.is_alive()
        self.process.stdout.close()
        self.process.stderr.close()
        assert self.process.returncode == 0, bytes(self.errors).decode("utf-8", errors="replace")


class RustContract(Contract):
    def __init__(self, args):
        super().__init__(args)
        self.table = "gh_e_" + self.attempt
        self.allocation = None
        self.controller = None
        self.revision = None
        self.renewable = False
        self.phase = 0
        self.evidence["suite"] = "rust-host-egress-adapter"
        self.evidence["scope"] = "actual static-address Rust controller; DNS/IPv6/Ethernet/credentials/API integration remain unverified"
        root = Path(__file__).resolve().parents[1]
        paths = [Path(__file__).resolve(), root/"images/agent/Dockerfile", root/"Cargo.toml", root/"Cargo.lock"]
        paths += list((root/"crates/egress").rglob("*.rs")) + [root/"crates/egress/Cargo.toml"]
        paths += list((root/"crates/policy/src").rglob("*.rs"))
        self.evidence["source_files_sha256"].update({p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
        self.save()

    def rpc(self, operation, error=False, **fields):
        reply = self.controller.request(operation, error=error, **fields)
        self.evidence.setdefault("controller_acknowledgements", []).append({"operation": operation, "reply": reply})
        if not error:
            self.revision = reply["result"]["revision"]
            if operation in ("open", "install", "quarantine", "remove"):
                self.renewable = False
            elif operation == "apply":
                self.renewable = True
        self.save()
        return reply

    def open(self):
        self.controller = Controller(self.helper)
        return self.rpc("open", allocation=self.allocation)

    def owned_table(self):
        entries = json.loads(self.exec(self.helper, "nft", "--json", "list", "table", "inet", self.table).stdout)["nftables"]
        tables = [e["table"] for e in entries if "table" in e]
        assert len(tables) == 1 and tables[0]["family"] == "inet" and tables[0]["name"] == self.table
        chains = [e["chain"]["name"] for e in entries if "chain" in e]
        assert self.owner.replace(":", "_") in chains
        assert "revision_" + str(self.revision) in chains
        return entries

    def packets(self):
        return sum(expr["counter"]["packets"] for entry in self.owned_table() if "rule" in entry
            for expr in entry["rule"]["expr"] if "counter" in expr)

    def control(self):
        super().control()
        if self.controller and self.renewable:
            self.rpc("renew", expected_revision=self.revision)

    def apply_config(self, config):
        self.rpc("apply", expected_revision=self.revision, config=config)

    def apply(self, ignored_fixture_script):
        # Reuse the independently established traffic oracle, substituting Rust
        # operations for its three explicit fixture phases, never its scripts.
        self.phase += 1
        if self.phase == 1:
            link = json.loads(self.exec(self.helper, "ip", "-json", "link", "show", "dev", self.bridge).stdout)[0]
            self.allocation = {"installation_id": str(uuid.uuid4()), "sandbox_id": str(uuid.uuid4()),
                "generation": str(uuid.UUID(self.attempt)), "bridge": self.bridge, "ifindex": link["ifindex"]}
            self.owner = "goldenhoop:" + hashlib.sha256(json.dumps(self.allocation, separators=(",", ":")).encode()).hexdigest()
            self.open()
            self.rpc("install", error=True)  # Unlabelled bridge must refuse.
            self.exec(self.helper, "ip", "link", "set", "dev", self.bridge, "alias", self.owner)
            self.table_attempted = True
            self.rpc("install")
            assert self.revision == 0
            self.rpc("remove", expected_revision=0, error=True)
            self.rpc("renew", expected_revision=0, error=True)
            second = Controller(self.helper)
            try:
                second.request("open", allocation=self.allocation, error=True)
            finally:
                second.close()
            foreign = dict(self.allocation, installation_id=str(uuid.uuid4()))
            second = Controller(self.helper)
            try:
                second.request("open", allocation=foreign, error=True)
            finally:
                second.close()
            self.check("allocation_alias_controller_lock_foreign_ownership_and_live_bridge_deletion_refuse")
        elif self.phase == 2:
            self.allow_config = {"policies": [{"default_action": "deny", "rules": [
                {"destination": self.target_ip, "ports": [19001], "action": "allow"}]}]}
            self.apply_config(self.allow_config)
            assert self.revision == 1
            self.rpc("apply", expected_revision=0, config={"policies": [{"default_action": "allow", "rules": []}]}, error=True)
            self.rpc("apply", expected_revision=1, config={"policies": [{"default_action": "deny", "rules": [
                {"destination": "example.test", "ports": [], "action": "allow"}]}]}, error=True)
            assert self.rpc("inspect")["result"]["revision"] == 1
            self.check("stale_revision_and_unimplemented_name_policy_refuse_without_mutation")
            self.kernel_policy_cases()
            self.apply_config(self.allow_config)
        elif self.phase == 3:
            previous = self.revision
            self.controller.close()
            self.controller = None
            # Real kernel timeout, independent of the stopped Rust process.
            time.sleep(11)
            before = self.packets()
            assert not self.stream.exchange()["ok"]
            assert not self.probe(self.guest, "tcp", self.target_ip, 19001)
            assert self.packets() > before
            super().control()
            self.check("controller_loss_expires_existing_and_new_flow_permission_in_kernel")
            self.open()
            self.rpc("renew", expected_revision=previous, error=True)
            self.rpc("apply", expected_revision=previous, config={"policies": [{"default_action": "allow", "rules": []}]}, error=True)
            self.rpc("quarantine", expected_revision=previous)
            self.check("restart_observation_cannot_renew_without_confirmed_quarantine")
            # Establish a new positive control after lease expiry. A previously
            # timed-out socket cannot prove an independent tightening event.
            self.apply_config(self.allow_config)
            self.stream.close()
            self.stream = Stream(self.guest, self.target_ip, self.attempt)
            assert self.stream.exchange()["ok"]
            self.rpc("quarantine", expected_revision=self.revision)
        else:
            raise AssertionError("unexpected traffic-oracle phase")
        self.owned_table()

    def kernel_policy_cases(self):
        def rule(action, ports=(), target=None):
            return {"destination": target or self.target_ip, "action": action, "ports": list(ports)}

        self.apply_config({"policies": [
            {"default_action": "deny", "rules": [rule("allow", target=self.target_ip + "/32")]},
            {"default_action": "deny", "rules": [rule("allow", [19001])]}]})
        assert self.probe(self.guest, "tcp", self.target_ip, 19001)
        assert not self.probe(self.guest, "tcp", self.target_ip, 19003)
        assert not self.probe(self.guest, "udp", self.target_ip, 19002)
        self.control()
        self.check("kernel_cidr_and_user_hierarchy_intersect_with_tcp_only_ports")
        for rules in [[rule("allow"), rule("deny", [19001])], [rule("deny", [19001]), rule("allow")]]:
            self.apply_config({"policies": [{"default_action": "deny", "rules": rules}]})
            assert not self.probe(self.guest, "tcp", self.target_ip, 19001)
            assert self.probe(self.guest, "tcp", self.target_ip, 19003)
            self.control()
        self.check("kernel_user_deny_precedes_allow_in_both_orders")
        self.apply_config({"policies": [{"default_action": "allow", "rules": []}],
            "deny_always": [rule("deny", [19001])], "allow_always": [rule("allow")]})
        assert not self.probe(self.guest, "tcp", self.target_ip, 19001)
        assert self.probe(self.guest, "tcp", self.target_ip, 19003)
        self.control()
        self.apply_config({"policies": [{"default_action": "deny", "rules": [rule("deny")]}],
            "allow_always": [rule("allow", [19001])]})
        assert self.probe(self.guest, "tcp", self.target_ip, 19001)
        assert not self.probe(self.guest, "tcp", self.target_ip, 19003)
        self.control()
        self.check("kernel_operator_deny_then_allow_precede_user_policy")
        self.apply_config({"policies": [{"default_action": "deny", "rules": []}],
            "allow_always": [rule("allow")], "tcp_cap": [19003]})
        assert not self.probe(self.guest, "tcp", self.target_ip, 19001)
        assert self.probe(self.guest, "tcp", self.target_ip, 19003)
        assert self.probe(self.guest, "udp", self.target_ip, 19002)
        self.control()
        self.check("kernel_tcp_cap_precedes_operator_allow_without_becoming_a_udp_cap")

    def cleanup(self):
        if self.stream:
            self.stream.close()
            self.stream = None
        for identity in docker("ps", "--all", "--filter", "label=dev.goldenhoop.attempt=" + self.attempt, "--format", "{{.ID}}").stdout.split():
            observed = json.loads(docker("inspect", identity).stdout)[0]
            self.owned(observed)
            if observed["Name"] != "/" + self.helper_name:
                docker("rm", "--force", "--volumes", identity)
        for identity in docker("network", "ls", "--filter", "label=dev.goldenhoop.attempt=" + self.attempt, "--format", "{{.ID}}").stdout.split():
            self.owned(json.loads(docker("network", "inspect", identity).stdout)[0])
            docker("network", "rm", identity)
        if self.table_attempted:
            self.ensure_helper()
            if self.controller is None:
                self.open()
            observed = self.rpc("inspect", allow_uncertain=True)["result"]
            self.rpc("remove", expected_revision=observed["revision"] or 0)
            self.evidence["rust_table_collection_confirmed"] = True
        if self.controller:
            self.controller.close()
            self.controller = None
        super().cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="goldenhoop-network-fixture:test")
    parser.add_argument("--runtime", choices=["runc", "runsc"], default="runc")
    parser.add_argument("--output", required=True)
    parser.add_argument("--remove-image", action="store_true")
    parser.add_argument("--receiver-publication", choices=["loopback", "routed"], default="loopback")
    parser.add_argument("--ci-host-diagnostics", action="store_true")
    arguments = parser.parse_args()
    if arguments.ci_host_diagnostics and os.environ.get("GITHUB_ACTIONS") != "true":
        parser.error('--ci-host-diagnostics requires an ephemeral GitHub Actions runner')
    RustContract(arguments).run()
