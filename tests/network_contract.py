"""IPv4 routed-filter prototype; no production egress capability is established."""
import argparse
import hashlib
import ipaddress
import json
import queue
import shlex
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from network_samples import CLIENT, HOST, IDENTITY, TARGET


def docker(*args, data=None, check=True):
    # Docker transports raw stdin to Linux. Windows text-mode pipes would turn
    # LF rule batches into CRLF, which nft correctly rejects as trailing junk.
    result = subprocess.run(["docker", *map(str, args)], input=data.encode("utf-8") if data is not None else None,
                            capture_output=True, timeout=35)
    result.stdout = result.stdout.decode("utf-8")
    result.stderr = result.stderr.decode("utf-8", errors="replace")
    if check and result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()}")
    return result


class Stream:
    def __init__(self, container, ip, token):
        self.process = subprocess.Popen(["docker", "exec", "--interactive", "--user", "1000:1000",
            container, "python3", "-u", "-c", CLIENT, "persistent", ip, "19001", token],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.rows = queue.Queue(maxsize=8)
        def read():
            for line in self.process.stdout:
                self.rows.put(line)
            self.rows.put(None)
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        try:
            assert self.receive() == {"connected": True}
        except BaseException:
            self.close()
            raise

    def receive(self):
        line = self.rows.get(timeout=6)
        assert line and len(line) < 8192, "fixture stream ended without a response"
        return json.loads(line)

    def exchange(self):
        self.process.stdin.write('{"action":"exchange"}\n')
        self.process.stdin.flush()
        return self.receive()

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=4)
        self.reader.join(timeout=2)
        self.process.stdout.close()
        self.process.stderr.close()


class Contract:
    def __init__(self, args):
        self.args = args
        self.attempt = uuid.uuid4().hex
        self.bridge = "ghnp" + self.attempt[:11]
        self.table = "ghnp_" + self.attempt
        self.comment = "goldenhoop-network-prototype:" + self.attempt
        self.helper_name = "goldenhoop-network-" + self.attempt + "-helper"
        self.helper = None
        self.guest = None
        self.stream = None
        self.table_attempted = False
        self.output = Path(args.output)
        root = Path(__file__).resolve().parents[1]
        self.evidence = {"suite": "ipv4-routed-filter-prototype", "runtime": args.runtime,
            "scope": "fixture mechanism only; production policy/DNS/IPv6/L2/TLS and flow collection are not established",
            "timestamp": datetime.now(timezone.utc).isoformat(), "attempt": self.attempt,
            "result": "failed", "cleanup": "unknown", "cases": [], "resources": [], "observations": [],
            "source_files_sha256": {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in [Path(__file__).resolve(), root/"tests/network_samples.py", root/"tests/fixtures/network.Dockerfile"]}}
        self.save()

    def save(self):
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(json.dumps(self.evidence, indent=2) + "\n", encoding="utf-8")

    def labels(self, role):
        return ["--label", "dev.goldenhoop.test=network-contract", "--label",
                "dev.goldenhoop.attempt=" + self.attempt, "--label", "dev.goldenhoop.role=" + role]

    def owned(self, record):
        labels = record.get("Labels", record.get("Config", {}).get("Labels", {})) or {}
        assert labels.get("dev.goldenhoop.attempt") == self.attempt
        assert labels.get("dev.goldenhoop.test") == "network-contract"

    def container(self, role, options, script, *args):
        name = "goldenhoop-network-" + self.attempt + "-" + role
        identity = docker("create", "--name", name, *self.labels(role), "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--restart", "no",
            *options, "--entrypoint", "python3", self.args.image, "-u", "-c", script, *args).stdout.strip()
        observed = json.loads(docker("inspect", identity).stdout)[0]
        self.owned(observed)
        assert observed["Image"] == self.evidence["image_id"], (observed["Image"], self.evidence["image_id"])
        assert all(mount["Type"] == "tmpfs" for mount in observed.get("Mounts", []))
        host = observed["HostConfig"]
        guest = role == "guest"
        expected_memory = 1073741824 if guest else 134217728
        assert host["ReadonlyRootfs"] and host["Memory"] == host["MemorySwap"] == expected_memory
        assert host["NanoCpus"] == (1000000000 if guest else 250000000) and host["PidsLimit"] == (256 if guest else 32)
        assert {cap.removeprefix("CAP_") for cap in host["CapDrop"]} == {"ALL"}
        assert {cap.removeprefix("CAP_") for cap in (host["CapAdd"] or [])} == ({"NET_ADMIN"} if role == "helper" else set())
        assert any("no-new-privileges" in item for item in host["SecurityOpt"])
        assert host["Runtime"] == (self.args.runtime if guest else "runc")
        self.evidence["resources"].append({"role": role, "container_id": identity,
            "boundary": {key: observed["HostConfig"].get(key) for key in
                ("Runtime", "NetworkMode", "ReadonlyRootfs", "CapDrop", "CapAdd", "SecurityOpt", "Memory", "MemorySwap", "NanoCpus", "PidsLimit")}})
        self.save()
        docker("start", identity)
        return identity

    def ensure_helper(self):
        result = docker("inspect", self.helper_name, check=False)
        if result.returncode == 0:
            observed = json.loads(result.stdout)[0]
            self.owned(observed)
            self.helper = observed["Id"]
            if not observed["State"]["Running"]:
                docker("start", self.helper)
            return
        # A successful listing distinguishes absence from daemon failure.
        assert not docker("ps", "-a", "--filter", "name=^/" + self.helper_name + "$", "--format", "{{.ID}}").stdout.strip()
        self.helper = self.container("helper", ["--runtime", "runc", "--network", "host", "--user", "0:0",
            "--cap-add", "NET_ADMIN", "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.25",
            "--pids-limit", "32", "--tmpfs", "/run:rw,nosuid,nodev,noexec,size=8m,mode=0700"], HOST)

    def exec(self, container, program, *args, data=None, check=True):
        return docker("exec", "--interactive", container, program, *args, data=data, check=check)

    def network(self, role, *options):
        identity = docker("network", "create", *self.labels(role), *options,
                          "goldenhoop-network-" + self.attempt + "-" + role).stdout.strip()
        observed = json.loads(docker("network", "inspect", identity).stdout)[0]
        self.owned(observed)
        self.evidence["resources"].append({"role": role, "network_id": identity, "options": observed["Options"], "ipam": observed["IPAM"]})
        self.save()
        return identity, observed

    def tables(self):
        return json.loads(self.exec(self.helper, "nft", "--json", "list", "tables").stdout)["nftables"]

    def owned_table(self):
        result = self.exec(self.helper, "nft", "--json", "list", "table", "inet", self.table)
        entries = json.loads(result.stdout)["nftables"]
        table = next(entry["table"] for entry in entries if "table" in entry)
        assert table["family"] == "inet" and table["name"] == self.table
        if "comment" in table:
            assert table["comment"] == self.comment
            self.evidence["owner_marker_validation"] = "nft-json-table-comment"
        else:
            # nft 1.0.6 omits table userdata from its JSON representation, while
            # its native listing retains it. Check the exact table-level marker.
            text = self.exec(self.helper, "nft", "list", "table", "inet", self.table).stdout
            comments = [shlex.split(line.strip()) for line in text.splitlines() if line.startswith("\tcomment ")]
            assert comments == [["comment", self.comment]], comments
            self.evidence["owner_marker_validation"] = "nft-text-table-comment"
        return entries

    def apply(self, rules):
        self.table_attempted = True
        self.exec(self.helper, "nft", "--file", "-", data=rules)
        self.owned_table()
        self.evidence.setdefault("transactions", []).append(rules)
        self.save()

    def packets(self):
        return sum(expr["counter"]["packets"] for entry in self.owned_table() if "rule" in entry
            and entry["rule"]["chain"] == "egress" for expr in entry["rule"]["expr"] if "counter" in expr)

    def probe(self, container, mode, ip, port):
        assert str(ipaddress.IPv4Address(ip)) == ip
        result = json.loads(self.exec(container, "python3", "-c", CLIENT, mode, ip, str(port), self.attempt).stdout)
        self.evidence["observations"].append({"origin": "workload" if container == self.guest else "trusted-control",
            "transport": mode, "address": ip, "port": port, **result})
        return result["ok"]

    def control(self):
        for mode, port in [("tcp", 19001), ("tcp", 19003), ("udp", 19002)]:
            assert self.probe(self.helper, mode, self.target_ip, port), (mode, port)
        assert self.probe(self.helper, "tcp", self.gateway, self.host_port)

    def check(self, name):
        self.evidence["cases"].append(name)
        self.save()
        print("passed: " + name, flush=True)

    def run(self):
        failure = None
        try:
            image = json.loads(docker("image", "inspect", self.args.image).stdout)[0]
            assert image["Config"]["Labels"].get("dev.goldenhoop.fixture") == "network-interop"
            self.evidence["image_id"] = image["Id"]
            self.evidence["docker"] = json.loads(docker("version", "--format", "{{json .Server}}").stdout)
            self.ensure_helper()
            links = json.loads(self.exec(self.helper, "ip", "-json", "link", "show").stdout)
            assert not any(link["ifname"] == self.bridge for link in links)
            guest_network, observed = self.network("guest-net", "--opt", "com.docker.network.bridge.name=" + self.bridge,
                                                  "--opt", "com.docker.network.bridge.enable_ip_masquerade=false")
            assert observed["Options"]["com.docker.network.bridge.name"] == self.bridge
            self.gateway = next(config["Gateway"] for config in observed["IPAM"]["Config"] if ipaddress.ip_network(config["Subnet"]).version == 4)
            assert str(ipaddress.IPv4Address(self.gateway)) == self.gateway
            target_network, _ = self.network("target-net", "--opt", "com.docker.network.bridge.gateway_mode_ipv4=routed")
            target = self.container("target", ["--runtime", "runc", "--network", target_network, "--user", "1000:1000",
                "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.25", "--pids-limit", "32",
                "--publish", "127.0.0.1::19001/tcp", "--publish", "127.0.0.1::19003/tcp", "--publish", "127.0.0.1::19002/udp"], TARGET, self.attempt)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                lines = docker("logs", target).stdout.splitlines()
                if any(json.loads(line).get("ready") is True for line in lines):
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("owned target fixture did not become ready")
            observed = json.loads(docker("inspect", target).stdout)[0]
            bindings = observed["NetworkSettings"]["Ports"]
            self.evidence["target_port_bindings"] = bindings
            self.save()
            # Native routed mode uses no host ports. Docker Desktop can also
            # return loopback-only proxy bindings; application probes still use
            # the target IP directly and must hit the owned FORWARD counters.
            assert all(not item["HostPort"] or item["HostIp"] in ("127.0.0.1", "::1")
                       for values in bindings.values() for item in (values or [])), bindings
            self.target_ip = next(iter(observed["NetworkSettings"]["Networks"].values()))["IPAddress"]
            config = json.dumps({"gateway": self.gateway, "token": self.attempt})
            self.exec(self.helper, "python3", "-c", "import os,sys;from pathlib import Path;Path('/run/probe-config.tmp').write_text(sys.argv[1]);os.replace('/run/probe-config.tmp','/run/probe-config.json')", config)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                ready = self.exec(self.helper, "cat", "/run/probe-ready.json", check=False)
                if ready.returncode == 0:
                    self.host_port = json.loads(ready.stdout)["port"]
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("trusted fixture service did not start")
            self.control()
            assert not any(entry.get("table", {}).get("name") == self.table for entry in self.tables())
            self.apply(f'''add table inet {self.table} {{ comment "{self.comment}"; }}
add chain inet {self.table} input {{ type filter hook input priority -190; policy accept; }}
add rule inet {self.table} input iifname "{self.bridge}" counter drop
add chain inet {self.table} egress
add chain inet {self.table} forward {{ type filter hook forward priority -190; policy accept; }}
add rule inet {self.table} forward iifname "{self.bridge}" jump egress
add rule inet {self.table} egress counter drop
''')
            self.guest = self.container("guest", ["--runtime", self.args.runtime, "--network", guest_network,
                "--user", "1000:1000", "--memory", "1g", "--memory-swap", "1g", "--cpus", "1", "--pids-limit", "256"],
                "import time;time.sleep(3600)")
            identity = json.loads(self.exec(self.guest, "python3", "-c", IDENTITY).stdout)
            assert identity["uid"] == identity["gid"] == 1000
            assert set(identity["groups"]).issubset({1000})
            assert int(identity["credentials"]["CapEff"], 16) == 0 and identity["credentials"]["NoNewPrivs"] == "1"
            assert identity["nft_exit_code"] != 0
            self.evidence["workload_identity"] = identity
            before = self.packets()
            assert not self.probe(self.guest, "tcp", self.target_ip, 19001)
            assert not self.probe(self.guest, "udp", self.target_ip, 19002)
            assert self.packets() > before
            self.control()
            self.check("default_deny_is_installed_before_unprivileged_workload_start")
            self.apply(f'''flush chain inet {self.table} egress
add rule inet {self.table} egress ip daddr {self.target_ip} tcp dport 19001 counter accept
add rule inet {self.table} egress counter drop
''')
            assert self.probe(self.guest, "tcp", self.target_ip, 19001)
            assert not self.probe(self.guest, "tcp", self.target_ip, 19003)
            assert not self.probe(self.guest, "udp", self.target_ip, 19002)
            self.control()
            self.check("exact_routed_tcp_permission_does_not_grant_other_tcp_or_udp")
            assert not self.probe(self.guest, "tcp", self.gateway, self.host_port)
            self.control()
            self.check("host_input_is_denied_while_the_owned_host_service_is_live")
            self.stream = Stream(self.guest, self.target_ip, self.attempt)
            assert self.stream.exchange()["ok"]
            self.apply(f"flush chain inet {self.table} egress\nadd rule inet {self.table} egress counter drop\n")
            before = self.packets()
            denied = self.stream.exchange()
            assert not denied["ok"]
            assert self.packets() > before
            self.control()
            self.evidence["tightening"] = {"existing_flow_observation": denied, "new_drop_packets": self.packets() - before,
                "scope": "packet denial observed; conntrack/socket collection and production revision acknowledgement are not tested"}
            self.check("tightening_denies_packets_of_an_existing_connection")
            self.evidence["result"] = "passed"
        except BaseException as error:
            failure = error
            self.evidence["error"] = str(error)
        finally:
            try:
                self.cleanup()
                self.evidence["cleanup"] = "complete"
            except BaseException as error:
                failure = failure or error
                self.evidence["cleanup_error"] = str(error)
                self.evidence["result"] = "failed"
            self.save()
            print(json.dumps({key: self.evidence.get(key) for key in ("suite", "runtime", "result", "cleanup", "error", "cleanup_error")}))
        if failure:
            raise failure

    def cleanup(self):
        if self.stream:
            self.stream.close()
        owned = docker("ps", "--all", "--filter", "label=dev.goldenhoop.attempt=" + self.attempt,
                       "--format", "{{.ID}}").stdout.split()
        for identity in owned:
            observed = json.loads(docker("inspect", identity).stdout)[0]
            self.owned(observed)
            if observed["Name"] != "/" + self.helper_name:
                docker("rm", "--force", "--volumes", identity)
        if self.table_attempted:
            self.ensure_helper()
            if any(entry.get("table", {}).get("name") == self.table for entry in self.tables()):
                self.owned_table()
                self.exec(self.helper, "nft", "delete", "table", "inet", self.table)
            assert not any(entry.get("table", {}).get("name") == self.table for entry in self.tables())
            self.evidence["owned_filter_table_absent"] = True
        remaining = docker("ps", "-a", "--filter", "label=dev.goldenhoop.attempt=" + self.attempt,
                           "--format", "{{.ID}}").stdout.split()
        for identity in remaining:
            self.owned(json.loads(docker("inspect", identity).stdout)[0])
            docker("rm", "--force", "--volumes", identity)
        networks = docker("network", "ls", "--filter", "label=dev.goldenhoop.attempt=" + self.attempt,
                          "--format", "{{.ID}}").stdout.split()
        for identity in networks:
            self.owned(json.loads(docker("network", "inspect", identity).stdout)[0])
            docker("network", "rm", identity)
        assert not docker("ps", "-a", "--filter", "label=dev.goldenhoop.attempt=" + self.attempt, "--format", "{{.ID}}").stdout.strip()
        assert not docker("network", "ls", "--filter", "label=dev.goldenhoop.attempt=" + self.attempt, "--format", "{{.ID}}").stdout.strip()
        self.evidence["cases"].append("owned_filter_table_networks_and_containers_confirmed_absent")
        if self.args.remove_image and self.evidence.get("image_id"):
            assert not docker("ps", "-a", "--filter", "ancestor=" + self.args.image, "--format", "{{.ID}}").stdout.strip()
            image = json.loads(docker("image", "inspect", self.args.image).stdout)[0]
            assert image["Id"] == self.evidence["image_id"] and image["Config"]["Labels"].get("dev.goldenhoop.fixture") == "network-interop"
            docker("image", "rm", "--no-prune", self.args.image)
            assert not docker("image", "ls", "--filter", "reference=" + self.args.image, "--format", "{{.ID}}").stdout.strip()
            self.evidence["image_removed"] = True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="goldenhoop-network-fixture:test")
    parser.add_argument("--runtime", choices=["runc", "runsc"], default="runc")
    parser.add_argument("--output", required=True)
    parser.add_argument("--remove-image", action="store_true")
    Contract(parser.parse_args()).run()
