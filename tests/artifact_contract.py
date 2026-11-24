"""Actual S3-compatible RustFS fixture, scoped to one fresh test installation."""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

IMAGE = "rustfs/rustfs@sha256:ee717072290bec9b11abfc0365f8310b00df1cd9b3639943edae47bdef05044a"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", timeout=45)
    if result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


class Contract:
    def __init__(self, args):
        self.args = args
        self.installation = str(uuid.uuid4())
        self.name = "goldenhoop-artifacts-" + self.installation
        self.access, self.secret = secrets.token_hex(12), secrets.token_urlsafe(32)
        self.bucket = "goldenhoop-" + uuid.uuid4().hex
        self.container = self.endpoint = self.image_id = None
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.volumes = []
        self.image_removed = None

    def admin(self, method, key="", query=None, data=b""):
        """Fixture-only SigV4 admin: create/list/delete this fresh bucket."""
        parsed = urllib.parse.urlsplit(self.endpoint)
        path = "/" + self.bucket + ("/" + urllib.parse.quote(key, safe="/") if key else "")
        query = urllib.parse.urlencode(sorted((query or {}).items()), quote_via=urllib.parse.quote)
        now = datetime.now(timezone.utc)
        date, stamp = now.strftime("%Y%m%d"), now.strftime("%Y%m%dT%H%M%SZ")
        payload = hashlib.sha256(data).hexdigest()
        canonical_headers = f"host:{parsed.netloc}\nx-amz-content-sha256:{payload}\nx-amz-date:{stamp}\n"
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical = "\n".join((method, path, query, canonical_headers, signed_headers, payload))
        scope = date + "/us-east-1/s3/aws4_request"
        to_sign = "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hashlib.sha256(canonical.encode()).hexdigest()
        signing_key = ("AWS4" + self.secret).encode()
        for value in (date, "us-east-1", "s3", "aws4_request"):
            signing_key = hmac.new(signing_key, value.encode(), hashlib.sha256).digest()
        signature = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
        headers = {"x-amz-date": stamp, "x-amz-content-sha256": payload,
                   "authorization": f"AWS4-HMAC-SHA256 Credential={self.access}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"}
        request = urllib.request.Request(self.endpoint + path + ("?" + query if query else ""),
                                         method=method, headers=headers, data=data if method == "PUT" else None)
        with self.client.open(request, timeout=20) as response:
            return response.read(1024 * 1024)

    def start(self):
        self.image_id = docker("image", "inspect", IMAGE, "--format", "{{.Id}}")
        environment = dict(os.environ, RUSTFS_ACCESS_KEY=self.access, RUSTFS_SECRET_KEY=self.secret)
        command = ["docker", "run", "--detach", "--name", self.name,
                   "--label", "dev.goldenhoop.test=artifact-contract",
                   "--label", f"dev.goldenhoop.installation={self.installation}",
                   "--label", "dev.goldenhoop.role=artifact-backend",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                   "--memory", "1g", "--cpus", "2", "--pids-limit", "256", "--read-only",
                   "--publish", "127.0.0.1::9000",
                   "--tmpfs", "/data:rw,nosuid,nodev,size=256m,uid=10001,gid=10001",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m,uid=10001,gid=10001",
                   "--tmpfs", "/logs:rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10001",
                   "--env", "RUSTFS_ACCESS_KEY", "--env", "RUSTFS_SECRET_KEY",
                   "--env", "RUSTFS_CONSOLE_ENABLE=false", "--env", "RUSTFS_OBS_LOG_DIRECTORY=/logs",
                   "--env", "RUSTFS_OBS_LOGGER_LEVEL=error", IMAGE, "/data"]
        self.container = subprocess.run(command, env=environment, capture_output=True, text=True, check=True, timeout=30).stdout.strip()
        mounts = json.loads(docker("inspect", "--format", "{{json .Mounts}}", self.container))
        self.volumes = [mount["Name"] for mount in mounts if mount["Type"] == "volume"]
        port = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Ports}}", self.container))["9000/tcp"][0]
        assert port["HostIp"] == "127.0.0.1"
        self.endpoint = "http://127.0.0.1:" + port["HostPort"]
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                with self.client.open(self.endpoint + "/health", timeout=1) as response:
                    if response.status == 200:
                        self.admin("PUT")
                        return
            except (OSError, urllib.error.HTTPError):
                pass
            if docker("inspect", "--format", "{{.State.Running}}", self.container) != "true":
                raise RuntimeError("S3 fixture stopped during startup")
            time.sleep(0.1)
        raise RuntimeError("S3 fixture did not become ready")

    def cleanup(self):
        if self.container is None:
            found = docker("ps", "-a", "--no-trunc", "--filter", f"name=^{self.name}$", "--format", "{{.ID}}")
            self.container = found or None
        if self.container:
            labels = json.loads(docker("inspect", "--format", "{{json .Config.Labels}}", self.container))
            assert labels["dev.goldenhoop.installation"] == self.installation
            assert labels["dev.goldenhoop.test"] == "artifact-contract"
            docker("rm", "-f", "-v", self.container)
        assert not docker("ps", "-a", "--filter", f"label=dev.goldenhoop.installation={self.installation}", "--format", "{{.ID}}")
        remaining_volumes = set(docker("volume", "ls", "--format", "{{.Name}}").splitlines())
        assert not remaining_volumes.intersection(self.volumes)
        if self.args.remove_image and self.image_id:
            assert not docker("ps", "-a", "--filter", f"ancestor={self.image_id}", "--format", "{{.ID}}")
            docker("image", "rm", self.image_id)
            self.image_removed = self.image_id not in docker("image", "ls", "--no-trunc", "--quiet").splitlines()
            assert self.image_removed

    def run(self):
        evidence = {"suite": "artifact-backend-fixture", "result": "failed", "cleanup": "unknown",
                    "timestamp": datetime.now(timezone.utc).isoformat(), "image": IMAGE, "installation_id": self.installation}
        failure = None
        try:
            self.start()
            environment = dict(os.environ, GOLDENHOOP_ARTIFACT_ENDPOINT=self.endpoint,
                               GOLDENHOOP_ARTIFACT_BUCKET=self.bucket, GOLDENHOOP_ARTIFACT_ACCESS_KEY=self.access,
                               GOLDENHOOP_ARTIFACT_SECRET_KEY=self.secret, GOLDENHOOP_ARTIFACT_INSTALLATION=self.installation)
            result = subprocess.run([str(Path(self.args.binary).resolve())], capture_output=True, text=True, encoding="utf-8", env=environment, timeout=120,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
            evidence["contract"] = json.loads(result.stdout)
            listed = ET.fromstring(self.admin("GET", query={"list-type": "2", "max-keys": "100"}))
            keys = [element.text for element in listed.iter() if element.tag.endswith("}Key") or element.tag == "Key"]
            assert not keys, keys
            evidence["remaining_bucket_objects"] = keys
            self.admin("DELETE")
            evidence["result"] = "passed"
        except BaseException as error:
            failure = error
            evidence["error"] = str(error).replace(self.access, "[redacted]").replace(self.secret, "[redacted]")
            if self.container:
                logs = subprocess.run(["docker", "logs", "--tail", "40", self.container], capture_output=True, text=True, encoding="utf-8", timeout=10)
                evidence["backend_logs"] = (logs.stdout + logs.stderr).replace(self.access, "[redacted]").replace(self.secret, "[redacted]")
        finally:
            try:
                self.cleanup()
                evidence["cleanup"] = "complete"
            except BaseException as error:
                evidence["cleanup_error"] = str(error)
                evidence["result"] = "failed"
                failure = failure or error
            root = Path(__file__).resolve().parents[1]
            paths = [root / "Cargo.toml", root / "Cargo.lock", Path(__file__).resolve()]
            paths.extend((root / "crates" / "artifacts").rglob("*.rs"))
            paths.append(root / "crates" / "artifacts" / "Cargo.toml")
            evidence["source_files_sha256"] = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
            evidence["image_id"] = self.image_id
            evidence["fixture_volumes"] = self.volumes
            evidence["image_removed"] = self.image_removed
            evidence["binary_sha256"] = hashlib.sha256(Path(self.args.binary).read_bytes()).hexdigest()
            rendered = json.dumps(evidence, indent=2)
            print(rendered)
            if self.args.output:
                Path(self.args.output).parent.mkdir(parents=True, exist_ok=True)
                Path(self.args.output).write_text(rendered + "\n", encoding="utf-8")
        if failure:
            raise RuntimeError("artifact contract failed; see redacted evidence") from None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output")
    parser.add_argument("--remove-image", action="store_true", help="only when this task pulled this image for the fixture")
    Contract(parser.parse_args()).run()
