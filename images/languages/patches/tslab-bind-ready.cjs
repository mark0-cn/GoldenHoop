// Build-time adaptation of the Apache-2.0 TSLab workload dependency.
// Its original LICENSE remains in the installed package.
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const manifest = require("./tslab-1.0.19-bind-ready.json");

const root = fs.realpathSync(process.argv[2]);
assert.equal(JSON.parse(fs.readFileSync(path.join(root, "package.json"))).version, manifest.version);
const target = path.join(root, manifest.target);
assert(fs.lstatSync(target).isFile() && !fs.lstatSync(target).isSymbolicLink());
const input = fs.readFileSync(target);
const digest = data => crypto.createHash("sha256").update(data).digest("hex");
const metadata = path.join(root, "GoldenHoop-PATCH.json");
const expected = JSON.stringify(manifest, null, 2) + "\n";
if (fs.existsSync(metadata)) {
  assert(fs.lstatSync(metadata).isFile() && !fs.lstatSync(metadata).isSymbolicLink());
  assert.equal(fs.readFileSync(metadata, "utf8"), expected);
}
const initial = digest(input);
let status = "already_patched";
if (initial !== manifest.patched_sha256) {
  assert.equal(initial, manifest.upstream_sha256, "unexpected published TSLab source; refusing to patch");
  const binding = [
    "        await Promise.all([",
    "            this.bindSocket(this.iopub, cinfo.iopub_port),",
    "            this.bindSocket(this.shell, cinfo.shell_port),",
    "            this.bindSocket(this.control, cinfo.control_port),",
    "            this.bindSocket(this.stdin, cinfo.stdin_port),",
    "            this.bindSocket(this.hb, cinfo.hb_port),",
    "        ]);",
    "",
  ].join("\n");
  const marker = "        this.hb = new zmq.Reply();\n";
  const source = input.toString("utf8");
  assert.equal(source.split(binding).length, 2);
  assert.equal(source.split(marker).length, 2);
  const notice = "        // GoldenHoop: complete all TSLab 1.0.19 socket binds before starting readers.\n";
  const output = source.replace(binding, "").replace(marker, marker + notice + binding);
  assert.equal(digest(output), manifest.patched_sha256, "patched source differs from the reviewed result");
  fs.writeFileSync(target, output);
  status = "patched";
}
assert.equal(digest(fs.readFileSync(target)), manifest.patched_sha256);
if (!fs.existsSync(metadata)) {
  fs.writeFileSync(metadata, expected, { flag: "wx", mode: 0o644 });
}
console.log(JSON.stringify({ status, version: manifest.version, sha256: manifest.patched_sha256 }));
