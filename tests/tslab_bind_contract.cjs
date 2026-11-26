// Deterministic tests of the published ZmqServer with deferred model sockets.
// These establish initialization order, not native kernel or runtime readiness.
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync(process.argv[2], "utf8");
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const state = { sockets: [], reads: [], binds: [], handled: 0 };
  let routers = 0;
  class Socket {
    constructor(role) {
      this.role = role;
      this.pending = [];
      this.closed = false;
      state.sockets.push(this);
    }
    bind() {
      state.binds.push(this.role);
      return new Promise((resolve, reject) => {
        this.resolve = resolve;
        this.reject = reject;
      });
    }
    [Symbol.asyncIterator]() {
      state.reads.push({ role: this.role, bound: state.sockets.every(s => s.bound) });
      return this;
    }
    next() {
      if (this.closed) return Promise.resolve({ done: true });
      return new Promise(resolve => this.pending.push(resolve));
    }
    close() {
      this.closed = true;
      for (const resolve of this.pending.splice(0)) resolve({ done: true });
    }
    finish() {
      this.bound = true;
      this.resolve();
    }
  }
  const zmq = {
    Publisher: class extends Socket { constructor() { super("iopub"); } },
    Router: class extends Socket { constructor() { super(["shell", "control", "stdin"][routers++]); } },
    Reply: class extends Socket { constructor() { super("hb"); } },
  };
  const config = { transport: "ipc", ip: "/owned-model", iopub_port: 1, shell_port: 2, control_port: 3, stdin_port: 4, hb_port: 5, key: "model-only" };
  const exports = {};
  const allowed = {
    crypto,
    fs: { readFileSync: () => JSON.stringify(config) },
    util: require("node:util"),
    "./converter": {},
    "./inspect": {},
    "./util": {},
    zeromq: zmq,
  };
  const context = {
    exports,
    Buffer,
    console,
    require: name => {
      assert(Object.hasOwn(allowed, name), `unexpected dependency: ${name}`);
      return allowed[name];
    },
  };
  new vm.Script(source, { filename: "published-tslab-jupyter.js" }).runInNewContext(context);
  const server = new exports.ZmqServer({ close() {}, handleKernel() { state.handled++; } }, "model-config");
  const initialized = server.init();
  initialized.catch(() => {});
  return { state, server, initialized };
}
async function cleanup(f) {
  for (const socket of f.state.sockets) socket.finish();
  f.server.close();
  await f.initialized.catch(() => {});
  await tick();
}
const cases = [
  ["all_five_binds_finish_before_any_receive_loop", async () => {
    const f = fixture();
    try {
      await tick();
      assert.equal(f.state.binds.length, 5);
      assert.equal(f.state.reads.length, 0, "receive loops started while binds were pending");
      for (const socket of f.state.sockets.slice(0, 4)) socket.finish();
      await tick();
      assert.equal(f.state.reads.length, 0, "receive loops started before the final bind");
      f.state.sockets[4].finish();
      await f.initialized;
      assert.deepEqual(f.state.reads.map(r => r.role), ["shell", "control", "hb"]);
      assert(f.state.reads.every(r => r.bound));
      assert.equal(f.state.handled, 0);
    } finally { await cleanup(f); }
  }],
  ["failed_bind_rejects_initialization_without_starting_readers", async () => {
    const f = fixture();
    try {
      await tick();
      assert.equal(f.state.binds.length, 5);
      f.state.sockets[2].reject(new Error("owned-model-bind-failure"));
      await assert.rejects(f.initialized, /owned-model-bind-failure/);
      assert.equal(f.state.reads.length, 0, "readers started despite a failed bind");
      assert.equal(f.state.handled, 0);
    } finally { await cleanup(f); }
  }],
];
(async () => {
  const results = [];
  for (const [name, test] of cases) {
    try { await test(); results.push({ name, result: "passed" }); }
    catch (error) { results.push({ name, result: "failed", error: String(error) }); }
  }
  const result = results.every(r => r.result === "passed") ? "passed" : "failed";
  console.log(JSON.stringify({ result, scope: "Deferred socket model of actual published code; no native readiness claim", source_sha256: crypto.createHash("sha256").update(source).digest("hex"), node: process.version, cases: results }));
  process.exitCode = result === "passed" ? 0 : 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
