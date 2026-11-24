# Native code-language adapters

GoldenHoop launches existing language kernels as workload dependencies. The Rust agent owns credentials, private IPC, lifecycle, queues, output bounds and process collection. The platform does not run an interpreter on the host. Current acceptance status and evidence are recorded in [progress](progress.md) and [reference coverage](reference-coverage.md); an adapter or enum declaration alone does not establish a verified runtime capability.

## Image contract

Python keeps its established literal `python3 -I -m ipykernel_launcher -f {connection_file}` launcher. Other languages use these fixed system kernelspec names:

| Language | Kernelspec directory | Interoperability fixture dependency | Fixture socket naming |
| --- | --- | --- | --- |
| Python | Built-in launch path | Debian IPyKernel | Dash |
| Java | `java` | IJava 1.3.0, Java 17, pinned upstream JeroMQ native-IPC build | Colon |
| Go | `gophernotes` | Gophernotes 0.7.6, Go 1.25.14, C compiler for dynamic imports | Colon |
| TypeScript | `tslab` | TSLab 1.0.19, Node 24.22.3 | Colon |
| Bash | `bash` | bash_kernel 0.10.0, filetype 1.2.0 | Dash |
| JavaScript | `jslab` | TSLab 1.0.19, Node 24.22.3 | Colon |

These versions describe the disposable fixture, not universal compatibility with every version or every language package. Additional imports require compatible dependencies in the chosen workload image and remain subject to its memory, task, filesystem and network limits. The image must already be cached; provisioning and probing never pull a replacement image or select a different language.

The agent searches `/usr/local/share/jupyter/kernels` followed by `/usr/share/jupyter/kernels`. It does not consult HOME, workspace kernelspecs, inherited JUPYTER_PATH or caller-selected executable paths. System roots cannot redirect to another tree; a kernel directory cannot escape its root, and the final kernelspec cannot be a symlink or nonregular file. Reads are bounded to 64 KiB and do not block opening a FIFO.

Specs contain 1-64 literal argv entries, at most 4096 bytes each, with exactly one `{connection_file}` occurrence. `{resource_dir}` expands to the resolved system kernel directory. Executables are absolute guest paths or basenames resolved against the fixed guest PATH. No shell or host-environment expansion occurs. The optional environment map is bounded to 32 string entries; private HOME, TMPDIR and Jupyter directories, PATH, USER and LANG are enforced after clearing inherited environment. The child drops supplementary groups, GID and UID before executing the image's program.

The 256-MiB temporary tmpfs permits compiled-code loading and remains charged to the sandbox's hard memory limit. It retains nosuid/nodev; the root stays read-only, and execution still uses the dropped workload identity. Compiler scratch and HOME caches stay under the generated private context tree and are removed before releasing its UID. This bound is separate from the 128-MiB workspace and does not provide additional memory or swap. Actual mount observations are necessary: the original implicit noexec mount blocked Go plugin loading even after compilation succeeded. Docker documents [exec/noexec and tmpfs memory accounting](https://docs.docker.com/engine/storage/tmpfs/).

For example, a compatible TSLab image can install:

```json
{
  "language": "typescript",
  "argv": ["node", "--experimental-vm-modules", "/opt/tslab/bin/tslab", "kernel", "--config-path", "{connection_file}"],
  "metadata": {"goldenhoop": {"ipc_path_style": "colon"}}
}
```

`ipc_path_style` accepts `dash` (the default) or `colon`. Both conventions name Unix sockets under the generated private context directory. The agent still supplies `transport=ipc`, fixed channel assignments and a fresh HMAC key. TCP and automatic transport fallback are not supported. Peer UID, bounded ZMTP framing, JSON HMAC, message identity/session and language-info checks apply to every language.

## Actual capability gate

Workers leave CodeContexts and `code_languages` empty unless configured with an explicit cached `--kernel-probe-image`. An optional reprobe withdraws previous language observations before doing work. Each of the six candidates gets its own fresh sandbox, a 60-second TTL and a 45-second probe deadline. The probe checks actual UID/group/capability observations, retained state, an idempotent side effect, output, explicit success/error replies and context collection. It then confirms whole-sandbox removal.

A failed candidate grants no language. An uncertain cleanup aborts the entire optional probe, including other successful candidates. Only after all candidate sandboxes are collected does an Available profile gain CodeContexts and its successful language set. New context/run requests and worker dispatch require that specific language as well as the capability. A positive fixture observation does not guarantee another workload image has the same dependency; missing or mismatched system specs fail before native context allocation.

Public-fixture tests can explicitly enable `GOLDENHOOP_TEST_BACKEND_DIAGNOSTICS=1` to retain per-language phase, elapsed time, failure and collection observations. Failed fixed-source runs additionally retain bounded kernel records/events. This switch is for administrator-selected public test images: normal worker runs do not print kernel data. The API contract fingerprints source, binaries and images before execution, including attempts that later fail, and retains these opt-in observations across worker restarts.

Each context retains its own interpreter state but shares its sandbox workspace and resource budget. Four agent-assigned UIDs scope collection and protect private connection material. These contexts are not separate sandboxes; use [isolated child sandboxes](isolated-sessions.md) for a separate runtime boundary.

## Kernel interoperability details

The [Jupyter messaging specification](https://jupyter-client.readthedocs.io/en/stable/messaging.html) defines current replies. Existing 5.0-5.3 kernels can omit the status field in kernel-info metadata. GoldenHoop has a limited compatibility rule for that omission: an explicit error/null/unknown status is refused, as is omission in 5.4/5.5. Authenticated matching shell info and matching output idle are both still required. This rule never applies to execute replies or code completion. EOF, process launch and a missing execution status cannot establish success.

Old Java base-kernel 2.3.0 [publishes startup with no message context](https://github.com/SpencerPark/jupyter-jvm-basekernel/blob/v2.3.0/src/main/java/io/github/spencerpark/jupyter/channels/JupyterConnection.java#L46). Its [header constructor](https://github.com/SpencerPark/jupyter-jvm-basekernel/blob/v2.3.0/src/main/java/io/github/spencerpark/jupyter/messages/Header.java#L40) consequently has no session. A fast subscription can observe that broadcast before kernel-info; the later S3 CLI startup failure is consistent with this race. During the initial output handshake only, GoldenHoop can discard up to eight authenticated protocol-5.3 status/starting notices with an absent/null session, kernel username, valid message ID, empty parent/metadata, exact starting content and no buffers. A discarded notice establishes neither epoch nor readiness. Shell traffic, other states/protocols/envelopes and every observation after readiness still use strict session validation. Independent signed vectors and a real Unix/ZMTP test server enforce these distinctions, including the flood bound and the requirement for matching shell-info plus output-idle. No code request is resent.

The fixture uses [IJava](https://github.com/SpencerPark/IJava/releases/tag/v1.3.0) with the checksum-pinned [JeroMQ native-IPC source](https://github.com/zeromq/jeromq/tree/3908fe3dabcba4d3de98ed0a6b85553690a1e006). Older released JeroMQ implementations emulate IPC with TCP and cannot satisfy this transport boundary. The new jar precedes IJava's bundled implementation on its guest classpath. The source and archive checksums are in the [fixture recipe](../images/languages/Dockerfile).

[Gophernotes](https://github.com/gopherdata/gophernotes/tree/900c58c5edf8e30c5a0aa4946b13aa914215d36c) and its interpreter/importer must use a compatible Go toolchain. The initial Go 1.27 fixture exposed an unsupported export-data format; the Go 1.25 fixture requires Cgo for dynamic imports. These are workload dependency failures and are reported as such. The inspected interpreter can also warn and skip generic bindings; those warnings remain in the collected output. Language support does not add features missing from the underlying interpreter. [TSLab](https://github.com/yunabe/tslab/tree/fd1b34c12b52882805c6287328dd7969136f8841) is installed globally so its bundled fallback type-root lookup can find the nested Node type definitions. Expression display behavior is kernel-specific: TSLab can emit a final expression on stdout, so printing and returning the same expression produces two observations.

Context UIDs need not have passwd entries. The inspected old Java UnixSystem helper returned default identity fields while `/proc/self/status` showed UID 20000, GID 1000, empty supplementary groups, zero effective capabilities and no-new-privileges. The identity probe therefore checks actual proc credentials. The [diagnostic](evidence/m2-java-identity-diagnostic-runc-windows-docker.json) preserves both observations.

## Clients and acceptance

Rust uses `CodeContextSpec { language: CodeLanguage::Go, ..Default::default() }`; Python sync/async use `CodeContextSpec(language="go")`; CLI uses `goldenhoop context-create SANDBOX --language go`. Source submission and results retain the existing context/run API and lifecycle. Kernel failure, uncertainty, cancellation and timeout remain distinct from OS command exit.

The native language contract runs state/replay/error, cancellation and deadline groups for each language. Cancellation/deadline cases create a forked setsid descendant and queued work, then require scoped collection and private-file absence. Tests use one CPU, 1 GiB with no additional swap, 256 tasks, no network and a read-only root. Every fixture attempt has an ownership ID and confirms container absence in its finally path.

The full public regression additionally retains mixed-language contexts across real API/worker restarts. Rust, Python sync/async and CLI each exercise every advertised language. Separate runc, gVisor and S3-backed CI gates are required; local runc results do not substitute for those profiles.
