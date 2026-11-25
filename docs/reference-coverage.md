# Reference coverage and remaining acceptance

GoldenHoop keeps the complete M0-M6 target. The independent APIs do not promise upstream SDK compatibility. Reference comparisons use the inspected OpenSandbox revision 8af823ed83f71209772d334df73626f90dd72496; a declaration or test fixture is not proof that a runtime works.

## Stateful code languages

The pinned reference [SupportedLanguage declaration](https://github.com/opensandbox-group/OpenSandbox/blob/8af823ed83f71209772d334df73626f90dd72496/sdks/code-interpreter/python/src/code_interpreter/models/code.py#L26) names six languages. GoldenHoop implements and verifies native stateful adapters for all six. Java startup fix e96da9f passes the complete [runc API gate](evidence/ci-45459741064/agent-runc/api-runc.json), [gVisor API gate](evidence/ci-45459741064/agent-runsc/api-runsc.json) and [S3-compatible API gate](evidence/ci-45459740159/api-s3/api-s3.json), with 28, 28 and 31 groups respectively. All four clients complete every language. Fresh profiles require CodeContexts plus an explicitly probed `code_languages` entry; missing/legacy entries grant no language. A command launching an interpreter is not evidence of a stateful context.

| Language | Current GoldenHoop evidence | Remaining work |
| --- | --- | --- |
| Python | Actual private/public contexts, state/replay/cancellation/recovery, child kernel and four clients on runc/gVisor; S3-backed API also passes | Preserve these gates |
| Java | Native lifecycle, driver probe, full runc/gVisor APIs and all four clients; complete S3 API gate | Preserve these gates |
| Go | Native lifecycle, driver probe, full runc/gVisor APIs and all four clients; complete S3 API gate | Preserve these gates; underlying interpreter feature limits remain explicit |
| TypeScript | Native lifecycle, driver probe, full runc/gVisor APIs and all four clients; complete S3 API gate | Preserve these gates |
| Bash | Separate Bash kernel, full runc/gVisor APIs and all four clients; complete S3 API gate | Preserve these gates |
| JavaScript | Native lifecycle, driver probe, full runc/gVisor APIs and all four clients; complete S3 API gate | Preserve these gates |

Language support must be explicit per verified image/profile. Missing dependencies or unavailable transport must not launch another language. Retain bounded decoding, authenticated messages, private connection material, separate interpreter identities, no uncertain resend, explicit kernel completion and confirmed collection. Supporting another kernel must not silently remove those boundaries. Actual language fixtures remain disposable workload dependencies; production platform code remains Rust.

## Remaining platform milestones

The isolated-child increment is verified through the full public/client contracts on runc, gVisor and the tested S3-compatible backend. All six native adapters and the complete M2 gates pass at e96da9f. At 2227e69, both 15-group trusted staged worker contracts pass actual protected DNS/policy application, finite lease renewal, tightening, pause/resume and crash recovery, alongside every retained packet gate. The [public policy and protected-creation implementation](network-policy.md) adds durable own-policy, ancestor lineage, dispatch settlement and actual environment probes. Supported-host public acceptance remains required. Without administrator configuration NetworkPolicy stays disabled; configured support requires actual probe application and confirmed collection. SecretInjection remains unadvertised.

M3 still requires acceptance of the new public provisioning/probe and five-level network paths, credentials bound to destination/method/path, scoped/revocable API keys and durable redacted audit. Staged worker or local unsupported-kernel acceptance does not establish public operation on a supported host or credentials. M4 still requires a real Firecracker/jailer/KVM path and disk/memory snapshot/restore evidence. M5 still requires the Rust Kubernetes/operator/PostgreSQL/placement/pool/batch/volume path and an actual cluster. M6 requires installation/upgrades, benchmarks, the complete capability matrix and a requirement-by-requirement release audit. Unimplemented capabilities and skipped hardware tests remain unverified.
