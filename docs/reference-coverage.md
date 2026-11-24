# Reference coverage and remaining acceptance

GoldenHoop keeps the complete M0-M6 target. The independent APIs do not promise upstream SDK compatibility. Reference comparisons use the inspected OpenSandbox revision 8af823ed83f71209772d334df73626f90dd72496; a declaration or test fixture is not proof that a runtime works.

## Stateful code languages

The pinned reference [SupportedLanguage declaration](https://github.com/opensandbox-group/OpenSandbox/blob/8af823ed83f71209772d334df73626f90dd72496/sdks/code-interpreter/python/src/code_interpreter/models/code.py#L26) names six languages. Its [example](https://github.com/opensandbox-group/OpenSandbox/blob/8af823ed83f71209772d334df73626f90dd72496/examples/code-interpreter/main.py) uses language-specific contexts. GoldenHoop's current CodeLanguage/API implements Python only. Remaining adapters are part of M2 acceptance and must not be counted as implemented because a command can launch the corresponding interpreter.

| Language | Current GoldenHoop evidence | Remaining work |
| --- | --- | --- |
| Python | Actual private/public contexts, state/replay/cancellation/recovery, child kernel and four clients on runc/gVisor; S3-backed API also passes | Preserve these gates |
| Java | Not implemented or advertised | Native adapter, installed workload dependency and actual retained-state/error/collection tests |
| Go | Not implemented or advertised | Native adapter, installed workload dependency and actual retained-state/error/collection tests |
| TypeScript | Not implemented or advertised | Native adapter, installed workload dependency and actual retained-state/error/collection tests |
| Bash | Persistent shell/PTY is verified; a Bash code context is not implemented | Separate code-context adapter and actual kernel protocol tests |
| JavaScript | Not implemented or advertised | Native adapter, installed workload dependency and actual retained-state/error/collection tests |

Language support must be explicit per verified image/profile. Missing dependencies or unavailable transport must not launch another language. Retain bounded decoding, authenticated messages, private connection material, separate interpreter identities, no uncertain resend, explicit kernel completion and confirmed collection. Supporting another kernel must not silently remove those boundaries. Actual language fixtures remain disposable workload dependencies; production platform code remains Rust.

## Remaining platform milestones

The isolated-child increment is verified through the full public/client contracts on runc, gVisor and the tested S3-compatible backend. M2 remains in progress while language coverage above is incomplete.

M3 still requires actual dynamic egress enforcement, credentials bound to destination/method/path, scoped/revocable API keys and durable redacted audit. Default-deny isolation alone does not establish these features. M4 still requires a real Firecracker/jailer/KVM path and disk/memory snapshot/restore evidence. M5 still requires the Rust Kubernetes/operator/PostgreSQL/placement/pool/batch/volume path and an actual cluster. M6 requires installation/upgrades, benchmarks, the complete capability matrix and a requirement-by-requirement release audit. Unimplemented capabilities and skipped hardware tests remain unverified.
