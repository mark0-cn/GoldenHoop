# Reference coverage and remaining acceptance

GoldenHoop keeps the complete M0-M6 target. The independent APIs do not promise upstream SDK compatibility. Reference comparisons use the inspected OpenSandbox revision 8af823ed83f71209772d334df73626f90dd72496; a declaration or test fixture is not proof that a runtime works.

## Stateful code languages

The pinned reference [SupportedLanguage declaration](https://github.com/opensandbox-group/OpenSandbox/blob/8af823ed83f71209772d334df73626f90dd72496/sdks/code-interpreter/python/src/code_interpreter/models/code.py#L26) names six languages. Its [example](https://github.com/opensandbox-group/OpenSandbox/blob/8af823ed83f71209772d334df73626f90dd72496/examples/code-interpreter/main.py) uses language-specific contexts. GoldenHoop now has native adapters for all six. The [18-group native gate](evidence/m2-six-language-agent-runc-windows-docker.json), [six-language driver probe](evidence/m2-six-language-probe-runc-windows-docker.json) and [all four client bindings](evidence/m2-six-language-clients-runc-windows-docker.json) pass locally on runc. The [initial public run](evidence/m2-six-language-api-clients-initial-runc-windows-docker.json) completed 27 API groups, including mixed-language service recovery, before its test-helper failure; the suite remains recorded as failed. The full 28-group runc/gVisor gates pass at diagnostic commit 5bf9ed3, and the Java startup fix e96da9f passes the complete 31-group local S3/API/client gate. Expanded runtime/S3 CI of that fix remains separate acceptance work. Fresh profiles require CodeContexts plus an explicitly probed `code_languages` entry; missing/legacy entries grant no language. A command launching an interpreter is not evidence of a stateful context.

| Language | Current GoldenHoop evidence | Remaining work |
| --- | --- | --- |
| Python | Actual private/public contexts, state/replay/cancellation/recovery, child kernel and four clients on runc/gVisor; S3-backed API also passes | Preserve these gates |
| Java | Native lifecycle, driver probe, full runc/gVisor APIs and all four clients; complete local S3 gate | Preserve the full runtime/client gates; current Java-startup-fix CI pending |
| Go | Native lifecycle, driver probe, full runc/gVisor APIs and all four clients; complete local S3 gate | Preserve the full runtime/client gates; current Java-startup-fix CI pending; underlying interpreter feature limits remain explicit |
| TypeScript | Native lifecycle, driver probe, full runc/gVisor APIs and all four clients; complete local S3 gate | Preserve the full runtime/client gates; current Java-startup-fix CI pending |
| Bash | Separate Bash kernel, full runc/gVisor APIs and all four clients; complete local S3 gate | Preserve the full runtime/client gates; current Java-startup-fix CI pending |
| JavaScript | Native lifecycle, driver probe, full runc/gVisor APIs and all four clients; complete local S3 gate | Preserve the full runtime/client gates; current Java-startup-fix CI pending |

Language support must be explicit per verified image/profile. Missing dependencies or unavailable transport must not launch another language. Retain bounded decoding, authenticated messages, private connection material, separate interpreter identities, no uncertain resend, explicit kernel completion and confirmed collection. Supporting another kernel must not silently remove those boundaries. Actual language fixtures remain disposable workload dependencies; production platform code remains Rust.

## Remaining platform milestones

The isolated-child increment is verified through the full public/client contracts on runc, gVisor and the tested S3-compatible backend. All six native adapters exist; M2 remains in progress until the Java startup fix passes the expanded runtime/S3 gates. Actual network work is still a mechanism prototype and prerequisite evidence, with no NetworkPolicy or SecretInjection capability advertisement.

M3 still requires actual dynamic egress enforcement, credentials bound to destination/method/path, scoped/revocable API keys and durable redacted audit. Default-deny isolation alone does not establish these features. M4 still requires a real Firecracker/jailer/KVM path and disk/memory snapshot/restore evidence. M5 still requires the Rust Kubernetes/operator/PostgreSQL/placement/pool/batch/volume path and an actual cluster. M6 requires installation/upgrades, benchmarks, the complete capability matrix and a requirement-by-requirement release audit. Unimplemented capabilities and skipped hardware tests remain unverified.
