# M3 delivery and acceptance

The remaining M3 work is delivered as independent increments: scoped API keys
and durable redacted audit; encrypted credential storage and bound forwarding;
transparent HTTP/TLS runtime integration and credential convergence; and the
full protected five-level network hierarchy. A failure in one area does not
prevent implementation of another. M3 remains incomplete until all pass.

Each increment runs the tests relevant to its changed boundary. Rust format,
lint and workspace tests remain repository checks. Expensive real-runtime,
network and artifact suites run together at stage acceptance, using the
`Stage acceptance` workflow on the exact candidate revision. The individual
suites can also be dispatched for a targeted diagnosis. A portable CI pass
alone cannot satisfy any runtime gate.

API keys have independent read, write, execute and network permissions and
either all resources or an explicit nonempty set of sandbox IDs. Resource
ownership is resolved for retained executions, operations, sessions, contexts,
runs and artifacts. An exact sandbox grant does not include descendants;
child collections and creation require an all-resource grant. Filtered global
collections require one authorized `sandbox_id`. Only the bootstrap
administrator creates/revokes keys, manages provider credentials or reads audit.
Provider credentials cannot be retrieved through public routes.

Key creation returns its high-entropy bearer token once. The database stores a
SHA-256 verifier. Revocation and expiry are checked on subsequent requests,
throughout SSE and before interactive controls. An admitted operation can
finish independently of its observer; revoking observation does not cancel
that operation. Retained transports check authority at most every 200 ms (100
ms for interactive sockets); a slow/unavailable check fails closed after 500
ms. Recording a revoked stream's audit observation is also bounded to 500 ms;
an unavailable audit writer cannot indefinitely retain that observer. Socket
writes retain their existing five-second deadline. Actual measured
transport tests remain necessary in addition to those configured bounds.

Audit uses monotonically ordered durable SQLite records. Lifecycle state
observations are appended by triggers in the same transaction as domain
changes, using only enum states, cleanup states, dispatch flags and revision
numbers. Authentication and HTTP outcomes are separate from execution or
collection outcomes. Commands, code, paths, query strings, errors containing
inputs, provider values and token/header values are excluded. Audit tables
refuse ordinary SQL updates/deletes; a host/database administrator remains
trusted. This is not an independently anchored tamper-proof log. Exporters
retain the first page's `through_sequence` as `through` on later pages, so
audit-read events cannot make a snapshot export grow indefinitely.

Provision a vault key explicitly with `goldenhoopd vault-init PATH`; API
startup accepts `--credential-key-file PATH`. Missing, malformed or (on Unix)
symlinked/permissive/unowned keys are refused. XChaCha20-Poly1305 encryption
uses a fresh random nonce and authenticates installation, sandbox, binding
and revision identity. Private binding metadata is encrypted alongside the
secret and checked against the public metadata. Idempotency fingerprints
use a domain-separated keyed HMAC. Plaintext is zeroized where owned by the
vault/broker; third-party HTTP/TLS buffers have their own bounded lifetimes.

Credential intent is available at
`/v1/sandboxes/{sandbox}/credentials/{binding}`. PUT uses an expected revision,
GET returns metadata, and DELETE starts revocation. Pending/Revoking records
do not claim installation or drained transports. SecretInjection remains
unadvertised until the actual runtime integration passes. A parser, vault
test or loopback HTTP broker test does not satisfy that gate.

Bound forwarding checks origin, port, method and path, rechecks authority after
asynchronous exchange, pins the independently authorized destination address,
verifies upstream TLS, disables redirect following and automatic retries, and
collects revoked streams. Provider secrets in response headers are removed;
response bodies are approved upstream application data and are not rewritten.
Upstream delivery uncertainty is not a replayable failure.

The component now accepts HTTP/1.1 and HTTP/2 over plaintext or TLS, validates
SNI/authority/port agreement, verifies upstream certificates, and supports bearer,
basic, custom-header and bounded path/query/header/body substitutions. Body
replacement buffers at most 1 MiB; larger bodies preserve their streaming bytes
while the other replacements remain active. Trailers and upgrades are refused.
The public CA is available at `/v1/sandboxes/{sandbox}/credential-ca`; its private
signing key is encrypted with installation/sandbox identity and restored across
restart. Missing previously provisioned CAs and wrong installation master keys
are refused. These components do not yet install trust or intercept container
traffic. Production native authority, runtime convergence and actual capability
probes remain required before SecretInjection is advertised.
