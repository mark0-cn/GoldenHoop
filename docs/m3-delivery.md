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
are refused. Clients explicitly trust that public CA for intercepted TLS;
certificate-pinned clients, upgrades and trailers have no bypass fallback.

The native implementation now redirects configured credential TCP ports to the
allocation's existing protected ingress. It adds no host/private destination
exemption. The accepted socket's original destination and exact owned source
select the sandbox; workload headers cannot select another allocation. Packet
authority requires the current native monotonic lease, immutable destination
floor, policy hierarchy and an exact live name/address grant for named hosts.
Configured credential ports refuse unmatched origins, methods and paths. Other
permitted ports retain their normal packet path.

The worker transfers bounded private binding/provider frames over its owned
controller channel. Those buffers are zeroized; provider material and private
CA keys are never mounted in a workload. Rotation, revocation and policy changes
fence dispatch and physically collect the previous controller before a fresh
snapshot is applied. Durable generation history prevents a different snapshot
from reusing an old process. Pending/Revoking remain intent; Active/Revoked are
observations after correlated installation/removal and native confirmation.
Active metadata alone is not a continuously valid packet lease.

Audit delivery uses a bounded private queue. Reading a batch does not authorize
dispatch: the worker commits an idempotent SQL batch and acknowledges exact
delivery IDs. The broker rechecks authority after that wait. `dispatch_intent`
is separate from an observed upstream HTTP response or consumed upstream body;
the historical `upstream_started` spelling was also a pre-dispatch intent.
Revoked bodies produce an error rather than a successful end of stream.

Worker configuration uses `--credential-key-file KEY` and `--credential-config
PRIVATE_JSON`, together with the protected network configuration. The optional
JSON fields are `exchanges` (named fixed HTTPS resolvers), `upstream_ca_pem`
(at most four operator-owned additional roots), and `probe`. Unix configuration
must be a private regular file owned by the service. A configured probe contains
`http_url`, `https_url`, a probe-only `credential`, and `expected_body`; its
numeric endpoints belong to an operator-owned receiver, use different TCP ports,
and must already satisfy the administrator destination floor. Never use a real
provider credential as a probe canary.

Only an actual ordinary-UID HTTP/TLS probe with durable response/body observations
and completed native collection publishes SecretInjection. A failed credential
probe withholds that capability while independently accepted networking remains
available. Missing probe configuration leaves SecretInjection unadvertised. The
implementation and its native gate are present; current supported-host results
and full M3 stage acceptance are still pending.
