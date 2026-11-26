# OpenSandbox egress comparison for M3

Inspected upstream commit
[`067a138cdaacce3f829fffb411acfc4001feefca`](https://github.com/opensandbox-group/OpenSandbox/commit/067a138cdaacce3f829fffb411acfc4001feefca),
dated 2026-11-26. This investigation supplements the older pinned coverage
baseline; it does not silently redefine GoldenHoop's acceptance requirements.
The findings below come from source inspection, not a claim that we ran the
upstream deployment.

## Interception depends on the network topology

The ordinary sidecar shares the application's network namespace. It redirects
outbound TCP in OUTPUT and excludes the proxy's UID to avoid a loop. Its native
nft variant covers both address families. The proxy runs as its own unprivileged
UID; CA material and lifecycle remain under trusted control.
[Source: transparent.go, lines 28-101](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/components/egress/pkg/iptables/transparent.go#L28-L101).

Fast Sandbox uses a different gateway path: PREROUTING DNAT keyed by the
sandbox's source IP, a listener reachable on the gateway, and SO_ORIGINAL_DST
for the actual upstream target. Its source comments explicitly reject matching
the sandbox veth in IP hooks: bridge netfilter can report the bridge as the
ingress device. That implementation relies on IPAM and withholding NET_ADMIN
and NET_RAW for source integrity.
[Source: gateway_mitm.go, lines 15-43 and 66-87](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/components/egress/pkg/iptables/gateway_mitm.go#L15-L87).

GoldenHoop already matches the owned bridge and its index in its inet redirect,
not the sandbox veth. Therefore this upstream warning is a diagnostic clue,
not evidence that removing GoldenHoop's interface checks is a fix. GoldenHoop
also retains a separate bridge-family source floor binding the veth, source
MAC and source IP; replacing it with capability removal alone would change
the existing isolation contract.

## A local proxy needs an INPUT enforcement path

After gateway DNAT, the connection goes to INPUT rather than FORWARD.
OpenSandbox dispatches intercepted INPUT traffic using source identity,
the proxy port and `ct status dnat`, then checks the conntrack original
destination and port against the subject's policy. Direct gateway access to
the proxy port does not receive that admission.
[Source: fastsandboxnft.go, lines 801-885](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/components/egress/pkg/fastsandboxnft/fastsandboxnft.go#L801-L885).

GoldenHoop uses its existing protected TCP gateway listener and validates the
original destination, source, current policy and native lease in the Rust
broker before opening upstream. Native diagnosis must establish the complete
path: source floor, original-destination floor, DNAT counter, local INPUT
accept and broker/receiver observation. A successfully installed redirect
alone proves none of these packets arrived.

## Updates are serialized and acknowledged; deadlines have different meanings

OpenSandbox's experimental revision coordinator uses prepare, commit and
readback with exact generation/epoch/digest identities. An uncertain commit
cannot be treated as an abort, and ordinary reads refuse uncertain authority.
[Source: coordinator.go, lines 37-63 and 106-190](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/components/egress/pkg/revision/coordinator.go#L37-L190).

Its Fast Sandbox policy update flushes and rebuilds subject chains and static
sets in one nft transaction while retaining dynamic sets. DNS and TCP refresh
are tracked separately; the default connection-refresh interval is 30 seconds.
This is not equivalent to GoldenHoop's finite controller-authority lease.
[Policy swap](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/components/egress/pkg/fastsandboxnft/fastsandboxnft.go#L668-L700),
[refresh interval and source deadlines](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/components/egress/pkg/nftables/manager.go#L37-L47).

The useful adaptation is fewer repeated native processes and one verified
transaction, not a longer GoldenHoop lease. The protected renewal increment
reuses complete before/after kernel observations for its returned receipt;
it preserves every floor verifier, revision check, native timeout deduction,
bridge identity and original sandbox deadline. The five-level native gate
must still prove it finishes inside the existing publication budget.

## Readiness and retirement are separate evidence

OpenSandbox keeps health pending until the listener, redirect and CA setup
finish. Proxy exit clears readiness; a latched down reason cannot be reversed
by an unrelated ready store.
[Launch/setup](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/components/egress/mitmproxy_transparent.go#L326-L421),
[health gate](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/components/egress/pkg/mitmproxy/health_gate.go#L27-L88).

Its experimental live credential-bound mode distinguishes rotations, admitted
requests, dispatch fencing and confirmed disconnects. Some requests can drain
until a configured deadline. The documentation also explicitly excludes
non-intercepted established traffic from that proxy's cleanup proof.
[Source: egress architecture, lines 76-80](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/docs/architecture/network/egress.md#L76-L80).

GoldenHoop's M3 acceptance continues to require its actual ordinary-UID HTTP
and TLS credential probe, durable audit acknowledgement, and collection of the
old controller/process/socket on revocation. Startup and successful readback
do not substitute for those observations.

## Compatibility is not interchangeable

The inspected upstream documentation explicitly says its egress features
cannot be relied on with gVisor or an additional transparent service-mesh
sidecar. GoldenHoop places the controller in the host network namespace and
must pass its own runc and gVisor packet tests; upstream support is not
evidence for those tests, and changing runtime is not an acceptance shortcut.
[Source: upstream compatibility warning](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/docs/architecture/network/egress.md#L160-L167).

## Current actions and verification boundary

- Retain exact ownership, source identity and original-target checks.
- Reduce duplicate processes in protected renewal without changing deadlines.
- Capture only owned-generation native counters during the failing private
  credential probe. These are read-only diagnostics, never authority grants.
- Keep the small private inet packet contract: TCP reaches the listener and
  SO_ORIGINAL_DST remains correct for both families through the redirect,
  main policy and immutable destination floor. It does not cover bridge-family
  floors, the production credential broker or runtime capability acceptance.
- Resolve focused five-level and credential gates before the single full
  stage-acceptance run. M3 remains pending until actual supported-host gates
  pass; no successful upstream source pattern changes that status.
