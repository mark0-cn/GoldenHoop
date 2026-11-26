# OpenSandbox egress comparison for M3

The investigations below preserve the sequence of failures, upstream comparisons and focused corrections. Their pending statements refer to those revisions. The accepted current composition and exact final Stage are recorded at the end.

## Follow-up: compare the Linux socket ABI with other transparent proxies

The ordinary-UID client eventually reached TCP but immediately received a
reset before an HTTP response. Comparing other implementations exposed a
concrete adapter defect. Linux's original-destination handlers copy the
family-specific sockaddr without updating the supplied optlen. GoldenHoop
supplied 128 bytes and then required optlen to be exactly 16 or 28, so even
successful native calls failed its format check and entered the bounded DNS
parser, which closed the HTTP stream.

[Mitmproxy](https://github.com/mitmproxy/mitmproxy/blob/046618526875cad96d23043bef78b3ffd422b033/mitmproxy/platform/linux.py#L9-L33)
supplies the exact family-specific buffer size.
[Envoy](https://github.com/envoyproxy/envoy/blob/baf651b810d1056c9d4b637ea1afe44d71de7094/source/common/network/utility.cc#L339-L390)
uses sockaddr_storage without the incompatible exact-small-return-length
requirement. The
[Linux handlers](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_conntrack_proto.c#L267-L367)
confirm that optlen is checked for capacity but not reduced after the copy.
The [source-inspection record](evidence/m3-original-destination-upstream-comparison.json)
retains exact revisions, blob and content hashes; these are source findings,
not claims of deploying the upstream projects.

The [actual private inet observations](evidence/m3-original-destination-optlen-native-windows-docker.json)
capture six ordinary-UID IPv4/IPv6 connections across redirect, policy and
immutable-destination-floor phases. All retain length 128 while containing
the correct native original destination. A
[second native check](evidence/m3-original-destination-exact-optlen-native-windows-docker.json)
also confirms exact 16/28-byte reads match those same valid address bytes.
Both collect all task-created resources. This is an adapter ABI component
proof; the unchanged production HTTP/TLS credential and durable-audit gate
must still accept the Rust correction before SecretInjection is advertised.
GoldenHoop now supplies the family size and retains the existing exact
family/length, source, original-target, policy and lifetime checks. It does
not substitute a local socket address for a failed original-target read.

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

Classic upstream policy tightening preserves established connections by
default; its policy mutation API offers `dropEstablished=true` for teardown.
This is another reason upstream reachability is not equivalent to GoldenHoop's
revocation/collection acceptance. The explicit teardown drops are retained
across subsequent applies instead of being erased by a table rebuild.
[Source: upstream policy replacement and port floor](https://github.com/opensandbox-group/OpenSandbox/blob/067a138cdaacce3f829fffb411acfc4001feefca/docs/architecture/network/egress.md#L39-L43).

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

## Historical actions and verification boundary

The owned counter probe subsequently confirmed the allocated bridge at the
inet hook, so GoldenHoop keeps that interface match. Packet visibility at
priority -400 but no arrival at -210 or DNAT is consistent with Docker's RAW
direct-container filter. Moby's implementation explicitly skips that filter
for internal networks and retains host access to its containers. The test
receiver therefore uses a separate internal network with no published host
ports; the guest packet must first reach the transparent proxy, whose trusted
host process opens the actual receiver connection. This is a fixture topology
correction, not a change to workload floors or their exact two receiver
exceptions, and requires native HTTP/TLS verification.
[Moby direct-access filter](https://github.com/moby/moby/blob/ef9054461f8e11d5e13e56806a70fc151759b205/daemon/libnetwork/drivers/bridge/internal/iptabler/endpoint.go#L35-L77),
[Docker networking hardening](https://docs.docker.com/engine/release-notes/28/).

- Retain exact ownership, source identity and original-target checks.
- Reduce duplicate processes in protected renewal without changing deadlines.
- Capture owned-generation native counters during the failing private
  credential probe. A separately owned observer uses counter-only rules to
  distinguish bridge/veth identities at each hook; it adds no verdict, NAT or
  mark and must confirm its tables and helper container absent afterward.
  These observations never grant authority.
- Keep the small private inet packet contract: TCP reaches the listener and
  SO_ORIGINAL_DST remains correct for both families through the redirect,
  main policy and immutable destination floor. It does not cover bridge-family
  floors, the production credential broker or runtime capability acceptance.
- Resolve focused five-level and credential gates before the single full
  stage-acceptance run. M3 remains pending until actual supported-host gates
  pass; no successful upstream source pattern changes that status.

## Response completion follow-up: Hyper and reqwest

Both native credential probes at 18231e5 now deliver the expected HTTP and TLS responses to their ordinary-UID clients and receiver. They still fail the independent completion-audit predicate, so SecretInjection remains unavailable. The transport and audit results are separate.

The pinned [Hyper H1 dispatcher](https://github.com/hyperium/hyper/blob/55247767429fb29753f724b467869aa6203db532/src/proto/h1/dispatch.rs#L383-L416) drops a body when its encoder no longer permits data. A Content-Length encoder can reach that point after the last byte, before our asynchronous wrapper observes upstream EOF and records BodyCompleted. Its [protocol rules](https://github.com/hyperium/hyper/blob/55247767429fb29753f724b467869aa6203db532/src/proto/h1/role.rs#L527-L551) also suppress body polling for HEAD and bodyless statuses. The local real-TLS regression reproduces both missing-audit cases.

The broker removes fixed-length framing for responses with pending asynchronous completion work, allowing Hyper to frame the stream through its terminal audit. For an upstream body whose [actual size hint is zero](https://github.com/seanmonstar/reqwest/blob/de55373434f07f42926599dbb5a88550d8e55112/src/async_impl/response.rs#L78-L94), it positively consumes EOF and acknowledges completion before returning headers; it retains metadata such as the HEAD representation length. Both paths recheck authority after the completion audit. This preserves streaming without a one-chunk delay and does not treat status or a header as delivery proof. [Pinned source record and before/after evidence](evidence/m3-response-stream-upstream-comparison.json).

The first hosted run of this regression exposes an additional test-fixture defect: workspace feature unification enables reqwest upstream H2 through object_store, whereas the isolated crate previously uses upstream H1. The raw Hyper fixture incorrectly sends data on HEAD over H2. [Axum removes that body after setting representation length](https://github.com/tokio-rs/axum/blob/c59208c86fded335cd85e388030ad59347b0e5ae/axum/src/routing/route.rs#L163-L171). The fixture now follows that pattern, and credentials explicitly enables reqwest/http2 so focused checks exercise the same transport. A focused before/after test reproduces the hosted 502 and then passes; ten Linux repeats assert actual upstream H2. Unexpected nonempty zero-size payloads still fail closed, while empty data frames do not replace EOF proof.

## Owned system resolver follow-up

At 912d40e both runtimes accept twelve credential groups, then libc cannot resolve the first named origin and the owned upstream receives no query. Moby [rebuilds user-defined-network resolver configuration for its embedded resolver](https://github.com/moby/moby/blob/ef9054461f8e11d5e13e56806a70fc151759b205/daemon/libnetwork/sandbox_dns_unix.go#L297-L329); its internal address is defined at line26. GoldenHoop's accepted standalone owned-resolver component already mounts an explicit read-only configuration, while public production creation omitted it.

The Rust driver now derives the resolver address from the actual owned network and installs public, content-addressed configuration through a bounded network-none Rust helper. The helper publishes atomically, refuses changed files/links and confirms root ownership, exact bytes and 0444 mode. The workload receives an exact read-only volume subpath. Startup and recovery cross-check both actual mounts and configured subpath/DNS against the real gateway. Resolver text supplies reachability only; original source, policy, grants and private lease remain mandatory. [Pinned source and component evidence](evidence/m3-system-resolver-upstream-comparison.json). Corrected hosted native DNS/TLS acceptance remains required.

The final live-owner observations at d79d988 show completed DNS installation and zero errors on both runtimes, with the last resolution taking 795/988 ms. The one-second client resolver setting cannot reliably cover serialized A and AAAA transactions. An ordinary-UID, network-none experiment reproduces the same EAI_AGAIN with 800 ms per answer and timeout:1, while timeout:5 returns both addresses in 1681 ms. This establishes a client-waiting incompatibility rather than a failed installation. The public owned configuration now uses five seconds and one attempt; native grant/install/lease deadlines remain unchanged.

The [glibc 2.36 resolver default](https://github.com/bminor/glibc/blob/c804cd1c00adde061ca51711f63068c103e94eef/resolv/resolv.h#L68) is five seconds. [Cilium's successful response path](https://github.com/cilium/cilium/blob/f631e869bfb6c9aed8d50d1c8bddd69289128d9d/pkg/fqdn/dnsproxy/proxy.go#L1119-L1135) also processes its response callback before publishing the DNS answer, providing a useful phase-order comparison. Its datapath and timeouts do not replace GoldenHoop's native confirmation or authority rules. [Pinned comparison](evidence/m3-client-dns-patience-upstream-comparison.json), [actual client experiment and confirmed collection](evidence/m3-libc-serialized-dns-latency-native-windows-docker.json). Complete production named-origin acceptance remains a separate gate.

## Accepted M3 composition

The final [combined Stage](https://github.com/mark0-cn/GoldenHoop/actions/runs/45839996451) at 24e313aeacb646d067f61a993794f588d02796c3 passes all seven jobs and all 63 [source-verified reports](evidence/m3-native-45839996451-archive.json) with Complete collection. Both runtimes accept the owned system resolver, named HTTP/TLS credential boundary, five-level recovery and complete destination enforcement. The relative-lifetime basic renewal regression is corrected by separating native observation from the stronger absolute-lifetime public receipt, retaining the same native verification and finite bounds. Earlier failures above remain historical evidence. [Acceptance summary](evidence/m3-stage-acceptance-final-summary.json).

## Further upstream boundaries applied during acceptance

The pinned [etcd lease response interface](https://github.com/etcd-io/etcd/blob/4e090c033abc29636df2f844fbdd363adffcd90b/api/etcdserverpb/rpc.proto) separates a remaining TTL from an original absolute expiry. The [comparison](evidence/m3-basic-renewal-ttl-upstream-comparison.json) informed the interface separation only: GoldenHoop basic renewal returns a completely verified finite native observation, while public policy receipts still require the original native context and absolute lifetime. No etcd renewal or authority semantics are imported. Both new relative-lifetime boundary cases pass in the final Stage.

The pinned [Moby wait conditions](https://github.com/moby/moby/blob/ef9054461f8e11d5e13e56806a70fc151759b205/api/types/container/waitcondition.go) and [Docker wait API](https://docs.docker.com/reference/api/engine/version/v1.57/operations/ContainerWait/) distinguish not-running from removed. The [captured runtime-loss review](evidence/m3-runtime-loss-collection-wait-input-validation-windows.json) and [shared collection-wait review](evidence/m3-shared-runtime-collection-wait-input-validation-windows.json) led to one positive whole-sandbox collection wait for both fault-injection callers. It shares the original 25/40-second execution budgets, requires Failed throughout and Complete plus actual runtime absence, and retains Unknown/no-replay controls. Production lifecycle behavior and resource limits are unchanged.

GitHub documents the [job timeout](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idtimeout-minutes) as an automatic whole-job cancellation budget. The fifth runc job hit its 40-minute watchdog after cold builds and sequential contracts; its interrupted destination suite remains failed with Unknown cleanup. The final accepted Stage ran under that original stricter wrapper. The only later [workflow metadata correction](evidence/m3-ci-watchdog-metadata-validation.json) reserves 60 minutes for cold builds and final collection; all step bytes, conditions, test deadlines, native leases and runtime inputs are identical.
