# Guest authority for native memory continuation

Protocol3 implements generation-bound native RPC and a private guest authority
transition. It is a prerequisite for capture/restore, not an implemented native
memory restore or public snapshot capability. Its separate real guest protocol
gate passes55 actual groups with371 verified inputs and Complete collection at
6c32d1a (run46025026061). Full M4-M6 remains active. The newer private capture/store
implementation is separate and cannot inherit that acceptance.

The first protocol3 gate46019365079 at b18bd35 failed before completed groups.
Its real private guest kernel boot omitted generation/task arguments because
`Machine::start` supplied them only for persistent VMs. Generation-scoped RPC
correctly refused the unscoped probe. Every native boot now supplies the same
identity/task contract and requires matching guest control observation. The
harness additionally checks the actual kernel command line. The original
failure has Complete collection and367 verified inputs; it remains Failed and
does not accept authority transfer. See the
[diagnosis](evidence/m4-guest-authority-probe-generation-diagnosis.json).

The corrected immutable source6c32d1a subsequently passes
[run46025026061](https://github.com/mark0-cn/GoldenHoop/actions/runs/46025026061):
the actual kernel command line contains its generation/task ceiling, old partial
and new old-generation writes leave no file effects after target thaw, target
effects and retained files verify, and Rust collects the original physical owner.
See the [acceptance summary](evidence/m4-guest-authority-acceptance-summary.json).

## Request boundary

Every native workload frame now has an explicit scope:

```json
{"guest_rpc":{"generation":"<current guest UUID>","request":{"method":"ping"}}}
```

PID1 refuses raw workload-agent frames on vsock. The generation is checked while
acquiring the same read guard that protects an accepted agent effect. That guard
remains held through a complete valid agent reply. An old request waiting for a
guard cannot gain target authority when admission reopens. Requests waiting for
a frame terminator also carry their original generation when eventually parsed.
The private agent Unix protocol used by Docker remains unchanged.

The envelope and scope reject unknown fields; the inner typed AgentRequest keeps
its existing parsing rules. A newly added test incorrectly assumed Serde's
internally tagged unit variants reject all inner extra fields. The original
failure is retained; the corrected negative payload uses an unknown method and
keeps the strict outer-envelope assertion. The upstream
[Serde issue/fix](https://github.com/serde-rs/serde/pull/3109) confirms that behavior;
no dependency fork or broad agent-protocol change is introduced.

UUID scope is not a secret or workload authentication credential. The reserved
host-CID2 endpoint, trusted PID1 and host/VMM process authentication remain the
control boundary.

## Frozen transition

`transfer_authority` carries source generation, target generation, capture barrier
and restoration operation. All identifiers must be non-nil, and source and target
must differ. The guest requires its exact current source and completed active
barrier, closed admission, confirmed drained effects, actual frozen membership
and checked rootfs sync. Authority and restoration intent commit under the writer
guard without an intervening await. Workloads remain frozen afterward.

The active barrier follows the target generation. Info reports the new authority;
old-generation thaw and workload RPC refuse. Only explicit target-generation thaw
can reopen admission. An exact transition retry reports the same intent and its
current frozen/resumed observation; it neither rotates again nor implicitly
thaws. Changed intents, reused restoration operations, generation rewinds and
history exhaustion refuse. The guest retains at most 128 generations and never
evicts history to admit an old identifier again.

The host AgentClient additionally requires the requested target to equal the
authenticated physical VMM instance. Its transition method accepts a positive
frozen response only. A resumed or unknown observation cannot stand in for that
boundary. Guest boot arguments retain the original generation; mutable current
authority lives in PID1 memory and is included in future memory capture.

## Required host orchestration

The guest cannot witness another VM's termination or enforce single use across
multiple copies of its memory. Before invoking this primitive, a future native
restore coordinator must establish a durable unique target claim, authenticate
and collect the source, verify immutable memory/state/disk content, load a fresh
VMM paused, and persist target ownership. It may then run PID1 with workloads
still frozen, transition authority, verify target state and explicitly thaw.
Guest application identifiers, cached randomness and existing execution handles
also need explicit public continuation semantics. This protocol does not rotate
arbitrary application secrets or implement multi-use memory templates.

The [authority workflow](../.github/workflows/firecracker-guest-authority.yml)
retains barrier/root52 and tests this protocol on the same physical VMM. It holds
an actual old partial frame across quiesce/transition/thaw, verifies old writes
have no file effect, verifies target-scoped effects and retained file data,
checks exact retries and changed intents, and requires Rust to collect the
unchanged physical owner. This is not a memory load, source-absence proof, new
target VMM, host restore claim or full restore acceptance.

The earlier protocol2 barrier and public selected-image foundations are accepted
at `376328c` in their own immutable reports. They do not accept this newer
protocol3 source. See [progress](progress.md), [quiescence](native-quiescence.md)
and the remaining [snapshot implementation contract](native-snapshots.md).
