# Interactive sessions

The private agent transport and durable session metadata have passed local and CI runc/gVisor contracts. Public REST, reconnectable WebSocket, worker integration and Rust SDK support are implemented and pass the local 16-case API/client suite. Their expanded CI is pending. Python SDK/CLI session bindings, code contexts and isolated child sandboxes remain in progress. This does not mark M2 complete.

SessionSpec describes an actual long-lived process with literal argv and an optional terminal size. A pipe shell such as /bin/sh retains its own variables and working directory across input writes. Its lifetime shares the normal command executor: one active command/session holds the workload identity, and subsequent commands wait. File RPCs remain independent. Multiple concurrent processes requiring separate cleanup boundaries belong to isolated child sandboxes, a later M2 increment.

Normal execution IDs, output events, bounded buffering, timeout, cancellation and descendant cleanup apply to sessions. Raw input does not produce a per-statement success result. Only actual process exit and confirmed descendant cleanup permit a terminal execution result. Disconnecting an observer does not terminate the process. Overall command and sandbox deadlines continue to apply.

## Input control

Each session accepts contiguous sequence numbers starting at 1. A repeated sequence with identical action returns its original receipt; different content or a sequence gap conflicts. Receipts identify the execution and control sequence. Applied acknowledges input delivery or resize, not successful shell/code execution. The limits are 1024 controls, 64 KiB per input and 1 MiB total decoded input per session.

A write has a five-second delivery window. Partial writes, broken pipes and timeouts remain Unknown and are never replayed; later writes are refused after uncertain delivery. This avoids silently duplicating partially consumed input. Cancellation remains available. The agent keeps receipts for its process lifetime; SQLite retains queued controls and their receipts. The worker queries the agent's existing receipt before attempting the same sequence. Previously observed running sessions that disappear from their agent trigger whole-sandbox cleanup rather than relaunch.

Schema 3 adds sessions and ordered controls without replacing existing sandbox, command, artifact or operation identities. Session creation shares the normal execution quota but has a separate idempotency scope. Duplicate controls return the original receipt; settled receipts cannot change. Rejected quota reservations do not consume the next sequence. Terminal execution publication atomically settles any still-unconfirmed input as Unknown. That observation does not claim that no bytes were consumed. Metadata tests actually close/reopen SQLite and upgrade a schema-2 fixture; they do not establish public session delivery.

Pipe sessions support closing stdin to deliver EOF. PTYs have one bidirectional device and cannot half-close stdin: CloseInput returns an explicit Rejected/UnsupportedCapability receipt. A caller can send terminal bytes or explicitly cancel the session. Resize on a pipe session is likewise unsupported.

## Public API

| Method | Path | Result |
| --- | --- | --- |
| POST | /v1/sandboxes/{id}/sessions | 202, session specification and execution |
| GET | /v1/sessions?sandbox_id=UUID&after=UUID&limit=100 | UUID-ordered session page |
| GET | /v1/sessions/{id} | Durable specification and execution |
| POST | /v1/sessions/{id}/controls | 202, pending or existing input receipt |
| GET | /v1/sessions/{id}/controls/{sequence} | Current receipt |
| POST | /v1/sessions/{id}/cancel | 202, persisted execution cancellation intent |
| GET | /v1/sessions/{id}/events | Resumable execution SSE |
| GET | /v1/sessions/{id}/socket?after=SEQUENCE | Authenticated WebSocket upgrade |

Create accepts `{"command":{"argv":["/bin/sh"]},"terminal":{"rows":24,"columns":80}}`; omit terminal for pipes. Idempotency-Key is required for create. Controls use their sequence/content as the idempotency identity, for example `{"sequence":1,"action":{"kind":"write","data_base64":"aGVscAo="}}`. Other actions are `{"kind":"close_input"}` and `{"kind":"resize","size":{"rows":40,"columns":100}}`. Dimensions are 1-1000. Concurrent writers must coordinate sequences and retain their last submitted sequence/content for recovery.

The API commits controls before delivery. Reading history or replaying a known control remains possible while the worker is unavailable. New input requires a fresh worker registration and a running, unexpired, uncancelled source; paused sources reject it without consuming a sequence. Pending input whose delivery cannot be confirmed when the execution ends is atomically recorded as Unknown. This does not claim that zero bytes reached the workload.

ShellSessions and Pty are advertised only after actual runtime probes verify persistent shell state, input replay, real controlling tty behavior, resize, output, process exit and cleanup. A missing optional capability does not enable a weaker runtime. The configured workload image must contain the requested executable.

## WebSocket and Rust client

Native WebSocket clients use the same Authorization bearer header as REST; query-string credentials are not accepted. Client messages are `{"kind":"control","value":CONTROL}`. Server messages have kind=session, event, control or error and a value containing the corresponding domain model. PTY events contain binary-safe base64 output. A control receipt acknowledges delivery separately from execution events.

Save the last delivered event sequence and reconnect using after. Disconnecting or explicitly closing the socket leaves the process running. Replaying a submitted input requires the same control sequence/content. Output history is durable and never reexecutes the command. Matching terminal result/completion and confirmed cleanup establish completion; socket EOF alone does not. The server bounds input messages to 128 KiB, concurrent sockets to 64 and each send to five seconds. Idle channels receive ping frames every ten seconds. A slow/disconnected observer is closed without cancelling the session.

Rust Client provides create_session, session, list_sessions, session_control, session_control_status, wait_session_control and session_socket. Ordinary execution cancel/events methods also accept a session's execution ID. Final control receipts can be Applied, Rejected or Unknown; inspect the state. SessionSocket exposes control, recv, cursor and close, validates event identity/order/completion and refuses premature EOF. Clients only use loopback WS or verified WSS derived from their validated API URL, without redirects or environment proxies. WSS uses public WebPKI roots; deployment-level TLS validation remains an M6 gate.

## Actual terminals

The Rust agent allocates a private pseudoterminal, creates a new session and attaches its slave as stdin/stdout/stderr and controlling terminal, then drops to workload UID 1000 with no effective capabilities. The master uses nonblocking readiness with Tokio. PTY stdout/stderr form one binary stream, exposed as stdout events. Window resize uses the kernel terminal operation and the foreground process group receives SIGWINCH. TERM is xterm-256color. The terminal inherits no host console, credential or daemon socket.

Implementation references: [Linux openpty](https://man7.org/linux/man-pages/man3/openpty.3.html), [controlling terminal operation](https://man7.org/linux/man-pages/man2/TIOCSCTTY.2const.html), [window size and SIGWINCH](https://man7.org/linux/man-pages/man2/TIOCSWINSZ.2const.html), and [Tokio AsyncFd readiness](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html).

The [actual 14-case local agent record](evidence/m2-session-agent-runc-windows-docker.json) verifies persistent shell state, queued normal commands, input replay refusal, real isatty/controlling-terminal identity, binary terminal input, SIGWINCH/size changes, unsupported half-close, uncertain write refusal, and cancellation of descendants that escape into another POSIX session. The same 14 cases pass on [actual gVisor CI](evidence/ci-45347370569/agent-runsc/agent-runsc.json). Cleanup is confirmed in both records.

The [16-case local API/client record](evidence/m2-session-api-runc-windows-docker.json) additionally verifies shell state through actual API/worker restarts, pause/resume input refusal, public PTY binary input/resize, queued input becoming Unknown after runtime loss, and paused interactive expiration while the API is down. The actual Rust SDK exercises REST controls and WebSocket disconnect/reconnect, replay without duplicate input, resize and explicit completion. Separate socket protocol tests refuse premature EOF, wrong IDs and sequence gaps. Test resources and temporary directories are removed.
