# Interactive sessions

The private agent session transport is implemented and has passed the actual local runc contract. Its expanded gVisor CI remains pending. Public session persistence, routes, SDK/CLI support and capability advertisement remain pending. This does not mark M2 complete.

SessionSpec describes an actual long-lived process with literal argv and an optional terminal size. A pipe shell such as /bin/sh retains its own variables and working directory across input writes. Its lifetime shares the normal command executor: one active command/session holds the workload identity, and subsequent commands wait. File RPCs remain independent. Multiple concurrent processes requiring separate cleanup boundaries belong to isolated child sandboxes, a later M2 increment.

Normal execution IDs, output events, bounded buffering, timeout, cancellation and descendant cleanup apply to sessions. Raw input does not produce a per-statement success result. Only actual process exit and confirmed descendant cleanup permit a terminal execution result. Disconnecting an observer does not terminate the process. Overall command and sandbox deadlines continue to apply.

## Input control

Each session accepts contiguous sequence numbers starting at 1. A repeated sequence with identical action returns its original receipt; different content or a sequence gap conflicts. Receipts identify the execution and control sequence. Applied acknowledges input delivery or resize, not successful shell/code execution. The limits are 1024 controls, 64 KiB per input and 1 MiB total decoded input per session.

A write has a five-second delivery window. Partial writes, broken pipes and timeouts remain Unknown and are never replayed; later writes are refused after uncertain delivery. This avoids silently duplicating partially consumed input. Cancellation remains available. Receipt history survives worker reconnection while the same agent process lives; durable public control metadata is the next integration increment. A lost agent must not be used to rerun an already started session.

Pipe sessions support closing stdin to deliver EOF. PTYs have one bidirectional device and cannot half-close stdin: CloseInput returns an explicit Rejected/UnsupportedCapability receipt. A caller can send terminal bytes or explicitly cancel the session. Resize on a pipe session is likewise unsupported.

## Actual terminals

The Rust agent allocates a private pseudoterminal, creates a new session and attaches its slave as stdin/stdout/stderr and controlling terminal, then drops to workload UID 1000 with no effective capabilities. The master uses nonblocking readiness with Tokio. PTY stdout/stderr form one binary stream, exposed as stdout events. Window resize uses the kernel terminal operation and the foreground process group receives SIGWINCH. TERM is xterm-256color. The terminal inherits no host console, credential or daemon socket.

Implementation references: [Linux openpty](https://man7.org/linux/man-pages/man3/openpty.3.html), [controlling terminal operation](https://man7.org/linux/man-pages/man2/TIOCSCTTY.2const.html), [window size and SIGWINCH](https://man7.org/linux/man-pages/man2/TIOCSWINSZ.2const.html), and [Tokio AsyncFd readiness](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html).

The [actual 14-case local agent record](evidence/m2-session-agent-runc-windows-docker.json) verifies persistent shell state, queued normal commands, input replay refusal, real isatty/controlling-terminal identity, binary terminal input, SIGWINCH/size changes, unsupported half-close, uncertain write refusal, and cancellation of descendants that escape into another POSIX session. It confirms removal of the test container. Separate gVisor results will be recorded before that profile is counted as verified.
