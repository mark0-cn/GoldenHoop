# TSLab socket initialization in the language fixture

The disposable six-language fixture installs TSLab 1.0.19. An actual
[f79409c S3 API run](evidence/ci-45714471421/api-s3/api-s3.json) failed after
27 API groups during Rust SDK TypeScript startup: ZeroMQ reported that a socket
was blocked by a bind or unbind operation. That failed record remains failed;
later independent successful runs do not explain it.

The [pinned upstream source](https://github.com/yunabe/tslab/blob/81289c8113bfdcd53637c0ca02ee0bc8def20e68/src/jupyter.ts#L743)
starts shell, control and heartbeat receive loops before awaiting the five socket
binds. `bindSocket` already awaits its own bind; the problem is the order in
`init`. The fixture adaptation moves the unchanged five-bind `Promise.all`
immediately after socket construction and before every receive loop. It does
not change authentication, message validation, startup deadlines or resources.

The [manifest](../images/languages/patches/tslab-1.0.19-bind-ready.json) records the
package version, upstream commit, registry integrity, Apache-2.0 license and exact
published/patched SHA-256 values. The
[build-time adaptation](../images/languages/patches/tslab-bind-ready.cjs) refuses
an unknown version, source or conflicting metadata before mutation. Reapplying
the exact result is idempotent. It adds a modification notice and an installed
`GoldenHoop-PATCH.json`; the original package license remains installed.

The [deferred-socket model](../tests/tslab_bind_contract.cjs) loads the actual
published module with fake sockets. It checks that no reader starts with any bind
pending, and that a rejected bind rejects initialization without starting readers.
Both cases [fail against the original source](evidence/m2-tslab-bind-order-initial-model-regression.json)
and [pass unchanged after adaptation](evidence/m2-tslab-bind-order-model-validation-windows.json).
The same validation checks idempotency and three refusal-without-mutation cases.
These results establish initialization order, not native ZeroMQ readiness.

The image build applies the adaptation and runs both model cases. An independent
[read-only image inspection](evidence/m2-tslab-bind-order-image-inspection-windows-docker.json)
checks the installed source hash, manifest and image label. This fixture contains
Node v24.22.3, TSLab 1.0.19 and ZeroMQ 6.8.0. The precise transitive ZeroMQ version
of the original failed run was not recorded. Actual six-language, driver and API
acceptance are separate runtime gates recorded in [progress](progress.md).

This adaptation belongs to the workload dependency fixture. It does not change
the production agent's authenticated Jupyter transport or authorize readiness
from a process launch, stream EOF or model result.
