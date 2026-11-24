# GoldenHoop

使用 Rust 实现的 Agent 沙箱平台：统一运行时接口、显式能力声明、独立 API，以及可审查的执行证据。

当前已实现并验证 M0-M1，正在实现 M2。Rust agent、驱动、独立 API/worker、Rust/Python SDK、Rust CLI、运行诊断、持久化制品、shell 和 PTY 已通过实际 runc/gVisor 测试。公开接口与客户端也已通过 Linux 上 S3 兼容后端实测。最终目标包括单机容器、Firecracker 微虚拟机和 Kubernetes，以及命令、文件、终端、解释器、隔离会话、网络与凭证、快照、模板、预热池、批量任务和诊断。

项目面向个人或小团队自托管，Linux x86_64 执行端优先，提供 Rust 与 Python SDK。默认断网，分阶段实现和提交。

详见 [设计](docs/design.md)、[路线图](docs/roadmap.md) 和 [实现进度](docs/progress.md)。

启动方式见 [API 与 worker](docs/control.md)。

调用方式见 [Rust/Python SDK 与 CLI](docs/clients.md)。

资源采样与退出信息见 [运行诊断](docs/diagnostics.md)。

制品保留、下载、恢复与清理语义见 [制品说明](docs/artifacts.md)。

持久 shell、真实 PTY、终端重连与输入确认见 [会话说明](docs/sessions.md)，其公开接口和四个客户端已通过实际 runc/gVisor 与 S3 兼容后端 CI。Python 代码上下文现已接入持久化公开 API、Rust SDK、Python 同步／异步 SDK 和 CLI，四个客户端的本地 runc 实测通过；原生内核探测也已通过 runc/gVisor。新增公开调用的 gVisor/S3 集成仍须单独验证。启用时须显式配置缓存的内核探测镜像。隔离子沙箱继续实现，见 [代码上下文](docs/code-contexts.md)。
