# GoldenHoop

使用 Rust 实现的 Agent 沙箱平台：统一运行时接口、显式能力声明、独立 API，以及可审查的执行证据。

当前已实现 M0 协议模型、状态机与运行时接口；尚未发布可用执行后端。最终目标包括单机容器、Firecracker 微虚拟机和 Kubernetes，以及命令、文件、终端、解释器、隔离会话、网络与凭证、快照、模板、预热池、批量任务和诊断。

项目面向个人或小团队自托管，Linux x86_64 执行端优先，提供 Rust 与 Python SDK。默认断网，分阶段实现和提交。

详见 [设计](docs/design.md)、[路线图](docs/roadmap.md) 和 [实现进度](docs/progress.md)。
