# GoldenHoop

使用 Rust 实现的 Agent 沙箱平台：统一运行时接口、显式能力声明、独立 API，以及可审查的执行证据。

当前 M0-M3 已在实测 Linux runc-development 与 gVisor 配置下完成验收。[完整阶段验收](https://github.com/mark0-cn/GoldenHoop/actions/runs/45839996451)在 24e313aeacb646d067f61a993794f588d02796c3 上通过全部 7 个任务和 63 份[源码指纹核验报告](docs/evidence/m3-native-45839996451-archive.json)，全部确认资源回收完成。范围包括六种语言的持久化代码上下文、隔离子沙箱、默认拒绝出网、五层策略继承与恢复、透明 HTTP/TLS 凭证代理、凭证轮换与撤销、受限 API 密钥及持久化脱敏审计；S3 兼容后端的公开接口、客户端与恢复回归同时通过。M4-M6 仍未整体验收，Kubernetes 等完整目标继续保留，详见路线图。

[Firecracker 基础本地运行时](docs/m4-delivery.md)已通过实际 KVM 的 23 组验证，包括 jailer/来宾执行、公开 API/Python SDK/Rust CLI、worker 强杀恢复、暂停/恢复、制品保留和独立过期回收。须显式启用并通过真实部署探测，只发布已验证的基础能力。[Rust 镜像任务](docs/image-preparation.md)已连接源导出、宿主资源核验、隔离转换和私有磁盘存储；生产 gVisor 与生成磁盘的 KVM 验证、完整分配恢复、快照恢复、模板、manager 强杀恢复和 M4 综合阶段仍待完成。

项目面向个人或小团队自托管，Linux x86_64 执行端优先，提供 Rust 与 Python SDK。默认断网，分阶段实现和提交。

详见 [设计](docs/design.md)、[路线图](docs/roadmap.md) 和 [实现进度](docs/progress.md)。

启动方式见 [API 与 worker](docs/control.md)。

调用方式见 [Rust/Python SDK 与 CLI](docs/clients.md)。

资源采样与退出信息见 [运行诊断](docs/diagnostics.md)。

制品保留、下载、恢复与清理语义见 [制品说明](docs/artifacts.md)。

持久 shell、真实 PTY、终端重连与输入确认见 [会话说明](docs/sessions.md)，其公开接口和四个客户端已通过实际 runc/gVisor 与 S3 兼容后端 CI。Python 代码上下文现已接入持久化公开 API、Rust SDK、Python 同步／异步 SDK 和 CLI，公开调用和四个客户端已通过实际 runc/gVisor 与 S3 兼容后端 CI，并验证重启恢复和清理。启用时须显式配置缓存的内核探测镜像。[隔离子沙箱](docs/isolated-sessions.md)已通过实际运行时与客户端契约；各语言能力仍须显式配置并通过实际部署探测，语义见 [代码上下文](docs/code-contexts.md)。

网络与凭证启用方式见 [M3 交付](docs/m3-delivery.md)。默认不发布网络与凭证注入能力；管理员配置后仍须通过真实部署探测并确认探测资源回收。[验收汇总](docs/evidence/m3-stage-acceptance-final-summary.json)记录本次准确范围与清理例外。
