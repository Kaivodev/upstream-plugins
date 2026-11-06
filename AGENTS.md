# Kaivo 上游插件开发规则

- 本仓库是公开的独立 Go 模块，负责版本化 ABI、wazero 宿主核心、Go 插件 SDK、上游协议翻译和构建/回放工具。payment 与 reconciliation 提供审批、密钥、网络出口和业务状态机；本仓库不改变资金状态、不实现服务接入。
- 只依赖标准库和固定版本 wazero，不使用 cgo、脚本引擎或私有模块。运行 Go 命令设置 GOWORK=off；Codex 沙箱另设 GOCACHE=/private/tmp/codex-gocache/upstream-plugins，不写进 Makefile 或 CI。
- 不保存真实密钥、商户号、凭据、个人信息；测试密钥运行时生成，fixtures 不能携带私钥或共享密钥。不得在日志、错误或回归报告中输出密钥。
- ABI 不兼容变更必须升级 ABI 版本，同步修改 abi、ABI.md、sdk、host 和回归覆盖。声明能力必须有对应导出；M4 对账操作当前明确不支持。
- 金额为带币种的十进制最小单位字符串，禁止浮点数。请求发出后的不确定失败只能报告结果未知。
- 编译固定 toolchain go1.27.3，使用 wasip1/wasm reactor、CGO_ENABLED=0、trimpath、buildvcs=false 和空 build ID；不得注入时间戳和本机路径。源码树摘要覆盖本模块生产 Go 源码、go.mod、go.sum。
- 沙箱和出口默认拒绝。HTTP 仅显式测试选项可用，生产使用方必须拒绝该选项。网络适配器不得自行重试、重定向或忽略取消。
- 修改后运行 GOWORK=off make fmt check build plugins-replay；govulncheck 不可用时如实说明。基准数值不作为 CI 门槛，CI 不代表真实渠道或支付资金链路验收。
- 仅修改本仓库并保留已有工作；未请求时不提交、推送。提交使用 Conventional Commits，正文包括 AI-Context、Decisions、Validation、Follow-up。
