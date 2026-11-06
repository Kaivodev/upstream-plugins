# upstream-plugins

公开的 Kaivo 上游协议插件仓库：版本化 JSON ABI、纯 Go wazero 宿主、Go SDK、两个仅测试用的 upstream-sim 插件，以及离线构建、打包、回放、源码复验与测试录制工具。

插件只翻译协议，不持明文密钥、不自行联网、不改变资金状态。payment / reconciliation 负责审批、账户与订单绑定、密钥版本、HTTP 实际出口和业务状态机。当前只交付六个支付操作；payment 接入属于下一任务，M4 对账接口只保留名称。完整调用约定和限制见 [ABI.md](ABI.md)。

## 构建与验证

固定 `toolchain go1.27.3`，构建工具会核对正在执行的工具链，离线构建插件，只允许标准库和本模块源码。wazero 固定 v1.12.0；不使用 cgo 或脚本引擎。

```sh
export GOWORK=off
make fmt check build plugins-replay
make bench
```

`check` 执行 vet 和 race 测试，测试期间从 testdata 的 Go 源码构建恶意 reactor，另验证两个实际插件。`plugins-replay` 构建全部插件到忽略的 dist/ 后回放全部 fixtures。基准不设置通过阈值。CI 使用 Go 1.27.x 初始化，再显式选择固定 1.27.3，执行完整验证和 govulncheck；本地有现成 govulncheck 时也应运行。

```sh
bin/pluginctl build --source plugins/sim_json_rsa --out dist/sim_json_rsa
bin/pluginctl package --dir dist/sim_json_rsa --out dist/package_json_rsa
bin/pluginctl replay --dir dist/package_json_rsa --out dist/report.json
bin/pluginctl verify --source plugins/sim_json_rsa --dir dist/package_json_rsa
```

包是包含 manifest.json、plugin.wasm、fixtures/ 的目录。build 不修改源码 manifest，写入固定工具链、源码提交、源码树摘要；未提交/脏工作区使用 `uncommitted`，生产审批方应拒绝它。构建不注入时间、绝对路径、VCS 自动元数据或 build ID。源码树摘要对排序后的生产 .go 文件（排除 testdata 和 _test.go）、go.mod、go.sum，依次写入大端 uint64 路径长度、路径、内容长度、内容后计算 SHA-256；同一源码树跨目录可复现。源码 manifest 与 fixtures 通过规范 manifest / 回归报告分别绑定，不混入源码树摘要。

## 宿主接入

```go
p, err := host.ReadPackage(packageDirectory)
// 检查 err；审批和 code/version 不可变校验在使用服务执行。
h, err := host.New(ctx, host.Options{PluginType: "payment"})
// 检查 err；服务退出时 h.Close(ctx)。
loaded, err := h.Load(ctx, p) // 先加载/编译，调用路径只使用 Loaded。
// 检查 err；env 实现 host.Environment。
result := h.Execute(ctx, loaded, abi.QueryPayment, inputJSON, env)
```

`Services` 提供环境接口的便捷实现；Secret/PublicKey/HTTP 缺省均不可用。宿主为每一步创建全新实例，每一步沙箱执行最多 200 ms、32 MiB；HTTP 每次默认 10 秒，使用方可用 `Options.RequestTimeout` 配置，最多 30 秒。生产宿主拒绝 `source_commit=uncommitted` 的包（`Options.TestOnlyAllowUncommitted` 仅供本地与回放），上传审批时应先用 `Manifest.Committed()` 拒绝。completed/rejected/unknown/not_sent 必须由业务层明确处理。尤其 unknown 保留原单并主动查询；回调通过也仅触发查单。默认 HTTPS，测试 HTTP 选项必须在生产配置拒绝。网络提供者必须遵守取消、不重试、不跳转并实施 DNS/IP/代理出口限制；本核心无法抢占不遵守 context 的任意 Go 环境实现。

## 编写插件

在 main 包 init 中向 sdk 注册六个普通 Go 处理函数。用 `sdk.Input[T]` 严格解析输入，通过 `sdk.Config/Sign/Verify/Equal/Log` 调用宿主，再返回 `sdk.Request/Result/Reject/Fail`。不写任何指针或内存代码，全部导入/导出由 SDK 提供；实例之间只通过 responses 传递已收到的上游响应。样例见 [JSON-RSA](plugins/sim_json_rsa/main.go)、[Form-MD5](plugins/sim_form_md5/main.go) 和共享的 [协议翻译](internal/simprotocol/protocol.go)。

金额使用带币种的最小单位字符串。签名可用 `sdk.Secret("shared")` 引用密钥拼接；Bearer 令牌头使用 `Bearer {{secret:access_token}}`，宿主发送时替换。签名、非密钥配置和请求头占位都不能用于导出凭据。

## fixtures 与录制

每个模拟器插件有 28 个用例：五个 HTTP 操作各覆盖成功、拒绝、超时、签名错误和金额不符；回调覆盖成功、签名错误和金额不符。所有账户/订单均为明确的本地测试数据。

本次使用相邻 upstream-sim 在 **test 环境、127.0.0.1:9080** 实录：成功、明确拒绝、破坏签名后得到的 HTTP 400、create 的真实超时以及真实回调（含签名错误、金额不符）。模拟器没有其他操作的延迟/应答金额篡改开关，因此其他操作的超时为构造传输故障，五个 HTTP 操作的金额不符为实录应答修改 amount。每个 fixture.source 明确标记来源。

有效请求签名在持久化前替换为占位；有效回调回放时使用运行时生成的测试密钥重新签名。业务正文、事件、金额与应答保持录制字节。fixture 中无私钥/共享密钥，公开随机种子只用于重放 WASI 随机，不是密钥。回归报告按 fixture 原始字节和实际结果生成；同一包两次回放摘要必须相同。修改 fixtures 必须重新生成并绑定报告摘要。

不带 `--case` 时使用本机回环模拟器的内置录制配方，显式开关不可省略；测试令牌从环境读取，不写入包。

```sh
# 先按 upstream-sim README 启动 test 环境；保持同一测试令牌在当前环境。
bin/pluginctl record --test-only --dir dist/sim_json_rsa \
  --sim-url http://127.0.0.1:9080 --out plugins/sim_json_rsa/fixtures
bin/pluginctl record --test-only --dir dist/sim_form_md5 \
  --sim-url http://127.0.0.1:9080 --out plugins/sim_form_md5/fixtures
make plugins-replay
```

内置配方需要模拟器自动生成的测试凭据，会读取受控凭据端点并在内存使用，监听临时回环回调端口、创建测试单、点击模拟付款并生成模拟退款。重录使用新的测试订单前缀，避免污染原测试订单幂等结果。

其他测试上游可以按单个操作输入录制：

```sh
bin/pluginctl record --test-only --dir dist/test_plugin --case case.local.json \
  --credentials-env PLUGIN_TEST_CREDENTIALS --out dist/test_plugin/fixtures
bin/pluginctl replay --dir dist/test_plugin --credentials-env PLUGIN_TEST_CREDENTIALS
```

case 是 `host.Fixture` 的输入计划，至少包含 name（operation/scenario）、operation、input、config；time/random_seed 省略时由录制器生成并记录，expected 可选指定预期 category/error_code。上游的测试单、故障场景和签名回调输入由调用者准备。录制器执行真实请求，不伪造应答或支付/退款前置条件；保持全部响应头和正文，传输错误记录为独立交换结果。HTTP 还需显式 `--allow-test-http`，默认只允许 HTTPS。

凭据环境值是严格 JSON：`secrets` 为引用名到仅测试用密钥文本的 map，`public_keys` 为引用名到 PKIX RSA 公钥 PEM 的 map。私钥/共享密钥只在内存中解析；记录前将头中已解析的凭据还原为引用占位，检查凭据原文/编码并拒绝泄漏。有效的通用回调保存原签名，重放时注入相同测试凭据；模拟器自动回调模板仍使用默认 Replay，或由 `ReplayWithEnvironment` 的协议签名器处理。不得使用真实账户或生产凭据。

## 使用边界

公开仓库不得放真实密钥、商户数据或个人信息；本地配置、密钥文件、编译产物被忽略。包加载不是审批，回放通过不是资金链路验收。宿主不存储证据、不执行平台订单状态变更；服务必须保留原始证据的加密存储、独立查询与对账、双人审批、生产禁用模拟器等边界。当前没有生产发布或相邻仓库修改。
