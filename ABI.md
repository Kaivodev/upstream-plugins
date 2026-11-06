# Kaivo plugin ABI v1

`abi.Version = 1`。不兼容修改必须升级版本，宿主与 SDK 同步修改。ABI 包只使用标准库，可以编译到 `wasip1/wasm`。当前仅实现 `payment`；`fetch_statement`、`parse_statement` 保留给 M4，声明它们的 statement 包当前不能加载。

## 模块与内存约定

固定 Go `go1.27.3`，官方工具链，`GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -buildvcs=false -buildmode=c-shared -ldflags=-buildid=`。模块导出 `memory`，不得导入内存、表、全局或其他非函数实体。

| 导出 | WASM 类型 | 行为 |
| --- | --- | --- |
| `_initialize` | `() -> ()` | WASI reactor 初始化，宿主首先调用，纳入执行预算 |
| `abi_version` | `() -> i32` | 必须返回 1 |
| `alloc` | `(i32 length) -> i32 pointer` | 分配输入缓冲区，长度 1..1048576，失败返回 0 |
| `dealloc` | `(i32 pointer, i32 length) -> ()` | 释放宿主分配的输入缓冲区 |
| 六个支付操作 | `(i32 pointer, i32 length) -> i64` | 输入 Call JSON，返回 Step JSON 的地址和长度 |

返回 `i64 = (uint64(pointer) << 32) | uint64(length)`，高 32 位为地址，低 32 位为字节数。所有地址为 wasm32 线性内存偏移。输出由插件持有，至少到下次操作入口调用前有效；宿主立即复制并关闭实例。SDK 管理全部指针、缓冲区和导出，作者注册普通 `func(sdk.Call) sdk.Step` 即可。

每个步骤实例都是全新的；初始化、版本检查、分配、操作和释放在同一实例执行。分步操作累计使用最多 **200 ms 的沙箱执行墙钟时间**（包含初始化与宿主函数），网络等待单独计时。达到预算时 wazero 关闭实例。每个实例最多 512 页、32 MiB；输入 Call 与输出 Step 各不超过 1 MiB。一次操作至多五个步骤，最终结果也占一步，因此最多四次 HTTP 交换。所有宿主导入累计最多 4096 次，其中 `kaivo` 最多 128 次。WASI 单次随机读取最多 64 KiB、累计 256 KiB，单次 fd_write 最多 64 个 iovec，防止单个宿主调用绕过执行预算。

JSON 必须是有效 UTF-8，深度不超过 64；拒绝未知字段、大小写别名、任意深度重复键、尾随数据和 null 根对象。必要字段与互斥关系还由语义校验检查。`[]byte` 按标准 JSON Base64 编码；字符串不经过浮点数转换。

## 分步协议

```json
{"input":{"order_id":"test_order","money":{"amount":"12345","currency":"CNY"}},"responses":[]}
```

`input` 使用对应操作的类型；`responses` 是宿主收到的完整历史响应。Step 严格二选一：

```json
{"request":{"method":"POST","url":"https://gateway.example/api","headers":{"Content-Type":["application/json"]},"body":"e30="}}
```

```json
{"result":{"outcome":"rejected","code":"channel_rejected"}}
```

Request 为 `{method, url, headers, body}`，Response 为 `{status, headers, body}`，头部是 `map[string][]string`，保留重复值。响应中不注入传输错误：传输错误立即终止操作，避免插件把“没有收到应答”编造成拒绝。

Result 为 `{outcome, code?, payment?, refund?, callback?}`。`completed` 必须且仅能包含该操作的输出对象；`rejected` 必须有不超过 128 字节的 code 且不能有输出对象；`unknown` 与 `error` 立即进入宿主失败分类。code 不能携带任意上游正文或调试栈。

## 操作形状

`Money = {amount, currency}`：amount 是无符号、无前导零（零除外）、最多 78 位的十进制**最小货币单位**字符串，currency 为 3..12 位大写字母/数字代码（首字符为字母）。调用输入要求金额大于零。`abi.ParseAmount` 返回 `*big.Int`；`abi.EqualMoney` 精确核对金额与币种。服务映射 int64 时还须检查 `IsInt64()`。两个模拟器插件只支持正 int64 的 CNY 分。

| 操作/导出名 | input | completed 输出 |
| --- | --- | --- |
| `create_payment` | `CreatePaymentInput`: order_id、money、method、callback_url；可选 bank_mode、instruction | payment |
| `query_payment` | `PaymentInput`: order_id、money（订单快照预期值） | payment |
| `close_payment` | 同 PaymentInput | payment |
| `refund` | `RefundInput`: order_id、refund_id、money | refund |
| `query_refund` | 同 RefundInput | refund |
| `verify_callback` | `CallbackInput`: order_id、money（已查得的原订单预期值）、method、headers、body；可选 raw_query、source_ip | callback |
| `fetch_statement` / `parse_statement` | 未定义 | M4，当前明确不支持 |

- `PaymentOutput = {order_id, upstream_id, money, status, url?, qrcode?, paid_at?}`。status 为 pending/paid/closed/failed/unknown；url 与 qrcode 至多一个，下单 pending 时必须有一个。url 必须 HTTPS（显式测试模式例外），paid_at 若存在必须 RFC3339Nano。
- `RefundOutput = {order_id, refund_id, upstream_refund_id, money, status}`。status 为 pending/succeeded/failed/unknown。模拟器没有独立上游退款号，使用它的 refund_id。
- `CallbackOutput = {event_id, order_id, upstream_id, money, status, ack}`。status 同付款状态，ack 是 Response，状态、Content-Type、正文必须与 manifest 回调规则一致。模拟器应答为 HTTP 200、text/plain、原文 `success`。

所有结果的 order_id/refund_id 必须与输入完全一致，money 必须精确一致。HTTP 支付操作没有收到响应就返回 completed/rejected 都不采信。回调 method 与 raw_query 规则遵循 manifest，body 不超过 64 KiB、raw_query 不超过 16 KiB；两个模拟插件只允许 POST 且不允许 query；服务先按不可信路由信息查找候选原订单，再把预期 ID/金额传入验签，回调结果只触发主动查单。证据保留、加密、摘要、channel_id 绑定与状态机属于使用服务，不由插件提供可信状态。

## `kaivo` 导入

所有函数类型均为 `(i32 in_ptr, i32 in_len, i32 out_ptr, i32 out_capacity) -> i32 out_len`。输入/输出均为 JSON；成功输出统一为 `{"value":...}`。SDK 提供 64 KiB 返回缓冲区。无效参数、超限、服务错误或密钥泄漏立即终止实例，不把服务错误原文交给插件。输入/容量最多 1 MiB。

| 函数 | 输入 | value |
| --- | --- | --- |
| `config` | `{name}` | manifest 声明的非密钥 string 配置 |
| `sign` | `{algorithm, key?, parts}` | md5/sha1/sha256/hmac-sha256 的小写 hex，rsa-sha256 的标准 Base64 |
| `verify` | `{algorithm, key, parts, signature}` | bool；当前只支持 rsa-sha256（PKCS#1 v1.5、SHA-256、至少 2048 位公钥） |
| `equal` | `{a, b}` | 常数时间比较 bool |
| `log` | `{level, message, fields?}` | true；level 为 debug/info/warn/error，fields 为 string map |

Part 为 `{data?: <Base64 bytes>, secret?: <reference name>}`，两者互斥；空 data 是空字节串。parts 最多 128 个，解析后总量最多 1 MiB。共享密钥可作为 part；HMAC 的 key 是 shared 引用；RSA 的 key 是 rsa-private 引用，私钥以 PKCS#8 PEM 在宿主解析。非 HMAC/RSA 算法不接受 key。算法只用于上游协议，不替代平台审批签名安全规则。

密钥解析仅发生在宿主，不存在读明文的导入。公钥也按 manifest 引用解析。宿主在执行前解析本次所有声明的密钥，检测其原文、大小写 hex、标准/URL Base64（含无填充形式）；宿主返回、插件输出、请求、响应和日志受到检查。密钥值及编码不得出现在插件输出/日志；检测后丢弃结果、停止执行并调用不含密钥的 Alert。插件不能通过响应反射取回请求头凭据。日志缓冲在整个操作结束后才交给 Logger，避免 stdout 分块漏检；每次操作日志最多 8 KiB、32 个写入事件，超出即终止。

## WASI 子集

只接受以下 WASI 导入（Go 标准库会链接其中的文件/描述符桩）：

`args_get`, `args_sizes_get`, `environ_get`, `environ_sizes_get`, `clock_time_get`, `random_get`, `sched_yield`, `poll_oneoff`, `proc_exit`, `fd_write`, `fd_read`, `fd_close`, `fd_seek`, `fd_fdstat_get`, `fd_fdstat_set_flags`, `fd_filestat_get`, `fd_prestat_get`, `fd_prestat_dir_name`, `path_open`, `path_filestat_get`。

无预打开文件、环境变量、命令行参数；stdin 默认 EOF。文件操作找不到可用的宿主文件系统，socket 导入不在白名单。stdout/stderr 转入上述受限缓冲。wall clock 来自 Environment；单调时钟按宿主虚拟 tick 前进；random 来自 Environment 的 Reader。`proc_exit`（包括 0）终止操作并报告 proc_exit，不等同于业务成功。

## HTTP 与分类

请求只能使用 HTTPS，Hostname 按 manifest 精确匹配，不做后缀匹配；不允许用户凭据和 URL 片段。仅 `Options.TestOnlyAllowHTTP` 允许 HTTP，生产服务必须在配置边界拒绝该选项。禁止 Host、Content-Length、Connection、Transfer-Encoding、代理凭据等传输控制头；头部总量最多 16 KiB，拒绝控制字符与不同大小写的重名头。请求/响应正文各最多 256 KiB，每次请求默认 10 秒（`Options.RequestTimeout`，最多 30 秒），禁止任何 3xx；只调用一次 RoundTripper，不自行重试。

**请求头凭据占位扩展**：例如 `Authorization: Bearer {{secret:access_token}}`。每个头值最多一个占位，引用必须声明为 shared；替换在宿主构造请求时完成，明文不回写插件。URL、正文和其他位置不替换。Environment.Transport 属于可信边界，负责 DNS/IP、代理、实际出口、连接安全与响应头资源限制，必须遵守 context，不能自行重试/重定向。调用方可以只提供受控传输，不需要允许默认网络。

| Category | 含义 |
| --- | --- |
| completed | 结构、ID、金额和协议结果通过校验 |
| rejected | 插件明确拒绝，且本操作已收到至少一个合法上游响应 |
| unknown | 已进入传输派发边界后遇到插件错误、超时、非法输出、金额不符、3xx 或传输失败；调用方只查询原单，不重新下单/退款 |
| not_sent | 尚未派发请求即失败，可安全重试；非法回调也使用该分类，不表示业务拒绝 |

`Execution` 还包含稳定的 error_code、请求/响应/步骤计数和可选 result；PeakMemoryBytes 只用于测量，不进入 JSON/回归摘要。raw wazero 堆栈和依赖错误不向调用方透传，避免凭据进入错误消息。

## manifest、包与回放

manifest 字段以 `host.Manifest` 为准：type(payment/statement)、code(`^[a-z0-9_]{2,32}$`)、SemVer 2 version、abi_version、精确 domains、secrets(name → shared/rsa-private)、public_keys、config(name → `{type:"string",required:bool}`)、capabilities、callback、build。配置名称为 `^[a-z][a-z0-9_]{0,63}$`，密钥/公钥/非密钥配置不得重名。callback 包含 methods、allow_query、content_types、ack_status、ack_content_type、ack_body；build 包含 go_version、source_commit、source_tree_sha256。

manifest 最大 64 KiB，plugin.wasm 最大 16 MiB。规范 manifest 为：严格解码到 Manifest 后重新序列化并将对象键按字节排序、无额外空白；数组顺序保留。包哈希 `SHA-256(normalized_manifest || plugin.wasm)`，不含分隔符和 fixtures。包目录与 fixture 文件禁止链接；fixtures 路径必须在 fixtures/ 下、规范相对路径、无重复/穿越，至多 256 个文件、单文件 1 MiB、总计 16 MiB。

Fixture 字段见 `host.Fixture`：name(operation/scenario)、source（来源说明）、operation、input、config、time（UTC RFC3339Nano）、random_seed（32 字节公开测试熵）、exchanges、expected，以及可选 test_only_resign_callback。每次操作回放使用固定 wall clock 和 SHA-256(seed||counter) 测试随机流；HTTP 替换为严格匹配录制请求的离线传输。请求的临时测试签名替换为 `TEST_SIGNATURE_REGENERATED_AT_REPLAY`；原始 JSON/其他业务字节仍精确比对。有效回调模板在内存中重新签名；fixture 不保存共享密钥/私钥。签名正确性另以真实录制和算法交叉测试验证。

请求头录制值可以保留 `{{secret:引用名}}`；离线传输只在宿主内存展开预期值后匹配，不将密钥写入报告。默认 Replay 支持模拟器回调模板。任意上游可以使用 `ReplayWithEnvironment` 提供临时测试凭据和回调模板签名器；框架仍强制使用录制的配置、时间、随机与离线出口，签名器必须保留业务字节。每个声明的支付能力必有 success/rejected/timeout/signature_error/amount_mismatch；verify_callback 只要求 success/signature_error/amount_mismatch，因为它禁止发请求。fixture 中的 expected 分类必须与场景语义一致。

回归报告包括版本、包哈希、按 path 排序的 case、fixture 原始字节 SHA-256、结果、计数与通过标记。报告使用对象键排序、无空白的规范 JSON，不包含耗时、内存或临时签名；SHA-256 对这些规范字节计算，不含末尾换行。单个失败或缺失场景使 Replay 返回错误；使用方不得继续审批。fixtures 不在包哈希里，必须和宿主生成的报告摘要一起绑定在审批材料中。
