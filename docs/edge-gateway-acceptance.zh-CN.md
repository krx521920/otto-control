# Otto Edge Gateway 长稳与成本容量验收

`scripts/edge-gateway-acceptance.mjs` 面向已经部署的真实 Edge Gateway，生成可版本化的
JSON 报告和逐请求 NDJSON 账本。它不替代供应商账单、外部安全审计或 24 小时环境本身，
而是把这些验收所需的流量、Token、成本和容量证据固定下来。

## 三种配置

| 配置 | 默认时长 | 默认并发 | 默认目标 RPS | 用途 |
| --- | ---: | ---: | ---: | --- |
| `ci-smoke` | 5 秒 | 4 | 10 | CI 或部署后的短时真实链路验证，最多 25 个请求 |
| `soak-24h` | 24 小时 | 8 | 2 | 内存、句柄、就绪状态和慢性错误观察 |
| `cost-load` | 5 分钟 | 128 | 200 | 高并发限流、上游容量和成本斜率验证 |

先生成无副作用计划：

```powershell
node scripts/edge-gateway-acceptance.mjs --profile=ci-smoke --plan-only
```

真实执行只从环境变量或文件读取访问令牌，不接受命令行明文令牌。所有执行都要求显式确认：

```powershell
$env:OTTO_EDGE_ACCEPTANCE_BASE_URL = 'https://edge.example.com'
$env:OTTO_EDGE_ACCEPTANCE_TOKEN = '<Control 签发的短时验收 Token>'
$env:OTTO_EDGE_OPERATIONS_TOKEN = '<运维只读 Token>'
$env:OTTO_EDGE_ACCEPTANCE_CONFIRM = 'RUN_REAL_EDGE_ACCEPTANCE'
node scripts/edge-gateway-acceptance.mjs --profile=ci-smoke --model='<测试模型>'
```

CI 应使用专用租户、专用模型额度和最多 25 次请求的短时 Token。不要复用生产用户 Token。

`soak-24h` 和 `cost-load` 不能复用一枚静态短时 Token。它们必须同时提供
`--control-url`、`--identity-file` 与 `--lease-token-file`；工具会使用部署租约按需续发
短时 Token，并在到期前 60 秒刷新。租约与 Token 均不会写入 NDJSON 或 JSON 报告。

24 小时长稳和高并发测试强制要求预算及输入、输出价格，工具按每次请求的最大输出量预留
最坏成本，预算不能覆盖一个请求时会拒绝启动：

```powershell
node scripts/edge-gateway-acceptance.mjs `
  --profile=soak-24h `
  --control-url=https://control.example.com `
  --identity-file=D:\secure\deployment-identity.json `
  --lease-token-file=D:\secure\lease-token `
  --model='<测试模型>' `
  --budget-usd=50 `
  --input-price-per-million-usd=1.25 `
  --output-price-per-million-usd=5 `
  --confirm=RUN_REAL_EDGE_ACCEPTANCE

node scripts/edge-gateway-acceptance.mjs `
  --profile=cost-load `
  --control-url=https://control.example.com `
  --identity-file=D:\secure\deployment-identity.json `
  --lease-token-file=D:\secure\lease-token `
  --duration-seconds=600 `
  --concurrency=256 `
  --rps=400 `
  --budget-usd=100 `
  --input-price-per-million-usd=1.25 `
  --output-price-per-million-usd=5 `
  --confirm=RUN_REAL_EDGE_ACCEPTANCE
```

## 验收证据

每次运行在 `reports/edge-acceptance` 下生成：

- `*.ndjson`：状态码、P50/P95/P99 所需延迟、Edge 请求 ID、供应商请求 ID和供应商返回的
  Token 用量；不记录访问令牌、提示正文或模型回复。
- `*.json`：错误率、吞吐、状态码分布、Token 与估算成本、30 天成本投影、峰值并发、
  带 30% 余量的观察值、就绪探测、运维容量起止快照、进程 RSS/Heap/CPU和事件循环延迟。

报告中的容量是本次负载下的观察值，不是产品硬上限。发布容量结论前，应至少在相同版本、
相同机器规格下重复三轮，配合服务器 CPU、内存、网络、Redis 与供应商控制台指标，并保留
原始报告。

## 对账步骤

1. 用 NDJSON 的 `edgeRequestId` 和 `upstreamRequestId` 对齐 Edge、Control 和供应商日志。
2. 汇总报告 `tokens`，按当次供应商价目计算估算费用。
3. 与 Control 的额度预留、结算、释放和不确定账单队列对齐。
4. 与供应商账单按模型、时间窗和 Token 数复核；差异不能只以金额比较。
5. 差异超过企业策略阈值时停止扩大流量，保留报告并进入人工核查。

真实 Redis 故障、Control 断网/策略过期/密钥撤销以及供应商 429、5xx、超时和慢流仍应由
独立故障注入脚本或受控测试代理执行；本工具负责在这些演练期间持续施压并记录用户侧结果。
