# Edge Gateway 多节点统一计费聚合

多边缘节点不共享本地计费 journal，也不得把 journal 放到 NFS/SMB。每个节点继续使用自己的
本地追加日志负责断网恢复，恢复连通后把签名执行回执提交到 Control 的 PostgreSQL 聚合队列。
PostgreSQL 是跨节点对账状态的唯一权威来源。

## 身份与顺序

- 每个节点使用不可复用的 `edge_<32 hex>` 身份和独立 Ed25519 执行回执密钥；同一密钥不能绑定
  两个节点。
- 管理员先注册执行回执公钥，再通过
  `POST /v1/admin/deployments/:deploymentId/edge-billing-nodes` 完成节点绑定。注册和撤销沿用
  双人审批，审计只记录节点、部署和公钥 ID，不记录私钥。
- `POST /v1/billing/edge-events` 使用短期 lease 认证。事件中的租户、部署、节点、公钥和签名回执
  必须全部匹配，服务端不信任 URL、节点自报租户或对象路径。
- 每个节点维护独立、从 1 开始且严格单调的序列。Control 可暂存先到达的高序号事件，但只处理
  `lastSequence + 1`；因此节点 A 的中断不会阻塞节点 B，也不会出现全局序列冲突。
- `eventId`、`receiptId`、`(nodeId, nodeSequence)` 均有唯一约束。相同 `eventId` 只有在规范化
  负载 SHA-256 完全相同时才作为幂等重放接受。

Edge Gateway 将注册得到的节点 ID 通过 Secret 文件映射到进程环境后启用聚合提交：

```text
OTTO_EDGE_BILLING_NODE_ID=edge_<32位小写十六进制>
```

未配置该值时保留旧的单节点回执接口，便于滚动升级；不得在多节点部署中使用旧模式。

## 状态机与恢复

事件状态为 `pending -> retrying -> reconciled`，连续 8 次处理失败后进入 `dead_letter`。重试采用
有上限的指数退避。处理执行回执、信用余额和节点序列时由 PostgreSQL 行锁与事务约束；即使
Control 在扣费后、更新队列状态前崩溃，下一次处理也会通过 `receiptId` 返回原结果，不会重复扣费。

乱序不会被静默丢弃。缺少的序列到达后，同一节点的连续事件会按序补齐。被撤销节点及其公钥
不能提交或继续处理事件。死信需要先解决额度、费率、Hold 或身份问题，再由有 `billing.manage`
权限的管理员调用：

```text
POST /v1/admin/billing/edge-aggregation/retry
{ "limit": 100 }
```

Control 进程还会每 10 秒扫描一次可处理事件。多实例可同时扫描；账户、节点序列、回执唯一键和
幂等事务保证只结算一次。

## 健康和对账

`GET /v1/admin/billing/edge-aggregation/status?deploymentId=<id>` 返回：

- 节点总数、活跃数和撤销数；
- `pending`、`retrying`、`deadLetter`、`reconciled` 数量；
- 存在序列缺口的节点数；
- 最早未完成事件时间。

生产告警至少覆盖：`deadLetter > 0`、`sequenceGaps > 0` 持续超过节点离线宽限期、最早未完成
事件年龄超过 SLA、活跃节点长时间没有 `lastSeenAt`。月度对账以 Control 已验证执行回执和信用
交易为准，按 `edgeNodeId`、`edgeEventId`、供应商请求 ID 对齐节点 journal、Control 账单与供应商
账单。节点本地文件只用于重传，不是统一账单权威源。
