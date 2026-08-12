# Otto Federation 生产运维手册

## 1. 安全边界

Federation 只保存和转发 E2EE 密文。网关可见部署 ID、消息类型、时间、大小、投递状态和必要的路由标识，不持有聊天、附件或 A2A 正文的解密密钥。任何运维操作都不得要求客户上传 E2EE 私钥。

生产拓扑由 Caddy、三个无状态 Federation 实例和共享的 Patroni PostgreSQL 组成。三个实例必须使用同一数据库，但必须与 Control 使用不同的管理员 Token 和指标 Token。

## 2. 私有服务器准入

准入前必须核对：

1. `deploymentId` 已绑定有效客户和 License。
2. 回调 origin 使用客户控制的 HTTPS 域名。
3. 客户服务器本地生成 Ed25519 密钥，只提交公钥。
4. 明确授权能力，只开放实际购买并启用的 `chat.e2ee`、`a2a.e2ee`。
5. 根据套餐设置消息数、密文字节和每分钟请求上限。

登记请求示例：

```http
POST /v1/admin/federation/deployments
Authorization: Bearer <federation-admin-token>
Content-Type: application/json

{
  "id": "deployment_customer_a",
  "displayName": "Customer A",
  "origin": "https://otto.customer-a.example",
  "capabilities": ["federation.v1", "chat.e2ee", "a2a.e2ee"],
  "maxPendingMessages": 10000,
  "maxPendingBytes": 536870912,
  "maxRequestsPerMinute": 1200
}
```

登记后先添加公钥，再从客户服务器完成目录查询、密文发送、领取和回执测试。不得跳过 License、域名所有权和联系人核验。

## 3. 密钥轮换

1. 客户服务器生成新 Ed25519 密钥。
2. 使用管理接口登记新公钥，并设置 `notBefore` 和可选的 `expiresAt`。
3. 新旧公钥并行至少一个最大消息 TTL，确认所有实例已改用新 key ID。
4. 撤销旧 key ID。被撤销的 key ID 永远不能重新激活。
5. 检查审计事件和拒绝指标，确认没有仍使用旧密钥的服务器。

紧急泄露时立即撤销密钥并把部署设为 `blocked`。确认事件处理完成后，只能登记全新的 key ID 再恢复部署。

## 4. 停用、黑名单与滥用处置

- 单客户停用：将部署状态设为 `disabled`。
- 安全事件：将部署状态设为 `blocked`，现有未投递密文立即过期。
- 双边纠纷：在任一部署下建立 block，双方未投递密文立即过期。
- HTTP 洪泛：Caddy/Fastify 先按来源限速，签名通过后再由 PostgreSQL 按 deploymentId 全局限速。
- 超过配额：返回 `429 RATE_LIMITED`。
- 收件箱容量耗尽：返回 `429 CAPACITY_EXCEEDED`。

每次处置必须记录事件编号、原因、操作人、开始时间、恢复条件和客户通知状态。恢复前检查公钥、License、积压量和最近拒绝原因，不允许只修改 UI 状态。

网关内的准入、状态、密钥和双边 block 审计可通过 `GET /v1/admin/federation/audit-events` 查询。该接口只返回操作元数据，不返回密文。

## 5. 容量与积压

```http
GET /v1/admin/federation/deployments/:deploymentId/operations
Authorization: Bearer <federation-admin-token>
```

响应提供消息数、密文字节和利用率，不返回任何 ciphertext。容量调整必须结合套餐和数据库增长趋势；不要通过无限提高上限掩盖客户端长期不领取消息的问题。

重点指标：

- `otto_federation_messages{status="pending"}`
- `otto_federation_queue_bytes{status="pending"}`
- `otto_federation_rejections_total{code="CAPACITY_EXCEEDED"}`
- `otto_federation_rejections_total{code="RATE_LIMITED"}`
- `otto_federation_http_requests_total`
- `otto_federation_http_request_duration_seconds`

## 6. 数据保留

待领取和已领取消息在信封 `expiresAt` 到期后变为 expired。delivered 和 expired 密文超过 `FEDERATION_DELIVERED_RETENTION_MS` 后删除；默认七天，可配置一小时至九十天。过期 nonce 和部署级限流窗口会随清理任务删除。

清理失败不得阻断实时投递，但必须告警。数据库备份仍按 Control 的加密备份、PITR 和异地保留策略执行。

## 7. 三实例验收

CI 和上线前验收必须启动 `federation-a`、`federation-b`、`federation-c`，再运行：

```sh
docker compose -f compose.ci.resolved.yaml \
  exec -T federation-a node --input-type=module < scripts/smoke-federation.mjs
```

烟测会从一个实例写入多条密文，同时向三个实例发起领取，并从不同实例确认。验收必须证明：没有重复租约、没有消息丢失、跨实例回执生效、重复发送保持幂等。

正式环境还要保存以下证据：三个实例健康结果、Prometheus 截图或查询结果、一次停用拒绝记录、一次过期删除记录和对应审计事件。证据不得包含 ciphertext、签名私钥、claim token 或管理员 Token。

三实例烟测必须将 JSON 输出保存为 `backups/reports/federation-three-replica.json`。随后运行
`deploy/drill-federation-failover.sh --confirm=FAILOVER_OTTO_FEDERATION_REPLICAS`，逐台停止并恢复
`federation-a`、`federation-b`、`federation-c`，证明 Caddy 联邦入口始终可用。CI 会把脱敏报告
作为 GitHub Actions artifact 保留 14 天；报告只允许包含提交号、时间、实例名和验收结论。
