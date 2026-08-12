# Otto 联邦网关协议 v1

## 1. 定位

Otto Federation 是跨私有部署的消息中继和信任边界，不是模型网关，也不是普通反向代理。
它基于 [Fastify](https://github.com/fastify/fastify)（MIT）构建独立进程，使用 PostgreSQL
保存部署目录、签名公钥、密文信封、投递状态和最小审计元数据。

Fastify 负责 HTTP 生命周期、限流和输入边界；部署身份、Ed25519 验签、防重放、A2A 授权、
幂等和投递状态机均由 Otto 自己的协议层实现。替换 Caddy、负载均衡器或 Fastify 不得改变这些安全语义。

## 2. 数据边界

网关可见：

- 发送和接收 deploymentId
- 信封类型、签发/过期时间、消息大小和投递状态
- 不透明的本地账号 ID、会话 ID 和 A2A scope
- ciphertext 的 SHA-256

网关不得获得：

- 聊天正文、附件明文或附件解密密钥
- A2A 问题、回答、工作日志、知识或日程正文
- 客户端 E2EE 私钥

`ciphertext` 必须是无填充 base64url，`contentType` 固定为
`application/otto-e2ee+json`。应用层先在私有服务器或桌面端完成 E2EE，再把密文交给网关。
结构化日志会遮盖 `ciphertext`、签名、领取令牌和管理员凭据。

## 3. 部署身份

每个私有部署有稳定的 `deploymentId`、HTTPS origin、能力列表和一个或多个 Ed25519 公钥。
公钥 ID 是 SPKI DER 的 SHA-256 前 16 个十六进制字符。私钥只存在于对应私有部署，不能上传到
Otto Control 或 Federation。

生产注册流程：

1. Control 管理员核验客户和 License 绑定关系。
2. 客户服务器本地生成 Ed25519 密钥。
3. 管理员把 deploymentId、HTTPS origin 和公钥登记到 Federation。
4. 旧公钥与新公钥可并行，完成轮换后撤销旧公钥。
5. deployment 被 blocked/disabled 或公钥被 revoked 后，所有新请求立即 fail-closed。

目录只允许按已知 deploymentId 和 keyId 单条查询，不开放客户全量枚举。

## 4. 签名信封

签名输入是 `canonicalJson(envelope)` 的 UTF-8 字节，算法固定 Ed25519：

```json
{
  "envelope": {
    "version": 1,
    "messageId": "fmsg_...",
    "type": "chat.message",
    "senderDeploymentId": "deployment_a",
    "recipientDeploymentId": "deployment_b",
    "issuedAt": "2026-08-02T10:00:00.000Z",
    "expiresAt": "2026-08-03T10:00:00.000Z",
    "nonce": "nonce_...",
    "contentType": "application/otto-e2ee+json",
    "ciphertext": "base64url...",
    "routing": {
      "conversationId": "conversation_...",
      "senderPrincipalId": "account_...",
      "recipientPrincipalId": "account_..."
    }
  },
  "signingKeyId": "0123456789abcdef",
  "signature": "ed25519:base64url..."
}
```

防护顺序：

1. 校验协议版本、长度、HTTPS 部署状态和目标。
2. 校验签发时间、时钟偏差、过期时间和最大 TTL。
3. 读取发送部署的 active 公钥并验签。
4. 原子写入 nonce，重放返回 409。
5. 检查双向黑名单和目标积压上限。
6. 在事务中消费 A2A grant 并写入消息。

同一发送部署重复提交完全相同的 `messageId + ciphertextSha256` 是幂等成功；相同 messageId
绑定不同密文或发送部署会被拒绝。

## 5. 离线投递与回执

接收部署用自身 Ed25519 私钥签署 `inbox/claim` 请求。网关通过 PostgreSQL
`FOR UPDATE SKIP LOCKED` 原子领取消息，返回一次性 claim token；数据库只存 token 的 SHA-256。

状态机：

```text
pending -> claimed -> delivered
    |          |
    +----------+-> expired
```

领取租约到期但没有 ack 时，消息可再次领取。ack 必须由目标 deployment 签名，并同时匹配
messageId、未过期租约和 claim token。消费者必须在本地成功持久化密文后再 ack。
已送达和已过期密文默认保留 7 天后自动清除，可用
`FEDERATION_DELIVERED_RETENTION_MS` 在 1 小时至 90 天之间调整。
每次领取还受 `FEDERATION_MAX_CLAIM_BYTES` 总字节预算约束，默认 4 MiB，避免积压的大消息
生成超大 HTTP 响应。该值不得小于单条密文上限 `FEDERATION_MAX_CIPHERTEXT_BYTES`。

大型附件不进入消息队列。客户端先以独立随机密钥流式执行 AES-256-GCM 加密，再由发送部署签名申请
短时 S3/MinIO 上传地址。网关校验密文大小和 SHA-256 后才将对象标记为 ready；消息只能引用
双方部署、状态和有效期均匹配的附件 ID。接收部署签名申请短时下载地址，客户端核对密文大小与
SHA-256 后在本机解密。网关、对象存储和双方企业服务器均不保存附件密钥、文件名或原文。
附件到期后数据库记录和对象一并清理；默认单个对象上限 1 GiB。

## 6. A2A 一次性授权

A2A grant 只能由资料拥有方 deployment 签名创建，至少绑定：

- owner/requester deployment
- owner/requester principal
- 明确 scope
- 过期时间
- maxUses，默认 1

`a2a.request` 的 scope、双方身份和目标必须完全匹配 grant。授权次数递增和消息写入在同一个事务中；
并发请求只有一个能成功。`a2a.response` 必须引用已授权请求，并反向匹配部署与双方 principal。

网关只检查授权元数据，不读取 A2A 问题和回答。接收方 Otto 仍必须显示用户批准界面，并在本地
限制可读取资料；联邦 grant 不能绕过 Otto 本地权限。

## 7. API

部署接口：

```text
GET  /health/live
GET  /health/ready
GET  /v1/federation/status
GET  /v1/federation/directory/:deploymentId
GET  /v1/federation/directory/:deploymentId/keys/:keyId
POST /v1/federation/envelopes
POST /v1/federation/inbox/claim
POST /v1/federation/inbox/ack
POST /v1/federation/a2a/grants
POST /v1/federation/a2a/grants/revoke
POST /v1/federation/attachments/uploads
POST /v1/federation/attachments/complete
POST /v1/federation/attachments/download
```

运维接口使用文件挂载的 `FEDERATION_ADMIN_TOKEN`，只允许 Control 后端或隔离运维网络调用：

```text
GET    /v1/admin/federation/status
GET    /v1/admin/federation/deployments
POST   /v1/admin/federation/deployments
PATCH  /v1/admin/federation/deployments/:deploymentId/status
POST   /v1/admin/federation/deployments/:deploymentId/keys
POST   /v1/admin/federation/deployments/:deploymentId/keys/:keyId/revoke
POST   /v1/admin/federation/deployments/:deploymentId/blocks
DELETE /v1/admin/federation/deployments/:deploymentId/blocks/:blockedDeploymentId
```

## 8. 生产拓扑

`compose.production.yaml` 提供三个无状态 Federation 实例，Caddy 按健康状态负载均衡，三者共享
Patroni PostgreSQL。消息领取、nonce 和 grant 消费依赖数据库事务，因此任一实例重启不会重复授权。

生产必须：

- 为 `FEDERATION_DOMAIN` 配置独立域名和 TLS
- 把 admin/metrics token 作为不同 Docker secret
- 限制 admin 路由只能由 Control 或运维网络访问
- 监控队列长度、HTTP 错误率、领取重试和数据库连接
- 定期轮换部署公钥；私钥使用客户 KMS/HSM 或权限严格的本地密钥文件
- 对 PostgreSQL 启用现有加密备份、PITR 和驻留策略
- 为加密附件配置独立 S3/MinIO 前缀、服务端加密、最小权限凭据和生命周期清理

## 9. 当前边界与后续阶段

v1 完成中央密文中继，能在 NAT、动态公网地址和接收方离线时工作。它不是 Matrix/Signal 的替代实现，
也不宣称单靠网关达到 Signal 等级安全。E2EE 密钥协商和设备信任继续由 Otto E2EE 模块负责。

后续可以在不改变信封格式的情况下增加：

- 多区域 Federation 节点和区域内路由
- 已互信部署间的直连投递，中央节点只做目录和离线后备
- Control 管理员 RBAC 前端代替直接使用 federation admin token
- 联邦域名所有权证明和自动公钥轮换协议
