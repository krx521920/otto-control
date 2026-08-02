# Otto 私有服务器联邦适配合同

## 目标

每个 Otto 私有服务器运行一个本地 federation adapter。它把现有企业私聊/A2A 数据模型与
Federation v1 信封互相转换，不让桌面端直接持有网关管理员凭据。

## 本地职责

1. 用 License 绑定的 deploymentId 启动；缺少授权模块 `federation` 时 fail-closed。
2. 生成或加载部署 Ed25519 私钥，私钥不进入数据库、日志、诊断包和 Control。
3. 发送前解析远端联邦地址，验证联系人已经由用户或企业管理员建立信任。
4. 使用 Otto E2EE 会话密钥加密正文/附件清单，再签署 Federation envelope。
5. 定时签署 claim 请求；密文成功落入本地持久队列后再 ack。
6. 使用目录公钥再次验证原始 envelope，随后才允许 E2EE 层解密。
7. 把远端 principal 映射为 `deploymentId:principalId`，禁止与本地 accountId 混淆。
8. A2A 仍走本地单次授权弹窗；联邦 grant 和本地用户批准必须同时有效。

## 能力握手

私有服务器至少声明：

```json
{
  "capabilities": ["chat.e2ee", "a2a.e2ee", "federation.v1"]
}
```

发送端不得向缺少对应能力的部署降级发送明文。旧 Otto Server 不认识联邦协议时，应明确显示
“对方服务器暂不支持跨企业协作”，不能静默改走普通企业消息接口。

## 本地数据映射

| Federation | Otto Server |
| --- | --- |
| `chat.message` | 远端私聊消息，正文在本地 E2EE 解密后显示 |
| `chat.receipt` | 已送达/已读状态，不作为聊天正文 |
| `a2a.request` | A2A 待授权队列；弹出接收方批准界面 |
| `a2a.response` | 精确匹配原 requestId，结束对应 A2A 请求 |

本地数据库应保存原始签名信封、验证结果和远端部署 ID；正文保存策略服从企业 E2EE 与留存设置。
不得把远端消息直接调用工具，必须继续使用现有 tool-free A2A runtime。

## 重试与幂等

- 本地 outbox 先落盘，再向 Federation 发送。
- 先调用 `FederationClient.createSignedEnvelope()`，把完整签名信封写入本地 outbox，
  再调用 `sendSignedEnvelope()`；重试必须复用同一 messageId、nonce、ciphertext 和签名。
- 收件箱以 `senderDeploymentId + messageId` 去重。
- 本地持久化失败时不 ack，等待 claim 租约后重新投递。
- E2EE 解密失败时隔离消息并提示安全异常，不丢弃证据，也不向 Agent 注入乱码。
