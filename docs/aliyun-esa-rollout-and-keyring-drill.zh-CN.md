# 阿里云 ESA 灰度发布与 Keyring 紧急撤销

本文规定 Otto Edge Gateway 在阿里云 ESA 上发布时的安全边界。仓库提供与云 SDK
解耦的状态机和预生产验收脚本；基础设施驱动负责把这些契约映射到 ESA API。本阶段不会
从开发机直接修改任何云资源。

## 不可变版本绑定

每个候选版本和当前基线都必须同时绑定以下内容：

- Worker 构建产物的 `sha256:<64位小写十六进制>` 摘要；
- 签名策略对象摘要；
- Keyring 修订号、完整对象摘要和活动 Key ID；
- 每个 ESA Secret 的提供方版本摘要，而不是 Secret 明文。

标签、`latest`、未版本化 Secret 和可变 EdgeKV Key 不能作为发布身份。部署驱动在暂存后
必须回读实际绑定；任何一项与候选清单不同，状态机在切流前失败关闭。

## 灰度状态机

实现位于 `src/edge-gateway/aliyun-esa-rollout.ts`。建议阶梯为 5%、25%、100%，并满足：

1. 首批流量不超过 10%，每一阶段只能单调增加，最后一步必须为 100%；
2. 每步切流都带确定性的幂等键；控制面重试不得创建第二个发布；
3. 健康样本必须达到最小请求数，并同时满足就绪、计费聚合就绪、错误率和 P95 门槛；
4. 探针必须回报它实际观察到的完整不可变版本绑定；只检查 HTTP 200 不算通过；
5. 任何阶段失败，立即把候选比例设为 0，恢复已钉住的基线并再次执行完整健康门槛；
6. 只有基线验证通过才能停用候选并写入 `rolled_back`；回滚验证失败必须进入
   `manual_intervention`，不得宣称发布或回滚成功；
7. 每个状态转换写入外部耐久 checkpoint。checkpoint 只含摘要、版本和健康数据，不含
   Secret、访问令牌或模型输入输出。

基础设施实现 `AliyunEsaRolloutDriver` 时，应把 checkpoint 写入独立于 ESA Worker 的
不可篡改审计存储，并为同一 `rolloutId` 加分布式锁。100% 健康门槛通过后可以停用旧
deployment 以避免继续接收流量，但不得删除它绑定的不可变 Worker、策略、Keyring 和
Secret 版本；这些旧版本只能在观察窗口结束后由单独的受审计退役任务清理。

## Keyring 紧急撤销预生产演练

演练入口是 `scripts/drill-esa-keyring-revocation.mjs`。它会执行已有的双人审批撤销流程，
然后在至少两个 ESA 预生产节点验证：

- 旧密钥签发且撤销前有效的 Token 在所有节点返回 401/`EDGE_UNAUTHORIZED`；
- 替代密钥签发的新 Token 在所有节点恢复成功；
- Control 公开 Keyring 由替代密钥签名并包含旧密钥的撤销状态；
- 审批请求、第二人批准、消费、探测和撤销事件存在完整审计证据。

脚本有三重防误操作：必须指定 `--environment=preproduction`、输入显式确认短语，并要求
Control 与每个节点都位于人工提供的预生产域名后缀。它拒绝单节点、重复节点、HTTP 地址
和 localhost。报告只保存节点 URL 的 SHA-256，不保存域名、管理员 Token、租户标识或
模型内容。

示例（占位值不能直接用于生产）：

```powershell
node scripts/drill-esa-keyring-revocation.mjs `
  --environment=preproduction `
  --confirm=REVOKE_OTTO_ESA_PREPRODUCTION_KEY `
  --allowed-host-suffix=pre.example.com `
  --control-url=https://control.pre.example.com `
  --node-urls=https://node-a.pre.example.com,https://node-b.pre.example.com `
  --identity-file=secrets/edge-acceptance-identity.json `
  --lease-token-file=secrets/edge-lease.token `
  --requester-token-file=secrets/requester.token `
  --approver-token-file=secrets/approver.token `
  --auditor-token-file=secrets/auditor.token `
  --subject-id=esa-keyring-drill `
  --model=acceptance-model `
  --key-id=0123456789abcdef `
  --replacement-key-id=fedcba9876543210 `
  --reason="批准的预生产紧急撤销演练" `
  --change-ticket=SEC-2026-0001 `
  --output=reports/esa-keyring-revocation.json
```

演练前必须确认替代密钥已提前分发且其 KMS/HSM `Sign` 探测通过。演练结束后不应“取消
撤销”旧 Key ID；测试租户应生成新的备用密钥，使 Keyring 重新具备双钥重叠能力。

## 仍需真实环境完成的事项

本状态机不替代以下人工和云端验收：ESA Secret/EdgeKV 实体创建、域名与 TLS、WAF 规则、
Terraform/ROS 资源落地、跨地域传播时延测量，以及生产变更审批。预生产演练报告只有在
真实 ESA 节点实际运行并由安全人员归档后，才能作为发布证据；单元测试报告不能代替它。
