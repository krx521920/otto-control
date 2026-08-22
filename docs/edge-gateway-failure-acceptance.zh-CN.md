# Edge Gateway 真实故障验收

本验收只能在独立的预生产部署执行。它会停止 Redis 和三个 Control 实例，并等待短期
签名策略自然过期；不得对生产租户直接执行。所有输出报告均不包含访问令牌、供应商
密钥或管理员凭据。

## 验收范围

`scripts/drill-edge-runtime-failures.mjs` 自动验证：

1. Redis 停止后 `/readyz` 变为非就绪，模型请求以 503 fail-closed，恢复 Redis 后请求恢复；
2. 重启网关取得新策略后停止全部 Control，网关在策略有效期内继续通过就绪检查，策略
   到期后转为非就绪，Control 恢复后自动恢复；
3. 专用故障供应商的连接超时、慢流、429、500 和 503；
4. 无论演练通过还是失败，脚本都会 best-effort 启动被它停止的 Redis 与 Control 服务。

`scripts/drill-edge-key-revocation.mjs` 是独立的破坏性演练。它调用现有的双人审批撤销流程，
重新加载网关以取得替代密钥签名的策略，确认旧签名密钥签发的 Edge Token 被拒绝，并
确认替代密钥签发的新 Token 可用。撤销不可逆，因此必须使用预生产专用密钥。

## 准备专用故障供应商

为预生产验收部署准备一个具有受信任 TLS 证书的专用域名。启动故障供应商：

```powershell
$env:OTTO_EDGE_FAULT_PROVIDER_HOST='0.0.0.0'
$env:OTTO_EDGE_FAULT_PROVIDER_PORT='9443'
$env:OTTO_EDGE_FAULT_PROVIDER_TLS_CERT_FILE='D:\secure\fault-provider-fullchain.pem'
$env:OTTO_EDGE_FAULT_PROVIDER_TLS_KEY_FILE='D:\secure\fault-provider-private-key.pem'
$env:OTTO_EDGE_FAULT_PROVIDER_SECRET=(Get-Content 'D:\secure\fault-provider-secret')
$env:OTTO_EDGE_FAULT_PROVIDER_TIMEOUT_MS='70000'
$env:OTTO_EDGE_FAULT_PROVIDER_SLOW_STREAM_MS='70000'
node scripts/edge-fault-provider.mjs
```

安全要求：

- 域名仅允许 Edge Gateway 出站访问；不要暴露到互联网；
- 供应商密钥必须使用独立随机值，不能复用真实模型密钥；
- 在预生产 Edge 签名策略中增加唯一模型 `otto-acceptance`，其上游指向该 HTTPS 服务，
  `secretBinding` 指向上述独立密钥；
- 将域名加入 `upstream_origins.json`，不要使用通配符；
- 策略的 `upstreamConnectTimeoutMs` 和 `upstreamIdleTimeoutMs` 必须分别小于故障服务的
  70 秒延迟；
- 不要把故障供应商加入生产策略，演练结束后停掉服务并删除专用策略。

故障标记通过普通模型输入传递。网关不会接受客户端指定上游地址或供应商密钥。故障服务
仅识别 `OTTO_EDGE_ACCEPTANCE:success|timeout|slow_stream|429|500|503` 六个固定值。

## 执行 Redis、Control 与供应商故障演练

先确认 Docker Compose 中的 `edge-gateway`、`edge-redis`、`control-a`、`control-b` 和
`control-c` 均健康，并为专用租户保留足够额度。然后执行：

```powershell
node scripts/drill-edge-runtime-failures.mjs `
  --confirm RUN_OTTO_EDGE_RUNTIME_FAILURES `
  --gateway-url https://edge.staging.example.com `
  --control-url https://control.staging.example.com `
  --identity-file D:\secure\edge-config\deployment_identity.json `
  --lease-token-file D:\secure\edge_lease_token `
  --subject-id edge_acceptance_operator `
  --model otto-acceptance `
  --working-directory D:\otto-control `
  --compose-file compose.production.yaml `
  --env-file .env.production `
  --project-name otto-control-staging `
  --output D:\evidence\edge-runtime-failures-2026-08-13.json
```

默认最长等待 17 分钟，以覆盖 15 分钟策略 TTL 和刷新/网络余量。若预生产策略 TTL 有
调整，可使用 `--policy-expiry-timeout-ms`，但脚本不允许低于 60 秒。超时、慢流场景的
客户端上限由 `--provider-timeout-ms` 控制，必须大于网关策略中的相应超时，且小于故障
服务延迟的不可接受上限。

通过标准：

- Redis 故障时不得访问上游，不得回退到内存限流；
- Control 断网时只允许使用仍在有效期内的已验证缓存，过期后必须 fail-closed；
- 429 保留为 429，500 保留为 500，503 可保留或在路由耗尽后归一化为 502；
- 上游无响应归一化为 502 `EDGE_UPSTREAM_UNAVAILABLE`；
- 慢流必须被空闲超时终止，不能无限占用并发槽；
- Redis、Control 恢复后 `/readyz` 与成功模型请求均恢复。

## 执行签名密钥撤销演练

准备两个不同人员的管理员会话令牌、审计令牌、当前活动密钥和可签名替代密钥。命令会
创建审批、由第二人批准、撤销活动密钥并切换替代密钥：

```powershell
node scripts/drill-edge-key-revocation.mjs `
  --confirm REVOKE_OTTO_EDGE_SIGNING_KEY `
  --gateway-url https://edge.staging.example.com `
  --control-url https://control.staging.example.com `
  --identity-file D:\secure\edge-config\deployment_identity.json `
  --lease-token-file D:\secure\edge_lease_token `
  --requester-token-file D:\secure\requester.session `
  --approver-token-file D:\secure\approver.session `
  --auditor-token-file D:\secure\auditor.session `
  --subject-id edge_acceptance_operator `
  --model otto-acceptance `
  --working-directory D:\otto-control `
  --compose-file compose.production.yaml `
  --env-file .env.production `
  --project-name otto-control-staging `
  --key-id 0123456789abcdef `
  --replacement-key-id fedcba9876543210 `
  --reason "scheduled pre-production Edge revocation drill" `
  --output D:\evidence\edge-key-revocation-2026-08-13.json
```

通过标准：公开 Keyring 已由替代密钥签名且包含撤销状态；网关重新加载后取得替代密钥
签发的策略并拒绝旧 Token，返回 401 `EDGE_UNAUTHORIZED`；替代密钥签发的新 Token 与
新策略可正常完成请求。报告中的
审批 ID 应与 Control 不可篡改审计记录一并归档。

## 证据与退出检查

每次演练归档以下材料：

- 两个 JSON 演练报告及 SHA-256；
- Compose 事件、Edge/Redis/Control 日志的只读导出；
- Prometheus 延迟、错误率、并发、熔断和 Redis 连接指标；
- Control 审批与密钥撤销审计记录；
- 执行人、复核人、环境、版本、镜像摘要、开始/结束时间和异常说明。

退出前再次执行 `docker compose ... --profile edge ps`，确认所有服务健康；核对计费保留已
结算或释放；停掉故障供应商；删除预生产专用访问 Token。任何阶段失败都不得把报告标为
通过，也不得以明文策略、内存限流、默认密钥或跳过计费方式恢复服务。
