# Edge Gateway 计费对账与外部保证

本文定义 Edge Gateway 在正式发布前的计费闭环、供应商账单对账、独立安全审计及模型供应商数据处理协议（DPA）门禁。工具只验证证据的结构、完整性、时效和摘要；不能替代会计、审计或律师的专业判断，也不会把尚未发生的外部审核标记为通过。

## 额度预留与结算不变量

每个需要计费的模型请求必须先通过 Control 创建 Hold。网关应在提供商调用结束后执行且仅执行一种终态转换：

- `settled`：以实际用量捕获 Hold 并释放剩余额度；
- `released`：未发生可计费用量，释放全部 Hold；
- `uncertain`：供应商已可能产生费用，但无法取得可信用量，转人工处理；
- `active`：仅允许出现在尚未结束的请求中，账期关闭时出现即阻断对账。

对账报告会把实际用量超过预留量标记为 `reservation_overrun`，把 `active` 或 `uncertain` 标记为 `unfinalized_reservation`。这两类问题不会被金额容差隐藏。

## Otto 与供应商账单对账

先分别把 Otto 账单和供应商账单转换为规范 JSON。模板位于：

- `docs/templates/edge-billing-otto-statement.template.json`
- `docs/templates/edge-billing-provider-statement.template.json`

`providerBillingKey` 必须是供应商返回的不可变用量/请求标识，不能使用用户名、提示词或文件名。若供应商只提供日级汇总，应由独立适配器生成“供应商、模型、账期、地域”聚合键，并让 Otto 导出按完全相同的维度聚合；不得用模糊时间匹配掩盖孤立费用。

执行：

```sh
node scripts/reconcile-edge-billing.mjs \
  --otto secure/otto-billing-2026-08.json \
  --provider secure/provider-billing-2026-08.json \
  --output evidence/edge-billing-reconciliation-2026-08.json
```

默认金额和用量容差均为零。只有财务批准的舍入规则才能使用 `--amount-tolerance-micros` 或 `--unit-tolerance`，并应将命令参数连同报告归档。退出码 `0` 表示完全通过，`2` 表示已生成报告但存在差异，`1` 表示输入或证据格式无效。

对账输入和输出属于财务证据，应加密保存、限制访问、设置保留期，并避免包含提示词、响应正文、API Key 或 E2EE 密钥。

## 外部安全审计门禁

外部审计必须由独立机构针对不可变发布候选物执行，并覆盖以下五个范围：

1. 身份验证、租户绑定、签名策略及策略过期；
2. 模型供应商 Secret 文件、日志脱敏及撤销；
3. 公网路由、TLS、Redis/Control 网络边界；
4. Hold、执行回执、幂等、崩溃恢复和账单完整性；
5. 超时、慢流、429/5xx、并发、限流和资源耗尽。

审计报告模板是 `docs/templates/edge-external-security-audit-evidence.template.json`。正式门禁要求零个未解决 Critical/High，报告文件摘要与状态清单完全一致，且报告未过期。Medium/Low 必须进入整改清单，但是否阻断由发布委员会另行提高规则，不能删除发现来获得通过。

## 模型供应商 DPA 审查门禁

每个生产策略引用的模型供应商都要单独完成 DPA 审查。模板位于 `docs/templates/model-provider-dpa-review.template.json`。至少确认：

- 数据控制者/处理者角色和服务范围；
- 数据地域、跨境依据及子处理者清单；
- 提示词、响应、附件和日志不得用于供应商模型训练；
- 安全事件通知不超过 72 小时；
- 服务终止或删除请求后不超过 90 天完成删除；
- 审计权、政府请求通知、删除接口和留存例外；
- 签署 DPA 的文件摘要、法务审核人、审核时间和有效期。

这些阈值是 Otto 的发布基线，不代表对所有司法辖区都充分。实际合同仍须由具备相应资格的律师审查。

## 机器门禁

状态清单位于 `security/edge-release-assurance-status.json`，故意保持 `blocked`，因为仓库当前没有真实的第三方审计报告或已签署 DPA。清单还要求五类技术证据：Redis/Control/供应商故障演练、签名密钥撤销、零未决差异的账单对账、实际持续至少 24 小时的长稳报告，以及高并发成本报告。每份报告必须绑定相同的不可变发布候选、校验 SHA-256 且仍在有效期内；仅有脚本或单元测试不算验收通过。日常 CI 仅校验清单格式：

```sh
node scripts/check-edge-release-assurance.mjs --allow-pending
```

正式发布使用严格模式：

```sh
node scripts/check-edge-release-assurance.mjs \
  --status security/edge-release-assurance-status.json \
  --root . \
  --output evidence/edge-release-assurance-result.json
```

严格模式只在所有外部证据存在、SHA-256 匹配、审批有效且所有供应商 DPA 均通过时退出 `0`。GitHub 的 `Edge production assurance` 工作流会在 `edge-v*` 标签和人工触发时执行严格门禁。正式发布环境必须把该工作流设置为发布审批的必需状态检查。

证据文件不建议提交仓库；可以保存在访问受控的 WORM 对象存储中，并在受保护的发布 runner 上拉取到清单声明的相对路径。状态清单只记录审核元数据和 SHA-256，不记录合同密文、审计报告正文或任何密钥材料。
