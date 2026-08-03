# Otto Control 灾难恢复与不可篡改证据操作规范

## 1. 验收边界

恢复成功不能只以“PostgreSQL 能启动”判断。每次逻辑恢复和 PITR 必须同时满足：

1. schema migration 存在且完整；
2. 全部 `control_*` 表（包括客户、部署、License、席位、积分、管理员、审批、更新和联邦网关）的行数及 SHA-256 与恢复点基线一致；
3. 审计链、外部锚、Witness 回执和 WORM 索引与基线一致；
4. 报告记录 RTO、RPO、数据库总指纹和基线匹配结果；
5. 演练在隔离数据库或隔离卷中进行，不连接生产服务端口。

基线文件只包含每张表的行数和规范化行流 SHA-256，不包含客户正文、Token、文件或数据库行。基线应与加密备份、代码提交、schema 版本一起归档。

生产库仍有写入时，不得先读取在线库再把该结果当作稍后备份的精确基线，因为两次操作不属于同一快照。应先生成新备份，在隔离库执行一次不带 expected manifest 的恢复演练，并把该恢复快照产生的 manifest 作为此备份的权威基线；只有 CI、预发布或已暂停写入的维护窗口可直接使用在线库基线。

## 2. 建立恢复基线

```bash
umask 077
sh deploy/recovery-data-manifest.sh \
  --output ./backups/reports/recovery-baseline.manifest
npm run backup:production
OTTO_CONTROL_RECOVERY_EXPECTED_MANIFEST="$PWD/backups/reports/recovery-baseline.manifest" \
  npm run drill:restore:production
```

PITR 应在目标时间之前建立基线，并确保目标时间之后的 WAL 已归档。演练脚本会在专用 `postgres-pitr-drill` 卷中恢复，记录最后重放事务时间、RPO 和 RTO，再执行相同的数据指纹验收。

## 3. 审计异常与 Witness 故障

Control 每 15 分钟执行一次完整保障检查，周期由 `CONTROL_RECOVERY_ASSURANCE_INTERVAL_MS` 控制：

- 审计链断裂、回滚或内容被修改：产生 `audit.integrity.alert`，严重级别为 `critical`；
- 外部 Witness 重试中：产生 `audit.witness.alert`，严重级别为 `warning`；
- Witness 终态失败或必需 WORM 证据失败：产生 `audit.witness.alert`，严重级别为 `critical`。

告警先进入 PostgreSQL outbox，再签名投递；网络失败不会丢失。破坏性篡改演练只能在一次性环境中进行，演练后必须销毁数据库卷，不能在生产库中直接修改审计行。

## 4. AWS Object Lock

使用 `deploy/aws-audit-worm.template.yaml` 创建独立 Bucket 和 KMS Key。生产运行角色无删除权限；单独的 MFA/审批演练角色拥有删除请求权限，但 COMPLIANCE Object Lock 仍必须拒绝删除。Bucket、KMS Key 和 CloudFormation 资源均使用 `Retain`，禁止因删除 Stack 清除证据。

从 `/v1/admin/audit-witness/worm/status` 取得已存储证据的 object key、version ID 和 SHA-256，然后使用演练角色执行：

```bash
npm run drill:audit:object-lock -- \
  --bucket BUCKET \
  --key OBJECT_KEY \
  --version-id VERSION_ID \
  --expected-sha256 SHA256 \
  --expected-drill-principal-arn arn:aws:iam::123456789012:role/otto-object-lock-drill \
  --output ./object-lock-drill-$(date -u +%Y%m%dT%H%M%SZ).json \
  --confirm=DELETE_LOCKED_AUDIT_EVIDENCE
```

脚本会先通过 STS 核验当前调用身份，并读取桶策略，确认该身份确实拥有 `s3:DeleteObjectVersion` 和 `s3:PutObjectRetention`，避免把普通 IAM 拒绝误报成 Object Lock 生效。随后分别尝试缩短 COMPLIANCE 保留期和删除真实版本；两次攻击都被拒绝，并且保留日期、版本号和对象字节保持一致时才通过。

## 5. 证据与频率

- 每周：隔离逻辑恢复；
- 每月：PITR、PostgreSQL 自动切换和 Control 多实例切换；
- 每季度：Object Lock 删除拒绝、全新主机恢复和 Witness 中断；
- 每次重大 schema、KMS、备份策略或存储供应商变更后：重做全部演练。

保留报告、GitHub Actions URL、CloudFormation Stack ID、CloudTrail 删除拒绝事件、数据库指纹和相关审计回执。报告不得包含管理员 Token、客户正文、私钥或数据库原始行。真实 AWS 演练未执行前，只能标记为“代码与自动化已就绪”，不能声称生产演练已经完成。
