# Otto Control 生产签名密钥运行手册

本手册用于 `CONTROL-02`。正式环境只允许 KMS/HSM 持有 License、策略、审计回执和发行证明的 Ed25519 私钥。Control 只能取得公钥和调用签名操作，不能读取、导出、删除或修改密钥策略。

## 角色与职责

| 角色 | 职责 | 禁止事项 |
| --- | --- | --- |
| 密钥负责人 A | 创建密钥、复核 Key ARN、公钥和保留策略 | 单独批准 Control 密钥切换 |
| 密钥负责人 B | 复核 IAM、灾备区域和恢复结果 | 与负责人 A 共用账号或 MFA |
| Control 运营管理员 | 发起轮换或吊销审批、保存演练报告 | 获得 `kms:CreateKey`、`kms:ScheduleKeyDeletion` 或私钥 |
| Control 安全管理员 | 使用独立 MFA 会话审批、复核审计链 | 审批自己发起的操作 |
| 审计人员 | 读取公开 keyring、审计事件和 WORM 证据 | 调用 `kms:Sign` |

负责人姓名、账号、MFA 设备、值班联系方式和替补人员必须记录在企业密码管理系统，不写入仓库。

## 创建主密钥、异地副本和 OIDC 角色

以下示例使用新加坡主区域和东京灾备区域。先由云安全管理员使用受控 AWS 会话执行：

```bash
aws cloudformation deploy \
  --region ap-southeast-1 \
  --stack-name otto-control-signing-primary \
  --template-file deploy/aws-kms-primary.template.yaml \
  --parameter-overrides EnvironmentName=production

PRIMARY_ARN=$(aws cloudformation describe-stacks \
  --region ap-southeast-1 \
  --stack-name otto-control-signing-primary \
  --query 'Stacks[0].Outputs[?OutputKey==`PrimaryKeyArn`].OutputValue' \
  --output text)

aws cloudformation deploy \
  --region ap-northeast-1 \
  --stack-name otto-control-signing-replica \
  --template-file deploy/aws-kms-replica.template.yaml \
  --parameter-overrides EnvironmentName=production PrimaryKeyArn="$PRIMARY_ARN"
```

取得副本 ARN 后，在 IAM 所在区域部署 OIDC 角色。账号中应预先存在 GitHub OIDC provider，并把 ARN 作为参数传入：

```bash
aws cloudformation deploy \
  --region ap-southeast-1 \
  --stack-name otto-control-signing-github-role \
  --template-file deploy/aws-kms-github-role.template.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubOidcProviderArn="$GITHUB_OIDC_PROVIDER_ARN" \
    GitHubRepository=krx521920/otto-control \
    GitHubEnvironment=production-signing \
    SigningKeyArns="$PRIMARY_ARN,$REPLICA_ARN"
```

GitHub `production-signing` Environment 必须配置至少一名独立审批人，不允许管理员绕过审批。工作流只换取 15 分钟会话，不保存 Access Key。

## 生成 KMS-only 生产配置

```bash
npm run bootstrap:production -- \
  --environment production \
  --public-url https://control.company.cn \
  --federation-public-url https://federation.company.cn \
  --acme-email operations@company.cn \
  --privacy-controller "Company Name" \
  --privacy-contact privacy@company.cn \
  --data-region CN-BJ \
  --aws-kms-key-arns "$PRIMARY_ARN,$REPLICA_ARN"

npm run preflight:deployment -- --env-file .env.production
```

生产引导只在 `signing/control_signer_keyring.json` 中保存不可变 Key ARN，不生成本地签名私钥。`signing/` 与数据库密码、管理员 Token 所在的 `secrets/` 分开挂载。旧部署升级时，应先创建 `signing/`，把 keyring 及其专属伴随文件迁入，并在 `.env.production` 设置 `OTTO_CONTROL_SIGNING_DIR=./signing`。

## 正常轮换

1. 创建新的 KMS 主密钥和灾备副本，将两组 ARN 同时加入 keyring，重启 Control。
2. 对新 keyId 执行 provider 探测，确保真实签名和本地验签成功。
3. 准备一份由旧 active key 签发且仍有效的 License ID。
4. 使用两个不同的 MFA 管理员会话，并由第三个仅具备 `audit.read`、`audit.verify` 权限的独立审计会话执行证据核验：

```bash
npm run drill:signing:rotation -- \
  --confirm ROTATE_OTTO_SIGNING_KEY \
  --control-url https://control.company.cn \
  --requester-token-file ./requester.session \
  --approver-token-file ./approver.session \
  --auditor-token-file ./auditor.session \
  --target-key-id NEW_KEY_ID \
  --legacy-license-id LEGACY_LICENSE_ID \
  --output ./backups/drills/signing-rotation-YYYYMMDD.json
```

演练必须证明旧 key 变为 `retired`、新 key 变为 `active`，并且旧 License 在轮换前后均能由退休公钥验证。报告还必须列出探测、审批申请、独立批准、审批消费和密钥切换的审计链序号与事件哈希，并保存完整性回执的签名摘要。退休公钥应至少保留到其签发的最后一份 License、离线授权和审计证据全部过期。

## 紧急吊销

确认泄露后，先冻结受影响云身份，再用已探测通过的备用 key 执行双人审批吊销：

```bash
npm run drill:signing:revoke -- \
  --confirm REVOKE_OTTO_SIGNING_KEY \
  --control-url https://control.company.cn \
  --requester-token-file ./requester.session \
  --approver-token-file ./approver.session \
  --auditor-token-file ./auditor.session \
  --key-id COMPROMISED_KEY_ID \
  --replacement-key-id VERIFIED_REPLACEMENT_KEY_ID \
  --reason "incident IR-2026-001" \
  --output ./backups/drills/signing-revocation-YYYYMMDD.json
```

脚本会验证公开 keyring 已标记旧 key 为 `revoked`、备用 key 已激活且 keyring 由备用 key 正确签名，同时核验探测、双人审批、审批消费和吊销事件已进入完整审计链。随后立即停止受影响 key 的 `kms:Sign` 权限，通知 Otto Server 刷新 keyring，并按事故流程处理仍引用被吊销 key 的 License。

## 区域故障和全部凭据丢失

- 主区域失败：`AwsKmsEd25519Signer` 只允许同一个 MRK 的异地副本接管，禁止切到不同密钥材料。
- Control 主机丢失：从 Git、`.env.production`、`secrets/` 备份和 KMS ARN 重建；无需恢复签名私钥。
- GitHub OIDC 角色失效：生产 Control 的实例角色仍可签名，修复 OIDC 后重跑实机工作流。
- 所有 KMS 访问失败：签名写操作 fail-closed。不得临时放入本地私钥；由双人审批恢复 IAM/KMS 或激活已登记的独立 HSM key。
- KMS key 被误禁用：安全负责人复核 CloudTrail 后重新启用；禁止创建同名但不同公钥的替代 key。

## 验收证据

每季度以及每次密钥变更后保存：CloudFormation change set、Key ARN 和公钥指纹、IAM Access Analyzer 结果、GitHub KMS workflow URL、provider/rotation/revocation 的 `0600` 报告、`/v1/admin/audit/verify` 回执和 WORM 锚定编号。报告不得包含管理员 Token、签名原文、私钥或客户内容。
