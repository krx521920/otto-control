# 阿里云 ESA 生产基础设施

本目录提供 Otto Edge Gateway 的阿里云 ESA Terraform 基线。它只声明阿里云官方
Provider 已公开支持的资源：ESA 站点、EdgeKV、Routine、证书、严格 TLS 和
Routine Route。模板不会购买套餐，不会保存阿里云 AccessKey、模型供应商密钥或 Control
私钥，也不会自动创建任何云资源。

## 安全边界

- Terraform 身份使用 CI 的 RAM 角色或临时凭据，禁止把 AccessKey 写进 `tfvars`、状态、
  仓库或日志。
- EdgeKV 只保存 Control 签名策略和 Control 公钥；不得保存模型密钥、访问令牌、聊天内容、
  提示词、回复或附件。
- 当前公开 ESA 文档没有证明普通环境变量具备“写入后不可读”的 Secret 语义；构建配置 API
  还能返回环境变量。因此模型供应商密钥不得放入 EdgeKV、Terraform 或普通构建变量。受控
  发布流水线只能接收经企业 KMS/密钥平台托管、不可读回的外部 Secret 版本引用，仓库仅保存
  `external-secret://.../versions/...` 引用；在真实 ESA 运行时绑定经过供应商确认前保持公网
  Route 关闭。
- `activate_public_route` 默认是 `false`。Secret、预生产灰度、健康探测和双人审批未产生
  `esa-release-...` 证据前，Terraform 无法开启公网 Route。
- Route 使用 `bypass=off`。Worker 失败时不得绕过鉴权直接回源；发布流水线还必须验证
  ESA 实际失败策略不会回退到未经鉴权的源站。
- TLS 1.0/1.1 被关闭，只启用严格密码套件、TLS 1.2/1.3、OCSP、HTTP/2 和 HTTP/3。
- 站点开启中等 WAF 安全级别与自动频控；上线前仍应在预生产环境验证流式响应不会被误拦。

## 为什么 Secret 与灰度不直接写进 Terraform

本模板锁定到已公开发布、包含 ESA 站点 WAF 字段的 Alibaba Cloud Provider 1.279.x。
稳定的 Routine 资源只创建 Routine；Routine 关联记录、代码上传、Secret 和双版本流量比例
没有全部覆盖为稳定 Terraform 资源。它们必须由受控 OpenAPI 发布步骤完成，并把不可变部署
ID 写入发布证据，不能把未公开的字段伪装成 Terraform 能力。把密钥
写成普通 Terraform 变量会让它
进入 Terraform state，破坏密钥边界。

因此正式流程分为两部分：

1. Terraform 创建默认关闭 Route 的站点、KV、域名、TLS、WAF 和 Routine 壳资源。
2. 受控发布流水线通过 ESA OpenAPI 创建 Routine 关联记录并上传 Worker，通过经安全审核的
   运行时集成注入企业 KMS/密钥平台中的版本化密钥，
   执行预生产灰度与自动回滚，将
   Secret 版本、代码部署 ID、健康报告摘要和两名批准人写入外部发布证据。证据通过预检后，
   才允许把 `activate_public_route` 改为 `true`。

这不是“手工跳过 IaC”，而是避免把 Secret 明文带入 Terraform state。外部步骤必须有不可
变审计记录，失败时保持 Route 关闭。

## 发布步骤

准备经过审查的 Worker bundle、Control 签名策略、公钥 Keyring、Secret 引用清单和发布证据：

```powershell
node scripts/preflight-aliyun-esa-iac.mjs `
  --worker=deploy/aliyun-esa/release/otto-edge-esa-worker.js `
  --policy=deploy/aliyun-esa/release/signed-policy.json `
  --keyring=deploy/aliyun-esa/release/control-public-keyring.json `
  --secret-bindings=deploy/aliyun-esa/release/secret-bindings.json `
  --canary-report=deploy/aliyun-esa/release/canary-report.json `
  --release-evidence=deploy/aliyun-esa/release/release-evidence.json
```

`deploy/aliyun-esa/release/` 已加入忽略清单。即使其中只有非秘密材料，也应由发布流水线按
制品摘要生成，不应由开发者随意提交。

复制变量示例并填入已有 ESA 套餐 ID、域名和 SHA-256：

```powershell
Set-Location deploy/aliyun-esa/terraform
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform fmt -check
terraform validate
terraform plan -out otto-esa.tfplan
```

首轮 `plan/apply` 必须保持 `activate_public_route=false`。完成域名所有权与证书签发、Secret
绑定、至少两个预生产节点的灰度验证和 Keyring 紧急撤销演练后，将证据 ID 写入
`release_evidence_id`，再由不同审批人审核第二次 `plan`，最后打开 Route。

## DNS、证书与回滚

本模板使用 CNAME 接入，输出 `site_id` 和 `edge_hostname`。DNS 管理员必须按照 ESA 控制台
给出的目标记录完成解析和所有权验证；证书签发前不能启用 Route。若域名由其他系统管理，
不要在本模块复制创建 DNS 记录。

Worker 发布回滚应重新部署已验证的旧代码版本，不得依赖 `terraform destroy`。阿里云的代码
部署属于发布事件，删除 Terraform 状态不等价于云端回滚。站点、KV、Routine 和证书均设置
`prevent_destroy`；灾难操作必须经过变更单和双人审批。

Keyring 紧急撤销继续使用仓库内的预生产演练工具。撤销后必须确认所有节点拒绝旧签名、接受
新签名，并把报告 SHA-256 写入发布证据。EdgeKV 是最终一致存储，传播窗口内必须维持双钥
或直接关闭公网 Route，不能把“写入 KV 成功”当成全节点生效。

## ROS 边界

ROS 已确认支持 `ALIYUN::ESA::Site`，但当前公开资源覆盖面不足以等价表达本模板的 EdgeKV、
Routine、TLS 与 WAF 安全基线。为避免形成表面成功、实际缺防护的部署，本阶段不提供降级版
ROS 模板。计算巢若要求 ROS，应以 ROS 创建调用本 Terraform 模块的受控部署步骤，并保留
相同的预检、双人审批和发布证据，不得编造或静默忽略缺失资源。
