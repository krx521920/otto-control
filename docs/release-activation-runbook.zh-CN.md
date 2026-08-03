# Otto 正式发行与更新激活手册

本文覆盖 Otto 与 Otto Green 的独立更新频道。Control 只验证、保存和分发发行证明，不持有 Windows、Apple、Linux 包签名私钥，也不在发行接口中接收这些私钥。

## 1. 发布前条件

- Control 生产预检已通过，`CONTROL_ARTIFACT_STORAGE_REQUIRED=true`。
- 发行桶已在创建时启用 Versioning 与 Object Lock，生产保留模式为 COMPLIANCE。
- 对象存储凭据只允许访问指定桶和 `otto-releases/` 前缀。
- `attestations/` 只包含 NSIETeam 隔离 runner 的 Ed25519 公钥和 keyring；私钥不得进入 Control 主机。
- Windows 安装包完成 Authenticode 与时间戳；macOS DMG 完成 Developer ID、notarization 和 stapling；服务器包完成 Ed25519 或 Sigstore 签名。
- `otto` 与 `otto-green` 是两个独立 distribution。部署必须被显式分配后才能查询对应频道。

运行：

```bash
npm run preflight:deployment -- --env-file .env.production
```

任何预检失败都禁止发布。`--allow-unmanaged-artifacts-for-test` 仅在 GitHub Actions 的 `CI=true` 环境可用，不得出现在生产命令或运维记录中。

## 2. 发布顺序

1. 为 `otto` 或 `otto-green` 创建 draft release，写入语义化版本、完整 source commit、canary/stable/required 频道和 manifest SHA-256。
2. 对每个安装包和 manifest 请求短期上传票据：`POST /v1/admin/update-releases/:releaseId/artifact-uploads`。
3. 严格使用票据返回的 URL、长度、SHA-256、加密和 Object Lock 请求头上传原始字节。
4. 在对应平台 runner 上运行 `npm run attest:release`。证明必须绑定 release ID、版本、source commit、平台、文件摘要和长度。
5. 调用 `POST .../artifact-uploads/complete`。Control 会重新读取对象元数据并验证对象版本、摘要、长度、静态加密、保留期、平台签名与证明签名。
6. 两名不同发布管理员审批后调用 `POST /v1/admin/update-releases/:releaseId/activate`。
7. 使用一台属于目标 distribution 的测试部署查询 `/v1/update-policy/resolve`，验证返回策略签名、版本、source commit、安装包平台和下载摘要。

Otto 与 Otto Green 必须分别创建 release、上传资产、审批和激活。不得复制数据库记录或只修改文件名复用另一 distribution 的发行物。

## 3. 灰度、暂停与回滚

- canary 只允许 1-100 的 rollout 百分比。部署 cohort 由 distribution、release 和 deployment ID 稳定计算，同一部署不会在重复查询时随机跳组。
- stable 与 required 固定为 100%；required 会返回 `mandatory=true`。
- 发现崩溃、签名异常或错误分发时，立即调用 `POST /v1/admin/update-releases/:releaseId/pause`。暂停后不会产生新的 update decision。
- 回滚必须经过双人审批。`POST .../rollback` 会重新验证上一版的对象、证明和 Control 签名，只有验证通过才恢复上一份 active policy。
- 吊销单个发行物同样需要双人审批，并会原子暂停受影响的 active release。

回滚只停止继续分发并恢复上一份策略，不声称自动卸载已经安装的新版本。客户端安装回退属于 Otto 桌面端的独立执行流程。

## 4. 验收证据

每次正式发布至少保存：

- source repository、完整 commit SHA、构建 workflow/run ID；
- 文件名、平台、长度、SHA-256；
- Authenticode/Apple/Linux 原生验证结果及证书指纹；
- runner 证明 key ID 和 Control 审计事件；
- S3 object key、version ID、加密方式和 Object Lock 到期时间；
- 两名审批人、激活时间、灰度范围；
- Otto 与 Otto Green 各自的策略查询和实际下载校验结果；
- 暂停与回滚演练记录。

未签名、摘要不符、source commit 不符、证明过期、证明 key 未受信、对象版本变化或保留期失效时，发行必须保持 draft/paused，不得人工修改数据库绕过。
