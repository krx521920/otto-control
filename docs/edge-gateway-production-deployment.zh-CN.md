# Otto Edge Gateway 单服务器生产部署

Edge Gateway 现已作为 `compose.production.yaml` 的正式 `edge` profile 编排。它与
Control、Federation 共用公网 Caddy，但使用独立进程、独立健康检查、独立持久状态和
专用 TLS Redis。未完成注册和预检前，禁止启用该 profile。

## 服务边界

- Caddy 为 `EDGE_DOMAIN` 自动申请和续期证书，只转发 `/v1/chat/completions`、
  `/v1/responses`、`/healthz` 和 `/readyz`。
- `/v1/operations/*`、计费恢复接口及未知路径不会暴露到公网。
- Edge Gateway 只通过 Docker 内网访问 Redis；Redis 关闭明文端口，仅监听 TLS 6379。
- Control、Redis 或签名策略不可用时 `/readyz` 返回非 2xx，Compose 会把实例标记为
  unhealthy，不会降级为内存限流或无计费模式。
- 模型供应商密钥使用 `${SECRET_BINDING}_FILE`，从只读
  `OTTO_EDGE_PROVIDER_SECRETS_DIR` 挂载；不得写入 `.env`、镜像或策略文件。

## 首次安装

先生成 Control 的生产环境。安装器会同时写入独立的 `EDGE_DOMAIN`（默认是
`edge.<Control 域名>`）和 Edge 目录，但保持 `OTTO_EDGE_ENABLED=false`：

```sh
npm run bootstrap:production -- \
  --environment production \
  --public-url https://control.company.cn \
  --federation-public-url https://federation.company.cn \
  --acme-email operations@company.cn \
  --privacy-controller '示例公司' \
  --privacy-contact privacy@company.cn \
  --data-region CN-BJ \
  --aws-kms-key-arns '<不可变 KMS Key ARN>'
```

在 Control 中完成部署注册、License 租约和 Edge 策略配置后，分别导出：

1. Control 公钥 Keyring；
2. 上游 HTTPS Origin 白名单；
3. 包含 licenseId、deploymentId、organizationId、machineFingerprint 的身份 JSON；
4. 当前在线租约令牌。

然后执行二阶段安装。命令拒绝符号链接、空文件、覆盖已有密钥以及无效身份：

```sh
npm run bootstrap:edge -- \
  --env-file .env.production \
  --control-public-keys-file /secure/control-public-keys.json \
  --upstream-origins-file /secure/upstream-origins.json \
  --deployment-identity-file /secure/deployment-identity.json \
  --lease-token-file /secure/lease-token \
  --provider-secret OPENAI_API_KEY=/secure/openai-api-key
```

该步骤会本地生成限流 HMAC 密钥、Redis 密码、Redis 私有 CA/服务端证书、Ed25519
执行回执密钥和运维令牌，并把环境切换为 `OTTO_EDGE_ENABLED=true`。Redis CA 私钥不
挂入任何运行容器，只用于后续受控轮换。

安装器要求每个上游策略 `secretBinding` 都有且只有一个 `--provider-secret`，并复制到
`edge-provider-secrets`。例如策略中的 `secretBinding` 是 `OPENAI_API_KEY` 时，安装器会
自动向环境文件写入文件引用，而不会写入密钥值：

```env
OPENAI_API_KEY_FILE=/run/otto-edge-provider-secrets/openai_api_key
```

先执行正式预检，再启动：

```sh
npm run preflight:deployment -- --environment production --env-file .env.production
docker compose -f compose.production.yaml --env-file .env.production --profile edge up -d
docker compose -f compose.production.yaml --env-file .env.production --profile edge ps
```

DNS 必须把 Control、Federation 和 Edge 三个域名指向该服务器，80/443 对外开放，
Redis 6379 和应用 7791 不得映射到宿主机公网。

## 健康、日志和恢复

- 存活探针：`https://<EDGE_DOMAIN>/healthz`。
- 就绪探针：`https://<EDGE_DOMAIN>/readyz`，同时验证签名策略、Control、Redis 和计费。
- 容器退出后由 `restart: unless-stopped` 自动拉起。
- Docker `json-file` 日志默认每个文件 20 MiB、保留 5 个，可通过
  `OTTO_EDGE_LOG_MAX_SIZE` 和 `OTTO_EDGE_LOG_MAX_FILES` 调整。
- 计费 journal 和 Redis AOF 使用独立 named volume；备份时应与 Control 数据库快照
  记录同一版本和时间点。

## 灰度前置验证、升级和回滚

正式镜像必须使用不可变仓库摘要。升级脚本先启动使用独立状态卷的 canary，确认它能
加载真实签名策略、连接 Control/TLS Redis 并通过 `/readyz`，才切换生产实例。生产实例
未通过就绪检查时会自动恢复旧镜像：

```sh
sh deploy/upgrade-edge-gateway.sh \
  --image=registry.company.cn/otto/edge@sha256:<64位摘要> \
  --confirm=UPGRADE_OTTO_EDGE
```

人工回滚只接受最近一次已记录的不可变旧镜像：

```sh
sh deploy/rollback-edge-gateway.sh --confirm=ROLLBACK_OTTO_EDGE
```

升级状态只保存镜像摘要，不保存令牌或密钥。若 canary 失败，生产实例保持不变；若自动
回滚也失败，脚本退出非零并要求人工接管。
