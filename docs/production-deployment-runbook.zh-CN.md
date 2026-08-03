# Otto Control 正式环境部署手册

本文用于从一台全新的 Ubuntu 24.04 LTS 主机复现 Otto Control 单机高可用部署。
预发布和正式环境必须使用不同主机、域名、部署身份、密钥、数据库卷和备份目录。
禁止复制正式环境的 `.env.production` 或 `secrets/` 到预发布环境。

## 1. 边界与最低条件

- Ubuntu 24.04 LTS x86_64，建议至少 8 核、16 GB 内存、200 GB SSD。
- Docker Engine 27 或更新版本，并安装 Compose v2 插件。
- Node.js 22.13 或更新版本，仅用于生成身份、预检和运维脚本。
- 两个独立公网域名，例如 `control.company.cn` 和 `federation.company.cn`。
- DNS 的 A/AAAA 记录已指向当前主机；80/443 可从公网访问。
- 22 端口仅允许堡垒机或管理网段；PostgreSQL、etcd、Control、Federation 不得映射到公网。
- 正式环境的法定运营主体、隐私联系人和数据驻留地域已经确认。

当前 Compose 在一台主机上运行 3 个 etcd、3 个 Patroni/PostgreSQL、3 个 Control、
3 个 Federation、HAProxy 和 Caddy。它可承受单个容器或进程故障，不能承受整台主机、
磁盘、Docker daemon 或公网 IP 故障。跨主机高可用需要把数据库和应用实例部署到不同
故障域，并在外部负载均衡器后提供至少两个边缘节点。

## 2. 安装主机依赖

以受控管理员身份执行，Docker 软件源和版本应纳入客户变更记录：

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git gnupg openssl
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
docker version
docker compose version
node --version
openssl version
```

生产维护建议使用独立的 `otto-control` 系统账号，并把仓库固定在 `/opt/otto-control`。
部署必须固定到已验收的提交，不得直接运行一个持续变化的工作树。

## 3. 创建相互隔离的身份

预发布主机：

```bash
npm ci
npm run bootstrap:production -- \
  --environment staging \
  --public-url https://control-staging.company.cn \
  --federation-public-url https://federation-staging.company.cn
npm run preflight:deployment -- --env-file .env.staging
```

正式主机必须显式填写业务和合规信息：

```bash
npm ci
npm run bootstrap:production -- \
  --environment production \
  --public-url https://control.company.cn \
  --federation-public-url https://federation.company.cn \
  --acme-email operations@company.cn \
  --privacy-controller "企业法定名称" \
  --privacy-contact privacy@company.cn \
  --data-region CN-BJ
npm run preflight:deployment -- --env-file .env.production
```

生成器使用排他写入，不会覆盖已有身份。数据库服务器证书覆盖
`postgres-router`、`postgres-1`、`postgres-2`、`postgres-3` 和本机回环地址，Control、Federation、
运维工具及数据库复制链路均使用 TLS。`postgres_tls_ca_private_key.pem` 只留在主机
密钥目录用于受控轮换，Compose 不会把它挂载进任何容器。

预检会验证域名、法务信息、数据地域、数据库 TLS、证书链、文件权限、Docker 和
Compose 配置。正式环境默认还会检查 DNS；只有离线审核配置时才可临时使用
`--skip-dns`，不得据此上线。任何预检错误都必须解决，不能删除检查项绕过。

## 4. 防火墙与启动

将 `10.0.0.0/8` 换成实际堡垒机或管理网段：

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 10.0.0.0/8 to any port 22 proto tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
sudo ufw enable
sudo ufw status verbose

docker compose -f compose.production.yaml --env-file .env.production \
  up -d --build --wait --wait-timeout 300
docker compose -f compose.production.yaml --env-file .env.production ps
curl --fail https://control.company.cn/health/ready
curl --fail https://federation.company.cn/health/ready
```

公网端口检查只能看到 80/443 和受限的 SSH。Prometheus 默认只绑定
`127.0.0.1:9090`，数据库网络和监控网络均为 Docker 内部网络。

## 5. 上线验收

上线前依次执行并保存 `backups/reports/` 下的报告：

```bash
npm run check
npm run preflight:deployment -- --env-file .env.production
sh deploy/backup-pitr-postgres.sh full
sh deploy/drill-postgres-failover.sh --confirm=FAILOVER_OTTO_CONTROL
sh deploy/drill-control-failover.sh --confirm=FAILOVER_OTTO_CONTROL_REPLICAS
sh deploy/drill-pitr-postgres.sh
```

验收证据至少包含：

1. 三个 Control 和三个 Federation 实例全部 ready。
2. 逐台停止 Control 时，公网 `/health/ready` 持续可用，停止的实例恢复后重新入池。
3. PostgreSQL 主库故障后，备用节点提升且 HAProxy 恢复写入。
4. PITR 在隔离卷中恢复并通过 schema、关键表和时间点检查。
5. Caddy 证书链有效，公网无法访问 `/metrics` 和 Federation 管理接口。
6. `secrets/`、备份密钥及签名密钥已进入独立备份和访问审计。

任一项失败都不得上线。演练脚本会在退出时恢复被停止的 Control/PostgreSQL 实例，
但操作人员仍须检查 `docker compose ... ps` 和告警状态。

## 6. 版本升级与重建

升级时先在预发布环境使用同一提交和同一流程通过预检、迁移、故障演练，再进入正式
变更窗口。不要重新运行 bootstrap 覆盖已有身份。新主机恢复顺序为：固定代码提交、
恢复主机密钥目录、恢复 pgBackRest/加密备份、运行预检、恢复数据库、启动服务、执行
完整验收。每季度至少在全新 Ubuntu 主机上重做一次该流程并记录用时、失败点和恢复
结果。
