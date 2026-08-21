# Otto 模型供应商接入清单

本文记录 Otto Edge Gateway 对 OpenAI、火山方舟（豆包）和智谱 BigModel 的接入边界。
代码完成不等于供应商已经通过生产审批；缺少真实账号、价格、合同或验收证据时，正式发布必须保持阻断。

## 当前支持范围

| 供应商 | 稳定 Provider ID | API 基地址 | 鉴权 | 当前范围 |
| --- | --- | --- | --- | --- |
| OpenAI | `openai` | `https://api.openai.com/v1` | Bearer API Key | Chat Completions、Responses、JSON/SSE usage |
| 火山方舟（豆包） | `volcengine-ark` | `https://ark.cn-beijing.volces.com/api/v3` | Bearer ARK API Key | Chat Completions、Responses、JSON/SSE usage |
| 智谱 BigModel | `zhipu-bigmodel` | `https://open.bigmodel.cn/api/paas/v4` | Bearer API Key | OpenAI 兼容 Chat Completions、JSON/SSE usage |

模型名称不能硬编码在网关中。Control 签名策略必须把 Otto 对外模型名映射到供应商当期有效的
模型 ID 或推理接入点。客户端不能提交上游 URL、认证头、Secret Binding 或真实模型 ID。

## 代码不能替代的外部材料

每家供应商上线前都必须补齐：

1. 完成企业实名认证并开通生产 API 账号。
2. 创建最小权限、可轮换的生产 API Key，并通过 Secret 文件或受控密钥服务交付网关。
3. 提供经过实测的模型 ID、地域、并发额度、每分钟请求和 Token 限制。
4. 提供带生效时间的输入、输出、缓存、工具或其他收费项价格表。
5. 提供供应商账单导出方式及能够关联 Otto `providerBillingKey` 的请求标识。
6. 签署并审核 DPA，明确数据地域、跨境依据、子处理者、不用于训练、日志留存、删除期限、
   安全事件通知和审计权。
7. 完成生产网络出口、DNS、证书链和供应商域名白名单验证。
8. 用真实小额请求完成流式、工具调用、429、5xx、超时、取消、退款和账单对账测试。

## 各供应商额外注意事项

### OpenAI

- 中国大陆生产部署必须单独评估网络可达性、数据出境和客户合同约束。
- 不能仅凭 Otto 不落盘正文就宣称无跨境处理；供应商仍会接收请求内容。
- 模型、地域和数据保留承诺必须以签署合同及当期供应商条款为准。

### 火山方舟（豆包）

- `model` 可能是模型 ID 或客户创建的推理接入点，必须由企业控制台实值配置。
- 流式 Chat Completions 必须请求 `stream_options.include_usage=true`，否则最后可能没有可信 usage。
- Coding Plan 使用不同基地址和套餐口径，不得静默混入通用方舟计费。

### 智谱 BigModel

- 标准对话接口可复用 OpenAI 兼容结构，但模型专属参数和特殊能力仍需逐项验收。
- 当前适配器只启用 Chat Completions；不会向智谱流式请求强塞 OpenAI 的
  `stream_options.include_usage`，而是只读取供应商实际返回的根级 `usage`。
- 编码套餐可能使用专属端点，不能自动当作通用 `/api/paas/v4` 路由。
- 以响应中的实际 usage 为准，不能使用本地字符数估算完成正式结算。

## 明确不在当前通用适配器范围内

- AK/SK 请求签名、OAuth 动态换 Token、mTLS 客户端证书。
- 非 OpenAI 格式的音频、视频、图像生成、批处理、文件上传和知识库接口。
- 供应商不返回可信 Token usage，或只在月底提供无法逐请求关联的汇总账单。
- 需要客户端直连供应商、暴露供应商 API Key 或允许客户端覆盖上游 URL 的方案。

上述场景必须增加独立适配器、计量器和契约测试，不能通过修改 Provider ID 绕过。

## 仍需继续开发的生产闭环

- 为三家供应商分别导入正式价格表，并记录价格版本、生效时间、缓存 Token、推理 Token 等计价维度。
- 在执行收据中补齐部署、客户、企业、路由、上游模型、供应商请求 ID 和价格版本，支持争议追溯。
- 为供应商账单提供专用导入器，并完成逐请求与月度总额双重对账；当前通用 JSON 对账器不能替代正式账单接入。
- 用受保护 runner 产生签名或 OIDC 可验证的 24 小时长稳、真实并发和真实金额证据。

## 官方接口资料

- OpenAI API：https://platform.openai.com/docs/api-reference
- 火山方舟：https://www.volcengine.com/docs/82379/
- 智谱 OpenAI 兼容接口：https://docs.bigmodel.cn/cn/guide/develop/openai/introduction
