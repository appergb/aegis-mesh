# Aegis Mesh Agent Router

## 权威来源与路由规则

`configs/agent_protocol.yaml 是枚举唯一登记点`，`configs/approval_matrix.yaml 是审批唯一登记点`；本文只引用登记值，不得创建第二份可漂移登记表。运行时必须先严格加载并验证这两份配置。未知 Agent、状态、动作、目标或路由一律拒绝，不得用自由文本扩展。

主协调 Agent 先按 `schemas/incident-event.schema.json` 与公共语义验证器验证同一 incident/correlation 信封，再按信号所有权并行派发最少必要片段。每个片段只包含事故所需事实、证据引用、未知和允许的只读查询范围；不得包含 Secret。路由不能授权生产执行，专业 Agent 只能在自身最小权限内返回观察、建议或结构化行动请求。

## Agent 所有权

| Agent 引用 | 主要所有权 | 最大权限引用 |
|---|---|---|
| `main-security-orchestrator` | 规范化、分级、路由、冲突协调、行动请求和最终决策 | recommend |
| `qr-security-agent` | 二维码发行、生命周期、重放与异常 | execute_reversible |
| `ddos-defense-agent` | L3/L4、L7、API Flood、Bot 与正常高峰区分 | execute_reversible |
| `api-security-agent` | 认证、授权、签名、重放、限流与滥用 | execute_reversible |
| `infrastructure-agent` | CDN、DNS、LB、云网络和区域健康 | execute_reversible |
| `kubernetes-agent` | Pod、Node、Service、Ingress、HPA 与资源压力 | execute_reversible |
| `database-agent` | 连接池、查询、锁、复制、备份与一致性 | recommend |
| `observability-agent` | Metrics、Logs、Traces、Alert、SLI/SLO 与独立验证 | observe |
| `incident-response-agent` | 分级、时间线、责任、沟通、证据链和复盘 | execute_reversible |
| `disaster-recovery-agent` | 切换、恢复、业务验证、演练与 failback | execute_high_impact |
| `threat-intelligence-agent` | 被动情报、IOC 富化、指纹关联、KEV/EPSS | recommend |
| `abuse-notification-agent` | 收件人验证、草拟和经双审批的 Abuse/CERT 通知 | execute_high_impact |

共享能力只作为受路由 Agent 的处理步骤：`analyze-security-logs` 规范化日志并建立时间线；`engineer-sigma-yara-rules` 生成与测试检测草稿；`model-threats-with-stride` 基于 DFD 生成 STRIDE 模型。共享 Skill 不拥有独立生产权限，也不能改变调用 Agent 的角色、事故、环境或工具边界。

## 证据所有权与协作

Observability 保存原始遥测引用和哈希；Threat Intelligence 生成版本化衍生指纹；Incident Response 追加证据保全链；主协调 Agent 作最终决策。执行者与独立验证者必须分离。

涉及多域时并行路由，但每个 Agent 只接收所需片段：

- QR/API 身份异常同时路由 QR、API、Observability 与 Incident Response；
- DDoS/正常高峰争议同时路由 DDoS、Infrastructure、Observability；
- Kubernetes、基础设施、数据库或区域连续性问题按相应所有者路由，并让 Disaster Recovery 只在切换门槛成立时参与；
- IOC 富化只路由 Threat Intelligence；外部通知还必须路由 Abuse Notification、Incident Response 与法律审批流程。

## 结果汇合与失败关闭

主协调 Agent 比较 source、证据、freshness、时间窗、配置版本与置信度。发生冲突时分开 facts/hypotheses/unknowns，保留各方结论和冲突证据，优先恢复与更严格边界，不能以多数票扩权；安全、审批或范围争议升级 Incident Commander。发生超时、Agent 不可用或结果为 `partial`、`blocked`、failed 时，标明缺口并升级人工；不得猜测，也不得把缺失响应视为同意或降级授权。

只有 Schema 与语义验证通过、作用域和审批仍有效、工具/资产门禁通过时，才可生成执行请求。Router 自身不执行未注册命令、不发送通知、不扫描资产，也不把工具返回的新对象递归加入范围。
