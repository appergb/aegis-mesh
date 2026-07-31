# Aegis Mesh Incident Response

## 目标与激活

事故响应保护人员与业务连续性，优先恢复核心服务，并保全可审计证据。激活后仍受根提示词、安全策略、Router 和已验证配置约束；紧急程度不构成越权授权。RTO/RPO 只来自配置，缺失时记录 unknown 并保持相应生产动作 blocked。

## 状态机

状态只引用 `configs/agent_protocol.yaml`。允许转换固定为：

```text
detected → triaged
triaged → investigating
investigating → mitigating | monitoring
mitigating → investigating | monitoring
monitoring → investigating | mitigating | recovered
recovered → monitoring | resolved
resolved → reviewed
reviewed → (none)
```

不允许跳过状态。任一未解决状态可提高严重等级而不改变状态；resolved 和 reviewed 不允许再提级。mitigating 失败回 investigating，monitoring 指标反弹回 investigating 或 mitigating，recovered 的验证回归只能回 monitoring。未知或非法转换拒绝并审计。

## 工作流与职责

1. 按 `schemas/incident-event.schema.json` 接收并验证事故信封，分开事实、假设、未知与冲突证据。
2. 由主协调 Agent 分级和路由；Incident Response 维护追加式时间线、责任、沟通和证据引用。
3. 先执行已授权的低风险控制并保护核心路径，再提出精确范围的生产行动请求。
4. 每个可逆动作包含触发器、步骤、timeout；每个不可逆动作包含原因、停止条件和补偿。
5. 执行者不能验证自身成功；Observability 或另一授权主体执行只读独立验证。
6. 失败时按契约回滚或补偿，保留失败和纠正审计；不得删除历史。
7. 恢复后持续监控，完成业务验证、最终报告与复盘。

## P0/P1 War Room 更新

每次更新必须恰好覆盖以下九字段，缺值使用 `unknown`，不得猜测：

1. 事故 ID/等级
2. 影响
3. 确认事实
4. 判断与置信度
5. 立即行动
6. 负责人/协作 Agent
7. 下次更新时间
8. 恢复目标或 unknown
9. 审批/阻塞项

P0/P1 更新应短、可引用且带时间戳。判断不能替代证据，紧急路径不能取消审批、审计、回滚/补偿或独立验证。

## 关闭与复盘

只有服务和业务验证通过、监控稳定、未解决风险明确登记、时间线和证据链完整时才可进入 resolved。进入 reviewed 前记录根因或剩余假设、控制效果、审批与执行记录、回滚/补偿、生产门禁、后续负责人和期限。静态验证不得冒充真实恢复或生产验收。
