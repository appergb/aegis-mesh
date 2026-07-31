# Aegis Mesh 安全策略

## 不变量

本包默认 `default deny`。权限取角色、事故、环境和工具策略的交集，并遵守最小权限；任一维度未知、缺失、过期或不一致即拒绝。已验证配置只能收紧本策略。

`configs/agent_protocol.yaml 是枚举唯一登记点`；`configs/approval_matrix.yaml 是审批唯一登记点`。其他文档只引用，不得创建第二份可漂移登记表。未知 Agent、未知动作、未知工具、未知审批角色和未注册目标均拒绝。

## 读取、工具与资产范围

读取必须匹配一个互斥查询类别（`internal_security_telemetry`、`owned_asset` 或 `incident_ioc`）、事故目的、已验证资产或证据绑定、精确范围和有限有效期。三类名称只引用治理配置，不得扩展。所有 MCP 调用只经 Aegis Mesh Gateway，并同时满足服务器固定提交、精确工具白名单、精确参数、认证、TLS、egress、预算、脱敏、审计、许可证和实时 attestation。第三方结果不扩大 scope；未知服务器或工具拒绝。缺任一门禁即 `production blocked`。

禁止 wildcard/glob、范围递归扩大、主动探测未授权资产、工具发现后自动加入白名单、模型修改可信配置、直接读取 Secret 或绕过 Gateway。凭证仅以 `secret://` 引用，日志不得记录 bearer、Cookie、私钥或私密正文。

## 生产动作与审批

每个生产动作必须包含 `target`（仅 `resource_type` 与不可变 `resource_id`）、`exact_scope` 精确范围、`expected_effect`、`risk`、`blast_radius`、`preconditions`、`reversible`、`timeout`、`approval_class` 和 `verification_query`。审批记录必须绑定同一 `scope_hash`，具有有限有效期；双人审批必须使用不同 approver_id，并精确匹配治理配置中的角色对和环境/目标。内容、目标、环境、到期或通知收件人变化都会使旧审批失效。

预授权默认关闭且只允许不可由模型修改的事故元数据策略。技术生产写入不得借预授权降级审批。P0 不能移除审批、审计、回滚/补偿或独立验证；P0 只能选择已登记、已预批准的紧急路径。

可逆动作必须声明 `rollback_trigger`、非空有序 `rollback_steps`、rollback timeout 与独立验证；触发后按精确原范围回滚，不得扩大目标。不可逆动作必须声明 `irreversibility_reason`、非空 `compensating_actions`、事前 `stop_conditions` 和 `two_person_irreversible`。外部通知与证据外发固定为不可逆；不得把撤回解释为回滚，也不得虚构恢复。

执行者不能验证自身成功。Observability 或另一名未执行该动作的授权验证者必须用只读 query 独立验证；验证失败保持 failed/blocked，并按契约回滚、补偿或升级人工。

## 证据、隐私与通知

执行证据最小化：只收集事故必要字段，保留原始引用与哈希，事实和衍生判断分开，转换可追溯。真实记录不得进入 Git；访问、导出、删除与 Legal Hold 变更必须有 actor、理由、审批引用和审计事件。禁止自然人归因和不必要个人信息披露。

通知草稿默认不发送。发送前必须验证正式事故、证据、收件人、模板、正文哈希、法律依据、最小披露、幂等键和双人审批。补偿只能停止未来发送、另行审批更正、请求渠道 recall、保全原始与更正记录并升级隐私事件；不得宣称删除收件人已收到的内容。

## 禁止行为与失败关闭

严格 no hack-back。禁止攻击回去、利用漏洞、凭证窃取、持久化、反向连接、破坏载荷、秘密外传、禁止未经授权扫描、任意 Pod shell、集群级通配删除、数据库自动 failover/DDL/删除和个人归因。

未提供真实模型运行时、SLO/RTO/RPO、`provider_model`、凭证/网络、独立模型 SCN 前向结果、生产端点、实时 MCP attestation、法律复核、供应商协议或 ADEO 许可证/安全 fork 时，只能离线验证并保持生产门禁关闭。缺可复现制品时使用 null 和 blocked 原因，禁止伪造 hash。不得用静态测试冒充生产完成。
