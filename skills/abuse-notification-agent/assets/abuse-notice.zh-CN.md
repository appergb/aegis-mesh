# 安全事件通知

通知编号：{{notice_id}}
事故编号：{{incident_id}}
模板版本：{{template_version}}
观察窗口：{{window_start}} 至 {{window_end}}（{{timezone}}）
受影响服务：{{affected_service}}

我们在上述窗口观察到与本服务有关的安全事件。经脱敏的请求模式为：

> {{redacted_request_pattern}}

经脱敏的事实摘要：

> {{redacted_evidence_summary}}

请停止相关流量并保全日志，以便贵方按照自身程序调查。若这是误报或需安全交换补充信息，请通过 {{appeal_security_channel}} 联系并引用通知编号。请勿通过普通渠道回传敏感日志或凭证。

依据复核边界，相关行为可能违反《中华人民共和国网络安全法》第二十九条；在满足相应法定事实和标准时，可能涉及《中华人民共和国刑法》第二百八十五条、第二百八十六条或现行《中华人民共和国治安管理处罚法》第三十三条。具体法律性质、是否违法、是否达到法定标准及责任均由有权机关依法认定。

正文哈希见 send_authorized 授权记录。

Aegis Mesh 安全响应团队
本通知由 Aegis-Mesh-General 辅助生成，并经授权人员审核后发送。
