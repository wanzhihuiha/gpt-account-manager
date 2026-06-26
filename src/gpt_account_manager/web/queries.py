"""Web 层查询参数装配 helper。

这里只负责把 `urllib.parse.parse_qs` 的结果收敛成 Handler 和下游接口
要用的入参结构，不读取文件、不做业务判定，也不掺杂存储或网络访问。
"""
from __future__ import annotations


def first_query_value(params: dict[str, list[str]], key: str, default: str = "") -> str:
    """按旧脚本的兼容语义读取第一个 query 参数值。

    这里保留“只要 key 存在就取第一个值”的行为，不会因为值是空串就自动
    回落到默认值，避免悄悄改变现有接口对空参数的处理语义。
    """
    values = params.get(key)
    if isinstance(values, list) and values:
        return str(values[0])
    return default


def build_message_query_payload(
    params: dict[str, list[str]],
    *,
    include_accounts: bool = False,
) -> dict[str, str]:
    """把消息列表筛选参数整理成既有消息服务使用的 payload。

    Handler 继续负责路由和授权，这里只把 query 参数装配成稳定字典，
    方便后续继续下沉路由代码时，不必在多个分支里重复同一份字段映射。
    """
    payload = {
        "query": first_query_value(params, "query", ""),
        "sender": first_query_value(params, "sender", ""),
        "source": first_query_value(params, "source", "all"),
        "mail_type": first_query_value(params, "mail_type", "all"),
        "category": first_query_value(params, "category", "all"),
        "account": first_query_value(params, "account", ""),
    }
    if include_accounts:
        payload["accounts"] = first_query_value(params, "accounts", "")
    return payload


def build_dashboard_stats_query(params: dict[str, list[str]]) -> dict[str, str]:
    """整理 dashboard 统计接口的 query 参数。

    这里故意保留字符串形态，把数值收敛和兜底继续留给现有统计函数，
    避免在 web 装配层和 service 层同时维护一套范围校验规则。
    """
    return {
        "days": first_query_value(params, "days", "30"),
        "limit": first_query_value(params, "limit", "300"),
        "tz_offset_minutes": first_query_value(params, "tz_offset", "480"),
    }


__all__ = [
    "build_dashboard_stats_query",
    "build_message_query_payload",
    "first_query_value",
]
