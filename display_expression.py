"""Display filter expressions for decoded packets."""

from __future__ import annotations

import ipaddress
import re


PROTOCOLS = {"http", "tcp", "udp", "ipv4", "ipv6", "icmp", "arp", "dns", "tls"}
FIELDS = {"ip.addr", "ip.src", "ip.dst", "port", "src.port", "dst.port", "tcp.port", "udp.port"}
TOKEN = re.compile(r'\s*("[^"\r\n]*"|==|!=|[()]|[^\s()=!"]+)')


def _text_search(packet, value, field=""):
    value = value.lower()
    if field == "src":
        return value in packet.source.lower()
    if field == "dst":
        return value in packet.destination.lower()
    if field == "info":
        return value in packet.info.lower()
    return value in " ".join((packet.source, packet.destination, packet.protocol, packet.info)).lower()


def compile_display_expression(expression: str):
    if not expression.strip():
        return lambda packet: True
    tokens, pos = [], 0
    while pos < len(expression):
        if expression[pos:].isspace():
            break
        match = TOKEN.match(expression, pos)
        if not match:
            raise ValueError(f"无效字符：{expression[pos]}")
        tokens.append(match.group(1))
        pos = match.end()
    if len(tokens) > 1 and '"' not in expression and not any(token.lower() in ("and", "or", "not", "==", "!=", "(", ")") for token in tokens):
        first = tokens[0].lower()
        if first not in FIELDS:
            if first.startswith(("src:", "dst:", "info:")):
                field, _, value = expression.strip().partition(":")
                return lambda packet: _text_search(packet, value.strip(), field.lower())
            return lambda packet: _text_search(packet, expression.strip())
    at = 0

    def peek():
        return tokens[at].lower() if at < len(tokens) else ""

    def take():
        nonlocal at
        if at == len(tokens):
            raise ValueError("表达式缺少条件")
        value = tokens[at]
        at += 1
        return value

    def atom():
        if peek() == "(":
            take()
            result = disjunction()
            if take() != ")":
                raise ValueError("缺少右括号")
            return result
        token = take()
        name = token.lower()
        if name in PROTOCOLS:
            return lambda packet, name=name: name.upper() in packet.tags
        if name not in FIELDS:
            field, separator, value = token.partition(":")
            if separator and field.lower() in ("src", "dst", "info"):
                if not value and peek() not in ("", "and", "or", ")"):
                    value = take()
            else:
                field, value = "", token
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            return lambda packet, value=value, field=field.lower(): _text_search(packet, value, field)
        operator = take().lower()
        if operator not in ("==", "!="):
            if name == "port" and operator.isdecimal():
                value, operator = operator, "=="
            else:
                raise ValueError(f"{name} 后需要 == 或 !=")
        else:
            value = take()
        if "port" in name:
            if not value.isdecimal() or not 0 <= int(value) <= 65535:
                raise ValueError("端口必须是 0–65535 的整数")
            port = int(value)

            def matches(packet):
                if name.startswith("tcp.") and "TCP" not in packet.tags:
                    return False
                if name.startswith("udp.") and "UDP" not in packet.tags:
                    return False
                values = ((packet.source_port,) if name == "src.port" else
                          (packet.destination_port,) if name == "dst.port" else
                          (packet.source_port, packet.destination_port))
                return any(item == port for item in values)
        else:
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError as exc:
                raise ValueError("IP 地址无效") from exc

            def matches(packet):
                values = ((packet.source,) if name == "ip.src" else
                          (packet.destination,) if name == "ip.dst" else
                          (packet.source, packet.destination))
                return address in values
        if operator == "!=":
            if "port" in name:
                return lambda packet: (packet.source_port is not None and
                                       (not name.startswith("tcp.") or "TCP" in packet.tags) and
                                       (not name.startswith("udp.") or "UDP" in packet.tags) and
                                       not matches(packet))
            return lambda packet: bool(packet.source or packet.destination) and not matches(packet)
        return matches

    def negation():
        if peek() == "not":
            take()
            child = negation()
            return lambda packet: not child(packet)
        return atom()

    def conjunction():
        result = negation()
        while peek() == "and":
            take()
            right, left = negation(), result
            result = lambda packet, left=left, right=right: left(packet) and right(packet)
        return result

    def disjunction():
        result = conjunction()
        while peek() == "or":
            take()
            right, left = conjunction(), result
            result = lambda packet, left=left, right=right: left(packet) or right(packet)
        return result

    predicate = disjunction()
    if at != len(tokens):
        raise ValueError(f"多余的内容：{tokens[at]}")
    return predicate
