"""Bounded DNS and HTTP message parsing."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass


DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 65: "HTTPS"}
DNS_CLASSES = {1: "IN", 3: "CH", 4: "HS"}


def _name(data: bytes, at: int) -> tuple[str, int]:
    labels, visited, next_at = [], set(), None
    for _ in range(128):
        if at >= len(data) or at in visited:
            raise ValueError("Invalid DNS name pointer")
        visited.add(at)
        size = data[at]
        if size == 0:
            return ".".join(labels) or ".", (at + 1 if next_at is None else next_at)
        if size & 0xC0 == 0xC0:
            if at + 1 >= len(data):
                raise ValueError("Truncated DNS pointer")
            pointer = ((size & 0x3F) << 8) | data[at + 1]
            if pointer >= len(data):
                raise ValueError("DNS pointer outside message")
            if next_at is None:
                next_at = at + 2
            at = pointer
            continue
        if size & 0xC0 or size > 63 or at + 1 + size > len(data):
            raise ValueError("Invalid DNS label")
        labels.append(data[at + 1:at + 1 + size].decode("ascii", "replace"))
        at += size + 1
    raise ValueError("DNS name too deep")


def _rdata(data: bytes, kind: int, at: int, length: int) -> str:
    raw = data[at:at + length]
    if kind == 1 and length == 4 or kind == 28 and length == 16:
        return str(ipaddress.ip_address(raw))
    if kind in (2, 5, 12):
        return _name(data, at)[0]
    if kind == 15 and length >= 3:
        return f"priority={struct.unpack_from('!H', data, at)[0]} {_name(data, at + 2)[0]}"
    if kind == 16:
        parts, pos = [], 0
        while pos < length:
            size = raw[pos]
            pos += 1
            parts.append(raw[pos:pos + size].decode("utf-8", "replace"))
            pos += size
        return " ".join(parts)
    return raw[:48].hex() + ("..." if length > 48 else "")


def parse_dns(data: bytes) -> tuple[str, list[tuple[str, str]]]:
    if len(data) < 12:
        raise ValueError("DNS header truncated")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data)
    fields = [("DNS transaction", f"0x{ident:04x}"), ("DNS direction", "response" if flags & 0x8000 else "query"),
              ("DNS opcode", str((flags >> 11) & 15)), ("DNS response code", str(flags & 15)),
              ("DNS flags", f"QR={int(bool(flags & 0x8000))} AA={int(bool(flags & 0x0400))} TC={int(bool(flags & 0x0200))} RD={int(bool(flags & 0x0100))} RA={int(bool(flags & 0x0080))}"),
              ("DNS counts", f"questions={qd} answers={an} authority={ns} additional={ar}")]
    at, first_name, first_answer = 12, "", ""
    for index in range(min(qd, 100)):
        name, at = _name(data, at)
        if at + 4 > len(data):
            raise ValueError("DNS question truncated")
        kind, klass = struct.unpack_from("!HH", data, at)
        at += 4
        first_name = first_name or name
        fields.append((f"Question {index + 1}", f"{name} {DNS_TYPES.get(kind, kind)} {DNS_CLASSES.get(klass, klass)}"))
    for section, count in (("Answer", an), ("Authority", ns), ("Additional", ar)):
        for index in range(min(count, 100)):
            name, at = _name(data, at)
            if at + 10 > len(data):
                raise ValueError("DNS resource record truncated")
            kind, klass, ttl, length = struct.unpack_from("!HHIH", data, at)
            at += 10
            if at + length > len(data):
                raise ValueError("DNS resource data truncated")
            value = _rdata(data, kind, at, length)
            at += length
            label = f"{name} {DNS_TYPES.get(kind, kind)} {value} TTL={ttl}"
            fields.append((f"{section} {index + 1}", label))
            if section == "Answer" and not first_answer:
                first_answer = value
    summary = f"{'response' if flags & 0x8000 else 'query'} {first_name}"
    if first_answer:
        summary += f" -> {first_answer}"
    summary += f" ID=0x{ident:04x}"
    return summary, fields


@dataclass
class HttpMessage:
    start_line: str
    headers: list[tuple[str, str]]
    body_length: int | None
    complete: bool
    offset: int
    size: int


def parse_http_stream(data: bytes) -> list[HttpMessage]:
    """Parse complete HTTP/1.x headers, with framing for CL/chunked bodies."""
    messages = []
    at = 0
    verbs = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"TRACE ", b"CONNECT ")
    while at < len(data) and len(messages) < 1000:
        header_end = data.find(b"\r\n\r\n", at)
        if header_end < 0 or header_end - at > 65536:
            break
        lines = data[at:header_end].split(b"\r\n")
        if not lines or not (lines[0].startswith(verbs) or lines[0].startswith(b"HTTP/1.")):
            break
        start_line = lines[0].decode("latin-1", "replace")
        headers = []
        for line in lines[1:]:
            if b":" not in line:
                continue
            name, value = line.split(b":", 1)
            headers.append((name.decode("latin-1", "replace").strip(), value.decode("latin-1", "replace").strip()))
        lookup = {name.lower(): value for name, value in headers}
        body_at = header_end + 4
        complete, body_length, end = True, 0, body_at
        if lookup.get("transfer-encoding", "").lower().endswith("chunked"):
            pos = body_at
            complete = False
            while pos < len(data):
                line_end = data.find(b"\r\n", pos)
                if line_end < 0:
                    break
                try:
                    size = int(data[pos:line_end].split(b";", 1)[0], 16)
                except ValueError:
                    break
                pos = line_end + 2
                if size == 0:
                    trailer_end = data.find(b"\r\n\r\n", pos)
                    if data[pos:pos + 2] == b"\r\n":
                        end, complete = pos + 2, True
                    elif trailer_end >= 0:
                        end, complete = trailer_end + 4, True
                    break
                if pos + size + 2 > len(data) or data[pos + size:pos + size + 2] != b"\r\n":
                    break
                pos += size + 2
            body_length = (end - body_at) if complete else None
        elif "content-length" in lookup:
            try:
                body_length = int(lookup["content-length"])
                if body_length < 0:
                    break
            except ValueError:
                break
            end = body_at + body_length
            complete = end <= len(data)
        elif start_line.startswith("HTTP/1."):
            try:
                status = int(start_line.split(" ", 2)[1])
            except (IndexError, ValueError):
                break
            if not (100 <= status < 200 or status in (204, 304)):
                body_length, complete, end = None, False, len(data)
        messages.append(HttpMessage(start_line, headers, body_length, complete, at, min(end, len(data)) - at))
        if not complete or end <= at:
            break
        at = end
    return messages


def parse_dns_tcp_stream(data: bytes) -> list[tuple[str, list[tuple[str, str]]]]:
    """Parse complete length-prefixed DNS messages in a TCP byte stream."""
    messages = []
    at = 0
    while at + 2 <= len(data) and len(messages) < 1000:
        length = struct.unpack_from("!H", data, at)[0]
        if length < 12 or at + 2 + length > len(data):
            break
        try:
            messages.append(parse_dns(data[at + 2:at + 2 + length]))
        except ValueError:
            break
        at += 2 + length
    return messages
