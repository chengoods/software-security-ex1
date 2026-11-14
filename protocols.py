"""Decode common Ethernet and IP protocols from captured bytes."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

from application_protocols import parse_dns, parse_http_stream


@dataclass
class Decoded:
    source: str = ""
    destination: str = ""
    protocol: str = "OTHER"
    info: str = ""
    details: list[tuple[str, str]] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    source_port: int | None = None
    destination_port: int | None = None
    tcp_sequence: int | None = None
    tcp_flags: int = 0
    tcp_payload: bytes = b""


def _ip(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))


def _mac(raw: bytes) -> str:
    return ":".join(f"{x:02x}" for x in raw)


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tcp_options(raw: bytes) -> list[tuple[str, str]]:
    result = []
    at = 0
    while at < len(raw):
        kind = raw[at]
        if kind == 0:
            break
        if kind == 1:
            at += 1
            continue
        if at + 2 > len(raw) or raw[at + 1] < 2 or at + raw[at + 1] > len(raw):
            result.append(("TCP option", "malformed"))
            break
        value = raw[at + 2:at + raw[at + 1]]
        if kind == 2 and len(value) == 2:
            label = "MSS=%d" % struct.unpack("!H", value)[0]
        elif kind == 3 and len(value) == 1:
            label = "Window scale=%d" % value[0]
        elif kind == 4 and not value:
            label = "SACK permitted"
        elif kind == 5 and len(value) % 8 == 0:
            label = "SACK " + ", ".join("%d-%d" % struct.unpack_from("!II", value, i) for i in range(0, len(value), 8))
        elif kind == 8 and len(value) == 8:
            label = "Timestamp TSval=%d TSecr=%d" % struct.unpack("!II", value)
        else:
            label = "type=%d data=%s" % (kind, value.hex())
        result.append(("TCP option", label))
        at += raw[at + 1]
    return result


def _dns_name(raw: bytes, at: int) -> str:
    labels, seen = [], set()
    for _ in range(32):
        if at >= len(raw) or at in seen:
            break
        seen.add(at)
        size = raw[at]
        if size == 0:
            break
        if size & 0xC0 == 0xC0:
            if at + 1 >= len(raw):
                break
            at = ((size & 0x3F) << 8) | raw[at + 1]
            continue
        if size > 63 or at + 1 + size > len(raw):
            break
        labels.append(raw[at + 1:at + 1 + size].decode("ascii", "replace"))
        at += 1 + size
    return ".".join(labels)


def decode(raw: bytes, linktype: int = 1) -> Decoded:
    out = Decoded()
    try:
        at = 0
        if linktype == 1:
            if len(raw) < 14:
                raise ValueError("Ethernet header truncated")
            dst, src, kind = struct.unpack_from("!6s6sH", raw)
            out.source, out.destination = _mac(src), _mac(dst)
            out.details += [("Ethernet source", out.source), ("Ethernet destination", out.destination), ("EtherType", f"0x{kind:04x}")]
            at = 14
            for _ in range(2):
                if kind not in (0x8100, 0x88A8):
                    break
                if len(raw) < at + 4:
                    raise ValueError("VLAN header truncated")
                vlan, kind = struct.unpack_from("!HH", raw, at)
                out.details.append(("VLAN ID", str(vlan & 0x0FFF)))
                at += 4
        elif linktype == 101:
            kind = 0x86DD if raw and raw[0] >> 4 == 6 else 0x0800
        elif linktype in (0, 108):
            if len(raw) < 4:
                raise ValueError("loopback header truncated")
            family = struct.unpack_from("<I", raw)[0]
            kind = 0x86DD if family in (24, 28, 30) else 0x0800
            at = 4
        else:
            out.info = f"Unsupported link type {linktype}"
            return out

        if kind == 0x0806:
            out.protocol = "ARP"
            out.tags.add("ARP")
            if len(raw) >= at + 28:
                operation = struct.unpack_from("!H", raw, at + 6)[0]
                out.source, out.destination = _ip(raw[at + 14:at + 18]), _ip(raw[at + 24:at + 28])
                out.info = f"{'request' if operation == 1 else 'reply'} {out.source} -> {out.destination}"
                out.details += [("ARP operation", str(operation)), ("Sender IP", out.source), ("Target IP", out.destination)]
            return out
        if kind == 0x0800:
            if len(raw) < at + 20:
                raise ValueError("IPv4 header truncated")
            ihl = (raw[at] & 15) * 4
            if raw[at] >> 4 != 4 or ihl < 20 or len(raw) < at + ihl:
                raise ValueError("invalid IPv4 header")
            total = struct.unpack_from("!H", raw, at + 2)[0]
            if total < ihl:
                raise ValueError("invalid IPv4 length")
            proto = raw[at + 9]
            frag = struct.unpack_from("!H", raw, at + 6)[0]
            out.source, out.destination = _ip(raw[at + 12:at + 16]), _ip(raw[at + 16:at + 20])
            out.tags.add("IPv4")
            out.details += [("IPv4 source", out.source), ("IPv4 destination", out.destination), ("TTL", str(raw[at + 8])), ("IP length", str(total)), ("IP protocol", str(proto))]
            ip_header = raw[at:at + ihl]
            out.details.append(("IPv4 header checksum", "0x%04x (%s)" % (struct.unpack_from("!H", raw, at + 10)[0], "valid" if _checksum(ip_header) == 0 else "invalid; possible checksum offload on local capture")))
            source_bytes, destination_bytes = raw[at + 12:at + 16], raw[at + 16:at + 20]
            fragmented = bool(frag & 0x3FFF)
            end = min(len(raw), at + total)
            at += ihl
            if fragmented:
                out.protocol, out.info = "IPv4", "Fragment offset=%d more=%s" % ((frag & 0x1FFF) * 8, bool(frag & 0x2000))
                return out
        elif kind == 0x86DD:
            if len(raw) < at + 40 or raw[at] >> 4 != 6:
                raise ValueError("IPv6 header truncated")
            length = struct.unpack_from("!H", raw, at + 4)[0]
            proto = raw[at + 6]
            out.source, out.destination = _ip(raw[at + 8:at + 24]), _ip(raw[at + 24:at + 40])
            out.tags.add("IPv6")
            out.details += [("IPv6 source", out.source), ("IPv6 destination", out.destination), ("Hop limit", str(raw[at + 7])), ("Next header", str(proto))]
            source_bytes, destination_bytes = raw[at + 8:at + 24], raw[at + 24:at + 40]
            fragmented = False
            ipv6_payload_end = at + 40 + length
            end = min(len(raw), ipv6_payload_end)
            at += 40
            for _ in range(8):
                if proto not in (0, 43, 44, 60, 51):
                    break
                if at + 2 > end:
                    raise ValueError("IPv6 extension truncated")
                next_proto = raw[at]
                size = 8 if proto == 44 else (raw[at + 1] + (2 if proto == 51 else 1)) * (4 if proto == 51 else 8)
                if size < 8 or at + size > end:
                    raise ValueError("invalid IPv6 extension")
                if proto == 44:
                    offset_flags = struct.unpack_from("!H", raw, at + 2)[0]
                    if offset_flags & 0xFFF9:
                        out.protocol, out.info = "IPv6", "Fragment offset=%d more=%s" % (offset_flags & 0xFFF8, bool(offset_flags & 1))
                        return out
                out.details.append(("IPv6 extension", f"type={proto} bytes={size}"))
                proto, at = next_proto, at + size
        else:
            out.info = f"EtherType 0x{kind:04x}"
            return out

        data = raw[at:end]
        if proto in (6, 17):
            name = "TCP" if proto == 6 else "UDP"
            if len(data) < (20 if proto == 6 else 8):
                raise ValueError(f"{name} header truncated")
            sport, dport = struct.unpack_from("!HH", data)
            out.source_port, out.destination_port = sport, dport
            out.protocol = name
            out.tags.add(name)
            out.info = f"{sport} -> {dport}"
            out.details += [(f"{name} source port", str(sport)), (f"{name} destination port", str(dport))]
            if proto == 6:
                hlen = (data[12] >> 4) * 4
                if hlen < 20 or hlen > len(data):
                    raise ValueError("invalid TCP header length")
                seq, ack = struct.unpack_from("!II", data, 4)
                out.tcp_sequence = seq
                out.tcp_flags = data[13]
                flags = ",".join(label for bit, label in ((1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"), (16, "ACK"), (32, "URG")) if data[13] & bit)
                out.info += f" [{flags}] Seq={seq} Ack={ack}"
                out.details += [("TCP sequence", str(seq)), ("TCP acknowledgment", str(ack)), ("TCP flags", flags)]
                out.details += [("TCP window", str(struct.unpack_from("!H", data, 14)[0])), ("TCP checksum", "0x%04x" % struct.unpack_from("!H", data, 16)[0])]
                out.details += _tcp_options(data[20:hlen])
            else:
                hlen = 8
                out.details.append(("UDP length", str(struct.unpack_from("!H", data, 4)[0])))
                out.details.append(("UDP checksum", "0x%04x" % struct.unpack_from("!H", data, 6)[0]))
            checksum = struct.unpack_from("!H", data, 16 if proto == 6 else 6)[0]
            declared = (total - ihl) if kind == 0x0800 else (ipv6_payload_end - at)
            if proto == 17:
                declared = struct.unpack_from("!H", data, 4)[0]
            if proto == 17 and checksum == 0 and kind == 0x0800:
                verdict = "disabled (IPv4)"
            elif len(data) < declared or fragmented or declared < hlen:
                verdict = "unverified (truncated or fragmented)"
            elif proto == 17 and checksum == 0:
                verdict = "invalid (IPv6 requires a checksum)"
            else:
                pseudo = source_bytes + destination_bytes
                if kind == 0x0800:
                    pseudo += struct.pack("!BBH", 0, proto, declared)
                else:
                    pseudo += struct.pack("!I3xB", declared, proto)
                verdict = "valid" if _checksum(pseudo + data[:declared]) == 0 else "invalid; possible checksum offload on local capture"
            out.details.append((name + " checksum status", verdict))
            payload = data[hlen:]
            if proto == 6:
                out.tcp_payload = payload
            if proto == 17 and 53 in (sport, dport) and len(payload) >= 12:
                out.protocol = "DNS"
                out.tags.add("DNS")
                out.info, dns_fields = parse_dns(payload)
                out.details += dns_fields
            elif proto == 6 and payload:
                messages = parse_http_stream(payload)
                if messages:
                    out.protocol = "HTTP"
                    out.tags.add("HTTP")
                    out.info = messages[0].start_line
                    for message in messages:
                        out.details.append(("HTTP start line", message.start_line))
                        out.details += [(f"HTTP {name}", value) for name, value in message.headers]
                        out.details.append(("HTTP body length", str(message.body_length) if message.body_length is not None else "unknown"))
                elif 443 in (sport, dport) and len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1:3] in (b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"):
                    out.protocol = "TLS"
                    out.tags.add("TLS")
                    out.info = f"TLS record type={payload[0]} length={int.from_bytes(payload[3:5], 'big')} (encrypted)"
                    out.details.append(("TLS record", out.info))
        elif proto in (1, 58):
            if len(data) < 2:
                raise ValueError("ICMP header truncated")
            out.protocol = "ICMPv6" if proto == 58 else "ICMP"
            out.tags.add("ICMP")
            out.info = f"type={data[0]} code={data[1]}"
            out.details += [("ICMP type", str(data[0])), ("ICMP code", str(data[1]))]
        else:
            out.protocol = "IPv6" if kind == 0x86DD else "IPv4"
            out.info = f"Next protocol {proto}"
    except (ValueError, struct.error) as exc:
        out.info = f"Decode note: {exc}"
    return out
