"""Bounded IPv4 and IPv6 fragment reassembly for analysis."""

from __future__ import annotations

import struct


class FragmentReassembler:
    def __init__(self):
        self.pending = {}

    def clear(self):
        self.pending.clear()

    def add(self, stamp, index, raw, linktype):
        fragment = self._extract(raw, linktype)
        if fragment is None:
            return None
        key, start, more, payload, prefix, ip_at, previous, next_header = fragment
        for old_key, item in list(self.pending.items()):
            if stamp - item["stamp"] > 30:
                del self.pending[old_key]
        if key not in self.pending and len(self.pending) >= 256:
            del self.pending[next(iter(self.pending))]
        item = self.pending.setdefault(key, {"stamp": stamp, "pieces": [], "indices": [], "end": None, "prefix": None})
        item["stamp"] = stamp
        if index not in item["indices"]:
            item["indices"].append(index)
        end = start + len(payload)
        if end > 65535 or (more and (not payload or len(payload) % 8)):
            del self.pending[key]
            return None
        if not more:
            if item["end"] is not None and item["end"] != end:
                del self.pending[key]
                return None
            item["end"] = end
        if start == 0:
            item["prefix"] = (prefix, ip_at, previous, next_header)
        for old_start, old_payload in item["pieces"]:
            if start < old_start + len(old_payload) and old_start < end:
                if start == old_start and payload == old_payload:
                    return None
                del self.pending[key]
                return None
        item["pieces"].append((start, payload))
        if item["end"] is None or item["prefix"] is None:
            return None
        cursor = 0
        pieces = sorted(item["pieces"])
        for position, data in pieces:
            if position != cursor:
                return None
            cursor += len(data)
        if cursor != item["end"]:
            return None
        prefix, ip_at, previous, next_header = item["prefix"]
        packet = bytearray(prefix + b"".join(data for _, data in pieces))
        if key[0] == 4:
            if len(packet) - ip_at > 65535:
                del self.pending[key]
                return None
            struct.pack_into("!H", packet, ip_at + 2, len(packet) - ip_at)
            struct.pack_into("!H", packet, ip_at + 6, 0)
            packet[ip_at + 10:ip_at + 12] = b"\0\0"
            header = packet[ip_at:len(prefix)]
            if len(header) % 2:
                header += b"\0"
            total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
            while total >> 16:
                total = (total & 65535) + (total >> 16)
            struct.pack_into("!H", packet, ip_at + 10, (~total) & 65535)
        else:
            if len(packet) - ip_at - 40 > 65535:
                del self.pending[key]
                return None
            packet[previous] = next_header
            struct.pack_into("!H", packet, ip_at + 4, len(packet) - ip_at - 40)
        indices = item["indices"]
        del self.pending[key]
        return bytes(packet), indices

    @staticmethod
    def _extract(raw, linktype):
        at = 0
        if linktype == 1:
            if len(raw) < 14:
                return None
            kind = int.from_bytes(raw[12:14], "big")
            at = 14
            for _ in range(2):
                if kind not in (0x8100, 0x88A8) or len(raw) < at + 4:
                    break
                kind = int.from_bytes(raw[at + 2:at + 4], "big")
                at += 4
        elif linktype == 101:
            kind = 0x86DD if raw and raw[0] >> 4 == 6 else 0x0800
        elif linktype in (0, 108):
            if len(raw) < 4:
                return None
            kind = 0x86DD if int.from_bytes(raw[:4], "little") in (24, 28, 30) else 0x0800
            at = 4
        else:
            return None
        if kind == 0x0800 and len(raw) >= at + 20 and raw[at] >> 4 == 4:
            size = (raw[at] & 15) * 4
            if size < 20 or len(raw) < at + size:
                return None
            length = int.from_bytes(raw[at + 2:at + 4], "big")
            if length < size or len(raw) < at + length:
                return None
            flags = int.from_bytes(raw[at + 6:at + 8], "big")
            start, more = (flags & 8191) * 8, bool(flags & 8192)
            if not start and not more:
                return None
            key = (4, raw[at + 12:at + 20], raw[at + 4:at + 6], raw[at + 9], linktype)
            return key, start, more, raw[at + size:at + length], raw[:at + size], at, 0, 0
        if kind != 0x86DD or len(raw) < at + 40 or raw[at] >> 4 != 6:
            return None
        end = at + 40 + int.from_bytes(raw[at + 4:at + 6], "big")
        if len(raw) < end:
            return None
        next_header, cursor, previous = raw[at + 6], at + 40, at + 6
        for _ in range(8):
            if next_header == 44:
                if cursor + 8 > end:
                    return None
                flags = int.from_bytes(raw[cursor + 2:cursor + 4], "big")
                start, more = flags & 65528, bool(flags & 1)
                if not start and not more:
                    return None
                key = (6, raw[at + 8:at + 40], raw[cursor + 4:cursor + 8], raw[cursor], linktype)
                return key, start, more, raw[cursor + 8:end], raw[:cursor], at, previous, raw[cursor]
            if next_header not in (0, 43, 60, 51) or cursor + 2 > end:
                break
            size = (raw[cursor + 1] + (2 if next_header == 51 else 1)) * (4 if next_header == 51 else 8)
            if size < 8 or cursor + size > end:
                return None
            previous, next_header, cursor = cursor, raw[cursor], cursor + size
        return None
