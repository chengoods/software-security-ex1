"""Read and write classic PCAP captures."""

from __future__ import annotations

import struct


def read_pcap(path: str):
    with open(path, "rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError("PCAP file header is incomplete")
        magic = header[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
        }
        if magic not in formats:
            raise ValueError("Unsupported PCAP format (PCAPNG is not supported)")
        endian, resolution = formats[magic]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHiiii", header[4:])
        if major != 2 or snaplen <= 0:
            raise ValueError("Invalid PCAP file header")
        packets = []
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("Truncated PCAP packet header")
            seconds, subsecond, captured, original = struct.unpack(endian + "IIII", record)
            if captured > snaplen or captured > 16_777_216:
                raise ValueError("Invalid PCAP packet length")
            data = stream.read(captured)
            if len(data) != captured:
                raise ValueError("Truncated PCAP packet data")
            packets.append((seconds + subsecond / resolution, data, original))
        return linktype, packets


def write_pcap(path: str, linktype: int, packets) -> None:
    with open(path, "wb") as stream:
        stream.write(struct.pack("<IHHiiii", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for stamp, data, original in packets:
            seconds = int(stamp)
            micros = min(999_999, round((stamp - seconds) * 1_000_000))
            stream.write(struct.pack("<IIII", seconds, micros, len(data), original))
            stream.write(data)
