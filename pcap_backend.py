"""Small ctypes binding for the libpcap/WinPcap API."""

from __future__ import annotations

import ctypes as C
import os
from dataclasses import dataclass


class Timeval(C.Structure):
    _fields_ = [("tv_sec", C.c_long), ("tv_usec", C.c_long)]


class PacketHeader(C.Structure):
    _fields_ = [("ts", Timeval), ("caplen", C.c_uint32), ("length", C.c_uint32)]


class PcapIf(C.Structure):
    pass


PcapIf._fields_ = [("next", C.POINTER(PcapIf)), ("name", C.c_char_p), ("description", C.c_char_p), ("addresses", C.c_void_p), ("flags", C.c_uint)]


class BpfProgram(C.Structure):
    _fields_ = [("bf_len", C.c_uint), ("bf_insns", C.c_void_p)]


class PcapStat(C.Structure):
    _fields_ = [("ps_recv", C.c_uint), ("ps_drop", C.c_uint), ("ps_ifdrop", C.c_uint)]


@dataclass(frozen=True)
class Device:
    name: str
    description: str


def _decode(value: bytes | None) -> str:
    if not value:
        return ""
    for encoding in ("utf-8", "mbcs" if os.name == "nt" else "latin-1"):
        try:
            return value.decode(encoding)
        except UnicodeDecodeError:
            pass
    return value.decode("latin-1", errors="replace")


class Pcap:
    def __init__(self) -> None:
        try:
            self.lib = C.WinDLL("wpcap.dll") if os.name == "nt" else C.CDLL("libpcap.so.1")
        except OSError as exc:
            raise RuntimeError("未找到抓包库。Windows 请安装 Npcap（兼容 WinPcap 模式）。") from exc
        lib = self.lib
        lib.pcap_findalldevs.argtypes = [C.POINTER(C.POINTER(PcapIf)), C.c_char_p]
        lib.pcap_findalldevs.restype = C.c_int
        lib.pcap_freealldevs.argtypes = [C.POINTER(PcapIf)]
        lib.pcap_open_live.argtypes = [C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p]
        lib.pcap_open_live.restype = C.c_void_p
        lib.pcap_next_ex.argtypes = [C.c_void_p, C.POINTER(C.POINTER(PacketHeader)), C.POINTER(C.POINTER(C.c_ubyte))]
        lib.pcap_next_ex.restype = C.c_int
        lib.pcap_close.argtypes = [C.c_void_p]
        lib.pcap_datalink.argtypes = [C.c_void_p]
        lib.pcap_datalink.restype = C.c_int
        lib.pcap_geterr.argtypes = [C.c_void_p]
        lib.pcap_geterr.restype = C.c_char_p
        lib.pcap_compile.argtypes = [C.c_void_p, C.POINTER(BpfProgram), C.c_char_p, C.c_int, C.c_uint32]
        lib.pcap_compile.restype = C.c_int
        lib.pcap_setfilter.argtypes = [C.c_void_p, C.POINTER(BpfProgram)]
        lib.pcap_setfilter.restype = C.c_int
        lib.pcap_freecode.argtypes = [C.POINTER(BpfProgram)]
        lib.pcap_lib_version.restype = C.c_char_p
        self.has_stats = True
        try:
            lib.pcap_stats.argtypes = [C.c_void_p, C.POINTER(PcapStat)]
            lib.pcap_stats.restype = C.c_int
        except AttributeError:
            self.has_stats = False

    def version(self) -> str:
        return _decode(self.lib.pcap_lib_version())

    def devices(self) -> list[Device]:
        first = C.POINTER(PcapIf)()
        error = C.create_string_buffer(256)
        if self.lib.pcap_findalldevs(C.byref(first), error) != 0:
            raise RuntimeError(_decode(error.value))
        result = []
        try:
            current = first
            while current:
                item = current.contents
                result.append(Device(_decode(item.name), _decode(item.description) or _decode(item.name)))
                current = item.next
        finally:
            if first:
                self.lib.pcap_freealldevs(first)
        return result

    def open(self, name: str, capture_filter: str = "") -> "Capture":
        error = C.create_string_buffer(256)
        handle = self.lib.pcap_open_live(name.encode("utf-8"), 65535, 1, 300, error)
        if not handle:
            raise RuntimeError(_decode(error.value) or "无法打开网卡，请检查抓包驱动与权限。")
        try:
            linktype = self.lib.pcap_datalink(handle)
            if capture_filter.strip():
                program = BpfProgram()
                if self.lib.pcap_compile(handle, C.byref(program), capture_filter.encode("utf-8"), 1, 0xFFFFFFFF) != 0:
                    raise RuntimeError("捕获过滤表达式错误：" + _decode(self.lib.pcap_geterr(handle)))
                try:
                    if self.lib.pcap_setfilter(handle, C.byref(program)) != 0:
                        raise RuntimeError("设置捕获过滤失败：" + _decode(self.lib.pcap_geterr(handle)))
                finally:
                    self.lib.pcap_freecode(C.byref(program))
            return Capture(self.lib, handle, linktype, self.has_stats)
        except Exception:
            self.lib.pcap_close(handle)
            raise


class Capture:
    def __init__(self, lib, handle: int, linktype: int, has_stats: bool = True) -> None:
        self.lib = lib
        self.handle = handle
        self.linktype = linktype
        self.has_stats = has_stats

    def stats(self) -> dict[str, int] | None:
        """Driver counters. ps_drop counts packets lost before reaching the app."""
        if not self.handle or not self.has_stats:
            return None
        stat = PcapStat()
        try:
            if self.lib.pcap_stats(self.handle, C.byref(stat)) != 0:
                return None
        except (AttributeError, OSError):
            return None
        return {"recv": stat.ps_recv, "drop": stat.ps_drop, "ifdrop": stat.ps_ifdrop}

    def next_packet(self) -> tuple[float, bytes, int] | None:
        header = C.POINTER(PacketHeader)()
        data = C.POINTER(C.c_ubyte)()
        result = self.lib.pcap_next_ex(self.handle, C.byref(header), C.byref(data))
        if result == 0:
            return None
        if result != 1:
            raise RuntimeError(_decode(self.lib.pcap_geterr(self.handle)) if result == -1 else "抓包已结束")
        info = header.contents
        return info.ts.tv_sec + info.ts.tv_usec / 1_000_000, C.string_at(data, info.caplen), info.length

    def close(self) -> None:
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None
