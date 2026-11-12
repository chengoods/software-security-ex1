"""Windows TCP connection ownership from the IP Helper API."""

from __future__ import annotations

import ctypes as ct
import ipaddress
import os
import struct
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Tuple


Endpoint = Tuple[str, int]
Connection = Tuple[Endpoint, Endpoint]


@dataclass(frozen=True)
class Owner:
    pid: int
    name: str


class TcpRow4(ct.Structure):
    _fields_ = [("state", ct.c_uint32), ("local_addr", ct.c_uint32),
                ("local_port", ct.c_uint32), ("remote_addr", ct.c_uint32),
                ("remote_port", ct.c_uint32), ("pid", ct.c_uint32)]


class TcpRow6(ct.Structure):
    _fields_ = [("local_addr", ct.c_ubyte * 16), ("local_scope", ct.c_uint32),
                ("local_port", ct.c_uint32), ("remote_addr", ct.c_ubyte * 16),
                ("remote_scope", ct.c_uint32), ("remote_port", ct.c_uint32),
                ("state", ct.c_uint32), ("pid", ct.c_uint32)]


def _port(value: int) -> int:
    return int.from_bytes(struct.pack("<I", value)[:2], "big")


def _address(raw: bytes, scope: int = 0) -> str:
    address = ipaddress.ip_address(raw)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    if scope and isinstance(address, ipaddress.IPv6Address) and address.is_link_local:
        return f"{address}%{scope}"
    return str(address)


class ProcessConnections:
    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("进程关联仅支持 Windows 实时抓包")
        self.iphlp = ct.WinDLL("iphlpapi.dll")
        self.kernel = ct.WinDLL("kernel32.dll", use_last_error=True)
        self.iphlp.GetExtendedTcpTable.argtypes = [ct.c_void_p, ct.POINTER(ct.c_uint32), ct.c_int, ct.c_uint32, ct.c_uint32, ct.c_uint32]
        self.iphlp.GetExtendedTcpTable.restype = ct.c_uint32
        self.kernel.OpenProcess.argtypes = [ct.c_uint32, ct.c_int, ct.c_uint32]
        self.kernel.OpenProcess.restype = ct.c_void_p
        self.kernel.QueryFullProcessImageNameW.argtypes = [ct.c_void_p, ct.c_uint32, ct.c_wchar_p, ct.POINTER(ct.c_uint32)]
        self.kernel.QueryFullProcessImageNameW.restype = ct.c_int
        self.kernel.CloseHandle.argtypes = [ct.c_void_p]

    def _name(self, pid: int) -> str:
        handle = self.kernel.OpenProcess(0x1000, 0, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return f"PID {pid}"
        try:
            buffer = ct.create_unicode_buffer(32768)
            size = ct.c_uint32(len(buffer))
            if self.kernel.QueryFullProcessImageNameW(handle, 0, buffer, ct.byref(size)):
                return PureWindowsPath(buffer.value).name or f"PID {pid}"
            return f"PID {pid}"
        finally:
            self.kernel.CloseHandle(handle)

    def _rows(self, family: int, row_type):
        size = ct.c_uint32(0)
        result = self.iphlp.GetExtendedTcpTable(None, ct.byref(size), 0, family, 5, 0)
        if result not in (0, 122):  # ERROR_INSUFFICIENT_BUFFER
            raise OSError(result, "GetExtendedTcpTable size query failed")
        for _ in range(3):
            buffer = ct.create_string_buffer(size.value)
            result = self.iphlp.GetExtendedTcpTable(buffer, ct.byref(size), 0, family, 5, 0)
            if result == 122:
                continue
            if result:
                raise OSError(result, "GetExtendedTcpTable failed")
            count = struct.unpack_from("<I", buffer.raw)[0]
            row_size = ct.sizeof(row_type)
            if 4 + count * row_size > len(buffer):
                raise ValueError("Invalid TCP connection table size")
            return [row_type.from_buffer_copy(buffer, 4 + i * row_size) for i in range(count)]
        raise OSError(122, "TCP connection table kept changing")

    def snapshot(self) -> dict[Connection, Owner]:
        connections = {}
        names = {}
        for row in self._rows(2, TcpRow4):  # AF_INET
            local = (_address(struct.pack("<I", row.local_addr)), _port(row.local_port))
            remote = (_address(struct.pack("<I", row.remote_addr)), _port(row.remote_port))
            if not remote[1] or not local[1]:
                continue
            if row.pid not in names:
                names[row.pid] = self._name(row.pid)
            connections[(local, remote)] = Owner(row.pid, names[row.pid])
        for row in self._rows(23, TcpRow6):  # AF_INET6
            local = (_address(bytes(row.local_addr), row.local_scope), _port(row.local_port))
            remote = (_address(bytes(row.remote_addr), row.remote_scope), _port(row.remote_port))
            if not remote[1] or not local[1]:
                continue
            if row.pid not in names:
                names[row.pid] = self._name(row.pid)
            connections[(local, remote)] = Owner(row.pid, names[row.pid])
        return connections
