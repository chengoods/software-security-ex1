"""Experiment 1A: GUI packet sniffer and basic protocol analyzer."""

from __future__ import annotations

import datetime as dt
import queue
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from tkinter import filedialog, messagebox, ttk

from pcap_backend import Pcap
from pcap_file import read_pcap, write_pcap
from protocols import Decoded, decode
from tcp_streams import FlowTracker
from application_protocols import parse_dns_tcp_stream
from process_connections import ProcessConnections


MAX_PACKETS = 20000
FILTERS = ("All", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ARP", "DNS", "TLS")


@dataclass
class Packet:
    stamp: float
    data: bytes
    original: int
    decoded: Decoded


def hex_dump(data: bytes) -> str:
    lines = []
    for at in range(0, len(data), 16):
        chunk = data[at:at + 16]
        hexpart = " ".join(f"{value:02x}" for value in chunk)
        textpart = "".join(chr(value) if 32 <= value < 127 else "." for value in chunk)
        lines.append(f"{at:08x}  {hexpart:<47}  {textpart}")
    return "\n".join(lines)


def stream_preview(data: bytes) -> tuple[str, str]:
    if not data:
        return "连续载荷为空", ""
    try:
        text = data[:65536].decode("utf-8")
        if all(char.isprintable() or char in "\r\n\t" for char in text):
            suffix = "\n…（预览限前 64 KiB）" if len(data) > 65536 else ""
            return "连续载荷（UTF-8 文本）", text + suffix
    except UnicodeDecodeError:
        pass
    preview = data[:4096]
    suffix = "\n…（十六进制预览限前 4 KiB）" if len(data) > len(preview) else ""
    return "连续载荷（二进制，十六进制 / ASCII）", hex_dump(preview) + suffix


class SnifferApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("实验 1A | 网络嗅探器")
        self.geometry("1200x760")
        self.minsize(850, 520)
        self.pcap = None
        self.devices = []
        self.packets: list[Packet] = []
        self.flows = FlowTracker()
        self.linktype = 1
        self.events: queue.Queue = queue.Queue(maxsize=5000)
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.dropped = 0
        self.connections = {}
        self.process_notice = ""
        self._build_ui()
        self.after(100, self._drain)
        self.after(150, self._load_devices)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        toolbar = ttk.Frame(self, padding=8)
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text="网卡").pack(side="left")
        self.device_var = tk.StringVar()
        self.device_box = ttk.Combobox(toolbar, textvariable=self.device_var, width=42, state="readonly")
        self.device_box.pack(side="left", padx=(5, 7))
        ttk.Button(toolbar, text="刷新", command=self._load_devices).pack(side="left")
        self.start_button = ttk.Button(toolbar, text="开始", command=self._start)
        self.start_button.pack(side="left", padx=(12, 3))
        self.stop_button = ttk.Button(toolbar, text="停止", command=self._stop, state="disabled")
        self.stop_button.pack(side="left", padx=3)
        ttk.Button(toolbar, text="打开 PCAP", command=self._open_file).pack(side="left", padx=(12, 3))
        ttk.Button(toolbar, text="保存 PCAP", command=self._save_file).pack(side="left", padx=3)
        ttk.Button(toolbar, text="TCP 流", command=self._show_flows).pack(side="left", padx=(12, 3))
        ttk.Button(toolbar, text="清空", command=self._clear).pack(side="left", padx=3)

        filterbar = ttk.Frame(self, padding=(8, 0, 8, 8))
        filterbar.pack(fill="x")
        ttk.Label(filterbar, text="捕获过滤 BPF").pack(side="left")
        self.capture_filter = tk.StringVar()
        ttk.Entry(filterbar, textvariable=self.capture_filter, width=34).pack(side="left", padx=(5, 16))
        ttk.Label(filterbar, text="显示协议").pack(side="left")
        self.display_filter = tk.StringVar(value="All")
        box = ttk.Combobox(filterbar, textvariable=self.display_filter, values=FILTERS, width=10, state="readonly")
        box.pack(side="left", padx=5)
        box.bind("<<ComboboxSelected>>", lambda _: self._refresh_list())
        ttk.Label(filterbar, text="显示搜索 (src:/dst:/info:)").pack(side="left", padx=(12, 0))
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self._refresh_list())
        ttk.Entry(filterbar, textvariable=self.search, width=28).pack(side="left", padx=5)

        vertical = ttk.Panedwindow(self, orient="vertical")
        vertical.pack(fill="both", expand=True, padx=8)
        list_frame = ttk.Frame(vertical)
        vertical.add(list_frame, weight=3)
        columns = ("number", "time", "source", "destination", "protocol", "length", "info")
        self.table = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="browse")
        labels = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        widths = (65, 110, 170, 170, 85, 75, 430)
        for column, label, width in zip(columns, labels, widths):
            self.table.heading(column, text=label)
            self.table.column(column, width=width, minwidth=50, stretch=(column == "info"))
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.table.yview)
        scrollbar.pack(side="right", fill="y")
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.bind("<<TreeviewSelect>>", self._selection)

        lower = ttk.Panedwindow(vertical, orient="horizontal")
        vertical.add(lower, weight=2)
        details_frame = ttk.LabelFrame(lower, text="协议字段")
        lower.add(details_frame, weight=1)
        self.details = ttk.Treeview(details_frame, columns=("value",), show="tree headings")
        self.details.heading("#0", text="字段")
        self.details.heading("value", text="值")
        self.details.column("#0", width=180)
        self.details.column("value", width=330)
        self.details.pack(fill="both", expand=True)
        bytes_frame = ttk.LabelFrame(lower, text="原始字节")
        lower.add(bytes_frame, weight=1)
        self.bytes_view = tk.Text(bytes_frame, wrap="none", font=("Consolas", 10), state="disabled")
        self.bytes_view.pack(fill="both", expand=True)
        self.status = tk.StringVar(value="就绪")
        ttk.Label(self, textvariable=self.status, anchor="w", padding=(8, 5)).pack(fill="x")

    def _load_devices(self) -> None:
        try:
            self.pcap = Pcap()
            self.devices = self.pcap.devices()
            names = [f"{item.description}  [{item.name}]" for item in self.devices]
            self.device_box["values"] = names
            if names:
                self.device_box.current(0)
            self.status.set(f"{len(names)} 个网卡 | {self.pcap.version()}")
        except Exception as exc:
            self.status.set(str(exc))

    def _start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        index = self.device_box.current()
        if index < 0 or not self.pcap:
            messagebox.showerror("无法开始", "请先选择网卡。")
            return
        if self.packets:
            self._clear()
        self.stop_event.clear()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.worker = threading.Thread(target=self._capture, args=(self.devices[index].name, self.capture_filter.get()), daemon=True)
        self.worker.start()

    def _capture(self, name: str, expression: str) -> None:
        capture = None
        try:
            capture = self.pcap.open(name, expression)
            self.events.put(("linktype", capture.linktype))
            try:
                process_lookup = ProcessConnections()
            except RuntimeError as exc:
                process_lookup = None
                self.events.put(("process_error", str(exc)))
            next_lookup = 0.0
            while not self.stop_event.is_set():
                item = capture.next_packet()
                if item:
                    try:
                        self.events.put_nowait(("packet", item))
                    except queue.Full:
                        self.dropped += 1
                if process_lookup and time.monotonic() >= next_lookup:
                    try:
                        self.events.put_nowait(("connections", process_lookup.snapshot()))
                    except queue.Full:
                        pass
                    except (OSError, ValueError) as exc:
                        self.events.put(("process_error", f"进程关联暂不可用：{exc}"))
                        process_lookup = None
                    next_lookup = time.monotonic() + 0.5
        except Exception as exc:
            self.events.put(("error", str(exc)))
        finally:
            if capture:
                capture.close()
            self.events.put(("stopped", None))

    def _stop(self) -> None:
        self.stop_event.set()
        self.status.set("正在停止抓包…")

    def _drain(self) -> None:
        for _ in range(250):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "linktype":
                self.linktype = value
                self.status.set(f"正在抓包 | 链路类型 {value}")
            elif kind == "packet":
                stamp, data, original = value
                if len(self.packets) < MAX_PACKETS:
                    decoded = decode(data, self.linktype)
                    index = len(self.packets)
                    self.packets.append(Packet(stamp, data, original, decoded))
                    flow = self.flows.add(stamp, index, decoded)
                    if flow and self.connections:
                        self.flows.attribute_flow(flow, self.connections)
                    self._add_row(index)
                else:
                    self.dropped += 1
            elif kind == "error":
                self.status.set(value)
                messagebox.showerror("抓包失败", value)
            elif kind == "connections":
                self.connections = value
                self.flows.attribute(value)
            elif kind == "process_error":
                self.process_notice = value
                self.status.set(value)
            elif kind == "stopped":
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.status.set(f"已停止 | 已保存 {len(self.packets)} 包 | 丢弃 {self.dropped} 包")
        self.after(100, self._drain)

    def _matches(self, packet: Packet) -> bool:
        protocol = self.display_filter.get()
        if protocol != "All" and protocol not in packet.decoded.tags:
            return False
        search = self.search.get().strip().lower()
        if search.startswith("src:"):
            return search[4:].strip() in packet.decoded.source.lower()
        if search.startswith("dst:"):
            return search[4:].strip() in packet.decoded.destination.lower()
        if search.startswith("info:"):
            return search[5:].strip() in packet.decoded.info.lower()
        return not search or search in " ".join((packet.decoded.source, packet.decoded.destination, packet.decoded.protocol, packet.decoded.info)).lower()

    def _add_row(self, index: int) -> None:
        packet = self.packets[index]
        if not self._matches(packet):
            return
        time = dt.datetime.fromtimestamp(packet.stamp).strftime("%H:%M:%S.%f")[:-3]
        self.table.insert("", "end", iid=str(index), values=(index + 1, time, packet.decoded.source, packet.decoded.destination, packet.decoded.protocol, packet.original, packet.decoded.info))

    def _refresh_list(self) -> None:
        if not hasattr(self, "table"):
            return
        self.table.delete(*self.table.get_children())
        for index in range(len(self.packets)):
            self._add_row(index)

    def _selection(self, _event) -> None:
        selection = self.table.selection()
        if not selection:
            return
        packet = self.packets[int(selection[0])]
        self.details.delete(*self.details.get_children())
        for label, value in packet.decoded.details:
            self.details.insert("", "end", text=label, values=(value,))
        self.bytes_view.configure(state="normal")
        self.bytes_view.delete("1.0", "end")
        self.bytes_view.insert("1.0", hex_dump(packet.data))
        self.bytes_view.configure(state="disabled")

    def _clear(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("正在抓包", "请先停止抓包。")
            return
        self.packets.clear()
        self.flows.clear()
        self.connections = {}
        self.process_notice = ""
        self.dropped = 0
        self._refresh_list()
        self.details.delete(*self.details.get_children())
        self.bytes_view.configure(state="normal")
        self.bytes_view.delete("1.0", "end")
        self.bytes_view.configure(state="disabled")
        self.status.set("已清空")

    def _open_file(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("正在抓包", "请先停止抓包。")
            return
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.cap"), ("All files", "*.*")])
        if not path:
            return
        try:
            linktype, items = read_pcap(path)
            if len(items) > MAX_PACKETS:
                raise ValueError(f"超过 {MAX_PACKETS} 包的显示上限")
            self._clear()
            self.linktype = linktype
            self.packets = [Packet(stamp, data, original, decode(data, linktype)) for stamp, data, original in items]
            for index, packet in enumerate(self.packets):
                self.flows.add(packet.stamp, index, packet.decoded)
            self._refresh_list()
            self.status.set(f"已打开 {len(items)} 包 | 链路类型 {linktype}")
        except Exception as exc:
            messagebox.showerror("打开失败", str(exc))

    def _save_file(self) -> None:
        if not self.packets:
            messagebox.showinfo("没有数据", "当前没有可保存的数据包。")
            return
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("正在抓包", "请先停止抓包。")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if path:
            try:
                write_pcap(path, self.linktype, ((p.stamp, p.data, p.original) for p in self.packets))
                self.status.set(f"已保存 {len(self.packets)} 包")
            except Exception as exc:
                messagebox.showerror("保存失败", str(exc))

    def _show_flows(self) -> None:
        window = tk.Toplevel(self)
        window.title("TCP 流追踪")
        window.geometry("1050x650")
        top = ttk.Frame(window, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="进程").pack(side="left")
        process_filter = tk.StringVar(value="全部")
        process_box = ttk.Combobox(top, textvariable=process_filter, width=34, state="readonly")
        process_box.pack(side="left", padx=(5, 12))
        columns = ("id", "endpoint_a", "endpoint_b", "process", "packets", "bytes", "http")
        list_frame = ttk.Frame(window)
        list_frame.pack(fill="x", padx=8)
        table = ttk.Treeview(list_frame, columns=columns, show="headings", height=10, selectmode="browse")
        for key, label, width in zip(columns, ("流", "端点 A", "端点 B", "进程 / PID", "包数", "载荷字节", "HTTP 消息"), (50, 180, 180, 230, 70, 100, 100)):
            table.heading(key, text=label)
            table.column(key, width=width, stretch=key.startswith("endpoint"))
        table.pack(side="left", fill="x", expand=True)
        list_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=table.yview)
        list_scrollbar.pack(side="right", fill="y")
        table.configure(yscrollcommand=list_scrollbar.set)
        detail = tk.Text(window, font=("Consolas", 10), wrap="none", state="disabled")
        detail.pack(fill="both", expand=True, padx=8, pady=8)

        def refresh() -> None:
            choice = process_filter.get()
            selection = table.selection()
            scroll_position = table.yview()[0]
            owners = {f"{owner.name} (PID {owner.pid})" for flow in self.flows.flows for owner in flow.owners.values()}
            choices = ["全部", "未知进程"] + sorted(owners)
            process_box["values"] = choices
            if choice not in choices:
                process_filter.set("全部")
                choice = "全部"
            table.delete(*table.get_children())
            for flow in self.flows.flows:
                owner_labels = sorted({f"{owner.name} (PID {owner.pid})" for owner in flow.owners.values()})
                if choice == "未知进程" and owner_labels:
                    continue
                if choice not in ("全部", "未知进程") and choice not in owner_labels:
                    continue
                directions = list(flow.directions.values())
                endpoint = lambda item: f"{item.endpoint[0]}:{item.endpoint[1]}"
                total = sum(direction.wire_bytes for direction in directions)
                http_count = sum(len(direction.http_messages) for direction in directions)
                table.insert("", "end", iid=str(flow.number), values=(flow.number, endpoint(directions[0]), endpoint(directions[1]), ", ".join(owner_labels) or "未知", len(flow.packet_indices), total, http_count))
            if selection and table.exists(selection[0]):
                table.selection_set(selection[0])
                table.focus(selection[0])
                select()
            table.yview_moveto(scroll_position)

        def select(_event=None) -> None:
            selected = table.selection()
            if not selected:
                return
            flow = self.flows.flows[int(selected[0]) - 1]
            lines = [f"流 #{flow.number} | 包: {', '.join(str(i + 1) for i in flow.packet_indices[:100])}"]
            if flow.owners:
                lines += [f"本机端点 {ip}:{port} -> {owner.name} (PID {owner.pid})" for (ip, port), owner in flow.owners.items()]
            else:
                lines.append("进程未知：离线 PCAP 不含 PID；实时连接可能已在查询前结束")
            if len(flow.packet_indices) > 100:
                lines.append("（包号仅显示前 100 个）")
            for direction in flow.directions.values():
                data, gaps = direction.reassemble()
                lines += ["", f"=== {direction.endpoint[0]}:{direction.endpoint[1]} -> 对端 ===",
                          f"包数={direction.packet_count}  载荷字节={direction.wire_bytes}  连续重组={len(data)}"]
                if gaps:
                    lines.append(f"缺口: {gaps[:10]}（仅显示首个缺口前数据）")
                if direction.truncated:
                    lines.append("此方向已达到 4 MiB 重组上限")
                messages = direction.http_messages
                for message in messages:
                    lines.append(f"HTTP: {message.start_line} | body={message.body_length} | {'complete' if message.complete else 'incomplete'}")
                    lines += [f"  {name}: {value}" for name, value in message.headers]
                if direction.endpoint[1] == 53 or any(item.endpoint[1] == 53 for item in flow.directions.values()):
                    for summary, fields in parse_dns_tcp_stream(data):
                        lines.append(f"DNS over TCP: {summary}")
                        lines += [f"  {name}: {value}" for name, value in fields]
                preview_label, preview_text = stream_preview(data)
                lines += ["", f"--- {preview_label} ---", preview_text]
            detail.configure(state="normal")
            detail.delete("1.0", "end")
            detail.insert("1.0", "\n".join(lines))
            detail.configure(state="disabled")

        table.bind("<<TreeviewSelect>>", select)
        process_box.bind("<<ComboboxSelected>>", lambda _: refresh())
        ttk.Button(top, text="刷新", command=refresh).pack(side="right")
        refresh()

        def periodic_refresh() -> None:
            if window.winfo_exists():
                refresh()
                window.after(1000, periodic_refresh)

        window.after(1000, periodic_refresh)

    def _close(self) -> None:
        self.stop_event.set()
        self.destroy()


if __name__ == "__main__":
    SnifferApp().mainloop()
