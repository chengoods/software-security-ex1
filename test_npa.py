"""Run with: python test_npa.py"""

import socket
import struct
import unittest
from unittest.mock import patch

from application_protocols import parse_dns, parse_dns_tcp_stream, parse_http_stream
from process_connections import Owner
from protocols import decode
from tcp_streams import FlowTracker
from app import stream_preview
from app import Packet, SnifferApp
from display_expression import compile_display_expression
from protocols import _checksum
from ip_fragments import FragmentReassembler


def packet(src, dst, sport, dport, seq, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 4096, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return decode(b"\0" * 12 + b"\x08\x00" + ip + tcp)


class NpaTests(unittest.TestCase):
    def test_ipv4_fragments_out_of_order(self):
        source, target = socket.inet_aton("192.0.2.1"), socket.inet_aton("198.51.100.2")
        udp = struct.pack("!HHHH", 40000, 9999, 24, 0) + b"abcdefghijklmnop"

        def frame(offset, more, payload):
            header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 7,
                                           offset // 8 | (0x2000 if more else 0), 64, 17, 0, source, target))
            struct.pack_into("!H", header, 10, _checksum(header))
            return b"\0" * 12 + b"\x08\x00" + header + payload

        first, last = frame(0, True, udp[:16]), frame(16, False, udp[16:])
        reassembler = FragmentReassembler()
        self.assertIsNone(reassembler.add(1, 0, last, 1))
        self.assertEqual(decode(first).protocol, "IPv4")
        completed = reassembler.add(2, 1, first, 1)
        self.assertEqual(completed[1], [0, 1])
        decoded = decode(completed[0])
        self.assertEqual(decoded.protocol, "UDP")
        self.assertEqual(decoded.destination_port, 9999)
        self.assertIn("valid", dict(decoded.details)["IPv4 header checksum"])
        self.assertEqual(completed[0][-len(udp):], udp)

    def test_ipv6_fragments_and_missing_piece(self):
        source = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        target = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        udp = struct.pack("!HHHH", 1234, 9999, 24, 0) + b"abcdefghijklmnop"

        def frame(offset, more, payload):
            fragment = struct.pack("!BBHI", 17, 0, offset | int(more), 12345)
            header = struct.pack("!IHBB16s16s", 0x60000000, len(fragment) + len(payload), 44, 64, source, target)
            return b"\0" * 12 + b"\x86\xdd" + header + fragment + payload

        first, last = frame(0, True, udp[:16]), frame(16, False, udp[16:])
        reassembler = FragmentReassembler()
        self.assertIsNone(reassembler.add(1, 0, first, 1))
        self.assertEqual(decode(first).protocol, "IPv6")
        completed = reassembler.add(2, 1, last, 1)
        self.assertEqual(completed[1], [0, 1])
        self.assertEqual(decode(completed[0]).destination_port, 9999)
        self.assertEqual(completed[0][-len(udp):], udp)

    def test_fragment_overlap_rejected(self):
        source, target = socket.inet_aton("192.0.2.1"), socket.inet_aton("198.51.100.2")

        def frame(offset, more, payload):
            header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 8,
                                 offset // 8 | (0x2000 if more else 0), 64, 17, 0, source, target)
            return b"\0" * 12 + b"\x08\x00" + header + payload

        reassembler = FragmentReassembler()
        self.assertIsNone(reassembler.add(1, 0, frame(0, True, b"abcdefghijklmnop"), 1))
        self.assertIsNone(reassembler.add(2, 1, frame(8, False, b"XXXXXXXX"), 1))
        self.assertFalse(reassembler.pending)

    def test_offline_import_shows_reassembly_and_keeps_original_packets(self):
        source, target = socket.inet_aton("192.0.2.1"), socket.inet_aton("198.51.100.2")
        udp = struct.pack("!HHHH", 40000, 9999, 24, 0) + b"abcdefghijklmnop"

        def frame(offset, more, payload):
            header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 10,
                                 offset // 8 | (0x2000 if more else 0), 64, 17, 0, source, target)
            return b"\0" * 12 + b"\x08\x00" + header + payload

        first, last = frame(0, True, udp[:16]), frame(16, False, udp[16:])
        records = [(1.0, last, len(last)), (2.0, first, len(first))]
        app = SnifferApp()
        try:
            with patch("app.filedialog.askopenfilename", return_value="synthetic.pcap"), \
                 patch("app.read_pcap", return_value=(1, records)):
                app._open_file()
            self.assertEqual(len(app.table.get_children()), 2)
            self.assertEqual([item.data for item in app.packets], [last, first])
            self.assertEqual(app.packets[0].decoded.protocol, "IPv4")
            self.assertEqual(app.packets[1].decoded.protocol, "UDP")
            self.assertIn("IP reassembly", dict(app.packets[1].decoded.details))
            app.display_filter.set("UDP")
            app._refresh_list()
            self.assertEqual(len(app.table.get_children()), 1)
            with patch("app.filedialog.asksaveasfilename", return_value="synthetic-out.pcap"), \
                 patch("app.write_pcap") as write:
                app._save_file()
            self.assertEqual(list(write.call_args[0][2]), records)
        finally:
            app.destroy()

    def test_display_expression_logic_and_fields(self):
        tcp = packet("192.0.2.1", "198.51.100.2", 50000, 80, 1, 0x18)
        self.assertTrue(compile_display_expression("tcp and port 80")(tcp))
        self.assertTrue(compile_display_expression("ip.addr == 192.0.2.1 and not udp")(tcp))
        self.assertTrue(compile_display_expression("(udp or http or tcp) and dst.port == 80")(tcp))
        self.assertFalse(compile_display_expression("udp or tcp and port 53")(tcp))
        with self.assertRaises(ValueError):
            compile_display_expression("tcp and")

    def test_display_filter_keeps_search_forms(self):
        tcp = packet("192.0.2.1", "198.51.100.2", 50000, 80, 1, 0x12)
        self.assertTrue(compile_display_expression("syn")(tcp))
        self.assertTrue(compile_display_expression("info:SYN")(tcp))
        self.assertTrue(compile_display_expression("info: SYN")(tcp))
        self.assertTrue(compile_display_expression("src:192.0.2")(tcp))
        self.assertTrue(compile_display_expression("192.0.2")(tcp))
        self.assertTrue(compile_display_expression("tcp and info:syn")(tcp))
        self.assertTrue(compile_display_expression("tcp and src:192.0.2")(tcp))
        tcp.info = "SYN ACK"
        self.assertTrue(compile_display_expression("SYN Ack")(tcp))
        self.assertTrue(compile_display_expression("tcp")(tcp))
        self.assertFalse(compile_display_expression("dst:192.0.2")(tcp))
        self.assertFalse(compile_display_expression("udp and info:syn")(tcp))
        self.assertTrue(compile_display_expression('info:"SYN"')(tcp))
        with self.assertRaises(ValueError):
            compile_display_expression("info:syn and")

    def test_cross_packet_http_tags_only_payload_packets(self):
        tracker = FlowTracker()
        a, b = "192.0.2.1", "198.51.100.2"
        request = b"GET /split HTTP/1.1\r\nHost: example.test\r\n\r\n"
        decoded = [packet(a, b, 50000, 80, 100, 2),
                   packet(a, b, 50000, 80, 101, 24, request[:12]),
                   packet(a, b, 50000, 80, 113, 24, request[12:])]
        records = [Packet(float(i), b"", 0, item) for i, item in enumerate(decoded)]
        app = object.__new__(SnifferApp)
        app.packets = records
        for i, item in enumerate(decoded):
            flow = tracker.add(float(i), i, item)
        changed = app._tag_flow_http(flow)
        self.assertEqual(changed, {1, 2})
        self.assertNotIn("HTTP", records[0].decoded.tags)
        self.assertTrue(all("HTTP" in records[i].decoded.tags for i in (1, 2)))

    def test_tcp_options_and_checksum_status(self):
        source, destination = socket.inet_aton("192.0.2.1"), socket.inet_aton("198.51.100.2")
        options = b"\x02\x04\x05\xb4\x03\x03\x07\x01\x04\x02\x01\x01\x08\x0a" + struct.pack("!II", 123, 456) + b"\x00\x00"
        tcp = bytearray(struct.pack("!HHIIBBHHH", 50000, 80, 100, 0, 0xB0, 2, 4096, 0, 0) + options)
        pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp))
        struct.pack_into("!H", tcp, 16, _checksum(pseudo + tcp))
        ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, source, destination))
        struct.pack_into("!H", ip, 10, _checksum(ip))
        decoded = decode(b"\0" * 12 + b"\x08\x00" + ip + tcp)
        fields = dict(decoded.details)
        self.assertIn("valid", fields["IPv4 header checksum"])
        self.assertEqual(fields["TCP checksum status"], "valid")
        self.assertEqual(fields["TCP window"], "4096")
        self.assertIn("MSS=1460", [value for key, value in decoded.details if key == "TCP option"])
        self.assertIn("Window scale=7", [value for key, value in decoded.details if key == "TCP option"])
        self.assertIn("SACK permitted", [value for key, value in decoded.details if key == "TCP option"])
        self.assertTrue(any("Timestamp TSval=123" in value for key, value in decoded.details if key == "TCP option"))
        broken = decode(b"\0" * 12 + b"\x08\x00" + ip + tcp[:-1] + b"\x01")
        self.assertIn("invalid", dict(broken.details)["TCP checksum status"])

    def test_udp_checksum_ipv6_and_ipv4_disabled(self):
        source = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        destination = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        udp = bytearray(struct.pack("!HHHH", 40000, 53, 11, 0) + b"abc")
        pseudo = source + destination + struct.pack("!I3xB", len(udp), 17)
        struct.pack_into("!H", udp, 6, _checksum(pseudo + udp))
        ip6 = struct.pack("!IHBB16s16s", 0x60000000, len(udp), 17, 64, source, destination)
        decoded = decode(b"\0" * 12 + b"\x86\xdd" + ip6 + udp)
        self.assertEqual(dict(decoded.details)["UDP checksum status"], "valid")
        ip4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 31, 1, 0, 64, 17, 0,
                          socket.inet_aton("192.0.2.1"), socket.inet_aton("198.51.100.2"))
        udp[6:8] = b"\0\0"
        decoded = decode(b"\0" * 12 + b"\x08\x00" + ip4 + udp)
        self.assertEqual(dict(decoded.details)["UDP checksum status"], "disabled (IPv4)")

    def test_stream_preview_uses_hex_for_binary(self):
        label, preview = stream_preview(b"POST / HTTP/1.1\r\n\r\n\x00\xff\x01")
        self.assertIn("十六进制", label)
        self.assertIn("50 4f 53 54", preview)
        self.assertNotIn("\ufffd", preview)

    def test_stream_preview_keeps_readable_text(self):
        label, preview = stream_preview("GET / HTTP/1.1\r\n备注: 测试\r\n".encode("utf-8"))
        self.assertIn("UTF-8", label)
        self.assertIn("备注: 测试", preview)

    def test_reorder_retransmit_bidirectional_http(self):
        tracker = FlowTracker()
        a, b = "192.0.2.1", "198.51.100.2"
        request = b"GET /item HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nDATA"
        segments = [
            packet(a, b, 50000, 80, 100, 0x02),
            packet(b, a, 80, 50000, 800, 0x12),
            packet(a, b, 50000, 80, 101 + 20, 0x18, request[20:]),
            packet(a, b, 50000, 80, 101, 0x18, request[:20]),
            packet(a, b, 50000, 80, 101, 0x18, request[:20]),
            packet(b, a, 80, 50000, 801, 0x18, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"),
        ]
        for i, decoded in enumerate(segments):
            tracker.add(float(i + 1), i, decoded)
        self.assertEqual(len(tracker.flows), 1)
        flow = tracker.flows[0]
        self.assertEqual(flow.directions[(a, 50000)].reassemble(), (request, []))
        self.assertEqual(flow.directions[(a, 50000)].http_messages[0].body_length, 4)
        self.assertTrue(flow.directions[(a, 50000)].http_messages[0].complete)
        self.assertEqual(flow.directions[(b, 80)].http_messages[0].start_line, "HTTP/1.1 200 OK")

    def test_gap_and_new_connection(self):
        tracker = FlowTracker()
        a, b = "192.0.2.1", "198.51.100.2"
        tracker.add(1, 0, packet(a, b, 50000, 80, 100, 2))
        tracker.add(2, 1, packet(a, b, 50000, 80, 101, 24, b"abc"))
        tracker.add(3, 2, packet(a, b, 50000, 80, 110, 24, b"xyz"))
        self.assertEqual(tracker.flows[0].directions[(a, 50000)].reassemble(), (b"abc", [(3, 9)]))
        tracker.add(4, 3, packet(a, b, 50000, 80, 500, 2))
        self.assertEqual(len(tracker.flows), 2)

    def test_syn_retransmission_stays_in_same_flow(self):
        tracker = FlowTracker()
        a, b = "192.0.2.1", "198.51.100.2"
        request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
        segments = [
            packet(a, b, 50000, 80, 100, 2),
            packet(a, b, 50000, 80, 100, 2),
            packet(a, b, 50000, 80, 101, 24, request[:12]),
            packet(a, b, 50000, 80, 100, 2),
            packet(a, b, 50000, 80, 113, 24, request[12:]),
        ]
        for index, decoded in enumerate(segments):
            tracker.add(index + 1, index, decoded)
        self.assertEqual(len(tracker.flows), 1)
        flow = tracker.flows[0]
        self.assertEqual(flow.packet_indices, list(range(len(segments))))
        self.assertEqual(flow.directions[(a, 50000)].reassemble(), (request, []))
        self.assertEqual(flow.directions[(a, 50000)].http_messages[0].start_line, "GET / HTTP/1.1")

    def test_late_syn_preserves_missing_prefix(self):
        tracker = FlowTracker()
        a, b = "192.0.2.1", "198.51.100.2"
        tracker.add(1, 0, packet(a, b, 50000, 80, 110, 24, b"tail"))
        tracker.add(2, 1, packet(a, b, 50000, 80, 100, 2))
        data, gaps = tracker.flows[0].directions[(a, 50000)].reassemble()
        self.assertEqual(data, b"")
        self.assertEqual(gaps, [(0, 9)])
        tracker.add(3, 2, packet(a, b, 50000, 80, 101, 24, b"123456789"))
        self.assertEqual(tracker.flows[0].directions[(a, 50000)].reassemble(), (b"123456789tail", []))

    def test_earlier_payload_rebases_contiguous_stream(self):
        tracker = FlowTracker()
        a, b = "192.0.2.1", "198.51.100.2"
        tracker.add(1, 0, packet(a, b, 50000, 80, 107, 24, b"world"))
        tracker.add(2, 1, packet(a, b, 50000, 80, 101, 24, b"hello "))
        self.assertEqual(tracker.flows[0].directions[(a, 50000)].reassemble(), (b"hello world", []))

    def test_earlier_payload_rebases_with_gap(self):
        tracker = FlowTracker()
        a, b = "192.0.2.1", "198.51.100.2"
        tracker.add(1, 0, packet(a, b, 50000, 80, 107, 24, b"world"))
        tracker.add(2, 1, packet(a, b, 50000, 80, 101, 24, b"hello"))
        self.assertEqual(tracker.flows[0].directions[(a, 50000)].reassemble(), (b"hello", [(5, 6)]))

    def test_http_chunked_headers(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nDATA\r\n0\r\n\r\n"
        parsed = parse_http_stream(raw)
        self.assertEqual(len(parsed), 1)
        self.assertTrue(parsed[0].complete)
        self.assertIn(("Content-Type", "text/plain"), parsed[0].headers)

    def test_http_informational_then_final(self):
        raw = (b"HTTP/1.1 100 Continue\r\n\r\n"
               b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        parsed = parse_http_stream(raw)
        self.assertEqual([item.start_line for item in parsed],
                         ["HTTP/1.1 100 Continue", "HTTP/1.1 200 OK"])
        self.assertTrue(all(item.complete for item in parsed))

    def test_dns_over_tcp_frames(self):
        question = b"\x07example\x03com\x00\x00\x01\x00\x01"
        message = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
        framed = struct.pack("!H", len(message)) + message
        self.assertEqual(len(parse_dns_tcp_stream(framed[:-1])), 0)
        self.assertEqual(len(parse_dns_tcp_stream(framed + framed)), 2)

    def test_dns_compressed_answer(self):
        name = b"\x07example\x03com\x00"
        query = name + b"\x00\x01\x00\x01"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.7")
        data = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + query + answer
        summary, fields = parse_dns(data)
        self.assertIn("203.0.113.7", summary)
        self.assertTrue(any("TTL=60" in value for _, value in fields))

    def test_flow_process_ownership_both_endpoints(self):
        tracker = FlowTracker()
        client = ("127.0.0.1", 50000)
        server = ("127.0.0.1", 8000)
        flow = tracker.add(1, 0, packet(client[0], server[0], client[1], server[1], 10, 2))
        tracker.attribute({(client, server): Owner(101, "client.exe"),
                           (server, client): Owner(202, "server.exe")})
        self.assertEqual(flow.owners[client].pid, 101)
        self.assertEqual(flow.owners[server].pid, 202)


if __name__ == "__main__":
    unittest.main()
