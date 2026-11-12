"""Run with: python test_npa.py"""

import socket
import struct
import unittest

from application_protocols import parse_dns, parse_dns_tcp_stream, parse_http_stream
from process_connections import Owner
from protocols import decode
from tcp_streams import FlowTracker


def packet(src, dst, sport, dport, seq, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 4096, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return decode(b"\0" * 12 + b"\x08\x00" + ip + tcp)


class NpaTests(unittest.TestCase):
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
