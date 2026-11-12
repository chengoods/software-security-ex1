"""End-to-end capture check using a locally generated marked UDP datagram."""

from __future__ import annotations

import argparse
import socket
import threading
import time

from pcap_backend import Pcap
from pcap_file import write_pcap
from protocols import decode


MARKER = b"EX1A-LIVE-CAPTURE-VERIFY"
PORT = 39991


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify that a selected capture adapter receives real UDP traffic")
    parser.add_argument("--list", action="store_true", help="list capture adapters")
    parser.add_argument("--adapter", type=int, help="zero-based adapter number from --list")
    parser.add_argument("--target", help="reachable IPv4 address on that adapter, e.g. its gateway")
    parser.add_argument("--seconds", type=float, default=5.0)
    parser.add_argument("--save", help="save captured packets to a PCAP file")
    args = parser.parse_args()
    backend = Pcap()
    devices = backend.devices()
    if args.list:
        for index, device in enumerate(devices):
            print(f"{index}: {device.description} [{device.name}]")
        return 0
    if args.adapter is None or not 0 <= args.adapter < len(devices) or not args.target:
        parser.error("supply --adapter N and --target IPv4, or use --list")
    device = devices[args.adapter]
    capture = backend.open(device.name, f"udp port {PORT}")
    records = []
    matched = []

    def send() -> None:
        time.sleep(0.3)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _ in range(12):
                sock.sendto(MARKER, (args.target, PORT))
                time.sleep(0.1)

    sender = threading.Thread(target=send)
    sender.start()
    try:
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            item = capture.next_packet()
            if not item:
                continue
            records.append(item)
            stamp, raw, original = item
            if MARKER in raw:
                decoded = decode(raw, capture.linktype)
                matched.append(decoded)
                print(f"MATCH {decoded.source} -> {decoded.destination} {decoded.protocol} {decoded.info} captured={len(raw)} original={original}")
    finally:
        sender.join()
        capture.close()
    if args.save and records:
        write_pcap(args.save, capture.linktype, records)
        print(f"Saved {len(records)} packet(s) to {args.save}")
    print(f"Adapter: {device.description}; captured={len(records)}; marked={len(matched)}")
    if matched and all(item.protocol == "UDP" and item.destination == args.target for item in matched):
        print("PASS: real traffic was captured and decoded")
        return 0
    print("FAIL: no marked packet was captured and decoded on this adapter")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
