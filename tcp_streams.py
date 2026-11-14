"""Bounded bidirectional TCP flow grouping and payload reassembly."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple

from application_protocols import HttpMessage, parse_http_stream
from process_connections import Owner
from protocols import Decoded


MAX_DIRECTION_BYTES = 4 * 1024 * 1024
Endpoint = Tuple[str, int]
FlowKey = Tuple[Endpoint, Endpoint]


@dataclass
class Direction:
    endpoint: Endpoint
    segments: list[tuple[int, bytes, int]] = field(default_factory=list)
    base: int | None = None
    seen_syn: bool = False
    syn_sequence: int | None = None
    truncated: bool = False
    packet_count: int = 0
    wire_bytes: int = 0

    def add(self, sequence: int, payload: bytes, syn: bool, index: int) -> None:
        self.packet_count += 1
        self.wire_bytes += len(payload)
        if syn:
            self.seen_syn = True
            self.syn_sequence = sequence if self.syn_sequence is None else self.syn_sequence
            sequence = (sequence + 1) & 0xFFFFFFFF
            if self.base is None:
                self.base = sequence
            else:
                earlier = (self.base - sequence + 2**31) % 2**32 - 2**31
                if earlier > 0:
                    self.segments = [(at + earlier, data, packet) for at, data, packet in self.segments]
                    self.base = sequence
        if not payload:
            return
        if self.base is None:
            self.base = sequence
        # Unwrap around the first observed sequence. Captures longer than 2 GiB
        # in one direction are outside this teaching tool's in-memory scope.
        start = (sequence - self.base + 2**31) % 2**32 - 2**31
        if start < 0:
            if self.seen_syn:
                if start + len(payload) <= 0:
                    return
                payload = payload[-start:]
                start = 0
            else:
                self.segments = [(at - start, data, packet) for at, data, packet in self.segments]
                self.base = sequence
                start = 0
        if start >= MAX_DIRECTION_BYTES:
            self.truncated = True
            return
        if start + len(payload) > MAX_DIRECTION_BYTES:
            payload = payload[:MAX_DIRECTION_BYTES - start]
            self.truncated = True
        self.segments.append((start, payload, index))

    def reassemble_with_sources(self) -> tuple[bytes, list[tuple[int, int]], list[tuple[int, int, int]]]:
        """Return contiguous prefix and uncovered offsets after the first gap."""
        if not self.segments:
            return b"", [], []
        output = bytearray()
        gaps = []
        sources = []
        end = 0
        for start, data, packet in sorted(self.segments, key=lambda item: item[0]):
            if start > end:
                gaps.append((end, start))
                end = start
            overlap = end - start
            if overlap < len(data):
                if not gaps:
                    offset = len(output)
                    output.extend(data[overlap:])
                    sources.append((offset, len(output), packet))
                end += len(data) - overlap
        return bytes(output), gaps, sources

    def reassemble(self) -> tuple[bytes, list[tuple[int, int]]]:
        data, gaps, _ = self.reassemble_with_sources()
        return data, gaps

    @property
    def http_messages(self) -> list[HttpMessage]:
        data, _ = self.reassemble()
        return parse_http_stream(data)


@dataclass
class Flow:
    number: int
    key: FlowKey
    directions: dict[Endpoint, Direction]
    packet_indices: list[int] = field(default_factory=list)
    start_time: float = 0.0
    last_time: float = 0.0
    closed: bool = False
    owners: dict[Endpoint, Owner] = field(default_factory=dict)

    def add(self, stamp: float, index: int, decoded: Decoded) -> None:
        endpoint = (decoded.source, decoded.source_port)
        direction = self.directions[endpoint]
        direction.add(decoded.tcp_sequence, decoded.tcp_payload, bool(decoded.tcp_flags & 2), index)
        self.packet_indices.append(index)
        if not self.start_time:
            self.start_time = stamp
        self.last_time = stamp
        if decoded.tcp_flags & 4:
            self.closed = True


class FlowTracker:
    def __init__(self) -> None:
        self.flows: list[Flow] = []
        self.active: dict[FlowKey, Flow] = {}

    def clear(self) -> None:
        self.flows.clear()
        self.active.clear()

    def attribute(self, connections: dict) -> None:
        """Attach each local endpoint's current owner to active live flows."""
        for flow in self.active.values():
            self.attribute_flow(flow, connections)

    @staticmethod
    def attribute_flow(flow: Flow, connections: dict) -> None:
        first, second = flow.key
        for local, remote in ((first, second), (second, first)):
            owner = connections.get((local, remote))
            if owner is not None:
                flow.owners[local] = owner

    def add(self, stamp: float, index: int, decoded: Decoded) -> Flow | None:
        if decoded.tcp_sequence is None or decoded.source_port is None or decoded.destination_port is None:
            return None
        source = (decoded.source, decoded.source_port)
        destination = (decoded.destination, decoded.destination_port)
        key = tuple(sorted((source, destination)))
        flow = self.active.get(key)
        # A new client SYN starts a new connection even if the same four-tuple
        # was used earlier. Avoid splitting on SYN retransmissions.
        new_syn = bool(decoded.tcp_flags & 2) and not bool(decoded.tcp_flags & 16)
        if flow is None or (new_syn and flow.directions[source].seen_syn and
                            flow.directions[source].syn_sequence != decoded.tcp_sequence):
            flow = Flow(len(self.flows) + 1, key, {source: Direction(source), destination: Direction(destination)})
            self.flows.append(flow)
            self.active[key] = flow
        flow.add(stamp, index, decoded)
        return flow
