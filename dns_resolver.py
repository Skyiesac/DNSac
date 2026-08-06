import random
import socket
import threading
import time

from byte_packet_buffer import BytePacketBuffer
from dns_core import DnsQuestion, QueryType, ResultCode
from dns_packet import DnsPacket
from dns_records import (
    DnsRecordA,
    DnsRecordAAAA,
    DnsRecordCNAME,
    DnsRecordMX,
    DnsRecordNS,
    DnsRecordUnknown,
)


_CACHE_LOCK = threading.Lock()
_DNS_CACHE: dict[tuple[str, int, int], tuple[float, DnsPacket, float]] = {}
ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "199.7.91.13",     # d.root-servers.net
]


def _cache_key(qname: str, qtype: QueryType, qclass: int = 1) -> tuple[str, int, int]:
    return (qname.lower(), int(qtype), qclass)


def _packet_ttl(packet: DnsPacket) -> int:
    ttls = [
        rec.ttl
        for rec in (packet.answers + packet.authorities + packet.resources)
        if hasattr(rec, "ttl") and rec.ttl > 0
    ]
    if not ttls:
        return 30
    return max(1, min(min(ttls), 3600))


def _clone_record_with_ttl(record, ttl: int):
    if isinstance(record, DnsRecordA):
        return DnsRecordA(record.domain, record.addr, ttl)
    if isinstance(record, DnsRecordAAAA):
        return DnsRecordAAAA(record.domain, record.addr, ttl)
    if isinstance(record, DnsRecordNS):
        return DnsRecordNS(record.domain, record.host, ttl)
    if isinstance(record, DnsRecordCNAME):
        return DnsRecordCNAME(record.domain, record.host, ttl)
    if isinstance(record, DnsRecordMX):
        return DnsRecordMX(record.domain, record.priority, record.host, ttl)
    if isinstance(record, DnsRecordUnknown):
        return DnsRecordUnknown(record.domain, record.qtype, record.record_class, record.data_len, ttl, record.rdata)
    return record


def _clone_cached_packet(packet: DnsPacket, remaining_ttl: int) -> DnsPacket:
    cloned = DnsPacket.new()
    cloned.header = packet.header
    cloned.questions = list(packet.questions)
    cloned.answers = [_clone_record_with_ttl(rec, remaining_ttl) for rec in packet.answers]
    cloned.authorities = [_clone_record_with_ttl(rec, remaining_ttl) for rec in packet.authorities]
    cloned.resources = [_clone_record_with_ttl(rec, remaining_ttl) for rec in packet.resources]
    return cloned


def _cache_get(qname: str, qtype: QueryType, qclass: int = 1) -> DnsPacket | None:
    key = _cache_key(qname, qtype, qclass)
    now = time.monotonic()
    with _CACHE_LOCK:
        item = _DNS_CACHE.get(key)
        if item is None:
            return None
        expires_at, packet, created_at = item
        if expires_at <= now:
            del _DNS_CACHE[key]
            return None
        remaining = max(1, int(expires_at - now))
        return _clone_cached_packet(packet, remaining)


def _cache_put(qname: str, qtype: QueryType, packet: DnsPacket, qclass: int = 1) -> None:
    ttl = _packet_ttl(packet)
    key = _cache_key(qname, qtype, qclass)
    with _CACHE_LOCK:
        now = time.monotonic()
        _DNS_CACHE[key] = (now + ttl, packet, now)


def _append_edns0(buffer: BytePacketBuffer) -> None:
    # Minimal EDNS0 OPT record with the DNSSEC OK (DO) bit set.
    buffer.set_u16(10, 1)   # additional record count
    buffer.write_u8(0)      # root name
    buffer.write_u16(41)    # OPT
    buffer.write_u16(1232)  # advertised UDP payload size
    buffer.write_u32(0x8000)  # DO bit
    buffer.write_u16(0)     # no OPT payload


def _is_opt_record(record) -> bool:
    return isinstance(record, DnsRecordUnknown) and record.qtype == 41


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected EOF from DNS TCP upstream")
        data.extend(chunk)
    return bytes(data)


def _server_socket_family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def _lookup_tcp(server: tuple[str, int], query_data: bytes, expected_id: int) -> DnsPacket:
    family = _server_socket_family(server[0])
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(4.0)
        sock.connect(server if family == socket.AF_INET else (server[0], server[1], 0, 0))
        sock.sendall(len(query_data).to_bytes(2, "big") + query_data)

        msg_len = int.from_bytes(_recv_exact(sock, 2), "big")
        raw_data = _recv_exact(sock, msg_len)

    res_buffer = BytePacketBuffer(max(4096, len(raw_data)))
    res_buffer.set_data(raw_data)
    res_buffer.pos = 0

    response = DnsPacket.from_buffer(res_buffer)
    if response.header.id != expected_id:
        raise ValueError("Transaction ID mismatch")
    return response


def lookup(qname: str, qtype: QueryType, server: tuple[str, int]) -> DnsPacket:
    """
    Takes a domain name and query type, forwards it to server,
    and returns the parsed DnsPacket response.
    """


    # Bind a UDP socket to an arbitrary port for outgoing queries
    family = _server_socket_family(server[0])
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)

        packet = DnsPacket.new()
        packet.header.id = random.randint(0, 65535)
        packet.header.recursion_desired = False
        packet.questions.append(DnsQuestion(qname, qtype))
        req_buffer = BytePacketBuffer()
        packet.write(req_buffer)
        _append_edns0(req_buffer)
        request_data = bytes(req_buffer.buf[:req_buffer.pos])

        for _ in range(3): #3 retries
            sock.sendto(request_data, server if family == socket.AF_INET else (server[0], server[1], 0, 0))

            #response
            res_buffer = BytePacketBuffer(4096)
            try:
                raw_data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue

            res_buffer.set_data(raw_data)
            res_buffer.pos = 0

            response = DnsPacket.from_buffer(res_buffer)
            if response.header.id != packet.header.id:
                continue

            if response.header.truncated_message:
                return _lookup_tcp(server, request_data, packet.header.id)

            return response

        raise TimeoutError("DNS upstream server timed out")

def recursive_lookup(
    qname: str,
    qtype: QueryType,
    depth: int = 0,
    visited: set[tuple[str, int]] | None = None,
    deadline: float | None = None,
) -> DnsPacket:
    """
    Performs an iterative/recursive DNS lookup starting from the root servers,
    traversing TLDs and authoritative name servers until it resolves the query.
    """
    if depth > 20:
        raise RuntimeError("Maximum DNS recursion depth exceeded")

    if deadline is None:
        deadline = time.monotonic() + 10.0
    if time.monotonic() > deadline:
        raise TimeoutError("DNS resolution deadline exceeded")

    if visited is None:
        visited = set()

    key = (qname.rstrip(".").lower(), int(qtype))
    if key in visited:
        raise RuntimeError("DNS resolution loop detected")
    visited.add(key)

    cached = _cache_get(qname, qtype)
    if cached is not None:
        return cached

    # Start from a root server and rotate if a root times out.
    root_index = 0
    ns = ROOT_SERVERS[root_index]

    while True:
        print(f"Attempting lookup of {qtype.name} {qname} with ns {ns}")

        server = (ns, 53)
        try:
            response = lookup(qname, qtype, server)
        except TimeoutError:
            if ns in ROOT_SERVERS:
                root_index = (root_index + 1) % len(ROOT_SERVERS)
                next_ns = ROOT_SERVERS[root_index]
                if next_ns != ns:
                    ns = next_ns
                    continue
            raise

        if response.answers and response.header.rescode == ResultCode.NOERROR:
            _cache_put(qname, qtype, response)
            return response
        if response.header.rescode == ResultCode.NXDOMAIN:
            _cache_put(qname, qtype, response)
            return response
        new_ns = response.get_resolved_ns(qname)
        if new_ns:
            ns = new_ns
            continue

        new_ns_name = response.get_unresolved_ns(qname)
        if not new_ns_name:
            _cache_put(qname, qtype, response)
            return response

        #start another recursive lookup to find the IP of the name server
        recursive_response = recursive_lookup(new_ns_name, QueryType.A, depth + 1, visited, deadline)

        # Pick a random IP from the result, and restart the loop
        random_ip = recursive_response.get_random_a()
        if not random_ip:
            random_ip = recursive_response.get_random_aaaa()
        if random_ip:
            ns = random_ip
        else:
            _cache_put(qname, qtype, response)
            return response
