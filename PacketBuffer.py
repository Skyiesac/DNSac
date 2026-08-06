from enum import IntEnum
import ipaddress
import socket
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

class BufferError(Exception):
    """Custom exception raised when reading or seeking out of buffer bounds."""
    pass


class ResultCode(IntEnum):
    """Represents DNS response codes (RCODE) found in the header."""
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5

    @classmethod
    def from_num(cls, num: int) -> "ResultCode":
        """Convert a raw number into a ResultCode, defaulting to NOERROR if unknown."""
        try:
            return cls(num)
        except ValueError:
            return cls.NOERROR


class ReprMixin:
    def __repr__(self):
        fields = ", ".join(f"{k}={v!r}\n" for k, v in vars(self).items())
        return f"{type(self).__name__}({fields})"


class BytePacketBuffer:
    """
    A buffer for handling binary DNS packets with a fixed size of 512 bytes,
    supporting DNS compression (label pointers/jumps).
    """

    def __init__(self, size: int = 512):
        self.buf = bytearray(size)
        self.pos = 0
        self.limit = 0

    def set_data(self, data: bytes) -> None:
        if len(data) > len(self.buf):
            raise BufferError("Packet is too large")
        self.buf[:len(data)] = data
        self.limit = len(data)

    def check_bounds(self, pos: int, length: int = 1) -> None:
        if pos < 0 or length < 0 or pos + length > self.limit:
            raise BufferError("Read outside packet bounds")

    def get_pos(self) -> int:
        """Current position within the buffer."""
        return self.pos

    def step(self, steps: int) -> None:
        """Step the buffer position forward a specific number of steps."""
        self.pos += steps

    def seek(self, pos: int) -> None:
        """Change the buffer position."""
        self.pos = pos

    def read(self) -> int:
        """Read a single byte and move the position one step forward."""
        self.check_bounds(self.pos)
        if self.pos >= len(self.buf):
            raise BufferError("End of buffer")
        res = self.buf[self.pos]
        self.pos += 1
        return res

    def get(self, pos: int) -> int:
        """Get a single byte without changing the buffer position."""
        self.check_bounds(pos)
        if pos >= len(self.buf):
            raise BufferError("End of buffer")
        return self.buf[pos]

    def get_range(self, start: int, length: int) -> bytes:
        """Get a range of bytes without changing the buffer position."""
        self.check_bounds(start, length)
        if start + length > len(self.buf):
            raise BufferError("End of buffer")
        return bytes(self.buf[start : start + length])

    def read_u16(self) -> int:
        """Read two bytes (big-endian), stepping two steps forward."""
        return (self.read() << 8) | self.read()

    def read_u32(self) -> int:
        """Read four bytes (big-endian), stepping four steps forward."""
        return (
            (self.read() << 24)
            | (self.read() << 16)
            | (self.read() << 8)
            | self.read()
        )

    def write(self, val: int) -> None:
        """Write a single byte and move the position one step forward."""
        if self.pos >= len(self.buf):
            raise BufferError("End of buffer")
        self.buf[self.pos] = val
        self.pos += 1

    def write_u8(self, val: int) -> None:
        """Write an 8-bit unsigned integer (1 byte)."""
        self.write(val)

    def write_u16(self, val: int) -> None:
        """Write a 16-bit unsigned integer (2 bytes, big-endian)."""
        self.write((val >> 8) & 0xFF)
        self.write(val & 0xFF)

    def write_u32(self, val: int) -> None:
        """Write a 32-bit unsigned integer (4 bytes, big-endian)."""
        self.write((val >> 24) & 0xFF)
        self.write((val >> 16) & 0xFF)
        self.write((val >> 8) & 0xFF)
        self.write(val & 0xFF)

    def set(self, pos: int, val: int) -> None:
        """Set a single byte at a specific position without changing the buffer's read/write position."""
        if pos >= len(self.buf):
            raise BufferError("Position out of buffer bounds")
        self.buf[pos] = val

    def set_u16(self, pos: int, val: int) -> None:
        """Set a 16-bit unsigned integer (2 bytes, big-endian) at a specific position."""
        self.set(pos, (val >> 8) & 0xFF)
        self.set(pos + 1, val & 0xFF)

    def read_qname(self) -> str:
        """
        Read a domain name (qname) handling DNS label compression (jumps).
        Returns the parsed domain name as a lowercase string.
        """
        pos = self.get_pos()
        jumped = False
        visited = set()

        out_parts = []
        total_length = 0

        while True:
            if pos in visited:
                raise BufferError("Compression pointer loop detected")
            visited.add(pos)
            if len(visited) > 20:
                raise BufferError("Too many compression jumps")

            len_byte = self.get(pos)

            # Check if the two most significant bits are set 0xC0= 11000000
            #If they are 11, it means this is not a label length, it is a pointer
            if (len_byte & 0xC0) == 0xC0:
                if (len_byte & 0xC0) == 0x80:
                    raise BufferError("Invalid DNS label encoding")
                # Update the main buffer position to right past the 2-byte jump pointer
                if not jumped:
                    self.seek(pos + 2)

                b2 = self.get(pos + 1)
                offset = (((len_byte ^ 0xC0) << 8) | b2)
                if offset >= self.limit:
                    raise BufferError("Compression pointer outside packet bounds")
                pos = offset

                jumped = True
                continue

            else:
                pos += 1

                # Length of 0 signals the end of the qname
                if len_byte == 0:
                    break

                if len_byte > 63:
                    raise BufferError("Label exceeds 63 bytes")

                total_length += len_byte + 1
                if total_length > 255:
                    raise BufferError("Domain name exceeds 255 bytes")

                str_buffer = self.get_range(pos, len_byte)
                # Decode as UTF-8/ASCII safely and convert to lowercase
                out_parts.append(str_buffer.decode("utf-8", errors="replace").lower())

                pos += len_byte

        # If we never jumped, update the buffer's reading position
        if not jumped:
            self.seek(pos)

        return ".".join(out_parts)

    def write_qname(self, qname: str) -> None:
        """
        Write a domain name into the buffer in DNS label format.
        'google.com' becomes [6] g o o g l e [3] c o m [0]
        """
        for label in qname.split('.'):
            len_val = len(label)
            if len_val > 0x3F:  # 63 characters max per label
                raise BufferError("Single label exceeds 63 characters of length")

            self.write_u8(len_val)
            
            for b in label.encode("ascii"):
                self.write_u8(b)
        self.write_u8(0)


class DnsHeader(ReprMixin):
    """
    Represents the 12-byte DNS header at the beginning of every DNS packet.
    """
    def __init__(self):
        self.id = 0                      # 16 bits (ID to match queries with responses)
        
        # Flags (Byte 2)
        self.recursion_desired = False     # 1 bit
        self.truncated_message = False     # 1 bit
        self.authoritative_answer = False  # 1 bit
        self.opcode = 0                    # 4 bits
        self.response = False              # 1 bit

        # Flags & Rcode (Byte 3)
        self.rescode = ResultCode.NOERROR  # 4 bits (uses ResultCode enum)
        self.checking_disabled = False     # 1 bit
        self.authed_data = False           # 1 bit
        self.z = False                     # 1 bit (reserved/zero)
        self.recursion_available = False   # 1 bit

        # Counts (16 bits each)
        self.questions = 0
        self.answers = 0
        self.authoritative_entries = 0
        self.resource_entries = 0

    @classmethod
    def read(cls, buffer: BytePacketBuffer) -> "DnsHeader":
        """
        Parses a DnsHeader by reading the first 12 bytes from the given BytePacketBuffer.
        """
        header = cls()
        header.id = buffer.read_u16()

        flags = buffer.read()
        header.recursion_desired = (flags & (1 << 0)) > 0
        header.truncated_message = (flags & (1 << 1)) > 0
        header.authoritative_answer = (flags & (1 << 2)) > 0
        header.opcode = (flags >> 3) & 0x0F
        header.response = (flags & (1 << 7)) > 0

        flags2 = buffer.read()
        header.rescode = ResultCode.from_num(flags2 & 0x0F)
        header.checking_disabled = (flags2 & (1 << 4)) > 0
        header.authed_data = (flags2 & (1 << 5)) > 0
        header.z = (flags2 & (1 << 6)) > 0
        header.recursion_available = (flags2 & (1 << 7)) > 0

        header.questions = buffer.read_u16()
        header.answers = buffer.read_u16()
        header.authoritative_entries = buffer.read_u16()
        header.resource_entries = buffer.read_u16()

        return header

    def write(self, buffer: BytePacketBuffer) -> None:
        """
        Serializes the DnsHeader and writes it into the given BytePacketBuffer.
        """
        buffer.write_u16(self.id)

        first_flag_byte = (
            (int(self.recursion_desired))
            | (int(self.truncated_message) << 1)
            | (int(self.authoritative_answer) << 2)
            | ((self.opcode & 0x0F) << 3)
            | (int(self.response) << 7)
        )
        buffer.write_u8(first_flag_byte)

        second_flag_byte = (
            (int(self.rescode) & 0x0F)
            | (int(self.checking_disabled) << 4)
            | (int(self.authed_data) << 5)
            | (int(self.z) << 6)
            | (int(self.recursion_available) << 7)
        )
        buffer.write_u8(second_flag_byte)
        buffer.write_u16(self.questions)
        buffer.write_u16(self.answers)
        buffer.write_u16(self.authoritative_entries)
        buffer.write_u16(self.resource_entries)


class QueryType(IntEnum):
    """Represents a DNS query type."""
    UNKNOWN = 0
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    MX = 15
    TXT = 16
    AAAA = 28
    SVCB = 64
    HTTPS = 65
    DNSKEY = 48
    
    @classmethod
    def from_num(cls, num: int) -> "QueryType":
        """
        Converts a number to a QueryType. 
        If Python doesn't recognize the number, it safely defaults to UNKNOWN.
        """
        try:
            return cls(num)
        except ValueError:
            return cls.UNKNOWN

class DnsQuestion(ReprMixin):
    def __init__(self, name: str = "", qtype_num: int = 1, qclass: int = 1):
        self.name: str = name
        self.qtype_num = qtype_num
        self.qclass = qclass

    @property
    def qtype(self) -> QueryType:
        return QueryType.from_num(self.qtype_num)

    @classmethod
    def read(cls, buffer: BytePacketBuffer) -> "DnsQuestion":
        question = cls()
        question.name = buffer.read_qname()
        question.qtype_num = buffer.read_u16()
        question.qclass = buffer.read_u16()

        return question

    def write(self, buffer: BytePacketBuffer) -> None:
        """
        Serializes the DnsQuestion and writes it into the given BytePacketBuffer.
        """
        buffer.write_qname(self.name)

        buffer.write_u16(self.qtype_num)
        buffer.write_u16(self.qclass)

class DnsRecord:
    """Base class for parsed DNS records (Answers, Authorities, Additional records)."""
    
    @classmethod
    def read(cls, buffer: BytePacketBuffer) -> "DnsRecord":
        """
        Parses a DNS record from the buffer based on its type 
        (A, NS, CNAME, MX, AAAA, or UNKNOWN).
        """
        domain = buffer.read_qname()

        qtype_num = buffer.read_u16()
        qtype = QueryType.from_num(qtype_num)
        
        record_class = buffer.read_u16()  # Class (for OPT, this is UDP payload size)
        ttl = buffer.read_u32()
        data_len = buffer.read_u16()

        if qtype == QueryType.A:
            if data_len != 4:
                raise BufferError("Invalid A record length")
            raw_addr = buffer.read_u32()
            
            # Convert 32-bit raw integer into a readable IP address string (e.g., '192.168.1.1')
            addr = str(ipaddress.ip_address(raw_addr))
            return DnsRecordA(domain=domain, addr=addr, ttl=ttl)

        elif qtype == QueryType.NS:
            rdata_start = buffer.get_pos()
            host = buffer.read_qname()
            if buffer.get_pos() - rdata_start != data_len:
                raise BufferError("Record length mismatch")
            return DnsRecordNS(domain=domain, host=host, ttl=ttl)

        elif qtype == QueryType.CNAME:
            rdata_start = buffer.get_pos()
            host = buffer.read_qname()
            if buffer.get_pos() - rdata_start != data_len:
                raise BufferError("Record length mismatch")
            return DnsRecordCNAME(domain=domain, host=host, ttl=ttl)

        elif qtype == QueryType.MX:
            rdata_start = buffer.get_pos()
            priority = buffer.read_u16()
            host = buffer.read_qname()
            if buffer.get_pos() - rdata_start != data_len:
                raise BufferError("Record length mismatch")
            return DnsRecordMX(domain=domain, priority=priority, host=host, ttl=ttl)

        elif qtype == QueryType.AAAA:
            # Read 16 bytes for IPv6 address
            if data_len != 16:
                raise BufferError("Invalid AAAA record length")
            raw_bytes = buffer.get_range(buffer.get_pos(), 16)
            buffer.step(16)
            addr = str(ipaddress.ip_address(raw_bytes))
            return DnsRecordAAAA(domain=domain, addr=addr, ttl=ttl)
        
        else:
            raw_rdata = buffer.get_range(buffer.get_pos(), data_len)
            buffer.step(data_len)
            return DnsRecordUnknown(
                domain=domain, 
                qtype=qtype_num, 
                record_class=record_class,
                data_len=data_len, 
                ttl=ttl,
                rdata=raw_rdata,
            )

    def write(self, buffer: BytePacketBuffer) -> int:
        """
        Serializes a DNS record into the buffer and returns the total number of bytes written.
        """
        start_pos = buffer.get_pos()
        
        def write_header(qtype: QueryType):
            buffer.write_qname(self.domain)
            buffer.write_u16(int(qtype))
            buffer.write_u16(1)  # Class IN
            buffer.write_u32(self.ttl)

        if isinstance(self, DnsRecordA):
            write_header(QueryType.A)
            buffer.write_u16(4)
            for octet in ipaddress.ip_address(self.addr).packed:
                buffer.write_u8(octet)

        elif isinstance(self, (DnsRecordNS, DnsRecordCNAME)):
            qtype = QueryType.NS if isinstance(self, DnsRecordNS) else QueryType.CNAME
            write_header(qtype)
            
            # Write variable length payload with length-patching
            pos = buffer.get_pos()
            buffer.write_u16(0)
            buffer.write_qname(self.host)
            buffer.set_u16(pos, buffer.get_pos() - (pos + 2))

        elif isinstance(self, DnsRecordMX):
            write_header(QueryType.MX)
            
            pos = buffer.get_pos()
            buffer.write_u16(0)
            buffer.write_u16(self.priority)
            buffer.write_qname(self.host)
            buffer.set_u16(pos, buffer.get_pos() - (pos + 2))

        elif isinstance(self, DnsRecordAAAA):
            write_header(QueryType.AAAA)
            buffer.write_u16(16)
            ip_obj = ipaddress.ip_address(self.addr)
            for i in range(0, 16, 2):
                buffer.write_u16((ip_obj.packed[i] << 8) | ip_obj.packed[i + 1])

        elif isinstance(self, DnsRecordUnknown):
            buffer.write_qname(self.domain)
            buffer.write_u16(self.qtype)
            buffer.write_u16(self.record_class)
            buffer.write_u32(self.ttl)
            buffer.write_u16(len(self.rdata))
            for b in self.rdata:
                buffer.write_u8(b)
            
        return buffer.get_pos() - start_pos

class DnsRecordUnknown(DnsRecord):
    def __init__(self, domain: str, qtype: int, record_class: int, data_len: int, ttl: int, rdata: bytes = b""):
        self.domain = domain
        self.qtype = qtype
        self.record_class = record_class
        self.data_len = data_len
        self.ttl = ttl
        self.rdata = rdata

    def __repr__(self):
        return f"DnsRecord.UNKNOWN(domain={self.domain}, qtype={self.qtype}, data_len={self.data_len}, ttl={self.ttl})"


class DnsRecordA(DnsRecord):
    def __init__(self, domain: str, addr: str, ttl: int):
        self.domain = domain
        self.addr = addr
        self.ttl = ttl

    def __repr__(self):
        return f"DnsRecord.A(domain={self.domain}, addr={self.addr}, ttl={self.ttl})"


class DnsRecordNS(DnsRecord):
    def __init__(self, domain: str, host: str, ttl: int):
        self.domain = domain
        self.host = host
        self.ttl = ttl

    def __repr__(self):
        return f"DnsRecord.NS(domain={self.domain}, host={self.host}, ttl={self.ttl})"


class DnsRecordCNAME(DnsRecord):
    def __init__(self, domain: str, host: str, ttl: int):
        self.domain = domain
        self.host = host
        self.ttl = ttl

    def __repr__(self):
        return f"DnsRecord.CNAME(domain={self.domain}, host={self.host}, ttl={self.ttl})"


class DnsRecordMX(DnsRecord):
    def __init__(self, domain: str, priority: int, host: str, ttl: int):
        self.domain = domain
        self.priority = priority
        self.host = host
        self.ttl = ttl

    def __repr__(self):
        return f"DnsRecord.MX(domain={self.domain}, priority={self.priority}, host={self.host}, ttl={self.ttl})"


class DnsRecordAAAA(DnsRecord):
    def __init__(self, domain: str, addr: str, ttl: int):
        self.domain = domain
        self.addr = addr
        self.ttl = ttl

    def __repr__(self):
        return f"DnsRecord.AAAA(domain={self.domain}, addr={self.addr}, ttl={self.ttl})"


class DnsPacket:
    """
    Represents a complete DNS packet, containing a header, 
    questions, answers, authorities, and resource records.
    """
    def __init__(self):
        self.header = DnsHeader()
        self.questions = []
        self.answers = []
        self.authorities = []
        self.resources = []

    @classmethod
    def new(cls) -> "DnsPacket":
        """Creates an empty DnsPacket."""
        return cls()

    @classmethod
    def from_buffer(cls, buffer: BytePacketBuffer) -> "DnsPacket":
        """
        Parses a complete DnsPacket from the raw binary buffer.
        """
        result = cls()
        result.header = DnsHeader.read(buffer)

        for _ in range(result.header.questions):
            # Creates a blank question with a dummy default query type (A, unknown)
            question = DnsQuestion.read(buffer)
            result.questions.append(question)

        for _ in range(result.header.answers):
            rec = DnsRecord.read(buffer)
            result.answers.append(rec)

        for _ in range(result.header.authoritative_entries):
            rec = DnsRecord.read(buffer)
            result.authorities.append(rec)

        for _ in range(result.header.resource_entries):
            rec = DnsRecord.read(buffer)
            result.resources.append(rec)

        return result

    def write(self, buffer: BytePacketBuffer) -> None:
        """
        Serializes the complete DnsPacket  and writes it into the buffer.
        """
        self.header.questions = len(self.questions)
        self.header.answers = len(self.answers)
        self.header.authoritative_entries = len(self.authorities)
        self.header.resource_entries = len(self.resources)
        self.header.write(buffer)
        for question in self.questions:
            question.write(buffer)
        for rec in self.answers:
            rec.write(buffer)
        for rec in self.authorities:
            rec.write(buffer)
        for rec in self.resources:
            rec.write(buffer)

    def get_random_a(self) -> str | None:
        """
        Picks an available A record (IPv4 address) from the answers section.
        """
        a_records = [
            record.addr for record in self.answers 
            if isinstance(record, DnsRecordA)
        ]
        if not a_records:
            return None
        # In Python, we can just return one (or pick randomly if multiple exist)
        return random.choice(a_records)

    def _get_ns(self, qname: str):
        """
        Helper generator yielding (domain, host) tuples from the authorities section
        that are authoritative for the given query name.
        """
        qname = qname.rstrip(".").lower()
        best_match = []
        best_len = -1
        for record in self.authorities:
            if isinstance(record, DnsRecordNS):
                domain = record.domain.rstrip(".").lower()
                if qname == domain or qname.endswith("." + domain):
                    if len(domain) > best_len:
                        best_match = [(record.domain, record.host)]
                        best_len = len(domain)
                    elif len(domain) == best_len:
                        best_match.append((record.domain, record.host))
        for item in best_match:
            yield item

    def get_resolved_ns(self, qname: str) -> str | None:
        """
        Looks for a name server in the authorities section whose matching IP address 
        is already bundled as a Glue record in the additional/resource section.
        """
        for _, host in self._get_ns(qname):
            for record in self.resources:
                if isinstance(record, DnsRecordA) and record.domain == host:
                    return record.addr
                if isinstance(record, DnsRecordAAAA) and record.domain == host:
                    return record.addr
        return None

    def get_unresolved_ns(self, qname: str) -> str | None:
        """
        Returns the hostname of an appropriate name server from the authorities section 
        when no bundled Glue record (A record) is available in the additional section.
        """
        for _, host in self._get_ns(qname):
            return host
        return None


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

def handle_query(sock: socket.socket, raw_data: bytes, src: tuple[str, int]) -> None:
    """
    Handles a single incoming DNS query packet, uses recursive_lookup() to resolve it 
    from the root servers up, packs the response, and sends it back to the client.
    """
    req_buffer = BytePacketBuffer(4096)
    req_buffer.set_data(raw_data)
    req_buffer.pos = 0

    request = DnsPacket.from_buffer(req_buffer)
    if request.header.response or request.header.opcode != 0:
        packet = DnsPacket.new()
        packet.header.id = request.header.id
        packet.header.response = True
        packet.header.rescode = ResultCode.NOTIMP
        res_buffer = BytePacketBuffer(512)
        packet.write(res_buffer)
        sock.sendto(bytes(res_buffer.buf[:res_buffer.pos]), src)
        return

    if not request.questions or len(request.questions) != 1 or request.questions[0].qclass != 1:
        packet = DnsPacket.new()
        packet.header.id = request.header.id
        packet.header.response = True
        packet.header.rescode = ResultCode.FORMERR
        res_buffer = BytePacketBuffer(512)
        packet.write(res_buffer)
        sock.sendto(bytes(res_buffer.buf[:res_buffer.pos]), src)
        return

    packet = DnsPacket.new()
    packet.header.id = request.header.id
    packet.header.recursion_desired = True
    packet.header.recursion_available = True
    packet.header.response = True

    if request.questions:
        question = request.questions[0]
        print(f"Received query: {question!r}")

        try:
            result = recursive_lookup(question.name, question.qtype)
            packet.questions.append(question)
            packet.header.rescode = result.header.rescode

            for rec in result.answers:
                print(f"Answer: {rec!r}")
                packet.answers.append(rec)
            for rec in result.authorities:
                print(f"Authority: {rec!r}")
                packet.authorities.append(rec)
            for rec in result.resources:
                if _is_opt_record(rec):
                    continue
                print(f"Resource: {rec!r}")
                packet.resources.append(rec)
        except Exception as e:
            print(f"Lookup error: {e}", file=sys.stderr)
            packet.header.rescode = ResultCode.SERVFAIL
    else:
        packet.header.rescode = ResultCode.FORMERR

    res_buffer = BytePacketBuffer(4096)
    packet.write(res_buffer)
    
    response_data = bytes(res_buffer.buf[:res_buffer.pos])
    sock.sendto(response_data, src)


def main() -> None:
    """
    Binds the local DNS server to port 2053 and runs an infinite loop 
    servicing incoming requests concurrently.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("127.0.0.1", 2053))
    print("DNS Server running on port 2053...")

    # Process packets in a small worker pool to handle concurrent clients.
    with ThreadPoolExecutor(max_workers=64) as executor:
        while True:
            try:
                raw_data, src = server_sock.recvfrom(4096)
                executor.submit(handle_query, server_sock, raw_data, src)
            except Exception as e:
                print(f"An error occurred: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()