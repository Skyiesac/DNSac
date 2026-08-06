import ipaddress

from byte_packet_buffer import BytePacketBuffer
from dns_core import BufferError, QueryType


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
