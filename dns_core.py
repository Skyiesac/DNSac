from enum import IntEnum


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


class ReprMixin:
    def __repr__(self):
        fields = ", ".join(f"{k}={v!r}\n" for k, v in vars(self).items())
        return f"{type(self).__name__}({fields})"


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
    def read(cls, buffer) -> "DnsHeader":
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

    def write(self, buffer) -> None:
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


class DnsQuestion(ReprMixin):
    def __init__(self, name: str = "", qtype_num: int = 1, qclass: int = 1):
        self.name: str = name
        self.qtype_num = qtype_num
        self.qclass = qclass

    @property
    def qtype(self) -> QueryType:
        return QueryType.from_num(self.qtype_num)

    @classmethod
    def read(cls, buffer) -> "DnsQuestion":
        question = cls()
        question.name = buffer.read_qname()
        question.qtype_num = buffer.read_u16()
        question.qclass = buffer.read_u16()

        return question

    def write(self, buffer) -> None:
        """
        Serializes the DnsQuestion and writes it into the given BytePacketBuffer.
        """
        buffer.write_qname(self.name)

        buffer.write_u16(self.qtype_num)
        buffer.write_u16(self.qclass)
