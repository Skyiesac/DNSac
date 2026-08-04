from enum import IntEnum
import ipaddress


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


class BytePacketBuffer:
    """
    A buffer for handling binary DNS packets with a fixed size of 512 bytes,
    supporting DNS compression (label pointers/jumps).
    """

    def __init__(self):
        self.buf = bytearray(512)
        self.pos = 0

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
        if self.pos >= 512:
            raise BufferError("End of buffer")
        res = self.buf[self.pos]
        self.pos += 1
        return res

    def get(self, pos: int) -> int:
        """Get a single byte without changing the buffer position."""
        if pos >= 512:
            raise BufferError("End of buffer")
        return self.buf[pos]

    def get_range(self, start: int, length: int) -> bytes:
        """Get a range of bytes without changing the buffer position."""
        if start + length > 512:
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

    def read_qname(self) -> str:
        """
        Read a domain name (qname) handling DNS label compression (jumps).
        Returns the parsed domain name as a lowercase string (e.g., 'www.google.com').
        """
        pos = self.get_pos()
        jumped = False
        max_jumps = 5
        jumps_performed = 0

        out_parts = []

        while True:
            if jumps_performed > max_jumps:
                raise BufferError(f"Limit of {max_jumps} jumps exceeded")

            len_byte = self.get(pos)

            # Check if the two most significant bits are set 0xC0= 11000000
            #If they are 11, it means this is not a label length, it is a pointer
            if (len_byte & 0xC0) == 0xC0:
                # Update the main buffer position to right past the 2-byte jump pointer
                if not jumped:
                    self.seek(pos + 2)

                b2 = self.get(pos + 1)
                offset = (((len_byte ^ 0xC0) << 8) | b2)
                pos = offset

                jumped = True
                jumps_performed += 1
                continue

            else:
                pos += 1

                # Length of 0 signals the end of the qname
                if len_byte == 0:
                    break

                str_buffer = self.get_range(pos, len_byte)
                # Decode as UTF-8/ASCII safely and convert to lowercase
                out_parts.append(str_buffer.decode("utf-8", errors="replace").lower())

                pos += len_byte

        # If we never jumped, update the buffer's reading position
        if not jumped:
            self.seek(pos)

        return ".".join(out_parts)


class DnsHeader:
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


class QueryType(IntEnum):
    """Represents a DNS query type."""
    UNKNOWN = 0
    A = 1
    NS = 2
    CNAME = 5
    MX = 15
    TXT = 16
    AAAA = 28
    
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

class DnsQuestion:
    def __init__(self, name: str = "", qtype: QueryType = QueryType.A):
        self.name: str = name
        self.qtype: QueryType = qtype

    @classmethod
    def read(cls, buffer: BytePacketBuffer) -> "DnsQuestion":
        question = cls()
        question.name = buffer.read_qname()
        qtype_num = buffer.read_u16()
        question.qtype = QueryType.from_num(qtype_num)
        
        # Ignore the class field
        _ = buffer.read_u16()

        return question

