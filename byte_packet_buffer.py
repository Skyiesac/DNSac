from dns_core import BufferError


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
