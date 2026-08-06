import random

from byte_packet_buffer import BytePacketBuffer
from dns_core import DnsHeader, DnsQuestion, ResultCode
from dns_records import DnsRecord, DnsRecordA, DnsRecordAAAA, DnsRecordNS


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
