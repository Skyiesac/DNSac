import socket
import sys
from concurrent.futures import ThreadPoolExecutor

from byte_packet_buffer import BytePacketBuffer
from dns_packet import DnsPacket
from dns_resolver import _is_opt_record, recursive_lookup
from dns_core import ResultCode


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
