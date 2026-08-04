import socket

query = bytes.fromhex("AAAA01000001000000000000") + b"\x06google\x03com\x00" + bytes.fromhex("00010001")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(query, ("8.8.8.8", 53))
#Change the IP AND port to your DNS server if you want to test it with your server

data, _ = s.recvfrom(512)

with open("response_packet.txt", "wb") as f:
    f.write(data)
print(len(data), "bytes written")