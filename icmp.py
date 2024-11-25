import socket
import struct
import time

def criar_pacote_icmp():
    header = struct.pack("bbHHh", 8, 0, 0, 0, 0)
    checksum = calcular_checksum(header)
    return struct.pack("bbHHh", 8, 0, checksum, 0, 0)

def calcular_checksum(header):
    if len(header) % 2:
        header += b'\x00'
    checksum = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    return ~checksum & 0xFFFF

def enviar_ping(host, timeout):
    try:
        icmp = socket.getprotobyname("icmp")
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as sock:
            sock.settimeout(timeout / 1000)
            packet = criar_pacote_icmp()
            sock.sendto(packet, (host, 1))
            start = time.time()
            sock.recvfrom(1024)
            return int((time.time() - start) * 1000)  # Retorna tempo em ms
    except socket.timeout:
        return None
