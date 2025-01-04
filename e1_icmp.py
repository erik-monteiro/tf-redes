import socket
import struct
import time
import os

def criar_pacote_icmp(seq):

    id_icmp = os.getpid() & 0xFFFF 
    header = struct.pack("bbHHh", 8, 0, 0, id_icmp, seq) 
    checksum = calcular_checksum(header)
    header = struct.pack("bbHHh", 8, 0, checksum, id_icmp, seq)
    return header

def calcular_checksum(header):

    if len(header) % 2:
        header += b'\x00'
    checksum = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    checksum = ~checksum & 0xFFFF
    return socket.htons(checksum)

def enviar_ping(host, timeout, seq):

    try:
        icmp = socket.IPPROTO_ICMP 
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as sock:
            sock.settimeout(timeout / 1000)
            packet = criar_pacote_icmp(seq)
            sock.sendto(packet, (host, 1))
            start = time.time()

            resposta, endereco = sock.recvfrom(1024)
            tempo_resposta = (time.time() - start) * 1000 

            tipo, codigo, checksum, id_icmp, seq_resposta = struct.unpack("bbHHh", resposta[20:28])
            if endereco[0] == host and tipo == 0 and id_icmp == (os.getpid() & 0xFFFF) and seq_resposta == seq:
                return int(tempo_resposta) 
            else:
                return None
    except socket.timeout:
        return None  
    except PermissionError:
        raise PermissionError("Permissões de administrador são necessárias para enviar pacotes ICMP.")
    except Exception as e:
        print(f"Erro: {e}")
        return None
