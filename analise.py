import struct
from datetime import datetime

def extrair_http(pacote):

    if len(pacote) > 54:  
        ip_header = pacote[14:34] 
        ip_src = struct.unpack("!4B", ip_header[:4])  
        ip_dst = struct.unpack("!4B", ip_header[4:8]) 
        
        tcp_header = pacote[34:54] 

        payload = pacote[54:].decode(errors="ignore")
        if "HTTP" in payload:  
            url = None
            for line in payload.splitlines():
                if line.startswith("GET") or line.startswith("POST"):
 
                    url = line.split(" ")[1]
                    break
            return url, ip_src, ip_dst
    return None

def extrair_dns(pacote):

    if len(pacote) > 42: 
        udp_header = pacote[34:42]  
        dns_data = pacote[42:]
        
        try:
            nome_dominio = None
            offset = 0
            while offset < len(dns_data):
                length = dns_data[offset]
                if length == 0: 
                    break
                nome_dominio = dns_data[offset + 1: offset + 1 + length].decode()
                offset += length + 1
            if nome_dominio:
                return nome_dominio
        except Exception as e:
            pass
    return None
