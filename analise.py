import struct
import socket
from datetime import datetime

import re

def salvar_historico(ip, url):
    url = ''.join(ch for ch in url if ch.isalnum() or ch in '.-_/')

    with open("historico.html", "a") as log_file:
        log_file.write('<html><header><title>Histórico de Navegação</title></header><body><ul>\n')
        log_file.write(f'<li>{datetime.now().strftime("%d/%m/%Y %H:%M")} - {ip} - <a href="{url}">{url}</a></li>\n')
        log_file.write('</ul></body></html>\n')


def extrair_http(pacote):
    """
    Função para extrair o URL de pacotes HTTP.
    """
    try:
        if len(pacote) < 54:
            return None

        ip_header = pacote[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        source_ip = socket.inet_ntoa(iph[8])
        destination_ip = socket.inet_ntoa(iph[9])

        tcp_header = pacote[34:54]
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)
        
        payload = pacote[54:]

        if b"GET" in payload or b"POST" in payload:
            start_idx = payload.find(b"Host: ")
            if start_idx != -1:
                host_start = start_idx + len("Host: ")
                host_end = payload.find(b"\r\n", host_start)
                if host_end != -1:
                    host = payload[host_start:host_end].decode('utf-8')
                    return host
    except Exception as e:
        print(f"[ERRO] Erro ao extrair HTTP: {e}")
        return None



def extrair_dns(pacote):
    """
    Função para extrair a consulta DNS de um pacote.
    """
    if len(pacote) < 28:
        return None

    ip_header = pacote[14:34]
    udp_header = pacote[34:42]
    dns_header = pacote[42:]

    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    source_ip = socket.inet_ntoa(iph[8])
    destination_ip = socket.inet_ntoa(iph[9])

    udp_len = struct.unpack("!HHHH", udp_header)
    dns_len = udp_len[3]
    dns_query = dns_header[:dns_len]

    try:
        domain = ""
        for i in range(12, dns_len):
            if dns_query[i] == 0:
                break
            domain += chr(dns_query[i])
        return domain
    except Exception as e:
        return None

def capturar_pacotes():

    while True:
        pacote = capturar_pacote()

        with open("log_bruto.txt", "a") as log_file:
            log_file.write(f"{datetime.now()} - Pacote Capturado: {pacote.hex()}\n")

        eth_header = pacote[:14] # 14 bytes para o cabeçalho Ethernet
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        if eth_protocol == 8:
            ip_header = pacote[14:34] # 20 bytes para o cabeçalho IP
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            ip_protocol = iph[6]
            source_ip = socket.inet_ntoa(iph[8])
            destination_ip = socket.inet_ntoa(iph[9])

            if ip_protocol == 17: # Protocolo UDP
                dns_query = extrair_dns(pacote)
                if dns_query:
                    print(f"DNS Query: {dns_query} | Host: {source_ip}")
                    salvar_historico(source_ip, dns_query)

            elif ip_protocol == 6: # Protocolo TCP
                tcp_header = pacote[34:54] # 20 bytes para o cabeçalho TCP
                source_port = struct.unpack("!H", tcp_header[:2])[0]
                dest_port = struct.unpack("!H", tcp_header[2:4])[0]

                if dest_port == 443 or source_port == 443: # HTTPS
                    print(f"HTTPS Connection: {source_ip} -> {destination_ip}")

                else:
                    result = extrair_http(pacote)
                    if result:
                        url, ip_src, ip_dst = result
                        print(f"URL Acessada: {url} | Host: {source_ip}")
                        salvar_historico(source_ip, url)
