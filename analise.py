import struct
import socket
from datetime import datetime

import re

def salvar_historico(ip, url):
    # Remove caracteres não imprimíveis da URL
    url = ''.join(ch for ch in url if ch.isprintable())

    # Formatação HTML para garantir a exibição adequada
    with open("historico.html", "a") as log_file:
        log_file.write(f'<div style="margin-bottom: 10px; border-bottom: 1px solid #ddd; padding-bottom: 5px;">\n')
        log_file.write(f'<p><strong>{datetime.now()} | IP: {ip}</strong></p>\n')
        log_file.write(f'<p><em>URL: {url}</em></p>\n')
        log_file.write('</div>\n')


def extrair_http(pacote):
    """
    Função para extrair o URL de pacotes HTTP.
    """
    try:
        # Verifica se o pacote tem um tamanho adequado
        if len(pacote) < 54:  # Um pacote TCP/IP com um cabeçalho básico
            return None
        
        # Cabeçalho IP
        ip_header = pacote[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        source_ip = socket.inet_ntoa(iph[8])
        destination_ip = socket.inet_ntoa(iph[9])

        # Cabeçalho TCP
        tcp_header = pacote[34:54]
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)
        
        # Extraímos a carga útil (dados do HTTP)
        payload = pacote[54:]

        # Tentamos encontrar um padrão de URL na carga útil HTTP
        if b"GET" in payload or b"POST" in payload:
            start_idx = payload.find(b"Host: ")
            if start_idx != -1:
                host_start = start_idx + len("Host: ")
                host_end = payload.find(b"\r\n", host_start)
                if host_end != -1:
                    host = payload[host_start:host_end].decode('utf-8')
                    return host  # Retorna o host da requisição HTTP
    except Exception as e:
        print(f"[ERRO] Erro ao extrair HTTP: {e}")
        return None



def extrair_dns(pacote):
    """
    Função para extrair a consulta DNS de um pacote.
    """
    # Verifica se o pacote tem comprimento suficiente para um cabeçalho DNS
    if len(pacote) < 28:
        return None

    # Extrai os cabeçalhos IP e UDP
    ip_header = pacote[14:34]
    udp_header = pacote[34:42]
    dns_header = pacote[42:]

    # IP (somente para fins de informação)
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    source_ip = socket.inet_ntoa(iph[8])
    destination_ip = socket.inet_ntoa(iph[9])

    # Cabeçalho UDP
    udp_len = struct.unpack("!HHHH", udp_header)
    dns_len = udp_len[3]  # Tamanho do conteúdo DNS

    # Extrair a consulta DNS (assumindo que a consulta está no formato correto)
    dns_query = dns_header[:dns_len]
    try:
        # Converte os bytes de consulta DNS para string
        domain = ""
        for i in range(12, dns_len):  # Começa após o cabeçalho DNS
            if dns_query[i] == 0:
                break
            domain += chr(dns_query[i])
        return domain
    except Exception as e:
        return None

def capturar_pacotes():
    # Aqui você faz a captura dos pacotes
    while True:
        pacote = capturar_pacote()  # Função para capturar pacotes (não implementada aqui)

        # Log completo em formato bruto
        with open("log_bruto.txt", "a") as log_file:
            log_file.write(f"{datetime.now()} - Pacote Capturado: {pacote.hex()}\n")

        # Analisar Ethernet
        eth_header = pacote[:14]
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        # Verificar se é um pacote IP (IPv4)
        if eth_protocol == 8:  # Protocolo IPv4
            ip_header = pacote[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            ip_protocol = iph[6]
            source_ip = socket.inet_ntoa(iph[8])
            destination_ip = socket.inet_ntoa(iph[9])

            # Se o protocolo for UDP (DNS) ou TCP (HTTP/HTTPS)
            if ip_protocol == 17:  # UDP (DNS)
                dns_query = extrair_dns(pacote)
                if dns_query:
                    print(f"DNS Query: {dns_query} | Host: {source_ip}")
                    salvar_historico(source_ip, dns_query)

            elif ip_protocol == 6:  # TCP (HTTP/HTTPS)
                # Identificar tráfego HTTP ou HTTPS
                # Adicionamos uma checagem para pacotes TCP na porta 443 (HTTPS)
                tcp_header = pacote[34:54]  # Cabeçalho TCP (para acessar portas)
                source_port = struct.unpack("!H", tcp_header[:2])[0]  # Porta de origem
                dest_port = struct.unpack("!H", tcp_header[2:4])[0]  # Porta de destino

                if dest_port == 443 or source_port == 443:  # Se for HTTPS (porta 443)
                    print(f"HTTPS Connection: {source_ip} -> {destination_ip}")
                    # Não podemos extrair conteúdo HTTPS aqui devido à criptografia

                else:  # Se for HTTP
                    result = extrair_http(pacote)
                    if result:
                        url, ip_src, ip_dst = result
                        print(f"URL Acessada: {url} | Host: {source_ip}")
                        salvar_historico(source_ip, url)
