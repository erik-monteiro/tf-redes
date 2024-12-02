import struct
import socket
from datetime import datetime
from urllib.parse import urlparse

def validar_url(url):
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        if '.' not in parsed.netloc:
            return False
        return True
    except Exception:
        return False

def limpar_url(url, comprimento_minimo=5):

    url = ''.join(ch if ch.isalnum() or ch in '.:/-' else '.' for ch in url)    
    url = url.lstrip('.')

    if len(url) < comprimento_minimo:
        return None

    return url

def extrair_dominio(url):
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        return None
    except Exception:
        return None

def salvar_historico(ip, url, protocolo="http"):
    try:
        url = limpar_url(url)
        if not url:
            return

        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"{protocolo}://{url}"

        if not validar_url(url):
            dominio = extrair_dominio(url)
            if dominio:
                url = f"{protocolo}://{dominio}"

        with open("historico.html", "a") as log_file:
            log_file.write(f'<li>{datetime.now().strftime("%d/%m/%Y %H:%M")} - {ip} - <a href="{url}" target="_blank">{url}</a></li>\n')

    except Exception:
        pass

def iniciar_html():
    try:
        with open("historico.html", "w") as log_file:
            log_file.write("<html><head><title>Histórico de Navegação</title></head><body>\n")
            log_file.write("<h1>Histórico de Navegação</h1>\n")
            log_file.write("<ul>\n")
    except Exception as e:
        print(f"[ERRO] Falha ao iniciar html: {e}")

def finalizar_html():
    try:
        with open("historico.html", "a") as log_file:
            log_file.write("</ul>\n</body></html>\n")
    except Exception as e:
        print(f"[ERRO] Falha ao finalizar: {e}")


def extrair_http(pacote):
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

