import struct

# Função para extrair dados HTTP (caso o pacote seja HTTP)
def extrair_http(pacote):
    # Verificando se o pacote tem TCP/IP e se é HTTP
    # A estrutura de um pacote TCP começa com 20 bytes de cabeçalho
    if len(pacote) > 54:  # 14 bytes de Ethernet + 20 de IP + 20 de TCP
        ip_header = pacote[14:34]  # Cabeçalho IP (IP: 14 - 34)
        ip_src = struct.unpack("!4B", ip_header[:4])  # Endereço IP de origem
        ip_dst = struct.unpack("!4B", ip_header[4:8])  # Endereço IP de destino
        
        tcp_header = pacote[34:54]  # Cabeçalho TCP (TCP: 34 - 54)
        # Vamos verificar se a payload do TCP contém uma solicitação HTTP
        payload = pacote[54:].decode(errors="ignore")  # Carregar a parte de dados como string
        if "HTTP" in payload:  # Verificar se é HTTP
            url = None
            for line in payload.splitlines():
                if line.startswith("GET") or line.startswith("POST"):
                    # Extrair a URL (em um GET ou POST)
                    url = line.split(" ")[1]
                    break
            return url, ip_src, ip_dst
    return None

# Função para extrair dados DNS (caso o pacote seja DNS)
def extrair_dns(pacote):
    # Verificando se o pacote é DNS
    if len(pacote) > 42:  # Cabeçalho Ethernet (14 bytes) + IP (20 bytes) + UDP (8 bytes)
        udp_header = pacote[34:42]  # Cabeçalho UDP (UDP: 34 - 42)
        # DNS começa após 8 bytes de cabeçalho UDP
        dns_data = pacote[42:]
        # DNS normalmente começa com um ID seguido por flags e uma seção de perguntas
        # Aqui vamos extrair o nome de domínio solicitado (domínio está no começo da seção de perguntas)
        
        try:
            nome_dominio = None
            offset = 0
            while offset < len(dns_data):
                # O primeiro byte indica o comprimento do domínio
                length = dns_data[offset]
                if length == 0:  # Fim do nome de domínio
                    break
                nome_dominio = dns_data[offset + 1: offset + 1 + length].decode()
                offset += length + 1
            if nome_dominio:
                return nome_dominio
        except Exception as e:
            pass
    return None
