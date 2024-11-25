import socket
from analise import extrair_http, extrair_dns
from relatorio import gerar_relatorio_html

def iniciar_sniffer(interface):
    """
    Inicia o sniffer para capturar pacotes DNS e HTTP.
    """
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    raw_socket.bind((interface, 0))
    historico = []
    print("[INFO] Sniffer iniciado. Pressione Ctrl+C para parar.")
    
    try:
        while True:
            pacote, _ = raw_socket.recvfrom(65535)
            dns = extrair_dns(pacote)
            if dns:
                historico.append({"data_hora": datetime.now(), "ip": "DNS", "url": dns})
            http = extrair_http(pacote)
            if http:
                historico.append({"data_hora": datetime.now(), "ip": "HTTP", "url": http[0]})
    except KeyboardInterrupt:
        print("\n[INFO] Sniffer finalizado.")
        gerar_relatorio_html(historico)