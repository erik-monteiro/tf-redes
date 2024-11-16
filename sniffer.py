import socket
import struct
from datetime import datetime

def iniciar_sniffer(interface):
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((interface, 0))
        historico = []
        print("Sniffer iniciado... Pressione Ctrl+C para parar.")
        while True:
            pacote = raw_socket.recvfrom(65565)[0]
            historico.extend(analise_pacote(pacote))
    except KeyboardInterrupt:
        print("\nSniffer finalizado.")
    return historico

def analise_pacote(pacote):
    # Análise de cabeçalhos Ethernet, IPv4, TCP/UDP, HTTP e DNS
    # Retorna uma lista de entradas para o histórico.
    # (Deixe vazio para implementação futura)
    return []
