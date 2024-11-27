import socket
import struct
from datetime import datetime
from analise import extrair_http, extrair_dns, salvar_historico

# Função para iniciar o sniffer de pacotes.
def start_sniffer(interface, stop_event):
    """
    Inicia o sniffer para capturar pacotes DNS e HTTP/HTTPS.
    """
    sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sniffer_socket.bind((interface, 0))

    print("Capturando pacotes DNS/HTTP...")

    while not stop_event.is_set(): 
        try:
            packet = sniffer_socket.recv(2048)

            with open("log_bruto.txt", "a") as log_file:
                log_file.write(f"{datetime.now()} - Pacote Capturado: {packet.hex()}\n") 

            eth_header = packet[:14]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8: 
                ip_header = packet[14:34]
                iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                ip_protocol = iph[6]
                source_ip = socket.inet_ntoa(iph[8])
                destination_ip = socket.inet_ntoa(iph[9])

                if ip_protocol == 17:
                    dns_query = extrair_dns(packet)
                    if dns_query:
                        salvar_historico(source_ip, dns_query)

                elif ip_protocol == 6:
                    result = extrair_http(packet)
                    if result:
                        url, ip_src, ip_dst = result
                        salvar_historico(source_ip, url)

        except KeyboardInterrupt:
            print("\nSniffer interrompido pelo usuário.")
            break
        except Exception as e:
            print(f"[ERRO] Ocorreu um erro ao processar o pacote: {e}")
            break

    sniffer_socket.close()
    print("Captura de pacotes finalizada.")

