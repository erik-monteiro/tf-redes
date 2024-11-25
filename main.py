import sys
from varredura import executar_varredura
from arpspoof import habilitar_ip_forwarding, executar_arpspoof
from sniffer import iniciar_sniffer
from relatorio import gerar_relatorio_html

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

def etapa2():
    habilitar_ip_forwarding()
    interface = input("Digite a interface de rede (ex.: eth0): ")
    alvo = input("Digite o IP do alvo: ")
    roteador = input("Digite o IP do roteador: ")
    executar_arpspoof(interface, alvo, roteador)

def etapa3():
    interface = input("Digite a interface de rede para monitorar (ex.: eth0): ")
    historico = iniciar_sniffer(interface)
    gerar_relatorio_html(historico)

if __name__ == "__main__":
    while True:
        escolha = menu()
        if escolha == "1":
            etapa1()
        elif escolha == "2":
            etapa2()
        elif escolha == "3":
            etapa3()
        elif escolha == "4":
            sys.exit()
        else:
            print("Opção inválida.")
