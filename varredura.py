import ipaddress
import time
from icmp import enviar_ping
from datetime import datetime

# Função para calcular os IPs válidos na rede, excluindo o endereço de rede e broadcast.
def calcular_intervalo_ips(rede):
    """Calcula os IPs válidos na rede, excluindo o endereço de rede e broadcast."""
    rede_obj = ipaddress.ip_network(rede, strict=False)
    return [str(ip) for ip in rede_obj.hosts()]

# Função para calcular o gateway (geralmente o primeiro IP válido da rede).
def calcular_gateway(rede):
    """Calcula o gateway (geralmente o primeiro IP válido da rede)."""
    rede_obj = ipaddress.ip_network(rede, strict=False)
    return str(list(rede_obj.hosts())[0])

# Função para executar a varredura na rede e identificar hosts ativos.
def executar_varredura(rede, timeout):
    """
    Realiza a varredura na rede para identificar hosts ativos e calcula o tempo total de varredura.
    """
    print(f"Iniciando varredura na rede {rede}...")
    hosts_ativos = []
    hosts = calcular_intervalo_ips(rede)

    inicio_varredura = time.time()

    for ip in hosts:
        tempo_resposta = enviar_ping(ip, timeout)
        if tempo_resposta is not None:
            hosts_ativos.append((ip, tempo_resposta))
            print(f"Host ativo: {ip} - Tempo de resposta: {tempo_resposta:.2f} ms")

    fim_varredura = time.time()
    tempo_total = fim_varredura - inicio_varredura

    rede_obj = ipaddress.ip_network(rede, strict=False)
    total_hosts = rede_obj.num_addresses - 2 

    print(f"\nNúmero de máquinas ativas: {len(hosts_ativos)}")
    print(f"Número total de máquinas na rede: {total_hosts}")
    print(f"Tempo total de varredura: {tempo_total:.2f} segundos")
    print("\nLista de hosts ativos:")
    for ip, tempo in hosts_ativos:
        print(f"IP: {ip} - Tempo de resposta: {tempo:.2f} ms")

    return hosts_ativos


if __name__ == "__main__":
    rede = input("Digite a rede no formato CIDR (ex.: 192.168.1.0/24): ")
    timeout = int(input("Digite o tempo limite de resposta (em ms): "))
    try:
        executar_varredura(rede, timeout)
    except PermissionError:
        print("Erro: É necessário executar este script como administrador (root).")
    except ValueError as e:
        print(f"Erro de valor: {e}")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")
