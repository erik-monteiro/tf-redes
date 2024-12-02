import time
from e1_icmp import enviar_ping


def calcular_intervalo_ips(rede):
    partes_rede = rede.split('/')
    endereco_base = partes_rede[0]
    mascara = int(partes_rede[1])

    ip_binario = ''.join([bin(int(octeto))[2:].zfill(8) for octeto in endereco_base.split('.')])
    mascara_binaria = '1' * mascara + '0' * (32 - mascara)

    rede_decimal = int(ip_binario, 2) & int(mascara_binaria, 2)
    broadcast_decimal = rede_decimal | (~int(mascara_binaria, 2) & 0xFFFFFFFF)

    ips_validos = []
    for ip_num in range(rede_decimal + 1, broadcast_decimal):
        ip = '.'.join(str((ip_num >> (8 * i)) & 0xFF) for i in range(3, -1, -1))
        ips_validos.append(ip)

    return ips_validos

def calcular_gateway(rede):
    ips_validos = calcular_intervalo_ips(rede)
    return ips_validos[0] if ips_validos else None

def executar_varredura(rede, timeout):
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

    total_hosts = len(hosts) 

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