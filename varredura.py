import ipaddress
from icmp import enviar_ping

def calcular_intervalo_ips(rede):
    """
    Calcula os IPs válidos na rede, excluindo o endereço de rede e broadcast.
    """
    rede_obj = ipaddress.ip_network(rede, strict=False)
    return [str(ip) for ip in rede_obj.hosts()]  # Exclui rede e broadcast

def executar_varredura(rede, timeout):
    """
    Realiza a varredura na rede para identificar hosts ativos.
    """
    print(f"Iniciando varredura na rede {rede}...")
    hosts_ativos = []
    hosts = calcular_intervalo_ips(rede)
    for ip in hosts:
        tempo_resposta = enviar_ping(ip, timeout)
        if tempo_resposta is not None:
            hosts_ativos.append((ip, tempo_resposta))
            print(f"Host ativo: {ip} - Tempo de resposta: {tempo_resposta:.2f} ms")
    return hosts_ativos



