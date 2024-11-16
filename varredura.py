import ipaddress
from icmp import enviar_ping

def executar_varredura(rede, timeout):
    hosts_ativos = []
    rede = ipaddress.ip_network(rede, strict=False)
    for host in rede.hosts():
        tempo_resposta = enviar_ping(str(host), timeout)
        if tempo_resposta is not None:
            hosts_ativos.append((str(host), tempo_resposta))
    return hosts_ativos
