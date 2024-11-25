from datetime import datetime


def iniciar_sniffer(interface):
    """
    Inicia o sniffer para capturar pacotes DNS e HTTP e grava logs continuamente.
    """
    log_file = "log_monitoramento.txt"

    if not os.path.exists(log_file):
        with open(log_file, "w") as f:
            f.write("timestamp|type|data|source_ip|destination_ip\n")
        print(f"[INFO] Arquivo de log '{log_file}' criado.")

    print(f"[INFO] Sniffer iniciado. Log sendo salvo em '{log_file}'. Pressione Ctrl+C para parar.")

    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    raw_socket.bind((interface, 0))

    try:

        with open(log_file, "a") as f:
            while True:
                pacote, _ = raw_socket.recvfrom(65535)

                dns = extrair_dns(pacote)
                if dns:
                    entrada = f"{datetime.now()}|DNS|{dns}|N/A|N/A\n"
                    f.write(entrada)
                    f.flush()
                    print(entrada.strip())

                http = extrair_http(pacote)
                if http:
                    entrada = f"{datetime.now()}|HTTP|{http[0]}|{http[1]}|{http[2]}\n"
                    f.write(entrada)
                    f.flush() 
                    print(entrada.strip())

    except KeyboardInterrupt:
        print("\n[INFO] Sniffer finalizado.")
    except Exception as e:
        print(f"[ERRO] Ocorreu um erro: {e}")