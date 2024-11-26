from datetime import datetime
import threading

def gerar_relatorio_html():
    try:
        with open("log.txt", "r") as log_file:
            linhas = log_file.readlines()

        if not linhas:
            print("[ERRO] O log está vazio. Certifique-se de que os pacotes estão sendo capturados.")
            return

        with open("relatorio.html", "w") as relatorio:
            relatorio.write("<html><head><title>Relatório de Rede</title></head><body>")
            relatorio.write("<h1>Relatório de Rede</h1>")
            relatorio.write("<h2>Pacotes Capturados</h2>")
            relatorio.write("<ul>")
            for linha in linhas:
                relatorio.write(f"<li>{linha}</li>")
            relatorio.write("</ul>")
            relatorio.write(f"<p>Gerado em: {datetime.now()}</p>")
            relatorio.write("</body></html>")

        print("[INFO] Relatório gerado com sucesso: relatorio.html")
    except Exception as e:
        print(f"[ERRO] Ocorreu um erro ao gerar o relatório: {e}")

def gerar_relatorio_em_thread():
    relatorio_thread = threading.Thread(target=gerar_relatorio_html)
    relatorio_thread.start()
