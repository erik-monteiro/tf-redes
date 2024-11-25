from datetime import datetime

def gerar_relatorio_html(historico):
    with open("historico_navegacao.html", "w") as f:
        f.write("<html><head><title>Histórico de Navegação</title></head><body>")
        f.write(f"<h1>Histórico de Navegação - Gerado em {datetime.now()}</h1>")
        f.write("<table border='1'><tr><th>Data e Hora</th><th>IP do Host</th><th>URL</th></tr>")
        for entrada in historico:
            f.write(f"<tr><td>{entrada['data_hora']}</td><td>{entrada['ip']}</td><td>{entrada['url']}</td></tr>")
        f.write("</table></body></html>")
