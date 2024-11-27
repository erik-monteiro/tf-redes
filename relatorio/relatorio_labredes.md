


##### Análise
[PREENCHER] explicar analise, pacotes DNS, HTTP... 
[PREENCHER] explicar como decapar e filtragem
analise.py
```bash
import struct
import socket
from datetime import datetime

import re

def salvar_historico(ip, url):
    url = ''.join(ch for ch in url if ch.isprintable())

    with open("historico.html", "a") as log_file:
        log_file.write(f'<div style="margin-bottom: 10px; border-bottom: 1px solid #ddd; padding-bottom: 5px;">\n')
        log_file.write(f'<p><strong>{datetime.now()} | IP: {ip}</strong></p>\n')
        log_file.write(f'<p><em>URL: {url}</em></p>\n')
        log_file.write('</div>\n')


def extrair_http(pacote):
    """
    Função para extrair o URL de pacotes HTTP.
    """
    try:
        if len(pacote) < 54:
            return None

        ip_header = pacote[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        source_ip = socket.inet_ntoa(iph[8])
        destination_ip = socket.inet_ntoa(iph[9])

        tcp_header = pacote[34:54]
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)
        
        payload = pacote[54:]

        if b"GET" in payload or b"POST" in payload:
            start_idx = payload.find(b"Host: ")
            if start_idx != -1:
                host_start = start_idx + len("Host: ")
                host_end = payload.find(b"\r\n", host_start)
                if host_end != -1:
                    host = payload[host_start:host_end].decode('utf-8')
                    return host
    except Exception as e:
        print(f"[ERRO] Erro ao extrair HTTP: {e}")
        return None



def extrair_dns(pacote):
    """
    Função para extrair a consulta DNS de um pacote.
    """
    if len(pacote) < 28:
        return None

    ip_header = pacote[14:34]
    udp_header = pacote[34:42]
    dns_header = pacote[42:]

    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    source_ip = socket.inet_ntoa(iph[8])
    destination_ip = socket.inet_ntoa(iph[9])

    udp_len = struct.unpack("!HHHH", udp_header)
    dns_len = udp_len[3]
    dns_query = dns_header[:dns_len]

    try:
        domain = ""
        for i in range(12, dns_len):
            if dns_query[i] == 0:
                break
            domain += chr(dns_query[i])
        return domain
    except Exception as e:
        return None

def capturar_pacotes():

    while True:
        pacote = capturar_pacote()

        with open("log_bruto.txt", "a") as log_file:
            log_file.write(f"{datetime.now()} - Pacote Capturado: {pacote.hex()}\n")

        eth_header = pacote[:14] # 14 bytes para o cabeçalho Ethernet
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        if eth_protocol == 8:
            ip_header = pacote[14:34] # 20 bytes para o cabeçalho IP
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            ip_protocol = iph[6]
            source_ip = socket.inet_ntoa(iph[8])
            destination_ip = socket.inet_ntoa(iph[9])

            if ip_protocol == 17: # Protocolo UDP
                dns_query = extrair_dns(pacote)
                if dns_query:
                    print(f"DNS Query: {dns_query} | Host: {source_ip}")
                    salvar_historico(source_ip, dns_query)

            elif ip_protocol == 6: # Protocolo TCP
                tcp_header = pacote[34:54] # 20 bytes para o cabeçalho TCP
                source_port = struct.unpack("!H", tcp_header[:2])[0]
                dest_port = struct.unpack("!H", tcp_header[2:4])[0]

                if dest_port == 443 or source_port == 443: # HTTPS
                    print(f"HTTPS Connection: {source_ip} -> {destination_ip}")

                else:
                    result = extrair_http(pacote)
                    if result:
                        url, ip_src, ip_dst = result
                        print(f"URL Acessada: {url} | Host: {source_ip}")
                        salvar_historico(source_ip, url)

```
##### Relatório
[PREENCHER] explicar extração de dados brutos e filtrados 
[PREENCHER] explicar os riscos do ataque e como se proteger em  nível de rede
gerar_relatorio.py
```bash
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

```

### Análise de Resultados

log_bruto.txt
```txt
(...)
2024-11-26 13:38:03.299482 - Pacote Capturado: 00e04c6822cb1c3bf35f5bcc080045000b5c64c14000680664d833694789c0a8026801bb80564895321a44f0da0380104001495100000101080a00be1f9b60c5182502ab59b1633965bb7b036c155271a173d6658e4a02fc43d3ce6f26fa4a234dec75f0719a8bfc44257d7c016ee9b07d93bce1f3347c735d35a6a9c9c675159641e018434a09fd4b924990420cf6e24e28ee764e04be977b5564c11958750af913ec01cba1b4b2e9a1a8e16f37a32dc921c104cb30d04afe6bd524febbf70f452aa89407075b81f0c0246358091d2e3285f706fcbb1d4a753432ab032a1fa88d3682e87edb411cb6591d27b092a34a857b701a45376f76c704bc222536c4738867a00fea2db3d65757f17d8dd5b6c560e8208eaf51b05b6ecb72a51e2d5e0dcf2476d7cf6cb5b0899d4b909604fca1e4b597630a9dff5fc9e2112a9b4cd6796e60c94215fcd738fa20a5ecff4a8cd2ed31645765409652337cd8c41a64687d8ff276f7ab3a31a35fa7fc8b4491d43db37f98f48969bfa2a9f1f840f08ed7c6f8dfffb381fa2b9879b3b4bcd3be928c304a530509db78f8e8413bf954ca7d8ad8f0675953f429c9631589a2eae4e616a2779ec39e94a496bd78bdfca7e24fd49860f9b7821e7f464f50d9a3bb1e60da8df270d1b1e4631b640f3bc219268237298e60c520b49825cafe82fb7ab5b33dd839106ac73b86fac7df80f1ed05238899fb35a9da43fa3724ac002335de072eb3dff3a2417b40d94eb6bac51dac76d9df0451e7a12e4c3df96ea43e6575bf97a1ff0aeb87497e59788ca197b5a172de300c66949fea283335f091b8fc6357054cb04b7c26fa12545149c182892b4a65d6155c2c71c4feac450bec1191d40ff0fa880390de8d1a060b2267eded6183203f85896c0b0184d7629ba53821c0c459778f6497d23a268c9565a0aa88395591064d8b59cd4bef1aadb4061cd8f8d066973f78ce2f23db6cd45aa952f7938b0b5fae932bdd95c2f5bf826b30c5f0e5fca330e00047234968ade9da12d3c1aa77aabb1689ba6b609fccba742621a84eb269b14ed2ef625d4bd91813bccb9e71b1214227edcff5c0811fd21910c67004bdd8252ea5d6b1ccff1a90e310ec34cbb0a5a570ab4d4a294abbca12c000082cd2bceb7e250b156cb01f37ae8557baa7f2a43ae66a34f55595234d6eda6fa82bc66144bbe9ab46d93d2bed7cd987619051df0eca4a2568661ec852b7bcc1e6fc92688b478e21b826f202cce00b7b112095d1cbc9de0c8a320472bba578a2c35f3554f1b6787c3b70324f38f7b310f462b1c3d44efc6fe332ab2b6941620f5d05d3ca93f900d8438cae31a5e3cae6ecc48b1d9953c78d6476e128fbf35310863869bf40e13421223696bbbba7a3fea63f8689900ed493b085c478256cc10e9484554295ec2d483819a5a07879a623d2c817533311c512efcc55bef72722c526deacff74aa9d9f639e62edcc09d049bb585c422634ac60af02751956f9d18861290b59787ced8b955d73ed8f71ea1bc6f6201ec58062a3fcafc5037e89b80b5c57fb93e848eae8ec30cdbdc9151241d8a6e48b54fb09d4e5614741389a4c2090b0ff228bcb9c516c7dbde5a1071bd8796e385d865ba4814b3c149886f315f12d73808f268d62a76470f0b20068db9f422aeb2574fd28440bba3b1dca792aaa0bb40a852bd361c48b1daa0c8078df91af816fa3a166f2c2bce80d99b839f00e0f1ae1a01c3e084285cc4f0f4cc5c05c03c1f550b45c287f8b04b761331f859360a583fe853f32b82e84e3da9cae621c3a7aa445f7178b9f2bcb43b3bbe690965f7b435232c60beacd693a7e62203be0e6d8279d6741333f45a45d427a1879558bac5b05cb53472452a3b26b96cf1cb545af823c9539aaa4f960c2be3d46352c8966de3517e0525859ef424eede1704746986227648d996b4b81e748f47f06d86ad8298e2fc3d55e6ab3379a86b9d3377be0a17f7ccc8479ad3bb65cb36de33121bdc1bdcc3bbe3beed1e792e147e5257c4c427893f76b5dfd0ea70ab51c7e86bd545c4d518e3e8135212e49accd7b9e4299fde6ee4cf8fe92ab1bab1f1d78e882dd35d88917757d91874f49a24053e392bef77b63708bd0f13726ca4168720cdeb99353de7d2904af301e2dfdc9b97fba1950793b1353a280cc614659a5a461cf971fba245a17b179b99238ac06c10060a8e9e780931ce1cff9da72a60379872a0f86a2c7931edaeb1f7da66efdfae7a2296609e537a41a3b98fb2bbbcc9940260783863ec1a1df96aceb97a14e22cf26061b455a0af1e978d2672c3c567cec7fd760503e4354c8b3e1a553f44cb38159f49aaefab3767201bcaa91de62c3c9b6aae1a5a46f201725f13121b8acd990183d5691dc0a70110a55a0c33bcf7a7c348c045a71023eb3f0b4217b0e86077a035cfbe62686af0ae41323a9a55feca7824630202e95b5cee6f33cc9441e9100d7c597d5dc6c922759ec384c7111e35d32d4887afabb840a34a6e84bdcf754236cf249dcb892b0fa312b7aef188a4432a9edc903eb89a35e5c169ffef61e68fcc79c4bcbc49313d53129168336fc6b61b92f3f4dd997cb11093da542d51fc5b93d1dd3748c1df2b1ac0eecd50984b9fb380d82877f7b7139a556ccfdfd4bd307864b027e6ac771aa9f9880c046e5c9df86307b8b96fd0d7197d6b2f5ef882b9f502dd5f75c8fbcfa1b8797e8cc92e142751ae804a4863bae717d76339d2e527d483e8de2e03bd2341b67a4f5bab9b765b145f7e41730332fffa1c4ac16de5d0cccb501e483b2b98d3d9298cf8fd77f62315666c5fd30155c625587a3a780c05e661744a124544bc3dff8e79b3c097d85f0164da1eadd8566a3e36ea5d462b1534765e6
2024-11-26 13:38:03.299919 - Pacote Capturado: 00e04c6822cb1c3bf35f5bcc0800450005c864c0400068066a6d33694789c0a8026801bb805648952c8644f0da038010400192da00000101080a00be1f9b60c51825c2b896893dce6fa9dcd2217605242634b4ae624bad15e2e8168e3fdf94c2e5f84b088909705c20b8c6cd80b8014b62dece139ae81af57111ca3751501b270290df14528a9c26055802dc44e53cd9c6c12694eb16a27bcc093fc75bd965b8ce2591ef9f556a883d521a33172f06d6148a3ac2aef630b54007fd8ee4bd739fd7772c001280e06b298001b06c534fc994f676bb40f44785b0a1edfe2096f4a58d51489af2cd3535f1a18703fcb8a07e8c30abd3d8ed26037641180b1560c1fa8ad6bd9024b5463d3ecd66248e3e33f82335961d5820ee84aedb4ef71ed0f76971c5cae15dafba8eb41e847d5d83f91e17f5bc2cf33c2197c1de3892d8dd4595ed739780654a59d29952e517a96eabd61dbadb64a730e3b286e0aea43d58b83c21c9ebbe24115ac5df8215d98211e2786e35459f6532f4a537db4a43d21ac694f63bae6cea79b1d96bcd8899ffe3a8f8f58b40636faee4d84e301fc0d5bee9b48754110f578360d6aa84c19efe2468979f840803061e95bf9df7e2f7aeadf77055e1d5625f8605784dcb9229fe395ad92e534d126abb108ea209a5eec35e05983fd18e10f52e9afa37c5bed269ab6b8c7791907183981bcad04e0872a7bdcbc27674244c4637ba78d6f7ecdc841137a449b2b913d464a8c72cce3fbfcb556d17e9f6fcef5fb23c32f211d6a0acf57624328064b182396087f98600eef649b9eb0d42eba1a28c646c73776110b81624500348672dabf5c3edb8f3a2fe9f4549f6183363f736fc3ba06f3f5ccc6ce6eb9df51a9c8eac38440eb5117f3c33ae0555025af83c171f855d85bfc3a3f0a214bed1656bafbf43bef22789ca9c24d8520b69d885d40fd596e1a5a1c8cab5130ab9b8245c2e9806fc9005b5dfbdf615f165cc57502b3c1ad39bd0f69b59fe7d46bdc066d6d5f14d12fbaf25d9edf8b4e5fac6ca16c22e4e048e8e04e20c64aaad31871a78c5475b82ad9ed969edbc54e4cfce412c665bca1313eb384ac0ca0f3bafc9f61e4f4deee0f85ab2702975e37b078b07fa33fc34379f1d4caa27dde939a7c2d4f0f097a8f11ffec8639bf466d27e1ebfff748b75268d02fd27d2496fb6a5f316b1c43439361edb737e11cb467e05d8af53dba198765794ad9d8e1147c555fac31eca3793a797e9f0cd711baa19aa1159a38edfb41c6dfdb78db072bb9139cd8b8b218fe635b07c900ac854e5f495e524be9562dd7592172b23bfa92ab70c0a25760e256e1bc80a25ec24c51cbb3b4900939d3ed42bceb98e6bbae9eba92749da5d1957211feb75d31188a9904b08fe45d9f23f4decf96623828af2f24639395a9eb90751935a2ca1e358ef916e3cb52ef81a3a3f8966ae37e9b0c8704818ebef53ef881158bf6d0b76b2acfdbae1f9432693ec1e06495879af2b9f447d365023f9797751216dc6e8e02130639e10d2b5defc0be1c4cafe5d8aa28aa7a90a52744c12ff9791ffb22e3dff96ade96804ce6c77310b274a8488fd1f88f8aab276a1de81e5b9bb6aa08ff110612717ab005470f5a4ac0d03c05691e6a02e747ced5f94feabd8965c9334066f9d16d8e4aa6988e033c31e1ad6cdbb6790f0c8f3d3d99f1b12f3d733d9235268e2e29c38082f90a56970a0d4acd567b769ea6ecdbc416e28c9e98771858487a226b628dd33da1c6181224abb72f950ed645dd94dbf8d0e8f357d5fd275014ce4c9713b92ab91cb0ec09d4910ccaed0204fcfe3849aede62c1a054c6442ebeb53053af65b1fafb58b02a0385738a3058d5a7aa1ec176f88651f949ebe8a6456ec94f4104c9fe3bbda13a8612ff57e64070986991ec9b5a45382b795accb78f587258e2f956d78e3508aacd549d6d2538dbe1c25c58746a215cbd5895631dd29fc327b0674e75c4dba004773dfa1a66c6e448ad03053a8d957a37bb87df6e9efa1ade45e2e20c1c2d286001eed35ed663b75b666daad83f72388dfdcfa8c043da833b1f3aac1cc894d20e56b1caf7a2585ae7aeee6e2f9e5e64c1a
(...)
```
historico.html
```html
```

### Conclusão


```bash
```
