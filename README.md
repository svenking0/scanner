Scanner - Ferramenta de Escaneamento de Portas

O Scanner é uma ferramenta de escaneamento de portas desenvolvida em Python que permite identificar portas abertas, fechadas e filtradas em um alvo específico. A ferramenta também pode capturar banners dos serviços em execução e realizar a captura de pacotes em uma interface de rede.


Funcionalidades:
Escaneamento de Portas: Identifica o estado das portas (abertas, fechadas e filtradas) em um endereço IP específico.
Captura de Banners: Obtém e exibe banners dos serviços executando nas portas abertas.
Sniffer de Pacotes: Captura e exibe pacotes de rede em uma interface especificada.
Relatório em HTML: Gera um relatório detalhado em HTML com os resultados do escaneamento.

Requisitos:
Python 3.x
Bibliotecas Python: scapy, html

Instalação:

Clone o repositório:
git clone https://github.com/seu_usuario/scanner.git
cd scanner

Instale as dependências:
pip install scapy

Uso:
Para utilizar a ferramenta, execute o script scanner.py com os seguintes parâmetros:
python3 scanner.py <IP> <porta_inicial> <porta_final>

Exemplo:
python3 scanner.py 192.168.1.1 1 100
Isso irá escanear as portas de 1 a 100 no endereço IP 192.168.1.1.
