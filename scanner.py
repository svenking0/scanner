import socket
import sys
from scapy.all import *
import threading
from datetime import datetime
from html import escape


RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

def print_banner():
    banner = r"""
 ___  ___ __ _ _ __  _ __   ___ _ __ _ __  _   _ 
/ __|/ __/ _` | '_ \| '_ \ / _ \ '__| '_ \| | | |
\__ \ (_| (_| | | | | | | |  __/ |_ | |_) | |_| |
|___/\___\__,_|_| |_|_| |_|\___|_(_)| .__/ \__, |
                                    |_|    |___/ 
                             Created by: Sven
    """
    print(banner)

def show_help():
    help_text = f"""
Uso: python3 scanner.py <IP> <porta_inicial> <porta_final>

{GREEN}Opções:{RESET}
  <IP>              - Endereço IP do alvo para escanear.
  <porta_inicial>   - Porta inicial para o escaneamento.
  <porta_final>     - Porta final para o escaneamento.

Funções:
  - Escaneamento de portas.
  - Captura de banners.
  - Sniffer de pacotes.

Exemplo:
  python3 scanner.py 192.168.1.1 1 100
    """
    print(help_text)


def generate_html_report(results, filename='relatorio.html'):
    with open(filename, 'w') as f:
        f.write('<html><body>')
        f.write('<h1>Relatório de Escaneamento</h1>')
        f.write(f'<p>Data: {datetime.now()}</p>')
        f.write('<h2>Resultados</h2>')
        f.write('<pre>' + escape(results) + '</pre>')
        f.write('</body></html>')

def port_scanner(target_ip, port_range):
    print(f"Escaneando {target_ip} de {port_range[0]} a {port_range[1]}")
    threads = []
    results = []
    for port in range(port_range[0], port_range[1] + 1):
        thread = threading.Thread(target=scan_port, args=(target_ip, port, results))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return results

def scan_port(target_ip, port, results):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target_ip, port))
    
    if result == 0:
        service = socket.getservbyport(port, 'tcp')
        result_str = f"{GREEN}[+] Porta {port} está aberta - Serviço: {service}{RESET}"
        print(result_str)
        results.append(result_str)
        banner_grabbing(target_ip, port)
    else:
        if result == 1:
            result_str = f"{YELLOW}[!] Porta {port} está filtrada{RESET}"
            print(result_str)
            results.append(result_str)
        else:
            result_str = f"{RED}[-] Porta {port} está fechada{RESET}"
            print(result_str)
            results.append(result_str)
    sock.close()

def banner_grabbing(ip, port):
    try:
        sock = socket.socket()
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        if banner:
            print(f"Banner da porta {port}: {banner}")
        else:
            print(f"Nenhum banner detectado na porta {port}")
        sock.close()
    except Exception as e:
        print(f"Não foi possível obter o banner na porta {port}: {e}")

def packet_sniffer(interface):
    print(f"Iniciando o sniffer na interface {interface}")
    packets = sniff(iface=interface, count=10)
    for packet in packets:
        print(packet.summary())

if __name__ == "__main__":
    if len(sys.argv) == 1:
        show_help()  
        sys.exit(0)
    
    if len(sys.argv) != 4:
        print("Uso: python3 scanner.py <IP> <porta_inicial> <porta_final>")
        sys.exit(1)

    print_banner()  # Exibe o banner ao iniciar o programa

    ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    
    
    results = port_scanner(ip, (start_port, end_port))
    
    
    generate_html_report('\n'.join(results))
    
    sniff_choice = input("Deseja iniciar o sniffer de pacotes? (s/n): ")
    if sniff_choice.lower() == 's':
        interface = input("Digite a interface de rede (ex: eth0, wlan0): ")
        packet_sniffer(interface)
