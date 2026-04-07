import requests
import sys
import re
import socket
import time
import threading
from typing import Optional, Dict, Union, List

class IPLocator:
    def __init__(self, use_https: bool = False):        
        self.base_url = "https://ip-api.com/json/" if use_https else "http://ip-api.com/json/"
        self.timeout = 10
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.last_request_time = 0
        self.min_request_interval = 1.0

    def validar_ip(self, ip: str) -> bool:        
        if not ip or ip.strip() == '':
            return False
            
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            partes = ip.split('.')
            if all(0 <= int(p) <= 255 for p in partes):
                return True
        
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if re.match(ipv6_pattern, ip):
            return True
            
        return False

    def is_ip_reservado(self, ip: str) -> bool:        
        if not ip:
            return False
            
        if ip == '0.0.0.0' or ip == '127.0.0.1' or ip == '255.255.255.255':
            return True
            
        if ip.startswith('10.'):
            return True
        if ip.startswith('192.168.'):
            return True
        if ip.startswith('172.'):
            partes = ip.split('.')
            if len(partes) >= 2:
                try:
                    segundo_octeto = int(partes[1])
                    if 16 <= segundo_octeto <= 31:
                        return True
                except ValueError:
                    pass
                        
        if ip == '::1' or ip == '::' or ip == 'fe80::' or ip.startswith('fc00:'):
            return True
            
        return False

    def resolver_dominio(self, dominio: str) -> Optional[str]:        
        try:
            return socket.gethostbyname(dominio)
        except (socket.gaierror, socket.herror):
            return None

    def _esperar_rate_limit(self):        
        tempo_atual = time.time()
        tempo_decorrido = tempo_atual - self.last_request_time
        if tempo_decorrido < self.min_request_interval:
            time.sleep(self.min_request_interval - tempo_decorrido)
        self.last_request_time = time.time()

    def localizar(self, alvo: str) -> Union[Dict, str]:        
        if not alvo or alvo.strip() == '':
            return "Erro: Por favor, digite um IP ou domínio válido."
        
        if self.validar_ip(alvo):
            ip = alvo
            if self.is_ip_reservado(ip):
                return f"Erro: IP reservado ({ip}) não pode ser localizado. Use um IP público."
        else:
            print(f"[*] Resolvendo domínio: {alvo}")
            ip = self.resolver_dominio(alvo)
            if not ip:
                return f"Erro: Não foi possível resolver o domínio '{alvo}'"
            print(f"[*] Domínio resolvido para IP: {ip}")
            if self.is_ip_reservado(ip):
                return f"Erro: Domínio resolve para IP reservado ({ip})"
        
        try:
            self._esperar_rate_limit()
            
            response = requests.get(
                f"{self.base_url}{ip}", 
                timeout=self.timeout,
                headers=self.headers
            )
            response.raise_for_status()
            
            data = response.json()

            if data.get('status') == 'success':
                return data
            else:
                mensagem = data.get('message', 'IP inválido ou não encontrado')
                return f"Erro da API: {mensagem}"
                
        except requests.exceptions.Timeout:
            return "Erro: Timeout na conexão com a API"
        except requests.exceptions.ConnectionError:
            return "Erro: Não foi possível conectar à API"
        except requests.exceptions.HTTPError as e:
            return f"Erro HTTP: {e}"
        except requests.exceptions.RequestException as e:
            return f"Erro na requisição: {e}"
        except ValueError as e:
            return f"Erro ao processar resposta da API: {e}"

class PortScanner:      
    PORTAS_COMUNS = {
        20: "FTP (Data)",
        21: "FTP (Control)",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP (Submission)",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt"
    }
    
    def __init__(self, timeout: float = 1.0, max_threads: int = 50):
        
        self.timeout = timeout
        self.max_threads = max_threads
        self.portas_abertas = []
        self.lock = threading.Lock()
    
    def testar_porta(self, host: str, porta: int) -> bool:
        
        if porta < 1 or porta > 65535:
            return False
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            resultado = sock.connect_ex((host, porta))
            sock.close()
            return resultado == 0
        except (socket.timeout, socket.error, OSError, ValueError):
            return False
    
    def scan_porta(self, host: str, porta: int):
        
        if self.testar_porta(host, porta):
            with self.lock:
                self.portas_abertas.append(porta)
                servico = self.PORTAS_COMUNS.get(porta, "Desconhecido")
                print(f"  [+] Porta {porta} aberta - {servico}")
    
    def scan_intervalo(self, host: str, inicio: int = 1, fim: int = 1024) -> List[int]:
        
        print(f"\n[*] Iniciando scan de portas em {host} (portas {inicio}-{fim})...")
        print(f"[*] Timeout: {self.timeout}s | Threads: {self.max_threads}")
        
        self.portas_abertas = []
        threads = []
        portas_para_scan = list(range(inicio, fim + 1))
        
        for i, porta in enumerate(portas_para_scan):
            thread = threading.Thread(target=self.scan_porta, args=(host, porta))
            threads.append(thread)
            thread.start()
            
            if len(threads) >= self.max_threads or i == len(portas_para_scan) - 1:
                for t in threads:
                    t.join()
                threads = []
        
        print(f"\n[*] Scan concluído! {len(self.portas_abertas)} porta(s) aberta(s).")
        return sorted(self.portas_abertas)
    
    def scan_portas_comuns(self, host: str) -> List[int]:
        
        print(f"\n[*] Escaneando portas comuns em {host}...")
        self.portas_abertas = []
        
        for porta, servico in self.PORTAS_COMUNS.items():
            if self.testar_porta(host, porta):
                self.portas_abertas.append(porta)
                print(f"  [+] Porta {porta} aberta - {servico}")
        
        print(f"\n[*] Scan concluído! {len(self.portas_abertas)} porta(s) comum(ns) aberta(s).")
        return sorted(self.portas_abertas)

def exibir_resultado(info: Dict):
    
    print("\n" + "="*40)
    print(f"📍 LOCALIZAÇÃO ENCONTRADA")
    print("="*40)
    print(f"🌐 IP:           {info.get('query', 'N/A')}")
    print(f"🏳️ País:         {info.get('country', 'N/A')} ({info.get('countryCode', 'N/A')})")
    print(f"🏙️ Região:       {info.get('regionName', 'N/A')}")
    print(f"🏙️ Cidade:       {info.get('city', 'N/A')}")
    print(f"📮 CEP:          {info.get('zip', 'N/A')}")
    print(f"🕐 Fuso Horário: {info.get('timezone', 'N/A')}")
    print(f"🏢 Provedor/ISP: {info.get('isp', 'N/A')}")
    print(f"📡 Organização:  {info.get('org', 'N/A')}")
    print(f"🗺️ Lat/Long:     {info.get('lat', 'N/A')}, {info.get('lon', 'N/A')}")
    
    lat = info.get('lat')
    lon = info.get('lon')
    if lat and lon:
        print(f"🔗 Google Maps:  https://www.google.com/maps?q={lat},{lon}")
        print(f"🔗 OpenStreetMap: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}")
    
    print("="*40)

def menu():
    locator = IPLocator(use_https=False)
    scanner = PortScanner(timeout=1.0, max_threads=100)
    
    print("-" * 60)
    print("🌍 LOCALIZADOR DE IP GEOGRÁFICO + SCANNER DE PORTAS - FERRAMENTA OSINT")
    print("-" * 60)
    print("[i] Digite 'sair' para encerrar")
    print("[i] Suporta IPs (IPv4/IPv6) e domínios (ex: google.com)")
    print("[i] Usando API HTTP (45 requisições/minuto)")
    print("[i] Scanner de portas com suporte a multithreading")
    print("-" * 60)
    
    while True:
        try:
            print("\n" + "="*30)
            print("MENU PRINCIPAL")
            print("="*30)
            print("1. Localizar IP/Domínio")
            print("2. Scan de portas comuns")
            print("3. Scan completo de portas (1-1024)")
            print("4. Scan personalizado de portas")
            print("5. Sair")
            print("="*30)
            
            opcao = input("\nEscolha uma opção (1-5): ").strip()
            
            if opcao == '5' or opcao.lower() in ['sair', 'exit', 'quit']:
                print("\n[!] Encerrando...")
                break
            
            if opcao == '1':
                alvo = input("\nDigite o IP ou Domínio para localizar: ").strip()
                
                if not alvo:
                    print("[!] Por favor, digite um IP ou domínio válido.")
                    continue
                
                print(f"\n[*] Consultando base de dados para: {alvo}...")
                info = locator.localizar(alvo)

                if isinstance(info, dict):
                    exibir_resultado(info)
                else:
                    print(f"\n[!] {info}")
            
            elif opcao == '2':
                alvo = input("\nDigite o IP ou Domínio para scan de portas comuns: ").strip()
                
                if not alvo:
                    print("[!] Por favor, digite um IP ou domínio válido.")
                    continue
                
                if locator.validar_ip(alvo):
                    ip = alvo
                else:
                    print(f"[*] Resolvendo domínio: {alvo}")
                    ip = locator.resolver_dominio(alvo)
                    if not ip:
                        print(f"[!] Não foi possível resolver o domínio '{alvo}'")
                        continue
                    print(f"[*] Domínio resolvido para IP: {ip}")
                
                if locator.is_ip_reservado(ip):
                    print(f"[!] IP reservado ({ip}) não pode ser escaneado.")
                    continue
                
                scanner.scan_portas_comuns(ip)
            
            elif opcao == '3':
                alvo = input("\nDigite o IP ou Domínio para scan completo (portas 1-1024): ").strip()
                
                if not alvo:
                    print("[!] Por favor, digite um IP ou domínio válido.")
                    continue
                
                if locator.validar_ip(alvo):
                    ip = alvo
                else:
                    print(f"[*] Resolvendo domínio: {alvo}")
                    ip = locator.resolver_dominio(alvo)
                    if not ip:
                        print(f"[!] Não foi possível resolver o domínio '{alvo}'")
                        continue
                    print(f"[*] Domínio resolvido para IP: {ip}")
                
                if locator.is_ip_reservado(ip):
                    print(f"[!] IP reservado ({ip}) não pode ser escaneado.")
                    continue
                
                print("\n[*] AVISO: Scan completo pode levar alguns minutos...")
                confirmacao = input("Deseja continuar? (s/n): ").strip().lower()
                if confirmacao == 's':
                    scanner.scan_intervalo(ip, 1, 1024)
                else:
                    print("[!] Scan cancelado.")
            
            elif opcao == '4':
                alvo = input("\nDigite o IP ou Domínio: ").strip()
                
                if not alvo:
                    print("[!] Por favor, digite um IP ou domínio válido.")
                    continue
                
                if locator.validar_ip(alvo):
                    ip = alvo
                else:
                    print(f"[*] Resolvendo domínio: {alvo}")
                    ip = locator.resolver_dominio(alvo)
                    if not ip:
                        print(f"[!] Não foi possível resolver o domínio '{alvo}'")
                        continue
                    print(f"[*] Domínio resolvido para IP: {ip}")
                
                if locator.is_ip_reservado(ip):
                    print(f"[!] IP reservado ({ip}) não pode ser escaneado.")
                    continue
                
                try:
                    inicio = int(input("Porta inicial (1-65535): ").strip())
                    fim = int(input("Porta final (1-65535): ").strip())
                    
                    if inicio < 1 or fim > 65535 or inicio > fim:
                        print("[!] Intervalo de portas inválido.")
                        continue
                    
                    print(f"\n[*] AVISO: Scan de {fim - inicio + 1} portas pode levar algum tempo...")
                    confirmacao = input("Deseja continuar? (s/n): ").strip().lower()
                    if confirmacao == 's':
                        scanner.scan_intervalo(ip, inicio, fim)
                    else:
                        print("[!] Scan cancelado.")
                        
                except ValueError:
                    print("[!] Por favor, digite números válidos para as portas.")
            
            else:
                print("[!] Opção inválida. Por favor, escolha uma opção de 1 a 5.")
                
        except KeyboardInterrupt:
            print("\n\n[!] Encerrando...")
            break
        except Exception as e:
            print(f"\n[!] Erro inesperado: {e}")

if __name__ == "__main__":
    try:
        menu()
    except Exception as e:
        print(f"\n[!] Erro fatal: {e}")
        sys.exit(1)
