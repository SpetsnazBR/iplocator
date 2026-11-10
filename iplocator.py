#!/usr/bin/env python3
"""IP-Locator — CLI de OSINT (geolocalização, portas e WHOIS).

Uso rápido::

    python iplocator.py                      # menu interativo
    python iplocator.py --serve              # interface web (Vue) local
    python iplocator.py --geo 8.8.8.8 --json # consulta única, saída JSON

A compatibilidade com a v1 é mantida: ``IPLocator`` e ``PortScanner`` seguem
importáveis daqui, com os mesmos métodos públicos.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from iplocator_core import (
    CacheManager,
    ConsultaWhois,
    IPLocator,
    LocalizadorGeo,
    PortScanner,
    WhoisClient,
    __version__,
    descrever_servico,
    identificar_alvo,
    normalizar_intervalo,
    resolver_dominio,
)
from iplocator_core.api import DIRETORIO_WEB_PADRAO, servir

__all__ = [
    "IPLocator",
    "PortScanner",
    "WhoisClient",
    "CacheManager",
    "exibir_banner",
    "exibir_menu",
    "exibir_resultado",
    "formatar_geo",
    "formatar_whois",
    "ler_opcao",
    "main",
]

# Códigos ANSI usados no terminal.
VERMELHO = "\033[31m"
AMARELO = "\033[33m"
NEGRITO = "\033[1m"
RESET = "\033[0m"

#: Rótulos exibidos para cada campo da geolocalização.
ROTULOS_GEO = {
    "provider": "Provedor",
    "country": "País",
    "countryCode": "Código",
    "regionName": "Região",
    "city": "Cidade",
    "zip": "CEP",
    "lat": "Latitude",
    "lon": "Longitude",
    "timezone": "Fuso",
    "isp": "ISP",
    "org": "Organização",
    "as": "ASN",
}


# ----------------------------------------------------------------------
# Interface de terminal
# ----------------------------------------------------------------------
def exibir_banner() -> None:
    """Mostra o banner estilizado em vermelho (pyfiglet é opcional)."""
    try:
        from pyfiglet import Figlet
    except ImportError:  # dependência opcional: segue sem o banner estilizado
        print(f"{VERMELHO}{NEGRITO}IP Locator {__version__}{RESET}")
        return
    banner = Figlet(font="slant").renderText("IP Locator")
    print(f"{VERMELHO}{banner}{RESET}")


def exibir_menu() -> None:
    """Menu principal apresentado ao usuário."""
    print(f"\n{NEGRITO}=== MENU ==={RESET}")
    print("1 – Localizar IP / domínio")
    print("2 – Escanear intervalo de portas")
    print("3 – Escanear portas comuns")
    print("4 – Consultar WHOIS / RDAP")
    print("5 – Cache (estatísticas / limpar)")
    print("6 – Abrir interface web (servidor local)")
    print("0 – Sair")
    print("-" * 30)


def ler_opcao() -> str:
    """Lê a opção do usuário, garantindo que seja válida."""
    validas = {"0", "1", "2", "3", "4", "5", "6"}
    opcao = input("\nEscolha uma opção: ").strip()
    while opcao not in validas:
        print("Opção inválida. Use 0, 1, 2, 3, 4, 5 ou 6.")
        opcao = input("Escolha uma opção: ").strip()
    return opcao


# ----------------------------------------------------------------------
# Formatação de saída (funções puras — cobertas pelos testes)
# ----------------------------------------------------------------------
def formatar_geo(dados: Dict[str, Any]) -> List[str]:
    """Monta as linhas de saída de um resultado de geolocalização."""
    linhas: List[str] = []
    chaves = ("provider",) + tuple(
        chave for chave in ROTULOS_GEO if chave != "provider"
    )
    for chave in chaves:
        valor = dados.get(chave)
        if valor in (None, ""):
            continue
        linhas.append(f"{ROTULOS_GEO.get(chave, chave.capitalize()):13}: {valor}")
    if dados.get("cache"):
        linhas.append(f"{'Cache':13}: reaproveitado")
    if dados.get("maps_url"):
        linhas.append(f"{'Mapa':13}: {dados['maps_url']}")
    return linhas


def formatar_whois(detalhe: Dict[str, Any]) -> List[str]:
    """Monta as linhas de saída de um resultado WHOIS/RDAP."""
    dados = detalhe.get("dados") or {}
    linhas = [f"{'Fonte':13}: {detalhe.get('fonte') or 'desconhecida'}"]
    if detalhe.get("cache"):
        linhas.append(f"{'Cache':13}: reaproveitado")
    campos = (
        ("handles", "Handle"),
        ("nome", "Nome"),
        ("netname", "Netname"),
        ("organizacao", "Organização"),
        ("pais", "País"),
        ("tipo", "Tipo"),
        ("intervalo", "Intervalo"),
        ("abuse_contato", "Abuso"),
        ("servidor", "Servidor"),
    )
    for chave, rotulo in campos:
        valor = dados.get(chave)
        if isinstance(valor, dict):
            valor = " - ".join(
                str(parte) for parte in valor.values() if parte not in (None, "")
            )
        if isinstance(valor, list):
            valor = ", ".join(str(parte) for parte in valor[:4])
        if valor in (None, "", (), []):
            continue
        linhas.append(f"{rotulo:13}: {valor}")
    eventos = dados.get("eventos") or {}
    if isinstance(eventos, dict):
        for acao, data in list(eventos.items())[:4]:
            linhas.append(f"{acao[:13]:13}: {data}")
    descricao = dados.get("descricao")
    if isinstance(descricao, list) and descricao:
        linhas.append(f"{'Descrição':13}: {' | '.join(descricao[:3])}")
    return linhas

# ----------------------------------------------------------------------
# Execução de consultas (usadas pela CLI e pelo menu)
# ----------------------------------------------------------------------
def executar_geo(
    locator: LocalizadorGeo,
    alvo: str,
    saida_json: bool = False,
) -> int:
    """Consulta a geolocalização e imprime o resultado."""
    detalhe = locator.localizar_detalhado(alvo)
    if saida_json:
        print(json.dumps(detalhe, ensure_ascii=False, indent=2, default=str))
        return 0 if detalhe.get("ok") else 1
    if not detalhe.get("ok"):
        print(f"{VERMELHO}{detalhe.get('erro')}{RESET}", file=sys.stderr)
        for erro in detalhe.get("erros", []):
            print(f"  - {erro['provider']}: {erro['erro']}", file=sys.stderr)
        return 1
    exibir_resultado(detalhe.get("dados") or {})
    return 0


def executar_whois(
    cliente: ConsultaWhois,
    alvo: str,
    saida_json: bool = False,
) -> int:
    """Consulta WHOIS/RDAP e imprime o resultado."""
    detalhe = cliente.consultar_detalhado(alvo)
    if saida_json:
        print(json.dumps(detalhe, ensure_ascii=False, indent=2, default=str))
        return 0 if detalhe.get("ok") else 1
    if not detalhe.get("ok"):
        print(f"{VERMELHO}{detalhe.get('erro')}{RESET}", file=sys.stderr)
        return 1
    print(f"\n{NEGRITO}=== WHOIS / RDAP ==={RESET}")
    for linha in formatar_whois(detalhe):
        print(linha)
    return 0


def executar_scan(
    cache: CacheManager,
    alvo: str,
    modo: str = "comuns",
    inicio: int = 1,
    fim: int = 1024,
    timeout: float = 1.0,
    servicos: bool = True,
    saida_json: bool = False,
) -> int:
    """Executa o scan de portas (comuns ou intervalo) e imprime o resultado."""
    info = identificar_alvo(alvo)
    if info["tipo"] == "invalido":
        print(
            f"{VERMELHO}Alvo inválido: informe um IP ou domínio.{RESET}",
            file=sys.stderr,
        )
        return 2
    host = info["ip"] or resolver_dominio(str(info["entrada"]))
    if not host:
        print(
            f"{VERMELHO}Não foi possível resolver '{alvo}'.{RESET}",
            file=sys.stderr,
        )
        return 2

    try:
        inicio, fim = normalizar_intervalo(int(inicio), int(fim))
    except (TypeError, ValueError) as exc:
        print(f"{VERMELHO}Intervalo inválido: {exc}{RESET}", file=sys.stderr)
        return 2

    scanner = PortScanner(
        timeout=timeout,
        detectar_servicos=servicos,
        cache=cache,
        verbose=not saida_json,
    )
    if modo == "comuns":
        scanner.scan_portas_comuns(host)
    else:
        scanner.scan_intervalo(host, inicio, fim)

    if saida_json:
        payload: Dict[str, Any] = {
            "ok": True,
            "alvo": alvo,
            "host": host,
            "modo": modo,
            "intervalo": [inicio, fim],
            "servicos": servicos,
        }
        payload.update(scanner.resumo())
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        return 0

    if not scanner.portas_abertas:
        print(f"\n{AMARELO}Nenhuma porta aberta encontrada.{RESET}")
        return 0
    print(f"\n{NEGRITO}=== Portas abertas em {host} ==={RESET}")
    for item in scanner.resultados_ordenados():
        print(f"  {int(item['porta']):5}  {descrever_servico(item)}")
    return 0



# ----------------------------------------------------------------------
# Ações do menu interativo
# ----------------------------------------------------------------------
def menu_localizar(locator: IPLocator) -> None:
    alvo = input("\nDigite o IP ou domínio a ser localizado: ").strip()
    if not alvo:
        print("Alvo vazio – operação cancelada.")
        return
    executar_geo(locator, alvo)


def menu_scan_intervalo(cache: CacheManager, timeout: float = 1.0) -> None:
    host = input("\nInforme o IP ou domínio a ser escaneado: ").strip()
    if not host:
        print("Alvo vazio – operação cancelada.")
        return
    try:
        inicio = int(input("Porta inicial (default 1): ").strip() or "1")
        fim = int(input("Porta final (default 1024): ").strip() or "1024")
    except ValueError:
        print("Valores de porta inválidos – usando 1-1024.")
        inicio, fim = 1, 1024
    executar_scan(
        cache, host, modo="intervalo", inicio=inicio, fim=fim, timeout=timeout
    )


def menu_scan_comuns(cache: CacheManager, timeout: float = 1.0) -> None:
    host = input("\nInforme o IP ou domínio a ser escaneado: ").strip()
    if not host:
        print("Alvo vazio – operação cancelada.")
        return
    executar_scan(cache, host, modo="comuns", timeout=timeout)


def menu_whois(cliente: WhoisClient) -> None:
    alvo = input("\nDigite o IP ou domínio para consulta WHOIS: ").strip()
    if not alvo:
        print("Alvo vazio – operação cancelada.")
        return
    executar_whois(cliente, alvo)


def menu_cache(cache: CacheManager) -> None:
    """Mostra as estatísticas do cache e oferece a limpeza."""
    stats = cache.stats()
    print(f"\n{NEGRITO}=== Cache ==={RESET}")
    print(f"{'Habilitado':13}: {'sim' if stats['habilitado'] else 'não'}")
    print(f"{'Diretório':13}: {stats.get('diretorio') or '-'}")
    print(f"{'Entradas':13}: {stats['entradas']}")
    print(f"{'Hits/Misses':13}: {stats['hits']}/{stats['misses']}")
    print(f"{'Taxa de acerto':13}: {stats['taxa_acerto'] * 100:.1f}%")
    for nome, dados in stats.get("namespaces", {}).items():
        print(
            f"  - {nome:8} ttl={dados['ttl']:.0f}s "
            f"entradas={dados['entradas']} hits={dados['hits']}"
        )
    if not cache.enabled:
        return
    resposta = input("\nLimpar o cache agora? (s/N): ").strip().lower()
    if resposta in {"s", "sim", "y", "yes"}:
        removidas = cache.clear()
        print(f"[*] Cache limpo ({removidas} entrada(s) removida(s)).")


def menu_servidor(host: str = "127.0.0.1", porta: int = 8000) -> None:
    """Sobe a API + interface web (bloqueia até Ctrl+C)."""
    web = Path(DIRETORIO_WEB_PADRAO)
    if not (web / "index.html").is_file():
        print(
            f"{VERMELHO}Interface web não encontrada em {web}{RESET}",
            file=sys.stderr,
        )
        return
    servir(host=host, porta=porta)


def exibir_resultado(info: Dict[str, Any]) -> None:
    """Imprime o resultado de uma geolocalização em formato de cartão.

    Mantida como API pública desde a v1; delega a formatação para
    :func:`formatar_geo` para não duplicar rótulos.
    """
    print(f"\n{NEGRITO}=== Dados do IP ==={RESET}")
    for linha in formatar_geo(info):
        print(linha)


def menu_interativo(
    locator: IPLocator,
    whois: WhoisClient,
    cache: CacheManager,
    host: str = "127.0.0.1",
    porta: int = 8000,
    timeout: float = 1.0,
) -> int:
    """Loop principal do menu em linha de comando."""
    exibir_banner()
    print(f"[i] Provedores: {', '.join(locator.provedores_ativos())}")
    print(f"[i] Cache: {'ativo' if cache.enabled else 'desativado'} "
          f"({cache.directory})")
    print("[i] Interface web: python iplocator.py --serve")
    while True:
        exibir_menu()
        opcao = ler_opcao()
        if opcao == "0":
            print("\nEncerrando…")
            return 0
        if opcao == "1":
            menu_localizar(locator)
        elif opcao == "2":
            menu_scan_intervalo(cache, timeout)
        elif opcao == "3":
            menu_scan_comuns(cache, timeout)
        elif opcao == "4":
            menu_whois(whois)
        elif opcao == "5":
            menu_cache(cache)
        elif opcao == "6":
            menu_servidor(host, porta)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def construir_parser() -> argparse.ArgumentParser:
    """Define os argumentos de linha de comando (também usados nos testes)."""
    parser = argparse.ArgumentParser(
        prog="iplocator",
        description=(
            "IP-Locator: geolocalização de IPs/domínios, scanner de portas com "
            "detecção de serviços e consulta WHOIS/RDAP."
        ),
        epilog=(
            "Exemplos:\n"
            "  python iplocator.py --serve\n"
            "  python iplocator.py --geo 8.8.8.8\n"
            "  python iplocator.py --whois github.com --json\n"
            "  python iplocator.py --scan 1.1.1.1 --mode comuns\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--serve", action="store_true", help="sobe a API + interface web (Vue)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="host do servidor web (padrão: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="porta do servidor web (padrão: 8000)"
    )
    parser.add_argument("--geo", metavar="ALVO", help="localiza um IP ou domínio")
    parser.add_argument(
        "--whois", metavar="ALVO", help="consulta WHOIS/RDAP de um IP ou domínio"
    )
    parser.add_argument(
        "--scan", metavar="ALVO", help="escaneia as portas de um IP ou domínio"
    )
    parser.add_argument(
        "--mode",
        choices=("comuns", "intervalo"),
        default="comuns",
        help="modo do scan (padrão: comuns)",
    )
    parser.add_argument(
        "--start", type=int, default=1, help="porta inicial do scan (padrão: 1)"
    )
    parser.add_argument(
        "--end", type=int, default=1024, help="porta final do scan (padrão: 1024)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="timeout por porta em segundos (padrão: 1.0)",
    )
    parser.add_argument(
        "--no-services",
        action="store_true",
        help="desliga a detecção de serviços (scan mais rápido)",
    )
    parser.add_argument(
        "--providers",
        metavar="LISTA",
        help="provedores de geolocalização separados por vírgula",
    )
    parser.add_argument(
        "--https", action="store_true", help="usa HTTPS no provedor ip-api"
    )
    parser.add_argument(
        "--json", action="store_true", help="imprime a saída em JSON"
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="desativa o cache de resultados"
    )
    parser.add_argument(
        "--clear-cache", action="store_true", help="limpa o cache e encerra"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="mostra log detalhado do servidor"
    )
    parser.add_argument(
        "--version", action="version", version=f"IP-Locator {__version__}"
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Ponto de entrada: escolhe entre CLI não interativa e menu."""
    args = construir_parser().parse_args(argv)
    cache = CacheManager(enabled=not args.no_cache)

    if args.clear_cache:
        removidas = cache.clear()
        print(f"[*] Cache limpo ({removidas} entrada(s) removida(s)).")
        return 0

    if args.serve:
        servir(host=args.host, porta=args.port, verbose=args.verbose)
        return 0

    nomes = (
        [nome.strip() for nome in str(args.providers).split(",") if nome.strip()]
        if args.providers
        else None
    )
    locator = IPLocator(use_https=args.https, providers=nomes, cache=cache)
    whois = WhoisClient(cache=cache)

    if args.geo:
        return executar_geo(locator, args.geo, saida_json=args.json)
    if args.whois:
        return executar_whois(whois, args.whois, saida_json=args.json)
    if args.scan:
        return executar_scan(
            cache,
            args.scan,
            modo=args.mode,
            inicio=args.start,
            fim=args.end,
            timeout=args.timeout,
            servicos=not args.no_services,
            saida_json=args.json,
        )
    return menu_interativo(
        locator, whois, cache, host=args.host, porta=args.port, timeout=args.timeout
    )


if __name__ == "__main__":
    sys.exit(main())

