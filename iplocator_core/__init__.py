"""Núcleo do IP-Locator: validação, cache, geolocalização, scan e WHOIS.

O pacote é importável isoladamente (``import iplocator_core``) e o módulo
``iplocator.py`` na raiz continua sendo o ponto de entrada da CLI.
"""

from __future__ import annotations

from .api import ContextoAPI, ServidorAPI, criar_servidor, servir
from .cache import CacheManager, TTLCache, diretorio_cache_padrao
from .geo import (
    GEO_PADRAO,
    ErroProvedor,
    IPLocator,
    ProvedorGeo,
    criar_provedores,
    normalizar_resultado,
    provedores_disponiveis,
)
from .protocols import ConsultaWhois, LocalizadorGeo, RespostaHTTP, SessaoHTTP
from .scanner import PortScanner, normalizar_intervalo, verificar_portas
from .services import (
    PORTAS_CONHECIDAS,
    detectar_servico,
    descrever_servico,
    nome_servico,
)
from .validation import (
    identificar_alvo,
    is_ip_reservado,
    normalizar_alvo,
    resolver_dominio,
    validar_dominio,
    validar_ip,
)
from .version import __version__
from .whois import (
    WhoisClient,
    consultar_whois,
    parse_rdap,
    parse_whois_texto,
)

__all__ = [
    "__version__",
    # cache
    "CacheManager",
    "TTLCache",
    "diretorio_cache_padrao",
    # geolocalização
    "GEO_PADRAO",
    "ErroProvedor",
    "IPLocator",
    "ProvedorGeo",
    "criar_provedores",
    "normalizar_resultado",
    "provedores_disponiveis",
    # protocolos de injeção (sessão/localizador/WHOIS)
    "ConsultaWhois",
    "LocalizadorGeo",
    "RespostaHTTP",
    "SessaoHTTP",
    # scan / serviços
    "PORTAS_CONHECIDAS",
    "PortScanner",
    "detectar_servico",
    "descrever_servico",
    "nome_servico",
    "normalizar_intervalo",
    "verificar_portas",
    # validação
    "identificar_alvo",
    "is_ip_reservado",
    "normalizar_alvo",
    "resolver_dominio",
    "validar_dominio",
    "validar_ip",
    # whois
    "WhoisClient",
    "consultar_whois",
    "parse_rdap",
    "parse_whois_texto",
    # api / web
    "ContextoAPI",
    "ServidorAPI",
    "criar_servidor",
    "servir",
]
