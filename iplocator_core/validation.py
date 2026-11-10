"""Validação e resolução de alvos (IP literal ou nome de domínio).

Todas as funções deste módulo são puras (exceto :func:`resolver_dominio`, que
consulta o DNS do sistema), o que mantém a suíte de testes determinística.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Dict, Optional

#: Rótulo de domínio conforme RFC 1123 (sem sublinhado, até 63 caracteres).
ROTULO_DOMINIO = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"

#: Domínio com pelo menos um ponto e TLD alfabético (ex.: ``example.com.br``).
PADRAO_DOMINIO = re.compile(
    rf"^(?=.{{4,253}}$)(?:{ROTULO_DOMINIO}\.)+[a-zA-Z]{{2,63}}$"
)

#: Tamanho máximo aceito para um alvo vindo de entrada do usuário/API.
TAMANHO_MAXIMO_ALVO = 253


def normalizar_alvo(alvo: str) -> str:
    """Remove espaços, esquema e colchetes de IPv6 (``[::1]`` -> ``::1``)."""
    if not isinstance(alvo, str):
        return ""
    limpo = alvo.strip()
    if limpo.startswith("[") and limpo.endswith("]"):
        limpo = limpo[1:-1]
    for esquema in ("http://", "https://"):
        if limpo.lower().startswith(esquema):
            limpo = limpo[len(esquema):]
    # Descarta caminho/porta eventualmente colados ao alvo.
    limpo = limpo.split("/")[0]
    if limpo.count(":") == 1:
        limpo = limpo.split(":")[0]
    return limpo.strip().rstrip(".")


def validar_ip(ip: str) -> bool:
    """Retorna ``True`` para IPv4/IPv6 válido (notação completa ou comprimida)."""
    if not ip or not str(ip).strip():
        return False
    try:
        ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return True


def validar_dominio(dominio: str) -> bool:
    """Valida sintaticamente um nome de domínio (não consulta o DNS)."""
    if not dominio:
        return False
    return bool(PADRAO_DOMINIO.match(dominio))


def is_ip_reservado(ip: str) -> bool:
    """Indica se o IP é privado, reservado, loopback ou de documentação.

    Usa ``ipaddress.is_global`` como critério: tudo que não é roteável na
    internet (RFC 1918, CGNAT 100.64/10, loopback, link-local, multicast,
    faixas de documentação e ``fc00::/7``) não é geolocalizável.
    """
    if not ip:
        return False
    try:
        endereco = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not endereco.is_global


def resolver_dominio(dominio: str) -> Optional[str]:
    """Resolve um domínio para IPv4 usando o resolvedor do sistema.

    Retorna ``None`` quando a resolução falha (NXDOMAIN, sem rede, etc.).
    """
    if not dominio:
        return None
    try:
        return socket.gethostbyname(dominio)
    except (socket.gaierror, socket.herror, OSError, UnicodeError):
        return None


def identificar_alvo(alvo: str) -> Dict[str, Optional[str]]:
    """Classifica o alvo em ``ip``, ``dominio`` ou ``invalido``.

    O dicionário devolvido sempre contém ``entrada``, ``tipo`` e ``ip``
    (``None`` até a resolução) e, quando houver erro, ``erro``.
    """
    entrada = normalizar_alvo(alvo)
    if not entrada:
        return {
            "entrada": entrada,
            "tipo": "invalido",
            "ip": None,
            "erro": "Alvo vazio",
        }
    if len(entrada) > TAMANHO_MAXIMO_ALVO:
        return {
            "entrada": entrada[:64],
            "tipo": "invalido",
            "ip": None,
            "erro": "Alvo maior que o permitido",
        }
    if validar_ip(entrada):
        return {"entrada": entrada, "tipo": "ip", "ip": entrada, "erro": None}
    if validar_dominio(entrada):
        return {
            "entrada": entrada,
            "tipo": "dominio",
            "ip": None,
            "erro": None,
        }
    return {
        "entrada": entrada,
        "tipo": "invalido",
        "ip": None,
        "erro": "Não é um IP nem um domínio válido",
    }
