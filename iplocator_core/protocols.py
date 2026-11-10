"""Protocolos estruturais usados na injeção de dependências.

Permitem substituir a sessão HTTP, o localizador e o cliente WHOIS por dublês
nos testes sem exigir herança: o Pylance/Pyright valida os dublês
estruturalmente, então a suíte e o editor concordam sobre os tipos.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol


class RespostaHTTP(Protocol):
    """Subconjunto de ``requests.Response`` consumido pelo núcleo."""

    status_code: int

    def json(self) -> Any:
        """Corpo da resposta já decodificado como JSON."""
        ...


class SessaoHTTP(Protocol):
    """Sessão HTTP mínima: apenas ``GET`` com timeout e cabeçalhos.

    Os parâmetros são *keyword-only* para casar com ``requests.Session.get``.
    """

    def get(
        self,
        url: str,
        *,
        timeout: Optional[float] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> RespostaHTTP:
        """Executa um GET e devolve uma resposta compatível."""
        ...


class LocalizadorGeo(Protocol):
    """O que a CLI realmente usa de um localizador de IPs."""

    def localizar_detalhado(self, alvo: str) -> Dict[str, Any]:
        """Consulta estruturada com ``ok``/``erro``/``dados``."""
        ...


class ConsultaWhois(Protocol):
    """O que a CLI realmente usa de um cliente WHOIS/RDAP."""

    def consultar_detalhado(self, alvo: str) -> Dict[str, Any]:
        """Consulta estruturada com ``ok``/``erro``/``dados``."""
        ...
