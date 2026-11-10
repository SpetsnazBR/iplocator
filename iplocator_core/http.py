"""Sessão HTTP compartilhada, com retry e cabeçalhos padrão.

Centralizar a sessão evita recriar conexões TLS a cada provedor e permite que
os testes injetem um objeto falso sem tocar a rede.
"""

from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 2.x e 1.x expõem o mesmo ``Retry`` em caminhos diferentes.
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover - fallback defensivo
    Retry = None  # type: ignore[assignment]

#: User-Agent usado em todas as requisições (alguns provedores rejeitam o padrão).
USER_AGENT = (
    "IPLocator/2.0 (+https://github.com/SpetsnazBR/iplocator) "
    "python-requests"
)

#: Cabeçalhos enviados por padrão em cada provedor.
CABECALHOS_PADRAO = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
}


def criar_sessao(
    retries: int = 1,
    backoff: float = 0.3,
    user_agent: str = USER_AGENT,
) -> requests.Session:
    """Cria uma :class:`requests.Session` com retry para GET e cabeçalhos.

    O retry cobre apenas falhas transitórias (429/5xx) e nunca erros 4xx de
    cliente, evitando repetir requisições inválidas.
    """
    sessao = requests.Session()
    sessao.headers.update({"User-Agent": user_agent, "Accept": "application/json"})
    if Retry is not None and retries > 0:
        politica = Retry(
            total=retries,
            connect=retries,
            read=retries,
            backoff_factor=backoff,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            raise_on_status=False,
        )
        adaptador = HTTPAdapter(max_retries=politica)
        sessao.mount("https://", adaptador)
        sessao.mount("http://", adaptador)
    return sessao
