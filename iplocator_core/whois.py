"""WHOIS/RDAP: dados de registro de IPs e dominios.

Estrategia: tenta RDAP (JSON sobre HTTPS, sem parsing fragil) e, se falhar,
cai para o protocolo WHOIS classico na porta 43 seguindo a referencia do IANA.
"""

from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote

import requests

from .cache import CacheManager
from .http import criar_sessao
from .protocols import SessaoHTTP
from .validation import identificar_alvo

#: Servico publico que redireciona para o RDAP do RIR/registro correto.
RDAP_BASE = "https://rdap.org"

#: Porta do protocolo WHOIS classico.
PORTA_WHOIS = 43

#: Limite de leitura de uma resposta WHOIS (evita servidor tagarela).
MAX_BYTES_WHOIS = 262144

#: Servidores WHOIS por registro regional (fallback sem IANA).
SERVIDORES_RIR: Dict[str, str] = {
    "arin": "whois.arin.net",
    "ripe": "whois.ripe.net",
    "apnic": "whois.apnic.net",
    "lacnic": "whois.lacnic.net",
    "afrinic": "whois.afrinic.net",
}

#: Servidores WHOIS de TLDs comuns (consulta direta).
SERVIDORES_TLD: Dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "br": "whois.registro.br",
    "info": "whois.afilias.net",
    "xyz": "whois.nic.xyz",
    "me": "whois.nic.me",
}

#: Marcadores de "nada encontrado" em respostas WHOIS.
MARCADORES_VAZIOS = (
    "no match for",
    "not found",
    "no entries found",
    "no data found",
    "no object found",
    "rate limit exceeded",
    "query rate limit",
)

#: Mapeamento chave-bruta -> campo normalizado (primeira ocorrencia vence).
MAPA_CAMPOS: Dict[str, str] = {
    "netname": "netname",
    "netrange": "intervalo",
    "cidr": "cidr",
    "inetnum": "intervalo",
    "inet6num": "intervalo",
    "orgname": "organizacao",
    "org-name": "organizacao",
    "organization": "organizacao",
    "owner": "organizacao",
    "descr": "descricao",
    "country": "pais",
    "created": "criado",
    "regdate": "criado",
    "registered": "criado",
    "changed": "atualizado",
    "last-modified": "atualizado",
    "updated": "atualizado",
    "abuse-mailbox": "abuse_contato",
    "orgabuseemail": "abuse_contato",
    "abuse-c": "abuse_handle",
    "mnt-by": "mantenedor",
    "status": "status",
    "domain": "dominio",
    "registrar": "registrar",
    "nserver": "servidores_dns",
    "expiry": "expira_em",
    "expires": "expira_em",
    "paid-till": "expira_em",
}


class ErroWhois(Exception):
    """Falha ao consultar RDAP/WHOIS (mensagem ja amigavel)."""


#: Segmento de URL usado pelo RDAP para cada tipo de alvo.
SEGMENTO_RDAP: Dict[str, str] = {"ip": "ip", "dominio": "domain"}


def tipo_alvo(alvo: str) -> str:
    """Classifica o alvo em ``ip``, ``dominio`` ou ``invalido``."""
    return str(identificar_alvo(alvo)["tipo"])


def extrair_referencia(texto: str) -> Optional[str]:
    """Le a linha ``refer:`` de uma resposta do IANA (quando existir)."""
    for linha in (texto or "").splitlines():
        chave, separador, valor = linha.partition(":")
        if separador and chave.strip().lower() in {"refer", "referralserver", "whois"}:
            candidato = valor.strip().split()[0] if valor.strip() else ""
            if candidato and "://" not in candidato:
                return candidato
    return None


def resposta_vazia(texto: str) -> bool:
    """Detecta respostas de "sem registro" / rate limit (ou vazias)."""
    if not (texto or "").strip():
        return True
    minusculo = (texto or "").lower()
    return any(marcador in minusculo for marcador in MARCADORES_VAZIOS)


def parse_whois_texto(texto: str) -> Dict[str, Any]:
    """Converte uma resposta WHOIS em texto num dicionario normalizado."""
    campos: Dict[str, Any] = {}
    descricoes: List[str] = []
    for linha in (texto or "").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith(("%", "#", ">", "*")):
            continue
        chave, separador, valor = linha.partition(":")
        if not separador:
            continue
        chave_normalizada = chave.strip().lower()
        valor = valor.strip()
        if not valor:
            continue
        destino = MAPA_CAMPOS.get(chave_normalizada)
        if destino == "descricao":
            if len(descricoes) < 5 and valor not in descricoes:
                descricoes.append(valor)
            continue
        if destino is None:
            campos.setdefault(chave_normalizada, valor)
            continue
        if destino == "servidores_dns":
            existentes = campos.get(destino)
            if isinstance(existentes, list):
                if len(existentes) < 8:
                    existentes.append(valor)
            else:
                campos[destino] = [valor]
            continue
        campos.setdefault(destino, valor)
    if descricoes:
        campos["descricao"] = descricoes
    campos.setdefault("encontrado", bool(campos) and not resposta_vazia(texto))
    campos["bruto"] = (texto or "")[:20000]
    return campos


def _valor_vcard(vcard: Any, chaves: tuple) -> Optional[str]:
    """Le um campo textual do ``vcardArray`` do RDAP (``fn``/``org``/``email``)."""
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for campo in vcard[1] or []:
        if not isinstance(campo, list) or len(campo) < 4:
            continue
        if str(campo[0]).lower() not in chaves:
            continue
        valor = campo[3]
        if isinstance(valor, list):
            valor = " ".join(str(parte) for parte in valor if parte)
        if valor:
            return str(valor).strip()
    return None


def parse_rdap(dados: Dict[str, Any]) -> Dict[str, Any]:
    """Normaliza um documento RDAP (IP ou dominio) em um dicionario simples."""
    eventos: Dict[str, str] = {}
    for evento in dados.get("events", []) or []:
        if not isinstance(evento, dict):
            continue
        acao = evento.get("eventAction")
        data = evento.get("eventDate")
        if acao and data:
            eventos.setdefault(str(acao), str(data))

    entidades: List[Dict[str, Any]] = []
    for entidade in dados.get("entities", []) or []:
        if not isinstance(entidade, dict):
            continue
        vcard = entidade.get("vcardArray")
        entidades.append(
            {
                "handle": entidade.get("handle"),
                "nome": _valor_vcard(vcard, ("fn", "org")),
                "papeis": list(entidade.get("roles") or []),
                "email": _valor_vcard(vcard, ("email",)),
            }
        )

    observacoes = [
        " ".join(str(parte) for parte in (item.get("description") or [])).strip()
        for item in (dados.get("remarks") or [])
        if isinstance(item, dict)
    ]
    links = [
        link.get("href")
        for link in (dados.get("links") or [])
        if isinstance(link, dict) and link.get("href")
    ]

    organizacao = None
    contato_abuso = None
    for entidade in entidades:
        papeis = {str(papel).lower() for papel in entidade.get("papeis", [])}
        if organizacao is None and entidade.get("nome"):
            organizacao = entidade["nome"]
        if contato_abuso is None and "abuse" in papeis and entidade.get("email"):
            contato_abuso = entidade["email"]

    return {
        "handles": dados.get("handle"),
        "nome": dados.get("name") or dados.get("ldhName"),
        "tipo": dados.get("type"),
        "organizacao": organizacao,
        "pais": dados.get("country"),
        "status": list(dados.get("status") or []),
        "intervalo": {
            "inicio": dados.get("startAddress"),
            "fim": dados.get("endAddress"),
            "versao_ip": dados.get("ipVersion"),
        },
        "eventos": eventos,
        "entidades": entidades[:15],
        "observacoes": [texto for texto in observacoes if texto][:5],
        "links": links[:10],
        "abuse_contato": contato_abuso,
        "bruto": dados,
    }


def _enviar_consulta(
    servidor: str,
    consulta: str,
    timeout: float = 10.0,
    porta: int = PORTA_WHOIS,
) -> str:
    """Abre conexao na porta 43, envia a consulta e le a resposta completa."""
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((servidor, int(porta)), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall((consulta.strip() + "\r\n").encode("utf-8", "replace"))
        partes: List[bytes] = []
        total = 0
        while total < MAX_BYTES_WHOIS:
            try:
                parte = sock.recv(4096)
            except (socket.timeout, OSError):
                break
            if not parte:
                break
            partes.append(parte)
            total += len(parte)
        return b"".join(partes).decode("utf-8", "replace")
    except (socket.timeout, socket.error, OSError, ValueError) as exc:
        raise ErroWhois(f"Falha ao consultar {servidor}: {exc}") from None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def servidores_whois(alvo: str) -> List[str]:
    """Lista candidatos (TLD/RIR -> IANA) para a consulta na porta 43."""
    tipo = tipo_alvo(alvo)
    candidatos: List[str] = []
    if tipo == "dominio" and "." in alvo:
        tld = alvo.rsplit(".", 1)[-1].lower()
        servidor = SERVIDORES_TLD.get(tld)
        if servidor:
            candidatos.append(servidor)
    candidatos.append("whois.iana.org")
    return candidatos




def consultar_porta43(
    alvo: str,
    servidor: Optional[str] = None,
    timeout: float = 10.0,
    seguir_referencia: bool = True,
) -> Optional[Dict[str, Any]]:
    """Consulta WHOIS classico (porta 43) e devolve o registro normalizado.

    Quando ``servidor`` nao e informado, tenta o servidor do TLD (dominios) ou
    o IANA, seguindo a linha ``refer:`` para o registro definitivo.
    """
    candidatos = [servidor] if servidor else servidores_whois(alvo)
    for indice, srv in enumerate(candidatos):
        try:
            texto = _enviar_consulta(srv, alvo, timeout)
        except ErroWhois:
            if indice == len(candidatos) - 1 and len(candidatos) == 1:
                raise
            continue
        referencia = extrair_referencia(texto) if seguir_referencia else None
        if referencia and referencia.lower() != srv.lower():
            try:
                texto_referido = _enviar_consulta(referencia, alvo, timeout)
            except ErroWhois:
                texto_referido = ""
            if texto_referido.strip():
                texto, srv = texto_referido, referencia
        if texto.strip() and not resposta_vazia(texto):
            dados = parse_whois_texto(texto)
            dados["servidor"] = srv
            dados["encontrado"] = True
            return dados
    return None


class WhoisClient:
    """Consulta RDAP/WHOIS com fallback e cache.

    :param cache: :class:`CacheManager` compartilhado (namespace ``whois``).
    :param session: sessao ``requests`` (injetavel nos testes).
    :param timeout: timeout por requisicao/conexao.
    :param usar_rdap: tenta RDAP (JSON) primeiro.
    :param usar_porta43: permite cair para o WHOIS classico.
    """

    def __init__(
        self,
        cache: Optional[CacheManager] = None,
        session: Optional[SessaoHTTP] = None,
        timeout: float = 10.0,
        usar_rdap: bool = True,
        usar_porta43: bool = True,
    ) -> None:
        self.cache = cache
        self.session: SessaoHTTP = (
            session if session is not None else criar_sessao()
        )
        self.timeout = float(timeout)
        self.usar_rdap = bool(usar_rdap)
        self.usar_porta43 = bool(usar_porta43)
        self.headers = {
            "User-Agent": "IPLocator/2.0",
            "Accept": "application/rdap+json, application/json",
        }

    # -- RDAP -------------------------------------------------------------
    def _consultar_rdap(self, alvo: str, tipo: str) -> Optional[Dict[str, Any]]:
        segmento = SEGMENTO_RDAP.get(tipo, tipo)
        url = f"{RDAP_BASE}/{segmento}/{quote(str(alvo), safe='')}"
        try:
            resposta = self.session.get(url, timeout=self.timeout, headers=self.headers)
        except requests.exceptions.Timeout:
            raise ErroWhois("Timeout na consulta RDAP") from None
        except requests.exceptions.RequestException as exc:
            raise ErroWhois(f"Falha na consulta RDAP: {exc}") from None
        status = getattr(resposta, "status_code", 200)
        if status == 404:
            return None
        if status == 429:
            raise ErroWhois("Limite de consultas RDAP excedido (429)")
        if status >= 400:
            raise ErroWhois(f"RDAP respondeu HTTP {status}")
        try:
            dados = resposta.json()
        except ValueError:
            raise ErroWhois("Resposta RDAP invalida (JSON malformado)") from None
        if not isinstance(dados, dict) or not dados:
            return None
        return {"fonte": "rdap", "url": url, "dados": parse_rdap(dados)}

    # -- orquestracao -----------------------------------------------------
    def _finalizar(
        self,
        alvo: str,
        tipo: str,
        chave: str,
        origem: Dict[str, Any],
        erros: List[Dict[str, str]],
        usar_cache: bool,
    ) -> Dict[str, Any]:
        resultado = {
            "ok": True,
            "alvo": str(alvo),
            "tipo": tipo,
            "fonte": origem.get("fonte"),
            "url": origem.get("url"),
            "dados": origem.get("dados") or {},
            "erros": erros,
            "cache": False,
        }
        if usar_cache and self.cache is not None:
            self.cache.set("whois", chave, resultado)
        return resultado

    def consultar_detalhado(
        self,
        alvo: str,
        usar_cache: bool = True,
    ) -> Dict[str, Any]:
        """Consulta estruturada (usada pela CLI, API e interface web)."""
        tipo = tipo_alvo(alvo)
        if tipo == "invalido":
            return {
                "ok": False,
                "alvo": alvo,
                "tipo": tipo,
                "erro": "Erro: informe um IP ou domínio válido para consulta WHOIS.",
                "codigo": "alvo_invalido",
                "erros": [],
            }
        chave = f"{tipo}:{str(alvo).strip().lower()}"
        if usar_cache and self.cache is not None:
            guardado = self.cache.get("whois", chave)
            if isinstance(guardado, dict):
                em_cache = dict(guardado)
                em_cache["cache"] = True
                em_cache["ok"] = True
                return em_cache

        erros: List[Dict[str, str]] = []
        if self.usar_rdap:
            try:
                rdap = self._consultar_rdap(alvo, tipo)
            except ErroWhois as exc:
                erros.append({"fonte": "rdap", "erro": str(exc)})
            else:
                if rdap:
                    return self._finalizar(alvo, tipo, chave, rdap, erros, usar_cache)

        if self.usar_porta43:
            try:
                bruto = consultar_porta43(alvo, timeout=self.timeout)
            except ErroWhois as exc:
                erros.append({"fonte": "whois", "erro": str(exc)})
            else:
                if bruto:
                    return self._finalizar(
                        alvo,
                        tipo,
                        chave,
                        {"fonte": "whois", "dados": bruto},
                        erros,
                        usar_cache,
                    )

        detalhes = "; ".join(f"{e['fonte']}: {e['erro']}" for e in erros)
        return {
            "ok": False,
            "alvo": alvo,
            "tipo": tipo,
            "erro": (
                "Erro: nenhuma fonte WHOIS retornou dados"
                + (f" ({detalhes})" if detalhes else "")
            ),
            "codigo": "sem_dados",
            "erros": erros,
        }

    def consultar(self, alvo: str) -> Union[Dict[str, Any], str]:
        """Versao simples: dicionario de dados ou mensagem de erro."""
        detalhe = self.consultar_detalhado(alvo)
        if detalhe.get("ok"):
            return detalhe.get("dados") or {}
        return str(detalhe.get("erro"))

    def cache_stats(self) -> Dict[str, Any]:
        return self.cache.stats() if self.cache is not None else {"habilitado": False}

    def limpar_cache(self) -> int:
        return self.cache.clear("whois") if self.cache is not None else 0


def consultar_whois(
    alvo: str,
    cache: Optional[CacheManager] = None,
    timeout: float = 10.0,
) -> Union[Dict[str, Any], str]:
    """Atalho funcional: ``consultar_whois("8.8.8.8")``."""
    return WhoisClient(cache=cache, timeout=timeout).consultar(alvo)

