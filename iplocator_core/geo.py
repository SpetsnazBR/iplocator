"""Geolocalização de IPs com múltiplos provedores, fallback e cache.

A saída é sempre normalizada para as mesmas chaves (as que o CLI já usava:
``query``, ``country``, ``regionName``, ``city``, ``zip``, ``lat``, ``lon``,
``timezone``, ``isp``, ``org``, ``as``), acrescentando ``provider``,
``maps_url`` e ``osm_url``.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

from .cache import CacheManager
from .http import criar_sessao
from .protocols import SessaoHTTP
from .validation import (
    identificar_alvo,
    is_ip_reservado,
    resolver_dominio,
    validar_ip,
)

#: Ordem de tentativa dos provedores (o primeiro que responder vence).
GEO_PADRAO: Tuple[str, ...] = (
    "ip-api",
    "ipwho.is",
    "ipapi.co",
    "ipinfo.io",
    "freeipapi",
    "geojs",
)

#: Campos normalizados presentes em qualquer resultado de sucesso.
CAMPOS_NORMALIZADOS = (
    "country",
    "countryCode",
    "region",
    "regionName",
    "city",
    "zip",
    "lat",
    "lon",
    "timezone",
    "isp",
    "org",
    "as",
)


class ErroProvedor(Exception):
    """Falha reportada pelo próprio provedor (payload de erro ou inválido)."""


def _texto(valor: Any) -> Optional[str]:
    """Normaliza valores textuais: ``None``/vazio viram ``None``."""
    if valor is None:
        return None
    texto = str(valor).strip()
    return texto or None


def _numero(valor: Any) -> Optional[float]:
    """Converte coordenadas textuais em ``float``, ignorando lixo."""
    if valor is None or isinstance(valor, bool):
        return None
    try:
        return float(valor)
    except (TypeError, ValueError):
        return None


def _primeiro(dados: Dict[str, Any], *chaves: str) -> Any:
    """Devolve o primeiro valor não vazio entre as chaves informadas."""
    for chave in chaves:
        valor = dados.get(chave)
        if valor not in (None, "", [], {}):
            return valor
    return None


class ProvedorGeo:
    """Contrato mínimo: URL de consulta + extração do payload normalizado."""

    nome: str = ""
    intervalo_minimo: float = 0.0
    usa_https: bool = True

    def url(self, ip: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def extrair(self, dados: Dict[str, Any]) -> Dict[str, Any]:  # pragma: no cover
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - conveniência de debug
        return f"<ProvedorGeo {self.nome}>"


class IPApiProvedor(ProvedorGeo):
    """ip-api.com — 45 req/min no plano gratuito (HTTP apenas)."""

    nome = "ip-api"
    intervalo_minimo = 1.2
    CAMPOS = (
        "status,message,country,countryCode,region,regionName,city,zip,"
        "lat,lon,timezone,isp,org,as,query"
    )

    def __init__(self, use_https: bool = False) -> None:
        self.usa_https = use_https

    def url(self, ip: str) -> str:
        base = (
            "https://ip-api.com/json/"
            if self.usa_https
            else "http://ip-api.com/json/"
        )
        return f"{base}{ip}?fields={self.CAMPOS}"

    def extrair(self, dados: Dict[str, Any]) -> Dict[str, Any]:
        if dados.get("status") != "success":
            raise ErroProvedor(
                _texto(dados.get("message")) or "IP inválido ou não encontrado"
            )
        return {
            "country": _texto(dados.get("country")),
            "countryCode": _texto(dados.get("countryCode")),
            "region": _texto(dados.get("region")),
            "regionName": _texto(dados.get("regionName")),
            "city": _texto(dados.get("city")),
            "zip": _texto(dados.get("zip")),
            "lat": _numero(dados.get("lat")),
            "lon": _numero(dados.get("lon")),
            "timezone": _texto(dados.get("timezone")),
            "isp": _texto(dados.get("isp")),
            "org": _texto(dados.get("org")),
            "as": _texto(dados.get("as")),
        }


class IpwhoisProvedor(ProvedorGeo):
    """ipwho.is — gratuito, HTTPS, sem necessidade de chave."""

    nome = "ipwho.is"

    def url(self, ip: str) -> str:
        return f"https://ipwho.is/{ip}"

    def extrair(self, dados: Dict[str, Any]) -> Dict[str, Any]:
        if not dados.get("success", False):
            raise ErroProvedor(_texto(dados.get("message")) or "Consulta recusada")
        conexao = dados.get("connection") or {}
        fuso = dados.get("timezone") or {}
        asn = _primeiro(conexao, "asn")
        organizacao = _texto(_primeiro(conexao, "org", "isp"))
        return {
            "country": _texto(dados.get("country")),
            "countryCode": _texto(dados.get("country_code")),
            "region": _texto(_primeiro(dados, "region", "region_code")),
            "regionName": _texto(_primeiro(dados, "region", "region_code")),
            "city": _texto(dados.get("city")),
            "zip": _texto(dados.get("postal")),
            "lat": _numero(dados.get("latitude")),
            "lon": _numero(dados.get("longitude")),
            "timezone": _texto(fuso.get("id") if isinstance(fuso, dict) else fuso),
            "isp": _texto(conexao.get("isp")),
            "org": organizacao,
            "as": f"AS{asn} {organizacao or ''}".strip() if asn else None,
        }


class IpapiCoProvedor(ProvedorGeo):
    """ipapi.co — gratuito com limite por minuto; JSON por IP."""

    nome = "ipapi.co"
    intervalo_minimo = 0.4

    def url(self, ip: str) -> str:
        return f"https://ipapi.co/{ip}/json/"

    def extrair(self, dados: Dict[str, Any]) -> Dict[str, Any]:
        if dados.get("error") or not _primeiro(dados, "ip", "country_code"):
            raise ErroProvedor(
                _texto(_primeiro(dados, "reason", "message")) or "Consulta recusada"
            )
        return {
            "country": _texto(dados.get("country_name")),
            "countryCode": _texto(dados.get("country_code")),
            "region": _texto(dados.get("region_code")),
            "regionName": _texto(dados.get("region")),
            "city": _texto(dados.get("city")),
            "zip": _texto(dados.get("postal")),
            "lat": _numero(dados.get("latitude")),
            "lon": _numero(dados.get("longitude")),
            "timezone": _texto(dados.get("timezone")),
            "isp": _texto(dados.get("org")),
            "org": _texto(dados.get("org")),
            "as": _texto(dados.get("asn")),
        }


class IpinfoProvedor(ProvedorGeo):
    """ipinfo.io — sem token devolve cidade/região/organização."""

    nome = "ipinfo.io"

    def url(self, ip: str) -> str:
        return f"https://ipinfo.io/{ip}/json"

    def extrair(self, dados: Dict[str, Any]) -> Dict[str, Any]:
        if dados.get("bogon") or dados.get("error") or not _primeiro(dados, "ip"):
            raise ErroProvedor(
                _texto(_primeiro(dados, "message", "error")) or "Consulta recusada"
            )
        latitude = longitude = None
        local = _texto(dados.get("loc"))
        if local and "," in local:
            partes = local.split(",", 1)
            latitude, longitude = _numero(partes[0]), _numero(partes[1])
        organizacao = _texto(dados.get("org"))
        return {
            "country": None,
            "countryCode": _texto(dados.get("country")),
            "region": _texto(dados.get("region")),
            "regionName": _texto(dados.get("region")),
            "city": _texto(dados.get("city")),
            "zip": _texto(dados.get("postal")),
            "lat": latitude,
            "lon": longitude,
            "timezone": _texto(dados.get("timezone")),
            "isp": organizacao,
            "org": organizacao,
            "as": organizacao,
        }



class FreeIpApiProvedor(ProvedorGeo):
    """freeipapi.com — gratuito, sem chave, sem dados de ASN."""

    nome = "freeipapi"

    def url(self, ip: str) -> str:
        return f"https://freeipapi.com/api/json/{ip}"

    def extrair(self, dados: Dict[str, Any]) -> Dict[str, Any]:
        if not _primeiro(dados, "ipAddress", "countryName"):
            raise ErroProvedor("Resposta sem dados de localização")
        return {
            "country": _texto(dados.get("countryName")),
            "countryCode": _texto(dados.get("countryCode")),
            "region": _texto(dados.get("regionName")),
            "regionName": _texto(dados.get("regionName")),
            "city": _texto(dados.get("cityName")),
            "zip": _texto(dados.get("zipCode")),
            "lat": _numero(dados.get("latitude")),
            "lon": _numero(dados.get("longitude")),
            "timezone": _texto(_primeiro(dados, "timeZone", "timezone")),
            "isp": None,
            "org": None,
            "as": None,
        }


class GeoJsProvedor(ProvedorGeo):
    """get.geojs.io — gratuito; devolve ASN e organização."""

    nome = "geojs"

    def url(self, ip: str) -> str:
        return f"https://get.geojs.io/v1/ip/geo/{ip}.json"

    def extrair(self, dados: Dict[str, Any]) -> Dict[str, Any]:
        if not _primeiro(dados, "ip", "country_name", "country_code2"):
            raise ErroProvedor("Resposta sem dados de localização")
        organizacao = _texto(_primeiro(dados, "organization_name", "organization"))
        asn = _primeiro(dados, "asn")
        nome_organizacao = _texto(dados.get("organization_name"))
        return {
            "country": _texto(dados.get("country_name")),
            "countryCode": _texto(_primeiro(dados, "country_code2", "country_code")),
            "region": _texto(dados.get("region")),
            "regionName": _texto(_primeiro(dados, "region", "region_name")),
            "city": _texto(dados.get("city")),
            "zip": _texto(dados.get("postal_code")),
            "lat": _numero(dados.get("latitude")),
            "lon": _numero(dados.get("longitude")),
            "timezone": _texto(dados.get("timezone")),
            "isp": nome_organizacao,
            "org": organizacao,
            "as": (
                f"AS{asn} {nome_organizacao or ''}".strip() if asn else None
            ),
        }


#: Registro de provedores disponíveis por nome público.
PROVEDORES: Dict[str, type] = {
    cls.nome: cls
    for cls in (
        IPApiProvedor,
        IpwhoisProvedor,
        IpapiCoProvedor,
        IpinfoProvedor,
        FreeIpApiProvedor,
        GeoJsProvedor,
    )
}


def provedores_disponiveis() -> List[str]:
    """Lista os nomes dos provedores na ordem padrão de tentativa."""
    return list(GEO_PADRAO)


def criar_provedores(
    nomes: Optional[Sequence[str]] = None,
    use_https: bool = False,
) -> List[ProvedorGeo]:
    """Instancia os provedores pedidos, ignorando nomes desconhecidos."""
    escolhidos = list(nomes) if nomes else list(GEO_PADRAO)
    instancias: List[ProvedorGeo] = []
    for nome in escolhidos:
        chave = (nome or "").strip().lower()
        classe = PROVEDORES.get(chave)
        if classe is None:
            continue
        instancias.append(
            classe(use_https=use_https) if classe is IPApiProvedor else classe()
        )
    return instancias


def normalizar_resultado(
    ip: str,
    dados: Dict[str, Any],
    provedor: str,
    cache_hit: bool = False,
) -> Dict[str, Any]:
    """Monta o dicionário final, mantendo as chaves históricas do projeto."""
    resultado: Dict[str, Any] = {
        "query": ip,
        "ip": ip,
        "status": "success",
        "provider": provedor,
        "cache": bool(cache_hit),
    }
    for campo in CAMPOS_NORMALIZADOS:
        resultado[campo] = dados.get(campo)
    latitude, longitude = resultado.get("lat"), resultado.get("lon")
    if latitude is not None and longitude is not None:
        resultado["maps_url"] = (
            f"https://www.google.com/maps?q={latitude},{longitude}"
        )
        resultado["osm_url"] = (
            "https://www.openstreetmap.org/?mlat="
            f"{latitude}&mlon={longitude}#map=12/{latitude}/{longitude}"
        )
    else:
        resultado["maps_url"] = None
        resultado["osm_url"] = None
    return resultado




class IPLocator:
    """Localiza IPs/domínios usando vários provedores com fallback e cache.

    :param use_https: usa HTTPS no ip-api (o plano gratuito é HTTP).
    :param providers: nomes dos provedores a usar (padrão: :data:`GEO_PADRAO`).
    :param cache: :class:`~iplocator_core.cache.CacheManager` compartilhado.
    :param session: sessão ``requests`` (os testes injetam uma falsa).
    :param timeout: timeout por requisição, em segundos.
    """

    def __init__(
        self,
        use_https: bool = False,
        providers: Optional[Sequence[str]] = None,
        cache: Optional[CacheManager] = None,
        session: Optional[SessaoHTTP] = None,
        timeout: float = 10.0,
        min_request_interval: float = 0.0,
    ) -> None:
        self.use_https = use_https
        self.timeout = float(timeout)
        self.session: SessaoHTTP = session if session is not None else criar_sessao()
        self.cache = cache if cache is not None else CacheManager()
        self.min_request_interval = max(0.0, float(min_request_interval))
        self.providers = criar_provedores(providers, use_https)
        if not self.providers:  # nomes inválidos: volta ao conjunto padrão
            self.providers = criar_provedores(None, use_https)
        self.last_request_time = 0.0
        self._ultima_requisicao: Dict[str, float] = {}
        self.headers = {"User-Agent": "IPLocator/2.0", "Accept": "application/json"}

    # -- compatibilidade com a API pública antiga -------------------------
    validar_ip = staticmethod(validar_ip)
    is_ip_reservado = staticmethod(is_ip_reservado)
    resolver_dominio = staticmethod(resolver_dominio)

    # -- infraestrutura ---------------------------------------------------
    def _esperar_rate_limit(self, provedor: Optional[ProvedorGeo] = None) -> None:
        """Respeita o intervalo mínimo do provedor (evita 429)."""
        intervalo = max(
            self.min_request_interval,
            provedor.intervalo_minimo if provedor is not None else 0.0,
        )
        if intervalo <= 0:
            self.last_request_time = time.time()
            return
        chave = provedor.nome if provedor is not None else "global"
        anterior = self._ultima_requisicao.get(chave, self.last_request_time)
        decorrido = time.time() - anterior
        if decorrido < intervalo:
            time.sleep(intervalo - decorrido)
        agora = time.time()
        self._ultima_requisicao[chave] = agora
        self.last_request_time = agora

    def _requisitar(self, url: str) -> Dict[str, Any]:
        """GET + JSON com mensagens amigáveis (levantando ``ErroProvedor``)."""
        try:
            resposta = self.session.get(url, timeout=self.timeout, headers=self.headers)
        except requests.exceptions.Timeout:
            raise ErroProvedor("Timeout na conexão com a API") from None
        except requests.exceptions.ConnectionError:
            raise ErroProvedor("Não foi possível conectar à API") from None
        except requests.exceptions.RequestException as exc:
            raise ErroProvedor(f"Erro na requisição: {exc}") from None
        status = getattr(resposta, "status_code", 200)
        if status == 429:
            raise ErroProvedor("Limite de requisições excedido (429)")
        if status >= 400:
            raise ErroProvedor(f"HTTP {status} do provedor")
        try:
            dados = resposta.json()
        except ValueError:
            raise ErroProvedor("Resposta inválida (JSON malformado)") from None
        if not isinstance(dados, dict):
            raise ErroProvedor("Resposta em formato inesperado")
        return dados

    def _resolver(self, alvo: str) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
        """Valida o alvo e resolve domínios (com cache de DNS).

        Devolve ``(ip, erro)``; quando ``erro`` não é ``None`` a consulta para.
        """
        info = identificar_alvo(alvo)
        tipo = info["tipo"]
        if tipo == "invalido":
            return None, {
                "codigo": "alvo_invalido",
                "erro": "Erro: Por favor, digite um IP ou domínio válido.",
            }
        ip = info["ip"]
        if tipo == "dominio":
            dominio = str(info["entrada"])
            cache_key = dominio.lower()
            ip = self.cache.get("dns", cache_key)
            if not ip:
                ip = self.resolver_dominio(dominio)
                if ip:
                    self.cache.set("dns", cache_key, ip)
            if not ip:
                return None, {
                    "codigo": "dns",
                    "erro": f"Erro: Não foi possível resolver o domínio '{dominio}'",
                }
        if ip is None:  # defensivo: nunca deve acontecer após a validação
            return None, {
                "codigo": "alvo_invalido",
                "erro": "Erro: Alvo inválido.",
            }
        if self.is_ip_reservado(ip):
            if tipo == "dominio":
                return None, {
                    "codigo": "ip_reservado",
                    "erro": f"Erro: Domínio resolve para IP reservado ({ip})",
                }
            return None, {
                "codigo": "ip_reservado",
                "erro": (
                    f"Erro: IP reservado ({ip}) não pode ser localizado. "
                    "Use um IP público."
                ),
            }
        return ip, None

    # -- consultas --------------------------------------------------------
    def localizar_detalhado(
        self,
        alvo: str,
        provedores: Optional[Sequence[str]] = None,
        usar_cache: bool = True,
    ) -> Dict[str, Any]:
        """Consulta estruturada, usada pela UI e pela API HTTP.

        Retorna sempre um dicionário com ``ok`` e, quando ``ok`` é ``False``,
        ``erro`` (string começando com "Erro") e ``codigo``.
        """
        ip, erro = self._resolver(alvo or "")
        if erro is not None:
            return {
                "ok": False,
                "alvo": alvo,
                "ip": None,
                "erro": erro["erro"],
                "codigo": erro["codigo"],
                "erros": [],
            }

        chave_cache = f"{ip}"
        if usar_cache:
            em_cache = self.cache.get("geo", chave_cache)
            if isinstance(em_cache, dict):
                resultado = dict(em_cache)
                resultado["cache"] = True
                return {
                    "ok": True,
                    "alvo": alvo,
                    "ip": ip,
                    "dados": resultado,
                    "provedor": resultado.get("provider"),
                    "cache": True,
                    "erros": [],
                }

        lista = (
            criar_provedores(provedores, self.use_https)
            if provedores
            else list(self.providers)
        )
        erros: List[Dict[str, str]] = []
        for provedor in lista:
            try:
                self._esperar_rate_limit(provedor)
                dados = self._requisitar(provedor.url(str(ip)))
                extraido = provedor.extrair(dados)
            except ErroProvedor as exc:
                erros.append({"provider": provedor.nome, "erro": str(exc)})
                continue
            except Exception as exc:  # noqa: BLE001 - um provedor não derruba os outros
                erros.append(
                    {"provider": provedor.nome, "erro": f"falha inesperada: {exc}"}
                )
                continue
            resultado = normalizar_resultado(str(ip), extraido, provedor.nome)
            if usar_cache:
                self.cache.set("geo", chave_cache, resultado)
            return {
                "ok": True,
                "alvo": alvo,
                "ip": ip,
                "dados": resultado,
                "provedor": provedor.nome,
                "cache": False,
                "erros": erros,
            }

        detalhes = "; ".join(f"{e['provider']}: {e['erro']}" for e in erros)
        return {
            "ok": False,
            "alvo": alvo,
            "ip": ip,
            "erro": (
                "Erro: nenhum provedor retornou dados"
                + (f" ({detalhes})" if detalhes else "")
            ),
            "codigo": "provedores",
            "erros": erros,
        }

    def localizar(
        self,
        alvo: str,
        provedores: Optional[Sequence[str]] = None,
    ) -> Any:
        """Versão compatível: ``dict`` de sucesso ou ``str`` com o erro."""
        detalhe = self.localizar_detalhado(alvo, provedores=provedores)
        if detalhe["ok"]:
            return detalhe["dados"]
        return detalhe["erro"]

    # -- utilitários ------------------------------------------------------
    def definir_provedores(self, nomes: Sequence[str]) -> List[str]:
        """Troca a ordem dos provedores ativos e devolve os nomes aceitos."""
        instancias = criar_provedores(nomes, self.use_https)
        if instancias:
            self.providers = instancias
        return [p.nome for p in self.providers]

    def provedores_ativos(self) -> List[str]:
        """Nomes dos provedores na ordem em que serão tentados."""
        return [p.nome for p in self.providers]

    def cache_stats(self) -> Dict[str, Any]:
        """Estatísticas do cache compartilhado."""
        return self.cache.stats()

    def limpar_cache(self, namespace: Optional[str] = None) -> int:
        """Limpa o cache (de um namespace ou de todos)."""
        return self.cache.clear(namespace)

