"""Testes dos provedores de geolocalização, normalização e fallback."""

from __future__ import annotations

import pytest
import requests

from apoio import (
    PAYLOAD_FREEIPAPI,
    PAYLOAD_GEOJS,
    PAYLOAD_IP_API,
    PAYLOAD_IPAPI_CO,
    PAYLOAD_IPINFO,
    PAYLOAD_IPWHOIS,
    RespostaFalsa,
    SessaoFalsa,
)
from iplocator_core import geo as modulo_geo
from iplocator_core.geo import (
    GEO_PADRAO,
    PROVEDORES,
    ErroProvedor,
    IPApiProvedor,
    IPLocator,
    criar_provedores,
    normalizar_resultado,
    provedores_disponiveis,
)


def test_existem_seis_provedores_na_ordem_padrao() -> None:
    assert len(GEO_PADRAO) == 6
    assert provedores_disponiveis() == list(GEO_PADRAO)
    assert set(GEO_PADRAO) == set(PROVEDORES)


@pytest.mark.parametrize(
    "nome,payload,campo,esperado",
    [
        ("ip-api", PAYLOAD_IP_API, "city", "Mountain View"),
        ("ip-api", PAYLOAD_IP_API, "as", "AS15169 Google LLC"),
        ("ipwho.is", PAYLOAD_IPWHOIS, "timezone", "America/Los_Angeles"),
        ("ipwho.is", PAYLOAD_IPWHOIS, "as", "AS15169 Google LLC"),
        ("ipapi.co", PAYLOAD_IPAPI_CO, "regionName", "California"),
        ("ipapi.co", PAYLOAD_IPAPI_CO, "country", "United States"),
        ("ipinfo.io", PAYLOAD_IPINFO, "city", "Mountain View"),
        ("ipinfo.io", PAYLOAD_IPINFO, "countryCode", "US"),
        ("freeipapi", PAYLOAD_FREEIPAPI, "city", "Mountain View"),
        ("freeipapi", PAYLOAD_FREEIPAPI, "timezone", "America/Los_Angeles"),
        ("geojs", PAYLOAD_GEOJS, "as", "AS15169 Google LLC"),
        ("geojs", PAYLOAD_GEOJS, "country", "United States"),
    ],
)
def test_parsers_normalizam_campos(
    nome: str, payload: dict, campo: str, esperado
) -> None:
    provedor = PROVEDORES[nome]()
    dados = provedor.extrair(payload)
    assert dados[campo] == esperado


@pytest.mark.parametrize(
    "nome,payload",
    [
        ("ip-api", {"status": "fail", "message": "private range"}),
        ("ipwho.is", {"success": False, "message": "IP inválido"}),
        ("ipapi.co", {"error": True, "reason": "RateLimited"}),
        ("ipinfo.io", {"bogon": True}),
        ("freeipapi", {}),
        ("geojs", {}),
    ],
)
def test_parsers_reportam_erro_do_provedor(nome: str, payload: dict) -> None:
    provedor = PROVEDORES[nome]()
    with pytest.raises(ErroProvedor):
        provedor.extrair(payload)


def test_ipinfo_converte_loc_em_lat_lon() -> None:
    dados = PROVEDORES["ipinfo.io"]().extrair(PAYLOAD_IPINFO)
    assert dados["lat"] == pytest.approx(37.4056)
    assert dados["lon"] == pytest.approx(-122.0775)
    assert dados["country"] is None
    assert dados["countryCode"] == "US"


def test_ip_api_usa_https_quando_pedido() -> None:
    assert IPApiProvedor(use_https=False).url("8.8.8.8").startswith("http://ip-api.com/")
    assert IPApiProvedor(use_https=True).url("8.8.8.8").startswith("https://ip-api.com/")


def test_criar_provedores_ignora_nomes_desconhecidos() -> None:
    instancias = criar_provedores(["ipinfo.io", "nao-existe", "geojs"])
    assert [p.nome for p in instancias] == ["ipinfo.io", "geojs"]


def test_criar_provedores_sem_lista_usa_padrao() -> None:
    instancias = criar_provedores(None, use_https=True)
    assert [p.nome for p in instancias] == list(GEO_PADRAO)
    assert instancias[0].url("8.8.8.8").startswith("https://")


def test_normalizar_resultado_inclui_urls_e_compatibilidade() -> None:
    resultado = normalizar_resultado(
        "8.8.8.8",
        PROVEDORES["ip-api"]().extrair(PAYLOAD_IP_API),
        "ip-api",
    )
    assert resultado["query"] == "8.8.8.8"
    assert resultado["ip"] == "8.8.8.8"
    assert resultado["status"] == "success"
    assert resultado["provider"] == "ip-api"
    assert resultado["cache"] is False
    assert "37.4056" in resultado["maps_url"]
    assert "openstreetmap" in resultado["osm_url"]


def test_normalizar_resultado_sem_coordenadas() -> None:
    resultado = normalizar_resultado("8.8.8.8", {"city": "X"}, "teste")
    assert resultado["maps_url"] is None
    assert resultado["osm_url"] is None
    assert resultado["lat"] is None


def _locator(cache, provedores=None, respostas=None, **kwargs) -> IPLocator:
    """``IPLocator`` com sessão falsa pronta para os testes."""
    return IPLocator(
        providers=provedores or ["ipwho.is"],
        cache=cache,
        session=SessaoFalsa(
            respostas if respostas is not None else {"ipwho.is": PAYLOAD_IPWHOIS}
        ),
        timeout=1.0,
        **kwargs,
    )


def test_localizar_retorna_dicionario_compativel(cache) -> None:
    locator = _locator(cache)
    resultado = locator.localizar("8.8.8.8")
    assert isinstance(resultado, dict)
    assert resultado["city"] == "Mountain View"
    assert resultado["provider"] == "ipwho.is"
    assert resultado["cache"] is False
    for campo in (
        "query",
        "country",
        "regionName",
        "zip",
        "lat",
        "lon",
        "timezone",
        "org",
        "as",
    ):
        assert campo in resultado


def test_segunda_consulta_usa_cache(cache) -> None:
    sessao = SessaoFalsa({"ipwho.is": PAYLOAD_IPWHOIS})
    locator = IPLocator(providers=["ipwho.is"], cache=cache, session=sessao)
    primeiro = locator.localizar_detalhado("8.8.8.8")
    segundo = locator.localizar_detalhado("8.8.8.8")
    assert primeiro["cache"] is False
    assert segundo["cache"] is True
    assert len(sessao.chamadas) == 1


def test_cache_desligado_refaz_a_consulta(cache) -> None:
    sessao = SessaoFalsa({"ipwho.is": PAYLOAD_IPWHOIS})
    locator = IPLocator(providers=["ipwho.is"], cache=cache, session=sessao)
    locator.localizar_detalhado("8.8.8.8", usar_cache=False)
    locator.localizar_detalhado("8.8.8.8", usar_cache=False)
    assert len(sessao.chamadas) == 2


def test_fallback_quando_provedor_responde_erro(cache) -> None:
    sessao = SessaoFalsa(
        {"ipwho.is": {"success": False, "message": "boom"}, "ipinfo.io": PAYLOAD_IPINFO}
    )
    locator = IPLocator(providers=["ipwho.is", "ipinfo.io"], cache=cache, session=sessao)
    detalhe = locator.localizar_detalhado("8.8.8.8")
    assert detalhe["ok"] is True
    assert detalhe["provedor"] == "ipinfo.io"
    assert detalhe["erros"][0]["provider"] == "ipwho.is"


def test_fallback_quando_provedor_devolve_http_500(cache) -> None:
    sessao = SessaoFalsa(
        {"ipwho.is": RespostaFalsa({}, status=500), "ipinfo.io": PAYLOAD_IPINFO}
    )
    locator = IPLocator(providers=["ipwho.is", "ipinfo.io"], cache=cache, session=sessao)
    detalhe = locator.localizar_detalhado("8.8.8.8")
    assert detalhe["ok"] is True
    assert "HTTP 500" in detalhe["erros"][0]["erro"]


def test_todos_os_provedores_falham(cache) -> None:
    sessao = SessaoFalsa({}, excecao=requests.exceptions.ConnectionError())
    locator = IPLocator(providers=["ipwho.is", "ipinfo.io"], cache=cache, session=sessao)
    resultado = locator.localizar("8.8.8.8")
    assert isinstance(resultado, str)
    assert resultado.startswith("Erro")
    detalhe = locator.localizar_detalhado("8.8.8.8")
    assert detalhe["ok"] is False
    assert detalhe["codigo"] == "provedores"
    assert len(detalhe["erros"]) == 2


def test_timeout_e_erro_de_json(cache) -> None:
    timeout = IPLocator(
        providers=["ipwho.is"],
        cache=cache,
        session=SessaoFalsa(excecao=requests.exceptions.Timeout()),
    )
    assert "Timeout" in timeout.localizar("8.8.8.8")

    malformado = IPLocator(
        providers=["ipwho.is"],
        cache=cache,
        session=SessaoFalsa({"ipwho.is": RespostaFalsa(erro_json=True)}),
    )
    assert "JSON" in malformado.localizar("8.8.8.8")


def test_alvo_vazio_e_invalido(cache) -> None:
    locator = _locator(cache)
    assert "Erro" in locator.localizar("")
    detalhe = locator.localizar_detalhado("???")
    assert detalhe["codigo"] == "alvo_invalido"


def test_ip_reservado_nao_consulta_api(cache) -> None:
    sessao = SessaoFalsa({"ipwho.is": PAYLOAD_IPWHOIS})
    locator = IPLocator(providers=["ipwho.is"], cache=cache, session=sessao)
    resultado = locator.localizar("192.168.0.10")
    assert isinstance(resultado, str)
    assert "reservado" in resultado
    assert sessao.chamadas == []



def test_dominio_resolvido_e_cacheado_no_dns(cache, monkeypatch) -> None:
    chamadas = []

    def resolver(dominio: str) -> str:
        chamadas.append(dominio)
        return "8.8.8.8"

    monkeypatch.setattr(IPLocator, "resolver_dominio", staticmethod(resolver))
    locator = _locator(cache)
    primeiro = locator.localizar_detalhado("example.com")
    segundo = locator.localizar_detalhado("example.com")
    assert primeiro["ok"] is True
    assert primeiro["ip"] == "8.8.8.8"
    assert segundo["ok"] is True
    assert chamadas == ["example.com"]  # segunda vez vem do cache de DNS
    assert cache.get("dns", "example.com") == "8.8.8.8"


def test_dominio_nao_resolvido(cache, monkeypatch) -> None:
    monkeypatch.setattr(IPLocator, "resolver_dominio", staticmethod(lambda _d: None))
    locator = _locator(cache)
    resultado = locator.localizar("naoexiste.example")
    assert isinstance(resultado, str)
    assert "resolver o domínio" in resultado


def test_dominio_que_resolve_para_ip_reservado(cache, monkeypatch) -> None:
    monkeypatch.setattr(
        IPLocator, "resolver_dominio", staticmethod(lambda _d: "10.0.0.5")
    )
    locator = _locator(cache)
    resultado = locator.localizar("interno.example.com")
    assert isinstance(resultado, str)
    assert "reservado" in resultado


def test_lista_de_provedores_por_consulta(cache) -> None:
    sessao = SessaoFalsa({"ipinfo.io": PAYLOAD_IPINFO, "ipwho.is": PAYLOAD_IPWHOIS})
    locator = IPLocator(providers=["ipwho.is"], cache=cache, session=sessao)
    detalhe = locator.localizar_detalhado("8.8.8.8", provedores=["ipinfo.io"])
    assert detalhe["provedor"] == "ipinfo.io"
    assert "ipinfo.io" in sessao.chamadas[0]


def test_definir_provedores_e_limpar_cache(cache) -> None:
    locator = _locator(cache)
    assert locator.provedores_ativos() == ["ipwho.is"]
    locator.localizar_detalhado("1.1.1.1")
    assert locator.cache_stats()["entradas"] >= 1
    assert locator.definir_provedores(["geojs", "ipinfo.io"]) == ["geojs", "ipinfo.io"]
    assert locator.limpar_cache("geo") == 1


def test_rate_limit_respeita_intervalo(cache, monkeypatch) -> None:
    esperas = []
    monkeypatch.setattr(
        modulo_geo.time, "sleep", lambda segundos: esperas.append(segundos)
    )
    locator = IPLocator(
        providers=["ip-api"],
        cache=cache,
        session=SessaoFalsa({"ip-api.com": PAYLOAD_IP_API}),
    )
    locator._esperar_rate_limit(locator.providers[0])
    locator._esperar_rate_limit(locator.providers[0])
    assert esperas and esperas[0] > 0

