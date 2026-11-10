"""Testes de WHOIS/RDAP: parsers puros e fallback de fontes."""

from __future__ import annotations

import pytest
import requests

from apoio import (
    PAYLOAD_RDAP_DOMINIO,
    PAYLOAD_RDAP_IP,
    WHOIS_TEXTO,
    WHOIS_TEXTO_VAZIO,
    RespostaFalsa,
    SessaoFalsa,
)
from iplocator_core import whois as modulo_whois
from iplocator_core.whois import (
    WhoisClient,
    consultar_porta43,
    consultar_whois,
    extrair_referencia,
    parse_rdap,
    parse_whois_texto,
    resposta_vazia,
    servidores_whois,
    tipo_alvo,
)


def test_tipo_alvo() -> None:
    assert tipo_alvo("8.8.8.8") == "ip"
    assert tipo_alvo("github.com") == "dominio"
    assert tipo_alvo("???") == "invalido"


def test_parse_whois_texto_normaliza_campos() -> None:
    dados = parse_whois_texto(WHOIS_TEXTO)
    assert dados["netname"] == "GOGL"
    assert dados["organizacao"] == "Google LLC"
    assert dados["pais"] == "US"
    assert dados["intervalo"] == "8.8.8.0 - 8.8.8.255"
    assert dados["criado"] == "2023-12-28T09:00:00Z"
    assert dados["atualizado"] == "2024-01-02T10:00:00Z"
    assert dados["abuse_contato"] == "network-abuse@google.com"
    assert dados["descricao"] == ["Google Public DNS"]
    assert dados["encontrado"] is True
    assert "inetnum" in dados["bruto"]


def test_parse_whois_texto_resposta_vazia() -> None:
    dados = parse_whois_texto(WHOIS_TEXTO_VAZIO)
    assert dados["encontrado"] is False


def test_parse_whois_texto_ignora_comentarios() -> None:
    dados = parse_whois_texto("% comentário: valor\n# outro: valor\n")
    assert dados["encontrado"] is False
    assert "comentário" not in dados


def test_extrair_referencia() -> None:
    assert extrair_referencia(WHOIS_TEXTO_VAZIO) == "whois.arin.net"
    assert extrair_referencia("inetnum: 1.2.3.0 - 1.2.3.255") is None
    assert extrair_referencia("") is None


@pytest.mark.parametrize(
    "texto",
    [
        'No match for "1.2.3.4"',
        "%ERROR:101: no entries found",
        "Query rate limit exceeded",
        "",
    ],
)
def test_resposta_vazia(texto: str) -> None:
    assert resposta_vazia(texto) is True


def test_resposta_com_dados_nao_e_vazia() -> None:
    assert resposta_vazia(WHOIS_TEXTO) is False


def test_servidores_whois_prioriza_tld() -> None:
    assert servidores_whois("github.com")[0] == "whois.verisign-grs.com"
    assert servidores_whois("8.8.8.8") == ["whois.iana.org"]


def test_parse_rdap_ip() -> None:
    dados = parse_rdap(PAYLOAD_RDAP_IP)
    assert dados["handles"] == "NET-8-8-8-0-1"
    assert dados["nome"] == "GOGL"
    assert dados["pais"] == "US"
    assert dados["organizacao"] == "Google LLC"
    assert dados["intervalo"]["inicio"] == "8.8.8.0"
    assert dados["intervalo"]["fim"] == "8.8.8.255"
    assert dados["eventos"]["registration"].startswith("2023-12-28")
    assert dados["abuse_contato"] == "network-abuse@google.com"
    assert dados["observacoes"] == ["Google Public DNS"]
    assert dados["links"] == ["https://rdap.arin.net/registry/ip/8.8.8.8"]
    assert len(dados["entidades"]) == 2
    assert dados["bruto"] == PAYLOAD_RDAP_IP


def test_parse_rdap_dominio() -> None:
    dados = parse_rdap(PAYLOAD_RDAP_DOMINIO)
    assert dados["nome"] == "GITHUB.COM"
    assert dados["organizacao"] == "GitHub, Inc."
    assert dados["status"] == ["client transfer prohibited"]


def test_parse_rdap_payload_minimo() -> None:
    dados = parse_rdap({})
    assert dados["handles"] is None
    assert dados["entidades"] == []
    assert dados["eventos"] == {}


def _cliente(cache, respostas=None, sessao=None, **kwargs) -> WhoisClient:
    return WhoisClient(
        cache=cache,
        session=sessao or SessaoFalsa(respostas or {"rdap.org/ip/": PAYLOAD_RDAP_IP}),
        timeout=1.0,
        **kwargs,
    )


def test_rdap_ip_com_sucesso(cache) -> None:
    cliente = _cliente(cache)
    detalhe = cliente.consultar_detalhado("8.8.8.8")
    assert detalhe["ok"] is True
    assert detalhe["fonte"] == "rdap"
    assert detalhe["tipo"] == "ip"
    assert detalhe["dados"]["organizacao"] == "Google LLC"
    assert detalhe["cache"] is False


def test_rdap_dominio_com_sucesso(cache) -> None:
    cliente = _cliente(cache, {"rdap.org/domain/": PAYLOAD_RDAP_DOMINIO})
    detalhe = cliente.consultar_detalhado("github.com")
    assert detalhe["ok"] is True
    assert detalhe["tipo"] == "dominio"
    assert detalhe["dados"]["nome"] == "GITHUB.COM"


def test_consulta_simples_retorna_dados(cache) -> None:
    cliente = _cliente(cache)
    dados = cliente.consultar("8.8.8.8")
    assert isinstance(dados, dict)
    assert dados["pais"] == "US"


def test_resultado_fica_em_cache(cache) -> None:
    sessao = SessaoFalsa({"rdap.org/ip/": PAYLOAD_RDAP_IP})
    cliente = _cliente(cache, sessao=sessao)
    cliente.consultar_detalhado("8.8.8.8")
    detalhe = cliente.consultar_detalhado("8.8.8.8")
    assert detalhe["cache"] is True
    assert len(sessao.chamadas) == 1


def test_rdap_404_cai_para_porta_43(cache, monkeypatch) -> None:
    monkeypatch.setattr(
        modulo_whois, "consultar_porta43", lambda *a, **k: parse_whois_texto(WHOIS_TEXTO)
    )
    cliente = _cliente(cache, sessao=SessaoFalsa({"rdap.org": RespostaFalsa({}, status=404)}))
    detalhe = cliente.consultar_detalhado("8.8.8.8")
    assert detalhe["ok"] is True
    assert detalhe["fonte"] == "whois"
    assert detalhe["dados"]["netname"] == "GOGL"


def test_erro_rdap_cai_para_porta_43(cache, monkeypatch) -> None:
    monkeypatch.setattr(
        modulo_whois, "consultar_porta43", lambda *a, **k: parse_whois_texto(WHOIS_TEXTO)
    )
    cliente = _cliente(
        cache,
        sessao=SessaoFalsa({"rdap.org": RespostaFalsa({"erro": "x"}, status=503)}),
    )
    detalhe = cliente.consultar_detalhado("8.8.8.8")
    assert detalhe["ok"] is True
    assert detalhe["fonte"] == "whois"
    assert detalhe["erros"][0]["fonte"] == "rdap"


def test_todas_as_fontes_falham(cache, monkeypatch) -> None:
    monkeypatch.setattr(modulo_whois, "consultar_porta43", lambda *a, **k: None)
    cliente = _cliente(
        cache,
        sessao=SessaoFalsa(excecao=requests.exceptions.ConnectionError()),
    )
    detalhe = cliente.consultar_detalhado("8.8.8.8")
    assert detalhe["ok"] is False
    assert detalhe["codigo"] == "sem_dados"
    assert detalhe["erro"].startswith("Erro")
    assert "rdap" in {e["fonte"] for e in detalhe["erros"]}
    assert isinstance(cliente.consultar("8.8.8.8"), str)


def test_alvo_invalido(cache) -> None:
    cliente = _cliente(cache)
    detalhe = cliente.consultar_detalhado("???")
    assert detalhe["ok"] is False
    assert detalhe["codigo"] == "alvo_invalido"


def test_json_malformado_no_rdap(cache, monkeypatch) -> None:
    monkeypatch.setattr(modulo_whois, "consultar_porta43", lambda *a, **k: None)
    cliente = _cliente(
        cache, sessao=SessaoFalsa({"rdap.org": RespostaFalsa(erro_json=True)})
    )
    detalhe = cliente.consultar_detalhado("8.8.8.8")
    assert detalhe["ok"] is False
    assert "JSON" in detalhe["erros"][0]["erro"]


def test_limpar_cache_e_stats(cache) -> None:
    cliente = _cliente(cache)
    cliente.consultar_detalhado("8.8.8.8")
    assert cliente.cache_stats()["entradas"] >= 1
    assert cliente.limpar_cache() == 1


def test_sem_cache_nao_guarda(cache) -> None:
    cliente = _cliente(cache)
    detalhe = cliente.consultar_detalhado("8.8.8.8", usar_cache=False)
    assert detalhe["ok"] is True
    assert cache.get("whois", "ip:8.8.8.8") is None


def test_consultar_porta43_le_resposta(monkeypatch) -> None:
    respostas = {"whois.iana.org": WHOIS_TEXTO_VAZIO, "whois.arin.net": WHOIS_TEXTO}
    consultados = []

    def envio(servidor, consulta, timeout=10.0, porta=43):
        consultados.append((servidor, consulta))
        return respostas[servidor]

    monkeypatch.setattr(modulo_whois, "_enviar_consulta", envio)
    dados = consultar_porta43("8.8.8.8")
    assert dados["netname"] == "GOGL"
    assert dados["servidor"] == "whois.arin.net"
    assert consultados[0][0] == "whois.iana.org"
    assert consultados[1][0] == "whois.arin.net"


def test_consultar_porta43_sem_resposta(monkeypatch) -> None:
    monkeypatch.setattr(
        modulo_whois,
        "_enviar_consulta",
        lambda *a, **k: 'No match for "1.2.3.4"',
    )
    assert consultar_porta43("8.8.8.8") is None


def test_consultar_whois_atalho(cache, monkeypatch) -> None:
    monkeypatch.setattr(
        modulo_whois,
        "criar_sessao",
        lambda *a, **k: SessaoFalsa({"rdap.org": RespostaFalsa({}, status=404)}),
    )
    monkeypatch.setattr(
        modulo_whois, "consultar_porta43", lambda *a, **k: parse_whois_texto(WHOIS_TEXTO)
    )
    dados = consultar_whois("8.8.8.8", cache=cache)
    assert isinstance(dados, dict)
    assert dados["netname"] == "GOGL"

