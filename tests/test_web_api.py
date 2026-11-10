"""Testes da API HTTP local (endpoints JSON, estáticos e CORS)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from apoio import PAYLOAD_IPWHOIS, PAYLOAD_RDAP_IP, SessaoFalsa
from iplocator_core.api import (
    DIRETORIO_WEB_PADRAO,
    ContextoAPI,
    _booleano,
    _numero,
    criar_servidor,
    resolver_estatico,
)
from iplocator_core.geo import IPLocator
from iplocator_core.whois import WhoisClient


@pytest.fixture
def servidor_api(cache):
    """Sobe a API em ``127.0.0.1`` (porta efêmera) com dublês de rede."""
    locator = IPLocator(
        providers=["ipwho.is"],
        cache=cache,
        session=SessaoFalsa({"ipwho.is": PAYLOAD_IPWHOIS}),
    )
    whois = WhoisClient(
        cache=cache, session=SessaoFalsa({"rdap.org/ip/": PAYLOAD_RDAP_IP})
    )
    contexto = ContextoAPI(
        cache=cache,
        locator=locator,
        whois=whois,
        web_dir=DIRETORIO_WEB_PADRAO,
        max_portas=10,
    )
    servidor = criar_servidor("127.0.0.1", 0, contexto=contexto)
    thread = threading.Thread(target=servidor.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{servidor.server_address[1]}"
    finally:
        servidor.shutdown()
        servidor.server_close()
        thread.join(timeout=2)


def _requisitar(url: str, metodo: str = "GET"):
    requisicao = urllib.request.Request(url, method=metodo)
    try:
        with urllib.request.urlopen(requisicao, timeout=10) as resposta:
            return resposta.status, dict(resposta.headers), resposta.read()
    except urllib.error.HTTPError as erro:
        return erro.code, dict(erro.headers), erro.read()


def _json(url: str, metodo: str = "GET"):
    status, cabecalhos, corpo = _requisitar(url, metodo)
    return status, json.loads(corpo.decode("utf-8")), cabecalhos


def test_health(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/health")
    assert status == 200
    assert dados["ok"] is True
    assert dados["versao"]
    assert dados["provedores"] == ["ipwho.is"]
    assert dados["cache"]["habilitado"] is True


def test_providers_e_ports(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/providers")
    assert status == 200
    assert "ip-api" in dados["provedores"]
    assert dados["ativos"] == ["ipwho.is"]

    status, dados, _ = _json(f"{servidor_api}/api/ports")
    assert status == 200
    assert dados["total"] == len(dados["portas"])
    assert any(item["porta"] == 443 for item in dados["portas"])


def test_geo_sucesso_e_cache(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/geo?target=8.8.8.8")
    assert status == 200
    assert dados["ok"] is True
    assert dados["dados"]["provider"] == "ipwho.is"
    assert dados["dados"]["city"] == "Mountain View"
    assert dados["cache"] is False

    status, dados, _ = _json(f"{servidor_api}/api/geo?target=8.8.8.8")
    assert status == 200
    assert dados["cache"] is True


def test_geo_sem_parametro(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/geo")
    assert status == 400
    assert dados["codigo"] == "parametro"


def test_geo_alvo_invalido(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/geo?target=%3F%3F%3F")
    assert status == 422
    assert dados["codigo"] == "alvo_invalido"


def test_geo_com_provedor_inexistente(servidor_api) -> None:
    status, dados, _ = _json(
        f"{servidor_api}/api/geo?target=8.8.8.8&providers=nao-existe"
    )
    assert status == 502
    assert dados["ok"] is False


def test_whois_sucesso(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/whois?target=8.8.8.8")
    assert status == 200
    assert dados["fonte"] == "rdap"
    assert dados["dados"]["pais"] == "US"


def test_whois_alvo_invalido(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/whois?target=%3F")
    assert status == 422
    assert dados["codigo"] == "alvo_invalido"


def test_cache_get_e_delete(servidor_api) -> None:
    _json(f"{servidor_api}/api/geo?target=8.8.8.8")
    status, dados, _ = _json(f"{servidor_api}/api/cache")
    assert status == 200
    assert dados["cache"]["entradas"] >= 1

    status, dados, _ = _json(f"{servidor_api}/api/cache", metodo="DELETE")
    assert status == 200
    assert dados["ok"] is True
    assert dados["removidas"] >= 1
    assert dados["cache"]["entradas"] == 0


def test_delete_em_rota_inexistente(servidor_api) -> None:
    status, _dados, _ = _json(f"{servidor_api}/api/geo", metodo="DELETE")
    assert status == 404


def test_scan_intervalo_detecta_porta_local(servidor_api, servidor_banner) -> None:
    porta = servidor_banner.porta
    status, dados, _ = _json(
        f"{servidor_api}/api/scan?target=127.0.0.1&mode=intervalo"
        f"&start={porta}&end={porta}&services=1"
    )
    assert status == 200
    assert dados["ok"] is True
    assert dados["modo"] == "intervalo"
    assert dados["portas"] == [porta]
    assert dados["resultados"][0]["produto"] == "OpenSSH"


def test_scan_modo_comuns(servidor_api, monkeypatch) -> None:
    from iplocator_core.scanner import PortScanner

    monkeypatch.setattr(
        PortScanner, "testar_porta", lambda self, host, porta: porta == 22
    )
    status, dados, _ = _json(
        f"{servidor_api}/api/scan?target=127.0.0.1&mode=comuns&services=0"
    )
    assert status == 200
    assert dados["portas"] == [22]
    assert dados["resultados"][0]["servico"] == "SSH"


def test_scan_alvo_invalido(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/scan?target=%3F")
    assert status == 422
    assert dados["codigo"] == "alvo_invalido"


def test_scan_modo_invalido(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/scan?target=127.0.0.1&mode=turbo")
    assert status == 400
    assert dados["codigo"] == "modo"


def test_scan_respeita_limite_de_portas(servidor_api) -> None:
    status, dados, _ = _json(
        f"{servidor_api}/api/scan?target=127.0.0.1&mode=intervalo&start=1&end=100"
    )
    assert status == 400
    assert dados["codigo"] == "limite"


def test_estatico_serve_index(servidor_api) -> None:
    status, cabecalhos, corpo = _requisitar(f"{servidor_api}/")
    assert status == 200
    assert cabecalhos["Content-Type"].startswith("text/html")
    assert b"IP-Locator" in corpo


def test_estatico_serve_assets(servidor_api) -> None:
    status, cabecalhos, corpo = _requisitar(f"{servidor_api}/app.js")
    assert status == 200
    assert "javascript" in cabecalhos["Content-Type"]
    assert b"createApp" in corpo

    status, cabecalhos, _ = _requisitar(f"{servidor_api}/styles.css")
    assert status == 200
    assert cabecalhos["Content-Type"].startswith("text/css")


def test_estatico_bloqueia_traversal(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/%2e%2e/iplocator.py")
    assert status == 404
    status, _cabecalhos, _corpo = _requisitar(f"{servidor_api}/nao-existe.html")
    assert status == 404


def test_rota_api_desconhecida(servidor_api) -> None:
    status, dados, _ = _json(f"{servidor_api}/api/inexistente")
    assert status == 404
    assert dados["codigo"] == "rota"


def test_options_responde_cors(servidor_api) -> None:
    status, cabecalhos, _ = _requisitar(
        f"{servidor_api}/api/health", metodo="OPTIONS"
    )
    assert status == 204
    assert cabecalhos["Access-Control-Allow-Origin"] == "*"
    assert "GET" in cabecalhos["Access-Control-Allow-Methods"]


def test_resolver_estatico_protege_traversal(tmp_path) -> None:
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("<html></html>", encoding="utf-8")
    (tmp_path / "segredo.txt").write_text("x", encoding="utf-8")

    assert resolver_estatico(web, "/") == (web / "index.html").resolve()
    assert resolver_estatico(web, "/index.html") == (web / "index.html").resolve()
    assert resolver_estatico(web, "/../segredo.txt") is None
    assert resolver_estatico(web, "/inexistente.html") is None
    assert resolver_estatico(web, "/index.html\x00") is None
    assert resolver_estatico(tmp_path / "nao-existe", "/") is None


def test_helpers_de_query() -> None:
    assert _booleano(None) is True
    assert _booleano("0") is False
    assert _booleano("true") is True
    assert _booleano("off") is False

    assert _numero(None, 1.0, 0.1, 10.0) == 1.0
    assert _numero("2.5", 1.0, 0.1, 10.0) == 2.5
    assert _numero("99", 1.0, 0.1, 10.0) == 10.0
    assert _numero("abc", 1.0, 0.1, 10.0) == 1.0

