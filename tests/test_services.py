"""Testes de detecção de serviços: catálogo, banner, HTTP e descrição."""

from __future__ import annotations

import http.server
import threading

import pytest

from iplocator_core import services as modulo_servicos
from iplocator_core.services import (
    detectar_http,
    detectar_servico,
    descrever_servico,
    identificar_produto,
    ler_banner,
    nome_servico,
    parse_cabecalhos_http,
)


def test_nome_servico_conhecido_e_desconhecido() -> None:
    assert nome_servico(22) == "SSH"
    assert nome_servico(3306) == "MySQL"
    assert nome_servico(8443) == "HTTPS Alt"
    assert nome_servico(65001) == "Desconhecido"


@pytest.mark.parametrize(
    "banner,produto,versao",
    [
        ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "OpenSSH", "9.6p1"),
        ("220 (vsFTPd 3.0.5)", "vsFTPd", "3.0.5"),
        ("220 mail.example.com ESMTP Postfix", "Postfix", None),
        ("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n", "nginx", "1.24.0"),
        ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\n", "Apache", "2.4.58"),
        ("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n", "Microsoft-IIS", "10.0"),
        ("RFB 003.008\n", "RFB", None),
    ],
)
def test_identificar_produto(banner: str, produto, versao) -> None:
    assert identificar_produto(banner) == (produto, versao)


def test_identificar_produto_sem_banner() -> None:
    assert identificar_produto("") == (None, None)
    assert identificar_produto("texto qualquer") == (None, None)


def test_parse_cabecalhos_http() -> None:
    resposta = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.24.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\ncorpo"
    )
    cabecalhos = parse_cabecalhos_http(resposta)
    assert cabecalhos["server"] == "nginx/1.24.0"
    assert cabecalhos["content-type"] == "text/html; charset=utf-8"
    assert "corpo" not in cabecalhos
    assert parse_cabecalhos_http("") == {}


def test_descrever_servico() -> None:
    info = {
        "porta": 443,
        "servico": "HTTPS",
        "produto": "nginx",
        "versao": "1.24.0",
        "tls": True,
        "certificado": {"cn": "example.com"},
        "http": {"status": "HTTP/1.1 200 OK"},
    }
    texto = descrever_servico(info)
    assert "HTTPS" in texto
    assert "nginx 1.24.0" in texto
    assert "TLS" in texto
    assert "CN=example.com" in texto
    assert "200 OK" in texto


def test_descrever_servico_minimo() -> None:
    assert descrever_servico({"porta": 1, "servico": "Desconhecido"}) == "Desconhecido"


@pytest.fixture
def servidor_http():
    """Servidor HTTP local que responde a ``HEAD /`` com ``Server`` fixo."""

    class Manipulador(http.server.BaseHTTPRequestHandler):
        server_version = "TestServidor/1.2.3"
        sys_version = ""

        def do_HEAD(self) -> None:  # noqa: N802 - assinatura da stdlib
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

        def log_message(self, format: str, *args) -> None:  # noqa: A002 - nome da stdlib
            pass

    servidor = http.server.HTTPServer(("127.0.0.1", 0), Manipulador)
    thread = threading.Thread(target=servidor.serve_forever, daemon=True)
    thread.start()
    try:
        yield servidor.server_address[1]
    finally:
        servidor.shutdown()
        servidor.server_close()
        thread.join(timeout=2)


def test_detectar_http_em_servidor_local(servidor_http) -> None:
    info = detectar_http("127.0.0.1", servidor_http, timeout=2.0)
    assert info is not None
    assert info["status"].startswith("HTTP/")
    assert info["servidor"] == "TestServidor/1.2.3"
    assert info["produto"] == "TestServidor"
    assert info["versao"] == "1.2.3"


def test_detectar_http_em_porta_fechada(porta_fechada) -> None:
    assert detectar_http("127.0.0.1", porta_fechada, timeout=0.3) is None


def test_ler_banner(servidor_banner) -> None:
    banner = ler_banner("127.0.0.1", servidor_banner.porta, timeout=2.0)
    assert "OpenSSH" in banner


def test_ler_banner_porta_fechada(porta_fechada) -> None:
    assert ler_banner("127.0.0.1", porta_fechada, timeout=0.2) == ""


def test_detectar_servico_por_banner(servidor_banner) -> None:
    info = detectar_servico("127.0.0.1", servidor_banner.porta, timeout=2.0)
    assert info["porta"] == servidor_banner.porta
    assert info["servico"] == "Desconhecido"
    assert info["produto"] == "OpenSSH"
    assert info["versao"] == "9.6p1"
    assert info["tls"] is False
    assert info["certificado"] is None


def test_detectar_servico_http_em_porta_catalogada(servidor_http, monkeypatch) -> None:
    monkeypatch.setattr(
        modulo_servicos, "PORTAS_HTTP", frozenset({servidor_http})
    )
    info = detectar_servico("127.0.0.1", servidor_http, timeout=2.0)
    assert info["servico"] == "HTTP"
    assert info["http"]["servidor"] == "TestServidor/1.2.3"
    assert info["produto"] == "TestServidor"


def test_detectar_servico_em_porta_fechada(porta_fechada) -> None:
    info = detectar_servico("127.0.0.1", porta_fechada, timeout=0.2)
    assert info["tls"] is False
    assert info["banner"] is None
    assert info["produto"] is None
    assert info["http"] is None
