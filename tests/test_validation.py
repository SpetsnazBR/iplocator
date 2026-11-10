"""Testes de validação/resolução de alvos."""

from __future__ import annotations

import socket

import pytest

from iplocator_core.validation import (
    identificar_alvo,
    is_ip_reservado,
    normalizar_alvo,
    resolver_dominio,
    validar_dominio,
    validar_ip,
)


@pytest.mark.parametrize(
    "entrada",
    [
        "8.8.8.8",
        "192.168.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "2001:4860:4860::8888",
        "::1",
        "fe80::1",
    ],
)
def test_validar_ip_aceita_enderecos_validos(entrada: str) -> None:
    assert validar_ip(entrada) is True


@pytest.mark.parametrize(
    "entrada",
    ["", "   ", "256.1.1.1", "1.2.3", "8.8.8.8.8", "abc", "1.2.3.-1", "8.8.8", None, 42],
)
def test_validar_ip_recusa_enderecos_invalidos(entrada) -> None:
    assert validar_ip(entrada) is False


@pytest.mark.parametrize(
    "entrada",
    ["example.com", "sub.exemplo.com.br", "a-b.example.io", "xn--bcher-kva.de"],
)
def test_validar_dominio_aceita_dominios(entrada: str) -> None:
    assert validar_dominio(entrada) is True


@pytest.mark.parametrize(
    "entrada",
    ["", "localhost", "exemplo", "-ruim.com", "ruim-.com", "com espaço.com", "a." + "b" * 64],
)
def test_validar_dominio_recusa_invalidos(entrada: str) -> None:
    assert validar_dominio(entrada) is False


@pytest.mark.parametrize(
    "ip",
    [
        "10.1.2.3",
        "172.16.5.4",
        "172.31.255.254",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.10.20",
        "100.64.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "fc00::1",
    ],
)
def test_is_ip_reservado_aceita_faixas_privadas(ip: str) -> None:
    assert is_ip_reservado(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2a00:1450:4001::1"])
def test_is_ip_reservado_recusa_ips_publicos(ip: str) -> None:
    assert is_ip_reservado(ip) is False


def test_is_ip_reservado_ignora_valores_invalidos() -> None:
    assert is_ip_reservado("") is False
    assert is_ip_reservado("não-é-ip") is False


@pytest.mark.parametrize(
    "entrada,esperado",
    [
        (" 8.8.8.8 ", "8.8.8.8"),
        ("https://example.com/caminho", "example.com"),
        ("http://example.com:8080/x", "example.com"),
        ("[::1]", "::1"),
        ("example.com:443", "example.com"),
        ("example.com.", "example.com"),
        ("", ""),
    ],
)
def test_normalizar_alvo(entrada: str, esperado: str) -> None:
    assert normalizar_alvo(entrada) == esperado


def test_identificar_alvo_classifica_ip_dominio_e_invalido() -> None:
    assert identificar_alvo("8.8.8.8")["tipo"] == "ip"
    assert identificar_alvo("8.8.8.8")["ip"] == "8.8.8.8"

    dominio = identificar_alvo("https://example.com/path")
    assert dominio["tipo"] == "dominio"
    assert dominio["entrada"] == "example.com"
    assert dominio["ip"] is None

    invalido = identificar_alvo("???")
    assert invalido["tipo"] == "invalido"
    assert invalido["erro"]

    vazio = identificar_alvo("   ")
    assert vazio["tipo"] == "invalido"


def test_identificar_alvo_limita_tamanho() -> None:
    alvo = "a" * 300 + ".com"
    assert identificar_alvo(alvo)["tipo"] == "invalido"


def test_resolver_dominio_usa_socket(monkeypatch) -> None:
    monkeypatch.setattr(socket, "gethostbyname", lambda dominio: "93.184.216.34")
    assert resolver_dominio("example.com") == "93.184.216.34"


@pytest.mark.parametrize(
    "excecao", [socket.gaierror("falhou"), socket.herror("falhou"), OSError("falhou")]
)
def test_resolver_dominio_trata_erros(monkeypatch, excecao) -> None:
    def explodir(_dominio):
        raise excecao

    monkeypatch.setattr(socket, "gethostbyname", explodir)
    assert resolver_dominio("example.com") is None


def test_resolver_dominio_vazio() -> None:
    assert resolver_dominio("") is None
