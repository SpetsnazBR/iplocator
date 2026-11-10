"""Testes do scanner de portas (intervalo, portas comuns e cache)."""

from __future__ import annotations

import pytest

from iplocator_core.scanner import (
    PortScanner,
    normalizar_intervalo,
    verificar_portas,
)


def test_normalizar_intervalo_ordena() -> None:
    assert normalizar_intervalo(80, 20) == (20, 80)
    assert normalizar_intervalo(1, 1024) == (1, 1024)
    assert normalizar_intervalo(443, 443) == (443, 443)


@pytest.mark.parametrize("inicio,fim", [(0, 10), (10, 70000), (-1, 5)])
def test_normalizar_intervalo_fora_dos_limites(inicio: int, fim: int) -> None:
    with pytest.raises(ValueError):
        normalizar_intervalo(inicio, fim)


@pytest.mark.parametrize("inicio,fim", [("1", 10), (1, None), (True, 10)])
def test_normalizar_intervalo_tipo_invalido(inicio, fim) -> None:
    with pytest.raises(TypeError):
        normalizar_intervalo(inicio, fim)


def test_testar_porta_aberta(servidor_banner) -> None:
    scanner = PortScanner(timeout=1.0, verbose=False)
    assert scanner.testar_porta("127.0.0.1", servidor_banner.porta) is True


def test_testar_porta_fechada(porta_fechada) -> None:
    scanner = PortScanner(timeout=0.3, verbose=False)
    assert scanner.testar_porta("127.0.0.1", porta_fechada) is False


@pytest.mark.parametrize("porta", [0, -1, 70000, "abc", None])
def test_testar_porta_invalida(porta) -> None:
    scanner = PortScanner(timeout=0.2, verbose=False)
    assert scanner.testar_porta("127.0.0.1", porta) is False


def test_scan_portas_comuns_com_transporte_mocado(monkeypatch) -> None:
    scanner = PortScanner(timeout=0.1, verbose=False, detectar_servicos=False)
    monkeypatch.setattr(
        scanner, "testar_porta", lambda host, porta: porta in {22, 80}
    )
    portas = scanner.scan_portas_comuns("127.0.0.1", usar_cache=False)
    assert portas == [22, 80]
    resumo = scanner.resumo()
    assert resumo["total_abertas"] == 2
    assert resumo["total_verificadas"] == len(PortScanner.PORTAS_COMUNS)
    assert [item["porta"] for item in scanner.resultados_ordenados()] == [22, 80]
    assert [item["servico"] for item in scanner.resultados_ordenados()] == [
        "SSH",
        "HTTP",
    ]


def test_scan_intervalo_com_transporte_mocado(monkeypatch) -> None:
    scanner = PortScanner(timeout=0.1, verbose=False, detectar_servicos=False)
    monkeypatch.setattr(scanner, "testar_porta", lambda host, porta: porta % 2 == 0)
    assert scanner.scan_intervalo("127.0.0.1", 1, 10, usar_cache=False) == [
        2,
        4,
        6,
        8,
        10,
    ]
    assert scanner.duracao >= 0
    assert scanner.resumo()["portas"] == [2, 4, 6, 8, 10]


def test_scan_intervalo_ordem_invertida(monkeypatch) -> None:
    scanner = PortScanner(timeout=0.1, verbose=False, detectar_servicos=False)
    monkeypatch.setattr(scanner, "testar_porta", lambda host, porta: porta == 5)
    assert scanner.scan_intervalo("127.0.0.1", 6, 4, usar_cache=False) == [5]


def test_scan_reaproveita_cache(cache, monkeypatch) -> None:
    chamadas = []

    def transporte(_host, porta):
        chamadas.append(porta)
        return porta == 80

    scanner = PortScanner(
        timeout=0.1,
        verbose=False,
        detectar_servicos=False,
        cache=cache,
    )
    monkeypatch.setattr(scanner, "testar_porta", transporte)
    primeiro = scanner.scan_intervalo("10.0.0.1", 79, 81)
    total_chamadas = len(chamadas)
    segundo = scanner.scan_intervalo("10.0.0.1", 79, 81)
    assert primeiro == segundo == [80]
    assert len(chamadas) == total_chamadas  # não houve nova varredura
    assert scanner.cache_hit is True
    assert scanner.resumo()["cache"] is True


def test_scan_sem_cache_repete_a_varredura(cache, monkeypatch) -> None:
    chamadas = []

    def transporte(_host, porta):
        chamadas.append(porta)
        return False

    scanner = PortScanner(
        timeout=0.1, verbose=False, detectar_servicos=False, cache=cache
    )
    monkeypatch.setattr(scanner, "testar_porta", transporte)
    scanner.scan_intervalo("10.0.0.2", 79, 80, usar_cache=False)
    total = len(chamadas)
    scanner.scan_intervalo("10.0.0.2", 79, 80, usar_cache=False)
    assert len(chamadas) == total * 2
    assert scanner.cache_hit is False


def test_scan_detecta_servico_real(servidor_banner) -> None:
    scanner = PortScanner(
        timeout=1.0,
        timeout_servico=2.0,
        verbose=False,
        detectar_servicos=True,
    )
    porta = servidor_banner.porta
    assert scanner.scan_intervalo("127.0.0.1", porta, porta, usar_cache=False) == [
        porta
    ]
    info = scanner.resultados_ordenados()[0]
    assert info["produto"] == "OpenSSH"
    assert info["versao"] == "9.6p1"


def test_scan_porta_individual(servidor_banner) -> None:
    scanner = PortScanner(timeout=1.0, verbose=False, detectar_servicos=False)
    scanner.scan_porta("127.0.0.1", servidor_banner.porta)
    assert scanner.portas_abertas == [servidor_banner.porta]


def test_verificar_portas_utilitario(servidor_banner) -> None:
    resultados = verificar_portas(
        "127.0.0.1", [servidor_banner.porta], timeout=2.0
    )
    assert [item["porta"] for item in resultados] == [servidor_banner.porta]


def test_verificar_portas_sem_portas_abertas(porta_fechada) -> None:
    assert verificar_portas("127.0.0.1", [porta_fechada], timeout=0.2) == []
