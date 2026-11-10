"""Testes da CLI: parser, formatação e despacho de comandos."""

from __future__ import annotations

import json

import pytest

import iplocator
from iplocator import (
    construir_parser,
    exibir_banner,
    executar_geo,
    executar_scan,
    executar_whois,
    formatar_geo,
    formatar_whois,
    main,
)
from iplocator_core.cache import CacheManager
from iplocator_core.geo import IPLocator
from iplocator_core.scanner import PortScanner


class LocatorFalso:
    """Dublê de ``IPLocator`` que devolve um detalhe pré-definido."""

    def __init__(self, detalhe: dict) -> None:
        self.detalhe = detalhe
        self.chamadas: list = []

    def localizar_detalhado(self, alvo, provedores=None):
        self.chamadas.append(alvo)
        return self.detalhe

    def provedores_ativos(self):
        return ["ip-api"]


class WhoisFalso:
    def __init__(self, detalhe: dict) -> None:
        self.detalhe = detalhe

    def consultar_detalhado(self, alvo: str) -> dict:
        return self.detalhe


def test_reexports_de_compatibilidade() -> None:
    assert iplocator.IPLocator is IPLocator
    assert iplocator.PortScanner is PortScanner
    assert iplocator.__version__


def test_parser_valores_padrao() -> None:
    args = construir_parser().parse_args([])
    assert args.host == "127.0.0.1"
    assert args.port == 8000
    assert args.mode == "comuns"
    assert args.start == 1
    assert args.end == 1024
    assert args.serve is False
    assert args.geo is None


def test_parser_aceita_flags() -> None:
    args = construir_parser().parse_args(
        ["--serve", "--port", "9000", "--no-cache", "--json", "--host", "0.0.0.0"]
    )
    assert args.serve is True
    assert args.port == 9000
    assert args.no_cache is True
    assert args.json is True
    assert args.host == "0.0.0.0"


def test_parser_version(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        construir_parser().parse_args(["--version"])
    assert excinfo.value.code == 0
    assert "IP-Locator" in capsys.readouterr().out


def test_banner_imprime_algo(capsys) -> None:
    exibir_banner()
    assert capsys.readouterr().out.strip()


def test_formatar_geo() -> None:
    linhas = formatar_geo(
        {
            "provider": "ip-api",
            "country": "United States",
            "city": "Mountain View",
            "lat": None,
            "cache": True,
            "maps_url": "https://maps.example/1",
        }
    )
    texto = "\n".join(linhas)
    assert "Provedor" in texto and "ip-api" in texto
    assert "Cidade" in texto
    assert "Latitude" not in texto
    assert "reaproveitado" in texto
    assert "https://maps.example/1" in texto


def test_formatar_whois() -> None:
    detalhe = {
        "fonte": "rdap",
        "cache": True,
        "dados": {
            "nome": "GOGL",
            "pais": "US",
            "intervalo": {"inicio": "8.8.8.0", "fim": "8.8.8.255"},
            "eventos": {"registration": "2023-12-28"},
            "descricao": ["Google Public DNS"],
        },
    }
    texto = "\n".join(formatar_whois(detalhe))
    assert "rdap" in texto
    assert "GOGL" in texto
    assert "8.8.8.0 - 8.8.8.255" in texto
    assert "2023-12-28" in texto
    assert "Google Public DNS" in texto


def test_executar_geo_sucesso(capsys) -> None:
    locator = LocatorFalso(
        {"ok": True, "dados": {"provider": "ip-api", "city": "M"}, "erros": []}
    )
    assert executar_geo(locator, "8.8.8.8") == 0
    assert "Cidade" in capsys.readouterr().out


def test_executar_geo_erro(capsys) -> None:
    locator = LocatorFalso(
        {
            "ok": False,
            "erro": "Erro: nenhum provedor retornou dados",
            "erros": [{"provider": "ipwho.is", "erro": "boom"}],
        }
    )
    assert executar_geo(locator, "8.8.8.8") == 1
    capturado = capsys.readouterr()
    assert "Erro: nenhum provedor" in capturado.err
    assert "ipwho.is" in capturado.err


def test_executar_geo_json(capsys) -> None:
    locator = LocatorFalso({"ok": True, "dados": {"city": "M"}, "erros": []})
    assert executar_geo(locator, "8.8.8.8", saida_json=True) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_executar_whois_sucesso_e_erro(capsys) -> None:
    cliente = WhoisFalso({"ok": True, "fonte": "rdap", "dados": {"nome": "GOGL"}})
    assert executar_whois(cliente, "8.8.8.8") == 0
    assert "GOGL" in capsys.readouterr().out

    falha = WhoisFalso({"ok": False, "erro": "Erro: sem dados"})
    assert executar_whois(falha, "8.8.8.8") == 1
    assert "Erro: sem dados" in capsys.readouterr().err


def test_executar_scan_alvo_invalido(capsys) -> None:
    cache = CacheManager(enabled=False)
    assert executar_scan(cache, "???") == 2
    assert "inválido" in capsys.readouterr().err


def test_executar_scan_intervalo_invalido(capsys) -> None:
    cache = CacheManager(enabled=False)
    assert executar_scan(cache, "127.0.0.1", modo="intervalo", inicio=0, fim=10) == 2
    assert "inválido" in capsys.readouterr().err


def test_executar_scan_json(servidor_banner, capsys) -> None:
    cache = CacheManager(enabled=False)
    porta = servidor_banner.porta
    codigo = executar_scan(
        cache,
        "127.0.0.1",
        modo="intervalo",
        inicio=porta,
        fim=porta,
        timeout=1.0,
        saida_json=True,
    )
    assert codigo == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["portas"] == [porta]
    assert payload["resultados"][0]["produto"] == "OpenSSH"


def test_executar_scan_texto_sem_portas_abertas(porta_fechada, capsys) -> None:
    cache = CacheManager(enabled=False)
    codigo = executar_scan(
        cache, "127.0.0.1", modo="intervalo", inicio=porta_fechada, fim=porta_fechada
    )
    assert codigo == 0
    assert "Nenhuma porta aberta" in capsys.readouterr().out


def test_main_menu_sai(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt="": "0")
    assert main([]) == 0


def test_main_limpa_cache(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("IPLOCATOR_CACHE_DIR", str(tmp_path / "cache"))
    assert main(["--clear-cache"]) == 0
    assert "Cache limpo" in capsys.readouterr().out


def test_main_despacha_geo(monkeypatch) -> None:
    monkeypatch.setattr(iplocator, "executar_geo", lambda *a, **k: 7)
    assert main(["--geo", "8.8.8.8"]) == 7


def test_main_despacha_whois(monkeypatch) -> None:
    monkeypatch.setattr(iplocator, "executar_whois", lambda *a, **k: 3)
    assert main(["--whois", "example.com"]) == 3


def test_main_despacha_scan(monkeypatch) -> None:
    monkeypatch.setattr(iplocator, "executar_scan", lambda *a, **k: 5)
    assert main(["--scan", "127.0.0.1", "--mode", "intervalo", "--start", "20"]) == 5


def test_main_serve_chama_servidor(monkeypatch) -> None:
    chamadas = {}
    monkeypatch.setattr(
        iplocator,
        "servir",
        lambda **kwargs: chamadas.update(kwargs),
    )
    assert main(["--serve", "--port", "9123", "--verbose"]) == 0
    assert chamadas["porta"] == 9123
    assert chamadas["verbose"] is True


def test_menu_servidor_delega_para_servir(monkeypatch) -> None:
    """Regressão: `menu_servidor` precisa resolver o diretório web sem NameError."""
    chamadas = {}
    monkeypatch.setattr(iplocator, "servir", lambda **kwargs: chamadas.update(kwargs))
    iplocator.menu_servidor(host="127.0.0.1", porta=9123)
    assert chamadas == {"host": "127.0.0.1", "porta": 9123}


def test_menu_servidor_sem_interface(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(iplocator, "DIRETORIO_WEB_PADRAO", tmp_path / "web-ausente")
    iplocator.menu_servidor(host="127.0.0.1", porta=9123)
    assert "não encontrada" in capsys.readouterr().err

