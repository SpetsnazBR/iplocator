"""Testes do utilitário de notas de release."""

from __future__ import annotations

import pytest

from iplocator_core.version import __version__
from tools import notas_release


def test_versao_do_codigo_corresponde_ao_pacote() -> None:
    assert notas_release.versao_do_codigo() == __version__


def test_extrair_secao_recorta_apenas_a_versao() -> None:
    changelog = (
        "# Changelog\n\n"
        "## [Não lançado]\n\n"
        "## [2.0.0] - 2026-11-10\n\n"
        "### Adicionado\n\n"
        "- item novo\n\n"
        "## [1.0.0] - 2020-01-01\n\n"
        "- antigo\n"
    )
    secao = notas_release.extrair_secao(changelog, "2.0.0")
    assert secao.startswith("## [2.0.0]")
    assert "item novo" in secao
    assert "antigo" not in secao


def test_extrair_secao_inexistente() -> None:
    assert notas_release.extrair_secao("# Changelog\n", "9.9.9") == ""


def test_montar_notas_da_versao_atual() -> None:
    notas = notas_release.montar_notas(f"v{__version__}")
    assert "### Adicionado" in notas
    assert "iplocator_core" in notas


def test_montar_notas_recusa_tag_divergente() -> None:
    with pytest.raises(SystemExit):
        notas_release.montar_notas("v0.0.1")


def test_main_grava_arquivo(tmp_path, capsys) -> None:
    destino = tmp_path / "notas.md"
    codigo = notas_release.main([f"v{__version__}", "--saida", str(destino)])
    assert codigo == 0
    assert destino.is_file()
    assert "Adicionado" in destino.read_text(encoding="utf-8")
    assert "gravadas" in capsys.readouterr().out


def test_main_imprime_na_saida_padrao(capsys) -> None:
    assert notas_release.main([f"v{__version__}"]) == 0
    assert "Adicionado" in capsys.readouterr().out
