#!/usr/bin/env python3
"""Valida a tag de release e gera as notas a partir do CHANGELOG.

Uso::

    python tools/notas_release.py v2.0.0                 # imprime as notas
    python tools/notas_release.py v2.0.0 --saida notas.md

O script falha (código 1) quando a tag não corresponde a
``iplocator_core/version.py`` ou quando o CHANGELOG não tem a seção da versão,
evitando publicar uma release inconsistente no GitHub Actions.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Optional, Sequence

RAIZ = Path(__file__).resolve().parent.parent
CHANGELOG = RAIZ / "CHANGELOG.md"
ARQUIVO_VERSAO = RAIZ / "iplocator_core" / "version.py"

PADRAO_VERSAO = re.compile(r"""__version__\s*=\s*["']([^"']+)["']""")


def versao_do_codigo() -> str:
    """Lê ``__version__`` de ``iplocator_core/version.py``."""
    conteudo = ARQUIVO_VERSAO.read_text(encoding="utf-8")
    achado = PADRAO_VERSAO.search(conteudo)
    if achado is None:
        raise SystemExit(f"Não foi possível encontrar __version__ em {ARQUIVO_VERSAO}")
    return achado.group(1)


def extrair_secao(changelog: str, versao: str) -> str:
    """Recorta a seção ``## [versao]`` do CHANGELOG (até o próximo título ``## ``)."""
    cabecalho = re.compile(
        rf"^##\s*\[?{re.escape(versao)}\]?\s*(?:-.*)?$", re.MULTILINE
    )
    achado = cabecalho.search(changelog)
    if achado is None:
        return ""
    resto = changelog[achado.end():]
    proximo = re.search(r"^##\s", resto, re.MULTILINE)
    fim = achado.end() + (proximo.start() if proximo else len(resto))
    return changelog[achado.start():fim].strip()


def montar_notas(tag: str) -> str:
    """Devolve as notas da versão da ``tag``, validando a consistência."""
    versao = versao_do_codigo()
    esperada = f"v{versao}"
    if tag != esperada:
        raise SystemExit(
            f"Tag '{tag}' não corresponde à versão do projeto ({esperada}). "
            "Atualize iplocator_core/version.py e pyproject.toml antes de tagear."
        )
    secao = extrair_secao(CHANGELOG.read_text(encoding="utf-8"), versao)
    if not secao:
        raise SystemExit(f"Seção [{versao}] ausente em {CHANGELOG.name}")
    return secao


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Ponto de entrada: imprime ou grava as notas da release."""
    parser = argparse.ArgumentParser(
        description="Valida a tag de release e extrai as notas do CHANGELOG.",
    )
    parser.add_argument("tag", help="tag da release (ex.: v2.0.0)")
    parser.add_argument("--saida", help="arquivo de destino (padrão: stdout)")
    args = parser.parse_args(argv)

    notas = montar_notas(args.tag)
    if args.saida:
        Path(args.saida).write_text(notas + "\n", encoding="utf-8")
        print(f"[*] Notas da release {args.tag} gravadas em {args.saida}")
    else:
        print(notas)
    return 0


if __name__ == "__main__":
    sys.exit(main())
