"""Configuração da suíte: garante o repositório no ``sys.path`` e fixtures comuns."""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path
from typing import Iterator

import pytest

RAIZ = Path(__file__).resolve().parent.parent
if str(RAIZ) not in sys.path:
    sys.path.insert(0, str(RAIZ))

from apoio import SessaoFalsa  # noqa: E402


@pytest.fixture(autouse=True)
def sem_cache_no_home(monkeypatch, tmp_path):
    """Impede que os testes escrevam no cache real do usuário."""
    monkeypatch.setenv("IPLOCATOR_CACHE_DIR", str(tmp_path / "cache-home"))
    monkeypatch.delenv("IPLOCATOR_CACHE_DISABLED", raising=False)
    monkeypatch.delenv("IPLOCATOR_CACHE_TTL", raising=False)


@pytest.fixture
def cache(tmp_path):
    """``CacheManager`` isolado em diretório temporário."""
    from iplocator_core.cache import CacheManager

    return CacheManager(directory=tmp_path / "cache", enabled=True)


@pytest.fixture
def sessao() -> SessaoFalsa:
    """Sessão HTTP falsa, sem nenhuma resposta pré-configurada."""
    return SessaoFalsa()


@pytest.fixture
def locator(cache):
    """``IPLocator`` com provedores sem rate limit (testes rápidos)."""
    from iplocator_core.geo import IPLocator

    return IPLocator(
        providers=["ipwho.is", "ipinfo.io"],
        cache=cache,
        session=SessaoFalsa(),
        timeout=1.0,
    )


class ServidorBanner:
    """Servidor TCP mínimo que envia um banner ao conectar (usa porta efêmera)."""

    def __init__(self, banner: bytes) -> None:
        self.banner = banner
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(5)
        self._socket.settimeout(0.5)
        self.porta = self._socket.getsockname()[1]
        self._parar = threading.Event()
        self._thread = threading.Thread(target=self._servir, daemon=True)

    def _servir(self) -> None:
        while not self._parar.is_set():
            try:
                conexao, _ = self._socket.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conexao.sendall(self.banner)
            except OSError:
                pass
            finally:
                try:
                    conexao.close()
                except OSError:
                    pass

    def __enter__(self) -> "ServidorBanner":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._parar.set()
        self._thread.join(timeout=2)
        try:
            self._socket.close()
        except OSError:
            pass


@pytest.fixture
def servidor_banner() -> Iterator[ServidorBanner]:
    """Banner SSH falso escutando em ``127.0.0.1``."""
    with ServidorBanner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n") as servidor:
        yield servidor


@pytest.fixture
def porta_fechada() -> int:
    """Porta livre que não está escutando (fechada) no momento do teste."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    porta = sock.getsockname()[1]
    sock.close()
    return porta
