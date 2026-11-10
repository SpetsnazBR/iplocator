"""Scanner de portas multithread com deteccao de servicos e cache opcional."""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .cache import CacheManager
from .services import (
    PORTAS_CONHECIDAS,
    detectar_servico,
    descrever_servico,
    nome_servico,
)

#: Limites validos de porta TCP.
PORTA_MINIMA = 1
PORTA_MAXIMA = 65535


def normalizar_intervalo(inicio: int, fim: int) -> Tuple[int, int]:
    """Valida, ordena e limita o intervalo ao range de portas TCP.

    Levanta :class:`TypeError` para valores nao inteiros e :class:`ValueError`
    quando algum extremo estiver fora de ``1..65535``.
    """
    for valor in (inicio, fim):
        if isinstance(valor, bool) or not isinstance(valor, int):
            raise TypeError("As portas devem ser numeros inteiros")
    if not (PORTA_MINIMA <= inicio <= PORTA_MAXIMA):
        raise ValueError(f"Porta inicial fora do intervalo 1-{PORTA_MAXIMA}")
    if not (PORTA_MINIMA <= fim <= PORTA_MAXIMA):
        raise ValueError(f"Porta final fora do intervalo 1-{PORTA_MAXIMA}")
    if inicio > fim:
        inicio, fim = fim, inicio
    return inicio, fim


class PortScanner:
    """Escaneia portas TCP e, opcionalmente, identifica o servico de cada uma.

    :param timeout: timeout de conexao por porta (segundos).
    :param max_threads: workers simultaneos.
    :param detectar_servicos: liga o banner grabbing/TLS por padrao.
    :param timeout_servico: timeout dos probes de servico.
    :param verbose: imprime o progresso (a API HTTP desliga).
    :param cache: :class:`CacheManager` para reaproveitar resultados recentes.
    """

    #: Mantido como atributo de classe para compatibilidade com a v1.
    PORTAS_COMUNS: Dict[int, str] = PORTAS_CONHECIDAS

    def __init__(
        self,
        timeout: float = 1.0,
        max_threads: int = 50,
        detectar_servicos: bool = True,
        timeout_servico: float = 1.5,
        verbose: bool = True,
        cache: Optional[CacheManager] = None,
    ) -> None:
        self.timeout = max(0.05, float(timeout))
        self.max_threads = max(1, int(max_threads))
        self.detectar_servicos = bool(detectar_servicos)
        self.timeout_servico = max(0.1, float(timeout_servico))
        self.verbose = bool(verbose)
        self.cache = cache
        self.portas_abertas: List[int] = []
        self.resultados: List[Dict[str, Any]] = []
        self.duracao = 0.0
        self.total_verificadas = 0
        self.cache_hit = False
        self.lock = threading.Lock()

    # ------------------------------------------------------------------
    # Baixo nivel
    # ------------------------------------------------------------------
    def testar_porta(self, host: str, porta: int) -> bool:
        """Tenta um connect TCP; ``True`` quando a porta aceita conexao."""
        try:
            numero = int(porta)
        except (TypeError, ValueError):
            return False
        if not (PORTA_MINIMA <= numero <= PORTA_MAXIMA):
            return False
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            return sock.connect_ex((host, numero)) == 0
        except (socket.timeout, socket.error, OSError, ValueError):
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _info(self, host: str, porta: int, com_servico: bool) -> Dict[str, Any]:
        """Monta o dicionario de resultado (com ou sem probe de servico)."""
        if not com_servico:
            return {
                "porta": porta,
                "servico": nome_servico(porta),
                "banner": None,
                "produto": None,
                "versao": None,
                "tls": False,
                "certificado": None,
                "http": None,
                "tls_versao": None,
                "cifra": None,
            }
        info = detectar_servico(host, porta, self.timeout_servico)
        info.setdefault("porta", porta)
        return info

    def _registrar(self, host: str, info: Dict[str, Any]) -> None:
        """Adiciona uma porta aberta ao estado compartilhado (thread-safe)."""
        porta = int(info["porta"])
        with self.lock:
            if porta not in self.portas_abertas:
                self.portas_abertas.append(porta)
            self.resultados.append(info)
        if self.verbose:
            print(f"  [+] Porta {porta} aberta - {descrever_servico(info)}")

    def _avaliar(
        self, host: str, porta: int, com_servico: bool
    ) -> Optional[Dict[str, Any]]:
        if not self.testar_porta(host, porta):
            return None
        info = self._info(host, porta, com_servico)
        self._registrar(host, info)
        return info

    def scan_porta(self, host: str, porta: int) -> None:
        """Testa uma unica porta e registra o resultado (compatibilidade v1)."""
        self._avaliar(host, porta, self.detectar_servicos)


    # ------------------------------------------------------------------
    # Varreduras
    # ------------------------------------------------------------------
    def _reset(self) -> None:
        with self.lock:
            self.portas_abertas = []
            self.resultados = []
        self.cache_hit = False

    @staticmethod
    def _chave_cache(
        host: str, inicio: int, fim: int, com_servico: bool, extra: str = ""
    ) -> str:
        return f"{host}:{inicio}-{fim}:{'svc' if com_servico else 'tcp'}{extra}"

    def _carregar_cache(self, chave: str) -> bool:
        """Reaproveita um resultado recente do cache (namespace ``scan``)."""
        if self.cache is None:
            return False
        guardado = self.cache.get("scan", chave)
        if not isinstance(guardado, dict):
            return False
        self.portas_abertas = [int(p) for p in guardado.get("portas", [])]
        self.resultados = list(guardado.get("resultados", []))
        self.duracao = float(guardado.get("duracao", 0.0))
        self.total_verificadas = int(guardado.get("total_verificadas", 0))
        self.cache_hit = True
        if self.verbose:
            print(
                f"[*] Resultado reaproveitado do cache "
                f"({len(self.portas_abertas)} porta(s) aberta(s))."
            )
        return True

    def _gravar_cache(self, chave: str) -> None:
        if self.cache is None:
            return
        self.cache.set(
            "scan",
            chave,
            {
                "portas": sorted(self.portas_abertas),
                "resultados": self.resultados,
                "duracao": self.duracao,
                "total_verificadas": self.total_verificadas,
            },
        )

    def _executar(self, host: str, portas: List[int], com_servico: bool) -> None:
        """Roda o scan de ``portas`` em paralelo e mede a duracao."""
        inicio_tempo = time.perf_counter()
        self.total_verificadas = len(portas)
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            list(executor.map(lambda p: self._avaliar(host, p, com_servico), portas))
        self.duracao = round(time.perf_counter() - inicio_tempo, 3)

    def scan_intervalo(
        self,
        host: str,
        inicio: int = 1,
        fim: int = 1024,
        detectar_servicos: Optional[bool] = None,
        usar_cache: bool = True,
    ) -> List[int]:
        """Escaneia ``inicio``-``fim`` e devolve a lista de portas abertas."""
        inicio, fim = normalizar_intervalo(inicio, fim)
        com_servico = (
            self.detectar_servicos
            if detectar_servicos is None
            else bool(detectar_servicos)
        )
        self._reset()
        chave = self._chave_cache(host, inicio, fim, com_servico)
        if usar_cache and self._carregar_cache(chave):
            return sorted(self.portas_abertas)

        if self.verbose:
            print(
                f"\n[*] Iniciando scan de portas em {host} "
                f"(portas {inicio}-{fim})..."
            )
            print(
                f"[*] Timeout: {self.timeout}s | Threads: {self.max_threads} | "
                f"Servicos: {'sim' if com_servico else 'nao'}"
            )

        self._executar(host, list(range(inicio, fim + 1)), com_servico)

        if self.verbose:
            print(
                f"\n[*] Scan concluido! {len(self.portas_abertas)} porta(s) "
                f"aberta(s) em {self.duracao}s."
            )
        self._gravar_cache(chave)
        return sorted(self.portas_abertas)

    def scan_portas_comuns(
        self,
        host: str,
        detectar_servicos: Optional[bool] = None,
        usar_cache: bool = True,
    ) -> List[int]:
        """Escaneia o catalogo de portas comuns em paralelo."""
        com_servico = (
            self.detectar_servicos
            if detectar_servicos is None
            else bool(detectar_servicos)
        )
        self._reset()
        portas = sorted(self.PORTAS_COMUNS)
        chave = self._chave_cache(
            host, portas[0], portas[-1], com_servico, extra=":comuns"
        )
        if usar_cache and self._carregar_cache(chave):
            return sorted(self.portas_abertas)

        if self.verbose:
            print(
                f"\n[*] Escaneando portas comuns em {host} "
                f"({len(portas)} portas)..."
            )

        self._executar(host, portas, com_servico)

        if self.verbose:
            print(
                f"\n[*] Scan de portas comuns concluido! "
                f"{len(self.portas_abertas)} encontradas em {self.duracao}s."
            )
        self._gravar_cache(chave)
        return sorted(self.portas_abertas)

    # ------------------------------------------------------------------
    # Visoes derivadas
    # ------------------------------------------------------------------
    def resultados_ordenados(self) -> List[Dict[str, Any]]:
        """Resultados completos ordenados por porta."""
        with self.lock:
            return sorted(self.resultados, key=lambda r: int(r.get("porta", 0)))

    def resumo(self) -> Dict[str, Any]:
        """Estrutura pronta para JSON (API/interface web)."""
        return {
            "portas": sorted(int(p) for p in self.portas_abertas),
            "resultados": self.resultados_ordenados(),
            "total_abertas": len(self.portas_abertas),
            "total_verificadas": self.total_verificadas,
            "duracao": self.duracao,
            "cache": self.cache_hit,
        }


def verificar_portas(
    host: str,
    portas: Iterable[int],
    timeout: float = 1.0,
    detectar_servicos: bool = False,
) -> List[Dict[str, Any]]:
    """Utilitario: testa uma lista arbitraria de portas e devolve as abertas."""
    lista = [int(p) for p in portas]
    scanner = PortScanner(
        timeout=timeout,
        max_threads=min(32, max(1, len(lista))),
        detectar_servicos=detectar_servicos,
        verbose=False,
    )
    resultados: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=scanner.max_threads) as executor:
        for info in executor.map(
            lambda p: scanner._avaliar(host, p, detectar_servicos), lista
        ):
            if info:
                resultados.append(info)
    return sorted(resultados, key=lambda r: int(r["porta"]))

