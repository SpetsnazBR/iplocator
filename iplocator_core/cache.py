"""Cache de resultados com TTL, política LRU e persistência em disco.

O cache é opcional e nunca derruba a aplicação: qualquer falha de I/O é
silenciada e a consulta segue pelo caminho normal (rede).

Variáveis de ambiente reconhecidas:

* ``IPLOCATOR_CACHE_DIR``      – diretório dos arquivos de cache
* ``IPLOCATOR_CACHE_TTL``      – TTL padrão (segundos)
* ``IPLOCATOR_CACHE_DISABLED`` – ``1``/``true`` desliga o cache
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Versão do formato persistido; arquivos de outra versão são descartados.
VERSAO_FORMATO = 1

ENV_CACHE_DIR = "IPLOCATOR_CACHE_DIR"
ENV_CACHE_TTL = "IPLOCATOR_CACHE_TTL"
ENV_CACHE_DISABLED = "IPLOCATOR_CACHE_DISABLED"


def cache_desabilitado_por_env() -> bool:
    """Lê ``IPLOCATOR_CACHE_DISABLED`` (``1``, ``true``, ``yes``, ``on``)."""
    valor = os.environ.get(ENV_CACHE_DISABLED, "")
    return valor.strip().lower() in {"1", "true", "yes", "on"}


def diretorio_cache_padrao() -> Path:
    """Resolve o diretório de cache respeitando XDG/``IPLOCATOR_CACHE_DIR``."""
    override = os.environ.get(ENV_CACHE_DIR)
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    return Path(base) / "iplocator"


def _ttl_por_env(padrao: float) -> float:
    """Lê ``IPLOCATOR_CACHE_TTL`` e valida o valor (ignora entradas inválidas)."""
    bruto = os.environ.get(ENV_CACHE_TTL, "").strip()
    if not bruto:
        return padrao
    try:
        valor = float(bruto)
    except ValueError:
        return padrao
    return valor if valor > 0 else padrao


class _Sentinela:
    """Marcador usado por ``__contains__`` para diferenciar ``None`` de ausência."""


_SENTINELA = _Sentinela()



class TTLCache:
    """Cache thread-safe em memória com expiração por TTL e LRU opcional.

    :param ttl: tempo de vida padrão em segundos.
    :param max_entries: limite de entradas; ao exceder, a menos recentemente
        usada é descartada.
    :param path: arquivo JSON opcional usado para persistir as entradas.
    :param clock: fonte de tempo injetável (facilita os testes).
    """

    def __init__(
        self,
        ttl: float = 3600.0,
        max_entries: int = 512,
        path: Optional[Path] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ttl = float(ttl)
        self.max_entries = max(1, int(max_entries))
        self.path = Path(path) if path is not None else None
        self._clock = clock
        self._dados: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._expirados = 0
        self._evictions = 0
        self._escritas = 0
        self._carregado = False

    # ------------------------------------------------------------------
    # Persistência
    # ------------------------------------------------------------------
    def _carregar(self) -> None:
        if self._carregado or self.path is None:
            self._carregado = True
            return
        self._carregado = True
        try:
            conteudo = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return
        try:
            bruto = json.loads(conteudo)
        except ValueError:
            return
        if not isinstance(bruto, dict) or bruto.get("version") != VERSAO_FORMATO:
            return
        entradas = bruto.get("entries")
        if not isinstance(entradas, dict):
            return
        agora = self._clock()
        for chave, registro in entradas.items():
            if not isinstance(registro, dict):
                continue
            expira = registro.get("exp")
            if not isinstance(expira, (int, float)) or expira <= agora:
                continue
            self._dados[str(chave)] = {"exp": float(expira), "val": registro.get("val")}
        self._aplicar_limite()

    def _salvar(self) -> None:
        """Grava o cache de forma atômica (arquivo temporário + ``os.replace``)."""
        if self.path is None:
            return
        with self._lock:
            agora = self._clock()
            entradas = {
                chave: {"exp": dados["exp"], "val": dados["val"]}
                for chave, dados in self._dados.items()
                if dados["exp"] > agora
            }
        payload = {
            "version": VERSAO_FORMATO,
            "ttl": self.ttl,
            "saved_at": self._clock(),
            "entries": entradas,
        }
        temporario = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporario = tempfile.mkstemp(
                prefix=".iplocator-", suffix=".json", dir=str(self.path.parent)
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as arquivo:
                json.dump(payload, arquivo, ensure_ascii=False)
            os.replace(temporario, self.path)
            temporario = None
        except (OSError, TypeError, ValueError):
            # Cache é uma otimização: falhas de escrita não quebram o fluxo.
            pass
        finally:
            if temporario and os.path.exists(temporario):
                try:
                    os.unlink(temporario)
                except OSError:
                    pass

    def recarregar(self) -> None:
        """Força a releitura do arquivo de persistência."""
        with self._lock:
            self._dados.clear()
            self._carregado = False
            self._carregar()

    # ------------------------------------------------------------------
    # API principal
    # ------------------------------------------------------------------
    def get(self, chave: str, padrao: Any = None) -> Any:
        """Devolve o valor válido para ``chave`` ou ``padrao`` se ausente/expirado."""
        with self._lock:
            self._carregar()
            registro = self._dados.get(chave)
            if registro is None:
                self._misses += 1
                return padrao
            if registro["exp"] <= self._clock():
                self._dados.pop(chave, None)
                self._expirados += 1
                self._misses += 1
                return padrao
            # Reinsere no fim do dicionário: em Python 3.7+ isso mantém a ordem LRU.
            self._dados[chave] = self._dados.pop(chave)
            self._hits += 1
            return registro["val"]

    def set(self, chave: str, valor: Any, ttl: Optional[float] = None) -> None:
        """Armazena ``valor`` com o TTL informado (ou o TTL padrão do cache)."""
        vida = self.ttl if ttl is None else float(ttl)
        if vida <= 0:
            return
        with self._lock:
            self._carregar()
            self._dados[chave] = {"exp": self._clock() + vida, "val": valor}
            self._escritas += 1
            self._aplicar_limite()
        self._salvar()

    def delete(self, chave: str) -> bool:
        """Remove uma entrada; devolve ``True`` se ela existia."""
        with self._lock:
            self._carregar()
            existia = chave in self._dados
            self._dados.pop(chave, None)
        if existia:
            self._salvar()
        return existia

    def clear(self) -> int:
        """Esvazia o cache e devolve quantas entradas foram descartadas."""
        with self._lock:
            self._carregar()
            removidas = len(self._dados)
            self._dados.clear()
        self._salvar()
        return removidas

    def purge_expirados(self) -> int:
        """Remove entradas vencidas e devolve a quantidade descartada."""
        agora = self._clock()
        with self._lock:
            self._carregar()
            vencidas = [c for c, d in self._dados.items() if d["exp"] <= agora]
            for chave in vencidas:
                self._dados.pop(chave, None)
            self._expirados += len(vencidas)
        if vencidas:
            self._salvar()
        return len(vencidas)

    def chaves(self) -> List[str]:
        """Lista as chaves ainda válidas."""
        agora = self._clock()
        with self._lock:
            self._carregar()
            return [c for c, d in self._dados.items() if d["exp"] > agora]

    def _aplicar_limite(self) -> None:
        """Descarta as entradas mais antigas até respeitar ``max_entries``."""
        while len(self._dados) > self.max_entries:
            mais_antiga = next(iter(self._dados))
            self._dados.pop(mais_antiga, None)
            self._evictions += 1

    def __len__(self) -> int:
        return len(self.chaves())

    def __contains__(self, chave: object) -> bool:
        return self.get(str(chave), _SENTINELA) is not _SENTINELA

    # ------------------------------------------------------------------
    # Estatísticas
    # ------------------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        """Métricas de uso — base da aba "Cache" da interface web."""
        with self._lock:
            self._carregar()
            total = self._hits + self._misses
            return {
                "ttl": self.ttl,
                "entradas": len(self.chaves()),
                "max_entradas": self.max_entries,
                "hits": self._hits,
                "misses": self._misses,
                "expirados": self._expirados,
                "evictions": self._evictions,
                "escritas": self._escritas,
                "taxa_acerto": round(self._hits / total, 4) if total else 0.0,
                "persistente": self.path is not None,
                "arquivo": str(self.path) if self.path else None,
            }


class CacheManager:
    """Agrupa caches por namespace, cada um com TTL próprio e arquivo próprio.

    Namespaces conhecidos: ``geo``, ``whois``, ``dns`` e ``scan``.
    """

    TTL_PADRAO: Dict[str, float] = {
        "geo": 86400.0,    # geolocalização muda pouco: 24 h
        "whois": 43200.0,  # registros WHOIS/RDAP: 12 h
        "dns": 600.0,      # resolução DNS: 10 min
        "scan": 300.0,     # resultados de portas: 5 min
    }

    def __init__(
        self,
        directory: Optional[Path] = None,
        enabled: bool = True,
        default_ttl: Optional[float] = None,
        max_entries_per_namespace: int = 256,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.directory = (
            Path(directory) if directory is not None else diretorio_cache_padrao()
        )
        self.enabled = bool(enabled) and not cache_desabilitado_por_env()
        self.default_ttl = (
            _ttl_por_env(3600.0) if default_ttl is None else float(default_ttl)
        )
        self.max_entries_per_namespace = max(1, int(max_entries_per_namespace))
        self._clock = clock
        self._caches: Dict[str, TTLCache] = {}
        self._lock = threading.RLock()

    def _cache(self, namespace: str) -> TTLCache:
        namespace = namespace or "default"
        with self._lock:
            cache = self._caches.get(namespace)
            if cache is None:
                ttl = self.TTL_PADRAO.get(namespace, self.default_ttl)
                caminho = self.directory / f"{namespace}.json" if self.enabled else None
                cache = TTLCache(
                    ttl=ttl,
                    max_entries=self.max_entries_per_namespace,
                    path=caminho,
                    clock=self._clock,
                )
                self._caches[namespace] = cache
            return cache

    def get(self, namespace: str, chave: str, padrao: Any = None) -> Any:
        if not self.enabled:
            return padrao
        return self._cache(namespace).get(chave, padrao)

    def set(
        self,
        namespace: str,
        chave: str,
        valor: Any,
        ttl: Optional[float] = None,
    ) -> None:
        if not self.enabled:
            return
        self._cache(namespace).set(chave, valor, ttl=ttl)

    def delete(self, namespace: str, chave: str) -> bool:
        if not self.enabled:
            return False
        return self._cache(namespace).delete(chave)

    def clear(self, namespace: Optional[str] = None) -> int:
        """Limpa um namespace (ou todos) e devolve o total de entradas removidas."""
        with self._lock:
            if namespace is not None:
                return self._cache(namespace).clear()
            total = 0
            for cache in self._caches.values():
                total += cache.clear()
            return total

    def purge_expirados(self) -> int:
        with self._lock:
            return sum(cache.purge_expirados() for cache in self._caches.values())

    def stats(self) -> Dict[str, Any]:
        """Estatísticas agregadas + por namespace (consumidas pela UI/CLI)."""
        with self._lock:
            namespaces = {nome: cache.stats() for nome, cache in self._caches.items()}
        entradas = sum(item["entradas"] for item in namespaces.values())
        hits = sum(item["hits"] for item in namespaces.values())
        misses = sum(item["misses"] for item in namespaces.values())
        return {
            "habilitado": self.enabled,
            "diretorio": str(self.directory) if self.enabled else None,
            "ttls": dict(self.TTL_PADRAO),
            "entradas": entradas,
            "hits": hits,
            "misses": misses,
            "taxa_acerto": round(hits / (hits + misses), 4) if (hits + misses) else 0.0,
            "namespaces": namespaces,
        }

    def namespace_de(self, namespace: str) -> TTLCache:
        """Expõe o cache bruto de um namespace (usado nos testes)."""
        return self._cache(namespace)

