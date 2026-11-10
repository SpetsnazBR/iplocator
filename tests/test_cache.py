"""Testes do cache TTL/LRU com persistência em disco."""

from __future__ import annotations

import json

import pytest

from iplocator_core.cache import (
    CacheManager,
    TTLCache,
    cache_desabilitado_por_env,
    diretorio_cache_padrao,
)


class Relogio:
    """Relógio controlável para testar expiração sem ``sleep``."""

    def __init__(self, inicio: float = 1000.0) -> None:
        self.agora = inicio

    def __call__(self) -> float:
        return self.agora

    def avancar(self, segundos: float) -> None:
        self.agora += segundos


def test_set_get_e_contagem() -> None:
    cache = TTLCache(ttl=60)
    cache.set("a", {"valor": 1})
    assert cache.get("a") == {"valor": 1}
    assert cache.stats()["hits"] == 1
    assert "a" in cache  # também conta como acerto
    assert len(cache) == 1
    assert cache.stats()["hits"] == 2


def test_chave_ausente_retorna_padrao() -> None:
    cache = TTLCache(ttl=60)
    assert cache.get("nada") is None
    assert cache.get("nada", "fallback") == "fallback"
    assert cache.stats()["misses"] == 2


def test_expira_apos_ttl() -> None:
    relogio = Relogio()
    cache = TTLCache(ttl=10, clock=relogio)
    cache.set("a", 1)
    relogio.avancar(9)
    assert cache.get("a") == 1
    relogio.avancar(2)
    assert cache.get("a") is None
    assert len(cache) == 0
    assert cache.stats()["expirados"] == 1


def test_ttl_customizado_por_entrada() -> None:
    relogio = Relogio()
    cache = TTLCache(ttl=100, clock=relogio)
    cache.set("curto", 1, ttl=5)
    cache.set("longo", 2)
    relogio.avancar(6)
    assert cache.get("curto") is None
    assert cache.get("longo") == 2


def test_ttl_zero_nao_armazena() -> None:
    cache = TTLCache(ttl=60)
    cache.set("a", 1, ttl=0)
    assert cache.get("a") is None


def test_lru_descarta_a_entrada_mais_antiga() -> None:
    cache = TTLCache(ttl=600, max_entries=2)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.get("a")  # "a" passa a ser a mais recente
    cache.set("c", 3)
    assert cache.get("b") is None
    assert cache.get("a") == 1
    assert cache.get("c") == 3
    assert cache.stats()["evictions"] >= 1


def test_delete_e_clear() -> None:
    cache = TTLCache(ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.delete("a") is True
    assert cache.delete("a") is False
    assert cache.clear() == 1
    assert len(cache) == 0


def test_purge_expirados() -> None:
    relogio = Relogio()
    cache = TTLCache(ttl=10, clock=relogio)
    cache.set("a", 1)
    cache.set("b", 2, ttl=100)
    relogio.avancar(11)
    assert cache.purge_expirados() == 1
    assert cache.chaves() == ["b"]


def test_persistencia_entre_instancias(tmp_path) -> None:
    arquivo = tmp_path / "geo.json"
    primeiro = TTLCache(ttl=600, path=arquivo)
    primeiro.set("8.8.8.8", {"city": "Mountain View"})
    assert arquivo.is_file()

    segundo = TTLCache(ttl=600, path=arquivo)
    assert segundo.get("8.8.8.8") == {"city": "Mountain View"}


def test_persistencia_descarta_expirados(tmp_path) -> None:
    arquivo = tmp_path / "geo.json"
    relogio = Relogio()
    cache = TTLCache(ttl=10, path=arquivo, clock=relogio)
    cache.set("a", 1)
    conteudo = json.loads(arquivo.read_text(encoding="utf-8"))
    assert conteudo["version"] == 1
    assert "a" in conteudo["entries"]

    relogio.avancar(50)
    cache.set("b", 2)  # regrava apenas o que ainda é válido
    recarregado = TTLCache(ttl=10, path=arquivo, clock=relogio)
    assert recarregado.get("a") is None
    assert recarregado.get("b") == 2


def test_arquivo_corrompido_e_ignorado(tmp_path) -> None:
    arquivo = tmp_path / "geo.json"
    arquivo.write_text("{invalido", encoding="utf-8")
    cache = TTLCache(ttl=60, path=arquivo)
    assert cache.get("a") is None


def test_versao_de_formato_desconhecida_e_ignorada(tmp_path) -> None:
    arquivo = tmp_path / "geo.json"
    arquivo.write_text(
        json.dumps({"version": 99, "entries": {"a": {"exp": 10**9, "val": 1}}}),
        encoding="utf-8",
    )
    cache = TTLCache(ttl=60, path=arquivo)
    assert cache.get("a") is None


def test_falha_de_escrita_nao_levanta(tmp_path) -> None:
    # Um diretório no lugar do arquivo força erro de I/O na persistência.
    destino = tmp_path / "cache.json"
    destino.mkdir()
    cache = TTLCache(ttl=60, path=destino)
    cache.set("a", 1)
    assert cache.get("a") == 1


def test_cache_manager_namespaces_e_ttls(tmp_path) -> None:
    gerenciador = CacheManager(directory=tmp_path / "cache")
    gerenciador.set("geo", "8.8.8.8", {"ok": True})
    gerenciador.set("whois", "ip:8.8.8.8", {"fonte": "rdap"})

    assert gerenciador.get("geo", "8.8.8.8") == {"ok": True}
    assert gerenciador.get("whois", "ip:8.8.8.8") == {"fonte": "rdap"}

    stats = gerenciador.stats()
    assert stats["habilitado"] is True
    assert stats["entradas"] == 2
    assert set(stats["namespaces"]) == {"geo", "whois"}
    assert stats["ttls"]["geo"] > stats["ttls"]["scan"]
    assert (tmp_path / "cache" / "geo.json").is_file()


def test_cache_manager_clear_por_namespace(tmp_path) -> None:
    gerenciador = CacheManager(directory=tmp_path / "cache")
    gerenciador.set("geo", "a", 1)
    gerenciador.set("scan", "b", 2)
    assert gerenciador.clear("geo") == 1
    assert gerenciador.get("geo", "a") is None
    assert gerenciador.get("scan", "b") == 2
    assert gerenciador.clear() == 1


def test_cache_manager_desabilitado(tmp_path) -> None:
    gerenciador = CacheManager(directory=tmp_path / "cache", enabled=False)
    gerenciador.set("geo", "a", 1)
    assert gerenciador.get("geo", "a") is None
    assert gerenciador.clear() == 0
    assert gerenciador.stats()["habilitado"] is False
    assert not (tmp_path / "cache").exists()


def test_cache_manager_purge(tmp_path) -> None:
    relogio = Relogio()
    gerenciador = CacheManager(directory=tmp_path / "cache", clock=relogio)
    gerenciador.set("scan", "a", 1)
    relogio.avancar(gerenciador.TTL_PADRAO["scan"] + 1)
    assert gerenciador.purge_expirados() == 1


def test_env_desabilita_cache(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("IPLOCATOR_CACHE_DISABLED", "true")
    assert cache_desabilitado_por_env() is True
    gerenciador = CacheManager(directory=tmp_path / "cache")
    assert gerenciador.enabled is False


def test_env_define_diretorio(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("IPLOCATOR_CACHE_DIR", str(tmp_path / "custom"))
    assert diretorio_cache_padrao() == tmp_path / "custom"


def test_env_ttl_invalido_usa_padrao(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("IPLOCATOR_CACHE_TTL", "abc")
    gerenciador = CacheManager(directory=tmp_path / "cache")
    assert gerenciador.default_ttl == 3600.0


def test_namespace_de_expoe_cache_bruto(tmp_path) -> None:
    gerenciador = CacheManager(directory=tmp_path / "cache")
    bruto = gerenciador.namespace_de("geo")
    bruto.set("chave", "valor")
    assert gerenciador.get("geo", "chave") == "valor"


def test_stats_de_ttl_cache_com_atributos() -> None:
    cache = TTLCache(ttl=30, max_entries=5)
    cache.set("a", 1)
    cache.get("a")
    cache.get("b")
    stats = cache.stats()
    assert stats["ttl"] == 30
    assert stats["max_entradas"] == 5
    assert stats["taxa_acerto"] == pytest.approx(0.5)
    assert stats["persistente"] is False

