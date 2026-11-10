"""API HTTP local que serve a interface Vue e expõe o núcleo em JSON.

Roda com a biblioteca padrão (``ThreadingHTTPServer``), sem dependências
extras. Por padrão escuta apenas em ``127.0.0.1``, evitando expor o scanner
para a rede sem intenção explícita (use ``--host 0.0.0.0`` se necessário).
"""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .cache import CacheManager
from .geo import IPLocator, provedores_disponiveis
from .scanner import PortScanner
from .services import PORTAS_CONHECIDAS
from .validation import identificar_alvo, resolver_dominio
from .version import __version__
from .whois import WhoisClient

#: Variável de ambiente que sobrescreve o diretório da interface web.
ENV_WEB_DIR = "IPLOCATOR_WEB_DIR"


def resolver_diretorio_web() -> Path:
    """Descobre o diretório da interface estática.

    Ordem de busca:

    1. ``IPLOCATOR_WEB_DIR`` (útil para servir a UI de outro lugar);
    2. ``web/`` na raiz do repositório (execução via ``python iplocator.py``);
    3. ``<prefix>/share/iplocator/web`` (instalação via ``pip``/wheel);
    4. ``./web`` (relativo ao diretório corrente).

    A primeira opção que contenha ``index.html`` vence; se nenhuma existir,
    devolve o primeiro candidato para que a mensagem de erro mostre o caminho
    mais provável.
    """
    candidatos = []
    override = os.environ.get(ENV_WEB_DIR, "").strip()
    if override:
        candidatos.append(Path(override).expanduser())
    candidatos.append(Path(__file__).resolve().parent.parent / "web")
    candidatos.append(Path(sys.prefix) / "share" / "iplocator" / "web")
    candidatos.append(Path.cwd() / "web")
    for candidato in candidatos:
        if (candidato / "index.html").is_file():
            return candidato
    return candidatos[0]


#: Diretório da interface web resolvido na importação do módulo.
DIRETORIO_WEB_PADRAO = resolver_diretorio_web()


#: Limite de portas por requisição de scan (proteção contra abuso acidental).
MAX_PORTAS_POR_CONSULTA = 4096

#: Tipos MIME servidos para os arquivos estáticos.
TIPOS_MIME: Dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".map": "application/json; charset=utf-8",
}


def resolver_estatico(web_dir: Path, caminho: str) -> Optional[Path]:
    """Resolve um caminho estático com proteção contra *path traversal*.

    Devolve ``None`` para caminhos vazios, inexistentes ou fora do diretório.
    """
    relativo = unquote(caminho or "/").strip("/")
    if not relativo:
        relativo = "index.html"
    if "\x00" in relativo:
        return None
    base = Path(web_dir).resolve()
    try:
        alvo = (base / relativo).resolve()
        alvo.relative_to(base)
    except (ValueError, OSError):
        return None
    return alvo if alvo.is_file() else None


def _booleano(valor: Optional[str], padrao: bool = True) -> bool:
    """Interpreta flags textuais de query string (``0``/``false``/``no``)."""
    if valor is None:
        return padrao
    return valor.strip().lower() not in {"0", "false", "no", "off", "nao", "não"}


def _numero(valor: Optional[str], padrao: float, minimo: float, maximo: float) -> float:
    """Converte um parâmetro numérico, aplicando limites (clamp)."""
    if valor is None or not str(valor).strip():
        return padrao
    try:
        numero = float(valor)
    except (TypeError, ValueError):
        return padrao
    return max(minimo, min(maximo, numero))


class ContextoAPI:
    """Dependências compartilhadas entre as requisições (injetáveis nos testes)."""

    def __init__(
        self,
        cache: Optional[CacheManager] = None,
        locator: Optional[IPLocator] = None,
        whois: Optional[WhoisClient] = None,
        scanner_factory: Optional[Callable[..., PortScanner]] = None,
        web_dir: Optional[Path] = None,
        max_portas: int = MAX_PORTAS_POR_CONSULTA,
        verbose: bool = False,
    ) -> None:
        self.cache = cache if cache is not None else CacheManager()
        self.locator = locator if locator is not None else IPLocator(cache=self.cache)
        self.whois = whois if whois is not None else WhoisClient(cache=self.cache)
        self.web_dir = Path(web_dir) if web_dir is not None else DIRETORIO_WEB_PADRAO
        self.max_portas = max(1, int(max_portas))
        self.verbose = bool(verbose)
        self.scanner_factory = scanner_factory or self._scanner_padrao
        self.criado_em = time.time()

    def _scanner_padrao(self, **kwargs: Any) -> PortScanner:
        return PortScanner(cache=self.cache, verbose=False, **kwargs)

    def scanner(self, **kwargs: Any) -> PortScanner:
        """Cria um scanner novo por requisição (evita estado compartilhado)."""
        return self.scanner_factory(**kwargs)

    def uptime(self) -> float:
        return round(time.time() - self.criado_em, 3)



class ManipuladorAPI(BaseHTTPRequestHandler):
    """Roteador HTTP: ``/api/*`` em JSON e o restante como arquivo estático."""

    server_version = f"IPLocatorAPI/{__version__}"
    protocol_version = "HTTP/1.0"

    # -- infraestrutura ---------------------------------------------------
    @property
    def contexto(self) -> ContextoAPI:
        return getattr(self.server, "contexto")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - nome da stdlib
        if getattr(self.server, "verbose", False):
            super().log_message(format, *args)

    def _cabecalhos_comuns(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")

    def _enviar(self, corpo: bytes, tipo: str, status: int = 200) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", tipo)
            self.send_header("Content-Length", str(len(corpo)))
            self.send_header("Cache-Control", "no-store")
            self._cabecalhos_comuns()
            self.end_headers()
            self.wfile.write(corpo)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, dados: Any, status: int = 200) -> None:
        corpo = json.dumps(dados, ensure_ascii=False, default=str).encode("utf-8")
        self._enviar(corpo, "application/json; charset=utf-8", status)

    def _erro(
        self,
        mensagem: str,
        status: int = 400,
        codigo: Optional[str] = None,
        **extra: Any,
    ) -> None:
        payload: Dict[str, Any] = {"ok": False, "erro": mensagem}
        if codigo:
            payload["codigo"] = codigo
        payload.update(extra)
        self._json(payload, status)

    @staticmethod
    def _param(params: Dict[str, list], *nomes: str, padrao: Any = None) -> Any:
        for nome in nomes:
            valores = params.get(nome)
            if valores and str(valores[0]).strip():
                return str(valores[0]).strip()
        return padrao

    # -- verbos HTTP ------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802 - assinatura da stdlib
        self.send_response(204)
        self._cabecalhos_comuns()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_DELETE(self) -> None:  # noqa: N802
        rota = urlparse(self.path).path.rstrip("/")
        try:
            if rota == "/api/cache":
                removidas = self.contexto.cache.clear()
                self._json(
                    {
                        "ok": True,
                        "removidas": removidas,
                        "cache": self.contexto.cache.stats(),
                    }
                )
                return
            self._erro("Recurso não encontrado", 404)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        rota = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)
        try:
            if rota == "/api" or rota.startswith("/api/"):
                self._rotas_api(rota, params)
            else:
                self._estatico(parsed.path)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # noqa: BLE001 - nunca derruba o servidor
            self._erro(f"Erro interno: {exc}", 500, codigo="interno")

    # -- rotas ------------------------------------------------------------
    def _rotas_api(self, rota: str, params: Dict[str, list]) -> None:
        rotas = {
            "/api": self._api_health,
            "/api/health": self._api_health,
            "/api/providers": self._api_providers,
            "/api/geo": self._api_geo,
            "/api/scan": self._api_scan,
            "/api/whois": self._api_whois,
            "/api/cache": self._api_cache,
            "/api/ports": self._api_ports,
        }
        manipulador = rotas.get(rota)
        if manipulador is None:
            self._erro("Endpoint não encontrado", 404, codigo="rota")
            return
        manipulador(params)

    def _api_health(self, params: Dict[str, list]) -> None:
        self._json(
            {
                "ok": True,
                "versao": __version__,
                "uptime": self.contexto.uptime(),
                "provedores": self.contexto.locator.provedores_ativos(),
                "cache": {
                    "habilitado": self.contexto.cache.enabled,
                    "entradas": self.contexto.cache.stats()["entradas"],
                },
            }
        )

    def _api_providers(self, params: Dict[str, list]) -> None:
        self._json(
            {
                "ok": True,
                "provedores": provedores_disponiveis(),
                "ativos": self.contexto.locator.provedores_ativos(),
            }
        )

    def _api_ports(self, params: Dict[str, list]) -> None:
        self._json(
            {
                "ok": True,
                "total": len(PORTAS_CONHECIDAS),
                "portas": [
                    {"porta": porta, "servico": servico}
                    for porta, servico in sorted(PORTAS_CONHECIDAS.items())
                ],
            }
        )

    def _api_cache(self, params: Dict[str, list]) -> None:
        self._json({"ok": True, "cache": self.contexto.cache.stats()})

    def _api_geo(self, params: Dict[str, list]) -> None:
        alvo = self._param(params, "target", "alvo")
        if not alvo:
            self._erro("Parâmetro 'target' é obrigatório", 400, codigo="parametro")
            return
        provedores = self._param(params, "providers", "provedores")
        lista = (
            [p.strip() for p in str(provedores).split(",") if p.strip()]
            if provedores
            else None
        )
        detalhe = self.contexto.locator.localizar_detalhado(alvo, provedores=lista)
        if detalhe.get("ok"):
            self._json(detalhe)
            return
        status = 502 if detalhe.get("codigo") == "provedores" else 422
        self._json(detalhe, status)

    def _api_whois(self, params: Dict[str, list]) -> None:
        alvo = self._param(params, "target", "alvo")
        if not alvo:
            self._erro("Parâmetro 'target' é obrigatório", 400, codigo="parametro")
            return
        detalhe = self.contexto.whois.consultar_detalhado(alvo)
        if detalhe.get("ok"):
            self._json(detalhe)
            return
        self._json(detalhe, 422 if detalhe.get("codigo") == "alvo_invalido" else 502)

    def _api_scan(self, params: Dict[str, list]) -> None:
        alvo = self._param(params, "target", "alvo", "host")
        if not alvo:
            self._erro("Parâmetro 'target' é obrigatório", 400, codigo="parametro")
            return
        info = identificar_alvo(alvo)
        if info["tipo"] == "invalido":
            self._erro(
                "Alvo inválido: informe um IP ou domínio",
                422,
                codigo="alvo_invalido",
            )
            return
        host = info["ip"] or resolver_dominio(str(info["entrada"]))
        if not host:
            self._erro(f"Não foi possível resolver '{alvo}'", 422, codigo="dns")
            return

        modo = str(self._param(params, "mode", "modo", padrao="comuns")).lower()
        if modo in {"range", "custom", "personalizado"}:
            modo = "intervalo"
        if modo not in {"comuns", "intervalo"}:
            self._erro(
                "Modo inválido (use 'comuns' ou 'intervalo')", 400, codigo="modo"
            )
            return

        com_servico = _booleano(self._param(params, "services", "servicos"))
        timeout = _numero(self._param(params, "timeout"), 1.0, 0.1, 10.0)
        inicio = int(_numero(self._param(params, "start", "inicio"), 1, 1, 65535))
        fim = int(_numero(self._param(params, "end", "fim"), 1024, 1, 65535))
        if inicio > fim:
            inicio, fim = fim, inicio
        if modo == "intervalo" and (fim - inicio + 1) > self.contexto.max_portas:
            self._erro(
                f"Intervalo acima do limite de {self.contexto.max_portas} portas",
                400,
                codigo="limite",
            )
            return

        scanner = self.contexto.scanner(
            timeout=timeout, detectar_servicos=com_servico
        )
        inicio_tempo = time.perf_counter()
        if modo == "comuns":
            scanner.scan_portas_comuns(host, detectar_servicos=com_servico)
        else:
            scanner.scan_intervalo(host, inicio, fim, detectar_servicos=com_servico)
        payload: Dict[str, Any] = {
            "ok": True,
            "alvo": alvo,
            "host": host,
            "modo": modo,
            "intervalo": [inicio, fim],
            "servicos": com_servico,
            "timeout": timeout,
            "duracao_total": round(time.perf_counter() - inicio_tempo, 3),
        }
        payload.update(scanner.resumo())
        self._json(payload)

    # -- arquivos estaticos ----------------------------------------------
    def _estatico(self, caminho: str) -> None:
        arquivo = resolver_estatico(self.contexto.web_dir, caminho)
        if arquivo is None:
            self._erro(
                "Arquivo não encontrado. Rode 'python iplocator.py --serve' "
                "a partir da raiz do projeto.",
                404,
                codigo="estatico",
            )
            return
        tipo = TIPOS_MIME.get(arquivo.suffix.lower(), "application/octet-stream")
        try:
            conteudo = arquivo.read_bytes()
        except OSError as exc:
            self._erro(f"Falha ao ler '{arquivo.name}': {exc}", 500, codigo="io")
            return
        self._enviar(conteudo, tipo)


class ServidorAPI(ThreadingHTTPServer):
    """Servidor que carrega o :class:`ContextoAPI` e roda cada request em thread."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        endereco: tuple,
        contexto: ContextoAPI,
        verbose: bool = False,
    ) -> None:
        self.contexto = contexto
        self.verbose = bool(verbose)
        super().__init__(endereco, ManipuladorAPI)


def criar_servidor(
    host: str = "127.0.0.1",
    porta: int = 8000,
    contexto: Optional[ContextoAPI] = None,
    web_dir: Optional[Path] = None,
    verbose: bool = False,
) -> ServidorAPI:
    """Cria o servidor (sem bloquear) — usado pela CLI e pelos testes."""
    if contexto is None:
        contexto = ContextoAPI(web_dir=web_dir, verbose=verbose)
    return ServidorAPI((host, int(porta)), contexto, verbose=verbose)


def servir(
    host: str = "127.0.0.1",
    porta: int = 8000,
    web_dir: Optional[Path] = None,
    verbose: bool = False,
) -> None:
    """Sobe a API + interface web e bloqueia até ``Ctrl+C``."""
    servidor = criar_servidor(host, porta, web_dir=web_dir, verbose=verbose)
    endereco_host, endereco_porta = servidor.server_address[:2]
    url = f"http://{endereco_host}:{endereco_porta}/"
    print(f"[*] Interface web: {url}")
    print("[*] API JSON:      " + url + "api/health")
    print("[*] Pressione Ctrl+C para encerrar.")
    try:
        servidor.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\n[*] Encerrando servidor…")
    finally:
        servidor.shutdown()
        servidor.server_close()

