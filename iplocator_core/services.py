"""Deteccao de servicos em portas abertas (banner grabbing + TLS + HTTP).

O modulo e deliberadamente conservador: toda falha de rede/timeout e tratada
como "sem informacao", nunca como excecao, porque ele roda dentro do scanner
multithread.
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple

#: Catalogo de portas conhecidas (nome amigavel usado na CLI e na UI).
PORTAS_CONHECIDAS: Dict[int, str] = {
    20: "FTP (Data)",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS-NS",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    514: "Syslog",
    515: "LPD",
    587: "SMTP Submission",
    631: "IPP",
    636: "LDAPS",
    873: "rsync",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MS SQL Server",
    1521: "Oracle DB",
    1883: "MQTT",
    2049: "NFS",
    2181: "ZooKeeper",
    2375: "Docker API",
    2376: "Docker API (TLS)",
    3000: "HTTP Alt (Grafana/Node)",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5000: "HTTP Alt (Flask)",
    5060: "SIP",
    5061: "SIP (TLS)",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "RabbitMQ",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    6443: "Kubernetes API",
    8000: "HTTP Alt",
    8080: "HTTP Alt / Proxy",
    8081: "HTTP Alt",
    8443: "HTTPS Alt",
    8883: "MQTT (TLS)",
    8888: "HTTP Alt (Jupyter)",
    9000: "HTTP Alt (PHP-FPM/SonarQube)",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch (Transport)",
    9443: "HTTPS Alt",
    11211: "Memcached",
    25565: "Minecraft",
    27017: "MongoDB",
}

#: Portas em que se espera HTTP em texto claro.
PORTAS_HTTP: frozenset = frozenset(
    {80, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200, 5985}
)

#: Portas em que se espera HTTP sobre TLS.
PORTAS_HTTP_TLS: frozenset = frozenset({443, 8443, 9443, 6443, 2376})

#: Portas com TLS mas que nao falam HTTP (IMAPS, SMTPS, LDAPS...).
PORTAS_TLS: frozenset = frozenset({443, 465, 636, 990, 993, 995, 5061, 8883}) | PORTAS_HTTP_TLS

#: Sondas enviadas quando o servico nao fala primeiro.
SONDAS: Dict[int, bytes] = {
    6379: b"PING\r\n",          # Redis
    11211: b"version\r\n",      # Memcached
    9200: b"GET / HTTP/1.0\r\n\r\n",
    25: b"EHLO iplocator.local\r\n",
    587: b"EHLO iplocator.local\r\n",
}

#: Identificacao de produto/versao a partir do banner.
PADROES_PRODUTO: List[Tuple[re.Pattern, int, Optional[int]]] = [
    (re.compile(r"\b(OpenSSH)[_ ]([\w.\-]+)", re.I), 1, 2),
    (re.compile(r"\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server)[/ ]?([\d.p]+)?", re.I), 1, 2),
    (re.compile(r"\b(Postfix)\b", re.I), 1, None),
    (re.compile(r"\b(Exim)\s+([\d.]+)", re.I), 1, 2),
    (re.compile(r"\b(Sendmail)\s+([\d.]+)", re.I), 1, 2),
    (re.compile(r"\b(Dovecot)\b", re.I), 1, None),
    (re.compile(r"\b(Courier)\b", re.I), 1, None),
    (re.compile(r"Server:\s*([A-Za-z][\w.\-]*)(?:/([\w.\-]+))?", re.I), 1, 2),
    (re.compile(r"\b(Apache)(?:/([\d.]+))?", re.I), 1, 2),
    (re.compile(r"\b(nginx)(?:/([\d.]+))?", re.I), 1, 2),
    (re.compile(r"\b(Microsoft-IIS)/([\d.]+)", re.I), 1, 2),
    (re.compile(r"\b(Caddy)\b", re.I), 1, None),
    (re.compile(r"\b(gunicorn|uvicorn|Jetty|lighttpd|Tomcat)\b", re.I), 1, None),
    (re.compile(r"\b(RabbitMQ)\b", re.I), 1, None),
    (re.compile(r"\b(VNC)\b", re.I), 1, None),
    (re.compile(r"\b(RFB)\b", re.I), 1, None),
    (re.compile(r"\b(MySQL)\b", re.I), 1, None),
    (re.compile(r"\b(PostgreSQL)\b", re.I), 1, None),
    (re.compile(r"\b(Redis)\b", re.I), 1, None),
    (re.compile(r"\b(RF\s*Banner)\b", re.I), 1, None),
]

#: Tamanho maximo lido de um banner (evita consumir memoria com servico falante).
MAX_BYTES_BANNER = 2048


def nome_servico(porta: int) -> str:
    """Nome amigavel da porta ou ``"Desconhecido"``."""
    return PORTAS_CONHECIDAS.get(int(porta), "Desconhecido")


def identificar_produto(banner: str) -> Tuple[Optional[str], Optional[str]]:
    """Extrai ``(produto, versao)`` do banner; ``(None, None)`` se nao houver."""
    if not banner:
        return None, None
    for padrao, grupo_produto, grupo_versao in PADROES_PRODUTO:
        achado = padrao.search(banner)
        if not achado:
            continue
        produto = achado.group(grupo_produto)
        versao = None
        if grupo_versao is not None and achado.lastindex and achado.lastindex >= grupo_versao:
            versao = achado.group(grupo_versao)
        return (produto.strip() if produto else None), (versao or None)
    return None, None


def parse_cabecalhos_http(resposta: str) -> Dict[str, str]:
    """Converte o cabecalho HTTP em dict (chaves minusculas, 1a ocorrencia)."""
    cabecalhos: Dict[str, str] = {}
    if not resposta:
        return cabecalhos
    linhas = resposta.replace("\r\n", "\n").split("\n")[1:]
    for linha in linhas:
        if not linha.strip():
            break
        if ":" not in linha:
            continue
        nome, _, valor = linha.partition(":")
        cabecalhos.setdefault(nome.strip().lower(), valor.strip())
    return cabecalhos


def _receber(sock: socket.socket, limite: int = MAX_BYTES_BANNER) -> bytes:
    """Le ate ``limite`` bytes tolerando timeouts (devolve o que chegou)."""
    partes: List[bytes] = []
    total = 0
    while total < limite:
        try:
            parte = sock.recv(min(1024, limite - total))
        except (socket.timeout, ssl.SSLError, OSError):
            break
        if not parte:
            break
        partes.append(parte)
        total += len(parte)
    return b"".join(partes)


def _contexto_tls() -> ssl.SSLContext:
    """Contexto TLS permissivo: interessa identificar o servico, nao validar CA."""
    contexto = ssl.create_default_context()
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE
    return contexto


def _resumir_certificado(certificado: Dict[str, Any]) -> Dict[str, Any]:
    """Extrai CN/emissor/validade/SAN de ``getpeercert()`` (sem depender de CA)."""

    def campo(secao: Any, chave: str) -> Optional[str]:
        for atributos in secao or ():
            for nome, valor in atributos:
                if nome == chave:
                    return str(valor)
        return None

    san = [
        valor
        for tipo, valor in certificado.get("subjectAltName", ())
        if tipo in ("DNS", "IP Address")
    ][:10]
    return {
        "cn": campo(certificado.get("subject"), "commonName"),
        "organizacao": campo(certificado.get("subject"), "organizationName"),
        "emissor": campo(certificado.get("issuer"), "commonName"),
        "valido_de": certificado.get("notBefore"),
        "valido_ate": certificado.get("notAfter"),
        "san": san,
    }


def detectar_tls(
    host: str,
    porta: int,
    timeout: float = 1.5,
) -> Optional[Dict[str, Any]]:
    """Tenta um handshake TLS; devolve versao/cifra/certificado ou ``None``."""
    socket_bruto: Optional[socket.socket] = None
    tls_socket: Optional[ssl.SSLSocket] = None
    try:
        socket_bruto = socket.create_connection((host, porta), timeout=timeout)
        socket_bruto.settimeout(timeout)
        tls_socket = _contexto_tls().wrap_socket(socket_bruto, server_hostname=None)
        cifra = tls_socket.cipher()
        try:
            certificado = tls_socket.getpeercert() or {}
        except ValueError:
            certificado = {}
        return {
            "versao": tls_socket.version(),
            "cifra": cifra[0] if cifra else None,
            "certificado": _resumir_certificado(certificado),
        }
    except (ssl.SSLError, socket.timeout, OSError, ValueError):
        return None
    finally:
        for sock in (tls_socket, socket_bruto):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def ler_banner(
    host: str,
    porta: int,
    timeout: float = 1.5,
    payload: bytes = b"",
    max_bytes: int = MAX_BYTES_BANNER,
    usar_tls: bool = False,
) -> str:
    """Le o banner de um servico (opcionalmente enviando uma sonda)."""
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((host, porta), timeout=timeout)
        sock.settimeout(timeout)
        if usar_tls:
            sock = _contexto_tls().wrap_socket(sock, server_hostname=None)
        if payload:
            sock.sendall(payload)
        bruto = _receber(sock, max_bytes)
    except (socket.timeout, ssl.SSLError, OSError, ValueError):
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    texto = bruto.decode("utf-8", "replace")
    return texto.replace("\x00", "").strip()


def detectar_http(
    host: str,
    porta: int,
    timeout: float = 1.5,
    usar_tls: bool = False,
) -> Optional[Dict[str, Any]]:
    """Envia ``HEAD /`` e interpreta a resposta HTTP (ou devolve ``None``)."""
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((host, porta), timeout=timeout)
        sock.settimeout(timeout)
        if usar_tls:
            sock = _contexto_tls().wrap_socket(sock, server_hostname=None)
        requisicao = (
            f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
            "User-Agent: IPLocator/2.0\r\nAccept: */*\r\n\r\n"
        )
        sock.sendall(requisicao.encode("ascii", "ignore"))
        bruto = _receber(sock, 4096)
    except (socket.timeout, ssl.SSLError, OSError, ValueError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    texto = bruto.decode("utf-8", "replace")
    if not texto.startswith("HTTP/"):
        return None
    produto, versao = identificar_produto(texto)
    cabecalhos = parse_cabecalhos_http(texto)
    return {
        "status": texto.split("\n")[0].strip(),
        "servidor": cabecalhos.get("server"),
        "produto": produto,
        "versao": versao,
        "cabecalhos": cabecalhos,
        "banner": texto[:512].strip(),
    }


def _aplicar_http(
    resultado: Dict[str, Any],
    resposta_http: Dict[str, Any],
    servico: str,
) -> Dict[str, Any]:
    """Mescla a resposta HTTP no resultado de deteccao."""
    resultado["http"] = {
        "status": resposta_http.get("status"),
        "servidor": resposta_http.get("servidor"),
        "cabecalhos": resposta_http.get("cabecalhos") or {},
    }
    if resposta_http.get("banner"):
        resultado["banner"] = resposta_http["banner"]
    if resposta_http.get("produto"):
        resultado["produto"] = resposta_http["produto"]
    if resposta_http.get("versao"):
        resultado["versao"] = resposta_http["versao"]
    if resultado["servico"] == "Desconhecido":
        resultado["servico"] = servico
    return resultado


def detectar_servico(
    host: str,
    porta: int,
    timeout: float = 1.5,
) -> Dict[str, Any]:
    """Identifica o servico de uma porta aberta.

    Estrategia: HTTP em claro -> TLS (+HTTP sobre TLS) -> banner cru. O
    resultado nunca levanta excecao; campos desconhecidos ficam ``None``.
    """
    porta = int(porta)
    resultado: Dict[str, Any] = {
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

    # 1) HTTP sem TLS (portas conhecidas por falar HTTP).
    if porta in PORTAS_HTTP:
        resposta = detectar_http(host, porta, timeout)
        if resposta is not None:
            return _aplicar_http(resultado, resposta, "HTTP")

    # 2) TLS: certificado, versao e, quando aplicavel, HTTP sobre TLS.
    if porta in PORTAS_TLS:
        tls = detectar_tls(host, porta, timeout)
        if tls is not None:
            resultado["tls"] = True
            resultado["certificado"] = tls.get("certificado")
            resultado["tls_versao"] = tls.get("versao")
            resultado["cifra"] = tls.get("cifra")
            if porta in PORTAS_HTTP_TLS:
                resposta = detectar_http(host, porta, timeout, usar_tls=True)
                if resposta is not None:
                    return _aplicar_http(resultado, resposta, "HTTPS")
            else:
                banner = ler_banner(host, porta, timeout, usar_tls=True)
                if banner:
                    resultado["banner"] = banner[:512]
                    produto, versao = identificar_produto(banner)
                    resultado["produto"], resultado["versao"] = produto, versao
            return resultado

    # 3) Banner cru (protocolos que falam primeiro: SSH, FTP, SMTP, MySQL...).
    banner = ler_banner(host, porta, timeout, payload=SONDAS.get(porta, b""))
    if banner.startswith("HTTP/"):
        cabecalhos = parse_cabecalhos_http(banner)
        produto, versao = identificar_produto(banner)
        return _aplicar_http(
            resultado,
            {
                "status": banner.split("\n")[0].strip(),
                "servidor": cabecalhos.get("server"),
                "produto": produto,
                "versao": versao,
                "cabecalhos": cabecalhos,
                "banner": banner[:512],
            },
            "HTTP",
        )
    if banner:
        resultado["banner"] = banner[:512]
        produto, versao = identificar_produto(banner)
        resultado["produto"], resultado["versao"] = produto, versao
        return resultado

    # 4) Porta desconhecida que nao falou nada: pode ser HTTPS silencioso.
    if porta not in PORTAS_TLS:
        tls = detectar_tls(host, porta, timeout)
        if tls is not None:
            resultado["tls"] = True
            resultado["certificado"] = tls.get("certificado")
            resultado["tls_versao"] = tls.get("versao")
            resultado["cifra"] = tls.get("cifra")
            resposta = detectar_http(host, porta, timeout, usar_tls=True)
            if resposta is not None:
                return _aplicar_http(resultado, resposta, "HTTPS")
    return resultado


def descrever_servico(info: Dict[str, Any]) -> str:
    """Resumo de uma linha usado pela CLI (ex.: ``SSH | OpenSSH 9.6 | TLS``)."""
    partes: List[str] = [str(info.get("servico") or "Desconhecido")]
    produto = info.get("produto")
    versao = info.get("versao")
    if produto:
        partes.append(f"{produto} {versao}".strip() if versao else str(produto))
    elif versao:
        partes.append(str(versao))
    if info.get("tls"):
        partes.append("TLS")
    certificado = info.get("certificado") or {}
    if isinstance(certificado, dict) and certificado.get("cn"):
        partes.append(f"CN={certificado['cn']}")
    if info.get("http") and info["http"].get("status"):
        partes.append(str(info["http"]["status"]))
    return " | ".join(partes)

