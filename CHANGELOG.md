# Changelog

Todas as mudanças relevantes deste projeto são documentadas neste arquivo.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/)
(`MAJOR.MINOR.PATCH`). Cada release corresponde a uma tag `vX.Y.Z`, e as notas
publicadas no GitHub são extraídas da seção correspondente abaixo.

## [Não lançado]

### Corrigido

- CI: a matriz do Python 3.9 passou a rodar em `ubuntu-22.04`, porque a imagem
  `ubuntu-latest` não disponibiliza mais essa versão.
- Pyright passou a resolver as dependências pelo venv do projeto
  (`venvPath`/`venv` no `pyproject.toml`), eliminando falsos positivos de
  import quando o ambiente não está ativado no terminal.

## [2.0.0] - 2026-11-10

Primeira release versionada: o script monofile vira um pacote reutilizável, ganha
interface web, cache persistente, múltiplos provedores de geolocalização,
detecção de serviços e WHOIS/RDAP.

### Adicionado

- Pacote **`iplocator_core`** importável, separando cache, geolocalização, scanner,
  detecção de serviços, WHOIS, validação e servidor HTTP.
- **Seis provedores de geolocalização** com *fallback* automático e saída
  normalizada: `ip-api`, `ipwho.is`, `ipapi.co`, `ipinfo.io`, `freeipapi` e `geojs`.
- **Cache de resultados** com TTL por namespace (`geo` 24 h, `whois` 12 h,
  `dns` 10 min, `scan` 5 min), política **LRU**, persistência atômica em
  `~/.cache/iplocator/` e estatísticas de hit/miss/taxa de acerto.
- **Detecção de serviços** nas portas abertas: catálogo de 68 portas, *banner
  grabbing*, sondas ativas (Redis, Memcached, SMTP), `HEAD` HTTP e handshake TLS
  com leitura de certificado (CN, SAN, emissor, validade).
- **Integração WHOIS/RDAP**: RDAP sobre HTTPS com *fallback* para o WHOIS
  clássico na porta 43 (referência do IANA e servidores de TLD).
- **Interface web estática em Vue 3** (sem etapa de build) com abas de
  geolocalização, portas, WHOIS e cache, servida pelo próprio projeto.
- **API HTTP local** (`/api/health`, `/api/providers`, `/api/ports`, `/api/geo`,
  `/api/scan`, `/api/whois`, `/api/cache`) com CORS, códigos de erro semânticos e
  proteção contra *path traversal*; limite de 4.096 portas por requisição.
- **CLI ampliada**: `--serve`, `--geo`, `--whois`, `--scan`, `--mode`, `--start`,
  `--end`, `--timeout`, `--no-services`, `--providers`, `--https`, `--json`,
  `--no-cache`, `--clear-cache`, `--verbose` e `--version`.
- **Suíte de testes offline** em `pytest` (dublês de rede, servidor TCP e HTTP
  locais) e **verificação de tipos com Pyright** (`iplocator_core/protocols.py`).
- **Empacotamento** com `pyproject.toml`, entry point `iplocator` e `web/` incluído
  no wheel (`share/iplocator/web`), permitindo `pip install` a partir da release.

### Alterado

- `iplocator.py` passou a ser apenas a camada de apresentação (menu + comandos),
  delegando a lógica ao pacote `iplocator_core`.
- `scan_intervalo`/`scan_portas_comuns` usam `ThreadPoolExecutor` e passaram a
  aceitar `detectar_servicos` e `usar_cache`.
- `requirements.txt` regravado em UTF-8 (a versão anterior estava em UTF-16 e
  quebrava o `pip install -r`) incluindo `pyfiglet`.
- `is_ip_reservado` passou a usar `ipaddress.is_global`, cobrindo CGNAT
  (`100.64/10`), link-local, multicast e faixas de documentação.

### Corrigido

- URL do RDAP usava o segmento `dominio` (404) em vez de `domain`.
- `menu_servidor` levantava `NameError` por falta do import de `pathlib.Path`
  (opção 6 do menu e `--serve` a partir do menu).
- Assinatura de `log_message` incompatível com `BaseHTTPRequestHandler`.
- Arquivo de cache corrompido ou de versão desconhecida agora é ignorado em vez
  de derrubar a execução.

### Compatibilidade

- `from iplocator import IPLocator, PortScanner` continua funcionando, com os
  mesmos métodos públicos e o mesmo formato de retorno (`dict` no sucesso,
  `str` iniciando em "Erro" na falha).
- Nenhuma release anterior foi tagueada: 2.0.0 é a primeira versão publicada e
  engloba também o histórico do script monofile.

### Requisitos

- Python 3.9+ (testado em 3.14), `requests>=2.28` e `pyfiglet>=0.8`.
