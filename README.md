# 🌍 IP-Locator

**Ferramenta OSINT em Python** para geolocalização de IPs/domínios, scanner de portas com detecção de serviços e consulta WHOIS/RDAP — com **CLI interativa**, **comandos de linha de comando** e **interface web estática em Vue 3** (sem etapa de build).

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT-green.svg)](LICENSE)
[![Testes](https://img.shields.io/badge/testes-236%20passando-brightgreen.svg)](#-testes)
[![Vue](https://img.shields.io/badge/Vue-3%20(CDN)-42b883.svg)](https://vuejs.org/)

> ⚠️ Use apenas em redes próprias ou com autorização explícita. Veja [Limitações e ética](#-limitações-e-ética).

## 📋 Índice

- [Destaques](#-destaques)
- [Arquitetura](#-arquitetura)
- [Instalação](#-instalação)
- [Uso rápido](#-uso-rápido)
- [Interface web (Vue)](#-interface-web-vue)
- [CLI](#-cli)
- [Cache de resultados](#-cache-de-resultados)
- [Provedores de geolocalização](#-provedores-de-geolocalização)
- [Detecção de serviços](#-detecção-de-serviços)
- [WHOIS / RDAP](#-whois--rdap)
- [API HTTP](#-api-http)
- [Testes](#-testes)
- [Limitações e ética](#-limitações-e-ética)
- [Contribuição](#-contribuição)
- [Licença](#-licença)

## ✨ Destaques

| Recurso | O que faz |
| --- | --- |
| 🌐 **6 provedores de geolocalização** | `ip-api`, `ipwho.is`, `ipapi.co`, `ipinfo.io`, `freeipapi` e `geojs`, com *fallback* automático e saída normalizada |
| 🗃️ **Cache inteligente** | TTL por namespace, política LRU, persistência atômica em disco, estatísticas de hit/miss e limpeza via CLI/API/UI |
| 🔍 **Scanner com detecção de serviços** | 68 portas catalogadas, *banner grabbing*, HTTP `HEAD` e handshake TLS com leitura de certificado (CN/SAN/emissor) |
| 📇 **WHOIS + RDAP** | Consulta RDAP (JSON) com *fallback* para o WHOIS clássico na porta 43, seguindo a referência do IANA |
| 🖥️ **Interface web estática** | Vue 3 via CDN, sem bundler: abas de geolocalização, portas, WHOIS e cache servidas por uma API local em `http.server` |
| 🧪 **236 testes** | `pytest` cobrindo parsers, cache, fallback, scanner, WHOIS, API e CLI — **nenhum teste acessa a internet** |
| 🧩 **Compatível com a v1** | `IPLocator` e `PortScanner` continuam importáveis de `iplocator.py` com os mesmos métodos |

## 🏗️ Arquitetura

```
iplocator/
├── iplocator.py               # CLI (menu interativo + subcomandos) e reexports da v1
├── iplocator_core/            # núcleo reaproveitável (importável isoladamente)
│   ├── api.py                 # servidor HTTP (stdlib) + API JSON + arquivos estáticos
│   ├── cache.py               # TTLCache e CacheManager (TTL, LRU, disco, estatísticas)
│   ├── geo.py                 # 6 provedores de geolocalização + fallback + cache
│   ├── http.py                # sessão requests compartilhada (retry/backoff, UA)
│   ├── protocols.py           # Protocols de injeção (sessão/localizador/WHOIS)
│   ├── scanner.py             # scanner multithread (ThreadPoolExecutor) + cache
│   ├── services.py            # banner grabbing, HTTP, TLS e catálogo de portas
│   ├── validation.py          # validação/resolução de IP e domínio
│   ├── version.py             # versão única do projeto
│   └── whois.py               # RDAP + WHOIS porta 43 (parsers puros e testáveis)
├── web/                       # interface estática Vue 3 (sem build)
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── tests/                     # suíte pytest (236 testes, 100% offline)
├── requirements.txt           # dependências de execução
├── requirements-dev.txt       # dependências de desenvolvimento (pytest, pyright)
├── pyproject.toml             # empacotamento, entry point `iplocator`, pytest e Pyright
└── .vscode/settings.json      # interpretador do venv, extraPaths e pytest no editor
```

**Fluxo de dados**

```
iplocator.py (CLI)  ─┐
                     ├─▶  iplocator_core.geo.IPLocator  ─▶  6 provedores HTTP  ─▶  CacheManager
iplocator_core.api  ─┘        iplocator_core.scanner      ─▶  services (banner/TLS)
   (servidor)                 iplocator_core.whois        ─▶  RDAP ──▶ porta 43
```

A interface em `web/` consome a mesma API JSON usada pelos testes, então CLI e UI
compartilham exatamente a mesma lógica de negócio.

## 📦 Instalação

### Pré-requisitos

- **Python 3.9+** (desenvolvido e testado em 3.14)
- **Conexão com internet** para as consultas de geolocalização/WHOIS (os testes não precisam)
- `curl`/navegador apenas para acessar a interface web

### Passos

```bash
git clone https://github.com/SpetsnazBR/iplocator.git
cd iplocator

# 1) Ambiente virtual (recomendado)
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2) Dependências de execução
pip install -r requirements.txt     # requests + pyfiglet

# 3a) Rodar direto do repositório
python iplocator.py

# 3b) ...ou instalar como comando (entry point `iplocator`)
pip install -e .
iplocator --version
```

Para desenvolvimento/testes:

```bash
pip install -r requirements-dev.txt   # inclui pytest
# ou: pip install -e ".[dev]"
```

## 🚀 Uso rápido

```bash
# Menu interativo (CLI clássica)
python iplocator.py

# Geolocalização pontual
python iplocator.py --geo 8.8.8.8
python iplocator.py --geo github.com --json

# Escolher/limitar provedores (ordem = ordem de tentativa)
python iplocator.py --geo 1.1.1.1 --providers ipwho.is,ipinfo.io

# Scanner de portas
python iplocator.py --scan 1.1.1.1 --mode comuns
python iplocator.py --scan 192.168.0.10 --mode intervalo --start 1 --end 1024
python iplocator.py --scan example.com --mode comuns --no-services --json

# WHOIS/RDAP
python iplocator.py --whois 8.8.8.8
python iplocator.py --whois github.com --json

# Interface web (Vue) em http://127.0.0.1:8000
python iplocator.py --serve
python iplocator.py --serve --host 0.0.0.0 --port 9000 --verbose

# Cache
python iplocator.py --clear-cache     # limpa tudo
python iplocator.py --no-cache        # ignora o cache nesta execução
```

### Saída de geolocalização

```
$ python iplocator.py --geo 1.1.1.1

=== Dados do IP ===
Provedor     : ip-api
País         : Australia
Código       : AU
Região       : Queensland
Cidade       : South Brisbane
CEP          : 4101
Latitude     : -27.4766
Longitude    : 153.0166
Fuso         : Australia/Brisbane
ISP          : Cloudflare, Inc
Organização  : APNIC and Cloudflare DNS Resolver project
ASN          : AS13335 Cloudflare, Inc.
Mapa         : https://www.google.com/maps?q=-27.4766,153.0166
```


## 🖥️ Interface web (Vue)

```bash
python iplocator.py --serve            # http://127.0.0.1:8000
```

A página é **estática** (HTML + JS + CSS) e usa **Vue 3 via CDN**, sem `npm`,
bundler ou etapa de build. O servidor embutido (`http.server`) faz duas coisas:

1. entrega `web/` (rota `/`) com tipos MIME corretos e proteção contra *path traversal*;
2. expõe a API JSON em `/api/*` usada pela página.

### Abas disponíveis

| Aba | O que mostra |
| --- | --- |
| **Geolocalização** | IP resolvido, país/região/cidade, coordenadas, ISP/ASN, provedor que respondeu, selo de cache, links de mapa e detalhes dos provedores que falharam |
| **Portas** | tabela com porta, serviço, produto/versão detectados, versão de TLS e banner/certificado; suporta portas comuns ou intervalo |
| **WHOIS** | handle, organização, país, intervalo, datas de registro/expiração, contato de abuso e a resposta bruta |
| **Cache** | entradas, hits/misses, taxa de acerto, TTL e contadores por namespace, com botão para limpar |

Recursos adicionais da UI:

- indicador de conexão com a API (com botão **reconectar**);
- checkboxes para escolher os provedores de geolocalização (ordem de *fallback*);
- botões **copiar JSON** em cada cartão;
- tema escuro responsivo, *toasts* e estados de carregamento;
- funciona também aberta via `file://` (o backend libera CORS): nesse caso a UI
  aponta para `http://127.0.0.1:8000`. Use `?api=http://host:porta` para outro endereço.

> O CDN do Vue exige internet no navegador. Sem rede, a página exibe uma mensagem
> indicando o uso da CLI (`python iplocator.py --geo 8.8.8.8`).

## ⌨️ CLI

### Menu interativo

```bash
python iplocator.py
```

```
=== MENU ===
1 – Localizar IP / domínio
2 – Escanear intervalo de portas
3 – Escanear portas comuns
4 – Consultar WHOIS / RDAP
5 – Cache (estatísticas / limpar)
6 – Abrir interface web (servidor local)
0 – Sair
```

### Flags

| Flag | Descrição |
| --- | --- |
| `--geo ALVO` | geolocaliza um IP ou domínio |
| `--whois ALVO` | consulta WHOIS/RDAP |
| `--scan ALVO` | escaneia portas do alvo |
| `--mode {comuns,intervalo}` | modo do scan (padrão `comuns`) |
| `--start` / `--end` | intervalo de portas (padrão `1`–`1024`) |
| `--timeout` | timeout por porta em segundos (padrão `1.0`) |
| `--no-services` | desliga a detecção de serviços (scan bruto mais rápido) |
| `--providers LISTA` | provedores de geolocalização separados por vírgula |
| `--https` | usa HTTPS no ip-api (o plano gratuito responde HTTP) |
| `--json` | saída em JSON (ideal para pipes/jq) |
| `--serve` `--host` `--port` | sobem a API + interface web (padrão `127.0.0.1:8000`) |
| `--no-cache` | ignora cache nesta execução |
| `--clear-cache` | limpa o cache e encerra |
| `--verbose` | log detalhado do servidor HTTP |
| `--version` | mostra a versão |

### Compatibilidade com a v1

Os nomes públicos continuam disponíveis:

```python
from iplocator import IPLocator, PortScanner

locator = IPLocator()                 # use_https=True também funciona
print(locator.localizar("8.8.8.8"))   # dict no sucesso, str "Erro: ..." na falha

scanner = PortScanner(timeout=1.0, max_threads=50)
print(scanner.scan_portas_comuns("127.0.0.1"))
```

Também é possível importar direto do núcleo:

```python
from iplocator_core import CacheManager, IPLocator, PortScanner, WhoisClient

cache = CacheManager()
locator = IPLocator(cache=cache)
whois = WhoisClient(cache=cache)
```


## 🗃️ Cache de resultados

O cache vive em `iplocator_core/cache.py` e é compartilhado por geolocalização,
WHOIS, DNS e scans.

- **TTL por namespace** — cada tipo de dado expira no seu ritmo:

  | Namespace | TTL padrão | Usado por |
  | --- | --- | --- |
  | `geo` | 24 h | resultados de geolocalização (chave = IP) |
  | `whois` | 12 h | RDAP/WHOIS (chave = `ip:8.8.8.8` ou `dominio:github.com`) |
  | `dns` | 10 min | resolução domínio → IP |
  | `scan` | 5 min | resultados de varredura (chave = host + intervalo + serviços) |

- **LRU com limite** — 256 entradas por namespace; ao exceder, a menos usada é descartada.
- **Persistência atômica** — um JSON por namespace em `~/.cache/iplocator/`
  (respeita `XDG_CACHE_HOME`), gravado com arquivo temporário + `os.replace`.
  Arquivos corrompidos ou de versão desconhecida são simplesmente ignorados.
- **Resiliência** — qualquer falha de I/O é silenciada: o cache é otimização, nunca
  ponto de falha. O status `cache: true` aparece no resultado quando houve acerto.
- **Observabilidade** — `hits`, `misses`, `expirados`, `evictions`, `taxa_acerto`
  e contadores por namespace, visíveis na aba **Cache** e em `--geo ... --json`.

### Configuração por ambiente

| Variável | Efeito |
| --- | --- |
| `IPLOCATOR_CACHE_DIR` | diretório dos arquivos de cache |
| `IPLOCATOR_CACHE_TTL` | TTL padrão (segundos) para namespaces não listados |
| `IPLOCATOR_CACHE_DISABLED` | `1`/`true` desliga o cache completamente |

```bash
IPLOCATOR_CACHE_DIR=/tmp/iplocator-cache python iplocator.py --geo 8.8.8.8
python iplocator.py --no-cache --geo 8.8.8.8     # ignora leitura e escrita
python iplocator.py --clear-cache                # limpa todos os namespaces
curl 'http://127.0.0.1:8000/api/cache' -X DELETE # limpeza via API
```

## 🌐 Provedores de geolocalização

A ordem abaixo é a ordem de tentativa; o primeiro que responder com sucesso vence,
e os demais nem são chamados. A saída é sempre **normalizada** para as mesmas chaves
(`country`, `countryCode`, `region`, `regionName`, `city`, `zip`, `lat`, `lon`,
`timezone`, `isp`, `org`, `as`, `query`), acrescentando `provider`, `cache`,
`maps_url` e `osm_url`.

| # | Provedor | Endpoint | Observações |
| --- | --- | --- | --- |
| 1 | `ip-api` | `ip-api.com/json/{ip}` | HTTP no plano gratuito (45 req/min ⇒ *pacing* de 1,2 s); `--https` usa TLS |
| 2 | `ipwho.is` | `ipwho.is/{ip}` | HTTPS, sem chave, traz ASN/organização |
| 3 | `ipapi.co` | `ipapi.co/{ip}/json/` | HTTPS, limite por minuto |
| 4 | `ipinfo.io` | `ipinfo.io/{ip}/json` | HTTPS; `loc` é convertido em `lat`/`lon` |
| 5 | `freeipapi` | `freeipapi.com/api/json/{ip}` | HTTPS, sem ASN |
| 6 | `geojs` | `get.geojs.io/v1/ip/geo/{ip}.json` | HTTPS, coordenação em texto convertida para número |

```bash
python iplocator.py --geo 8.8.8.8 --providers ipwho.is,geojs   # só estes dois, nesta ordem
curl 'http://127.0.0.1:8000/api/geo?target=8.8.8.8&providers=ipinfo.io'
```

Detalhes de implementação:

- sessão `requests` compartilhada com `Retry` (429/5xx, backoff) e `User-Agent` próprio;
- erros viram itens em `erros[]` (`{"provider": ..., "erro": ...}`) sem interromper a cadeia;
- `timeout`, `Referer`/`Accept` e *pacing* por provedor são configuráveis no construtor de `IPLocator`;
- IPs privados/reservados e domínios que resolvem para eles são rejeitados antes de qualquer requisição
  (`ipaddress.is_global` como critério, o que cobre `10/8`, `172.16/12`, `192.168/16`, `100.64/10`,
  loopback, link-local, multicast e faixas de documentação).

## 🔍 Detecção de serviços

O scanner (`iplocator_core/scanner.py`) usa `ThreadPoolExecutor` (50 workers por padrão)
e, para cada porta aberta, o módulo `services.py` tenta identificar o serviço em três frentes:

1. **HTTP em texto claro** — envia `HEAD / HTTP/1.0` e lê status, cabeçalho `Server` e produto;
2. **TLS** — handshake permissivo (sem validar CA) para capturar versão/cifra e o certificado
   (CN, organização, emissor, validade, SANs), com `HEAD` sobre TLS nas portas web;
3. **Banner cru** — leitura do que o serviço fala primeiro (SSH, FTP, SMTP, MySQL, VNC...)
   e sondas ativas quando necessário (`PING` no Redis, `version` no Memcached, `EHLO` no SMTP).

O catálogo cobre **68 portas** (21, 22, 25, 53, 80/443, 445, 993, 1433, 3306, 3389,
5432, 6379, 8080, 8443, 9200, 27017, entre outras). Produto e versão saem de
regexes sobre o banner (`OpenSSH_9.6p1`, `nginx/1.24.0`, `vSFTPd 3.0.5`, `Postfix`...).

```bash
python iplocator.py --scan 127.0.0.1 --mode comuns
python iplocator.py --scan example.com --mode intervalo --start 8000 --end 8100 --json
```

```
=== Portas abertas em 127.0.0.1 ===
    631  IPP | CUPS/2.4
```

O resultado estruturado (`/api/scan` ou `--json`) traz, por porta:
`porta`, `servico`, `banner`, `produto`, `versao`, `tls`, `tls_versao`, `cifra`,
`certificado{cn, san, emissor, valido_de, valido_ate}` e `http{status, servidor}`.

## 📇 WHOIS / RDAP

`WhoisClient` consulta **RDAP** (`https://rdap.org/{ip|domain}/{alvo}`, JSON sobre HTTPS)
e, se não houver registro ou ocorrer erro, cai para o **WHOIS clássico na porta 43**
seguindo a linha `refer:` do IANA (ou o servidor do TLD, quando conhecido).

Campos normalizados: `handles`, `nome`, `tipo`, `organizacao`, `pais`, `status`,
`intervalo{inicio,fim,versao_ip}`, `eventos{registration,last changed,...}`,
`entidades[{handle,nome,papeis,email}]`, `observacoes`, `links`, `abuse_contato`, `bruto`.

```bash
python iplocator.py --whois 8.8.8.8
python iplocator.py --whois github.com --json
curl 'http://127.0.0.1:8000/api/whois?target=github.com'
```

```
=== WHOIS / RDAP ===
Fonte        : rdap
Handle       : 1264983250_DOMAIN_COM-VRSN
Nome         : GITHUB.COM
Organização  : MarkMonitor Inc.
registration : 2007-10-09T18:20:50Z
expiration   : 2028-10-09T18:20:50Z
```

Os parsers (`parse_rdap`, `parse_whois_texto`) são funções **puras** — recebem
texto/JSON e devolvem dicionário —, o que permite testá-los sem rede.


## 🌐 API HTTP

Base: `http://127.0.0.1:8000` (ou o `--host/--port` escolhido). Todas as respostas
são JSON com `ok: true|false`, cabeçalho `Access-Control-Allow-Origin: *` e
`Cache-Control: no-store`.

| Método | Rota | Parâmetros | Descrição |
| --- | --- | --- | --- |
| `GET` | `/api/health` | — | versão, uptime, provedores ativos e estado do cache |
| `GET` | `/api/providers` | — | provedores disponíveis e ordem ativa |
| `GET` | `/api/ports` | — | catálogo de 68 portas conhecidas |
| `GET` | `/api/geo` | `target` (ou `alvo`), `providers` | geolocalização com fallback |
| `GET` | `/api/whois` | `target` | WHOIS/RDAP |
| `GET` | `/api/scan` | `target`, `mode`, `start`, `end`, `services`, `timeout` | scanner com detecção de serviços |
| `GET` | `/api/cache` | — | estatísticas do cache |
| `DELETE` | `/api/cache` | — | limpa o cache e devolve o total removido |
| `GET` | `/`, `/app.js`, `/styles.css` | — | interface estática |

No `/api/scan`, `mode` aceita `comuns` (catálogo) ou `intervalo` (usa `start`/`end`);
`services=0` desliga a detecção e `timeout` é limitado a `0.1`–`10` segundos.

Códigos de retorno: `200` sucesso, `400` parâmetro inválido (inclusive intervalo
acima de **4096 portas** por requisição), `404` rota/arquivo inexistente,
`422` alvo inválido ou DNS não resolvido e `502` quando todas as fontes externas falham.

```bash
curl -s http://127.0.0.1:8000/api/health
curl -s 'http://127.0.0.1:8000/api/geo?target=8.8.8.8&providers=ipwho.is'
curl -s 'http://127.0.0.1:8000/api/scan?target=127.0.0.1&mode=comuns&services=0'
curl -s 'http://127.0.0.1:8000/api/whois?target=8.8.8.8'
curl -s http://127.0.0.1:8000/api/cache
curl -s -X DELETE http://127.0.0.1:8000/api/cache
```

Exemplo de resposta de `/api/geo` (campos abreviados):

```json
{
  "ok": true,
  "alvo": "8.8.8.8",
  "ip": "8.8.8.8",
  "provedor": "ip-api",
  "cache": false,
  "erros": [],
  "dados": {
    "query": "8.8.8.8",
    "country": "United States",
    "countryCode": "US",
    "regionName": "Virginia",
    "city": "Ashburn",
    "zip": "20149",
    "lat": 39.03,
    "lon": -77.5,
    "timezone": "America/New_York",
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "as": "AS15169 Google LLC",
    "provider": "ip-api",
    "cache": false,
    "maps_url": "https://www.google.com/maps?q=39.03,-77.5",
    "osm_url": "https://www.openstreetmap.org/?mlat=39.03&mlon=-77.5#map=12/39.03/-77.5"
  }
}
```

## 🧪 Testes

```bash
pip install -r requirements-dev.txt
python -m pytest                 # 236 testes
python -m pytest -q tests/test_cache.py
python -m pytest -k "fallback or cache" -v
```

A suíte é **determinística e offline**: nenhum teste abre conexão externa.
Para isso são usados:

- `tests/apoio.py` — `SessaoFalsa`/`RespostaFalsa` (dublês de `requests.Session`
  com payloads reais de cada provedor, RDAP e WHOIS);
- `tests/conftest.py` — fixtures de `CacheManager` em `tmp_path`, servidor TCP local
  que emite banner (`ServidorBanner`), porta fechada garantida e isolamento do
  `IPLOCATOR_CACHE_DIR` (nada é gravado no home do usuário);
- `http.server` real em `127.0.0.1:0` para validar detecção HTTP e o servidor da API.

| Arquivo | Cobertura |
| --- | --- |
| `test_validation.py` | IPv4/IPv6, reservados, domínios, normalização e DNS |
| `test_cache.py` | TTL, LRU, persistência, arquivo corrompido, env vars, estatísticas |
| `test_geo.py` | os 6 parsers, erros de provedor, fallback, cache, DNS, rate limit |
| `test_services.py` | catálogo, regex de produto, banner, HTTP e descrição |
| `test_scanner.py` | limites de intervalo, portas comuns/intervalo, cache, serviço real |
| `test_whois.py` | `parse_rdap`, `parse_whois_texto`, RDAP→porta 43, cache, erros |
| `test_web_api.py` | todos os endpoints, códigos de erro, CORS, estáticos, traversal |
| `test_cli.py` | parser, formatação, `--json`, menu, `--clear-cache`, `--serve` |

### Verificação de tipos

O projeto usa **Pyright** (o mesmo motor do **Pylance** no VS Code) em modo `basic`,
configurado em `[tool.pyright]` do `pyproject.toml`:

```bash
pip install -r requirements-dev.txt     # pytest + pyright
python -m pyright                       # 0 errors, 0 warnings
```

Os pontos de injeção de dependência (sessão HTTP, localizador e cliente WHOIS) são
descritos por **Protocols** (`iplocator_core/protocols.py`), então os dublês da suíte
são validados estruturalmente — o editor e os testes concordam sobre os tipos.

### Sublinhados vermelhos no VS Code

Se os `.py` aparecerem com linhas vermelhas, na ordem de probabilidade:

1. **Interpretador errado** — o Pylance está usando o Python do sistema, que não tem
   `requests`/`pyfiglet`/`pytest` instalados. Confirme em *Python: Select Interpreter*
   que está escolhido `.venv/bin/python` (o `.vscode/settings.json` do repositório já
   aponta para ele). Sintoma típico: *“Import 'requests' could not be resolved”*.
2. **Ambiente não instalado** — rode `pip install -r requirements-dev.txt` dentro do venv.
3. **Erro real de tipo/código** — rode `python -m pyright` e `python -m pytest`:
   é a mesma checagem que o editor faz, mas com saída no terminal.

O `.vscode/settings.json` versionado define interpretador, `extraPaths`
(`.` e `tests/`), modo de checagem e a integração do pytest com a pasta `tests/`.



## ⚠️ Limitações e ética

### Limitações técnicas

1. **Rate limits** — `ip-api` (45 req/min no plano gratuito) e os demais provedores
   têm limites próprios; o *pacing* reduz erros 429, mas não os elimina.
2. **Precisão** — geolocalização por IP é aproximada (cidade/provedor), nunca endereço exato.
3. **IPv6** — a validação aceita IPv6, mas a maioria dos provedores gratuitos
   devolve dados incompletos para esses endereços.
4. **Scan** — portas altas/intervalos grandes dependem do timeout; sem `--no-services`
   cada porta aberta recebe sondas adicionais. A API limita 4.096 portas por requisição.
5. **WHOIS** — alguns registros estão atrás de captcha/limite; nesses casos a consulta
   pode falhar mesmo com RDAP e porta 43 disponíveis.
6. **Vue via CDN** — a interface precisa de internet no navegador (a CLI não).

### Considerações éticas e legais

> **Aviso**: use esta ferramenta apenas em sistemas próprios ou com autorização
> escrita. Acessar/escanear sistemas de terceiros sem permissão pode ser crime.

1. Escaneamento de portas pode ser interpretado como tentativa de intrusão.
2. Respeite a privacidade e os termos de serviço das APIs utilizadas.
3. Não use os dados para perseguição, doxxing ou vigilância.
4. Verifique a legislação local antes de qualquer uso.

## 🤝 Contribuição

1. Faça um *fork* e crie uma branch: `git checkout -b feat/minha-feature`
2. Rode os testes antes de abrir o PR: `python -m pytest`
3. Mantenha o padrão **Conventional Commits** em português, no imperativo e com escopo:

   ```
   feat(geo): adiciona provedor geojs ao fallback
   fix(whois): corrige segmento RDAP para dominios
   perf(cache): evita regravacao completa do arquivo
   test(scanner): cobre timeout de servico
   docs(readme): documenta a interface web
   chore(deps): atualiza requests
   ```

4. Um assunto por commit; use o corpo para explicar o *motivo* quando não for óbvio.

### Roadmap

- [x] Cache de resultados (TTL + LRU + disco + estatísticas)
- [x] Mais APIs de geolocalização (6 provedores com fallback)
- [x] Detecção de serviços nas portas (banner, HTTP, TLS)
- [x] Integração com WHOIS/RDAP
- [x] Interface gráfica (página estática com Vue 3)
- [ ] Exportação de resultados (CSV/JSON em arquivo)
- [ ] Suporte a proxy
- [ ] Streaming do scan via WebSocket

## 📄 Licença

Distribuído sob a licença **MIT** — veja [LICENSE](LICENSE).

## 📞 Suporte

- Documentação das APIs: [ip-api](https://ip-api.com/docs), [ipwho.is](https://ipwho.is),
  [ipapi.co](https://ipapi.co/api/), [ipinfo.io](https://ipinfo.io/developers),
  [freeipapi](https://freeipapi.com), [geojs](https://get.geojs.io/), [RDAP](https://rdap.org)
- Problemas ou sugestões: abra uma *issue* no repositório

## ⭐ Reconhecimentos

- [ip-api.com](https://ip-api.com/) e demais provedores gratuitos de geolocalização
- [Vue.js](https://vuejs.org/) pela interface reativa sem etapa de build
- Comunidade Python pelas bibliotecas `requests` e `pyfiglet`

---

**Nota**: ferramenta fornecida "como está", sem garantias de qualquer tipo. O autor
não se responsabiliza pelo uso indevido. Use com responsabilidade e dentro da lei.

**Última atualização**: Novembro de 2026

