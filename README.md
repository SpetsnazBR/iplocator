# 🌍 IP-Locator - Ferramenta OSINT de Geolocalização e Scanner de Portas

Uma ferramenta Python para geolocalização de IPs e domínios, combinada com scanner de portas multithread. Ideal para análises OSINT, pentesting e administração de redes.

## 📋 Índice

- [Funcionalidades](#funcionalidades)
- [Instalação](#instalação)
- [Uso](#uso)
- [Classes e Métodos](#classes-e-métodos)
- [Exemplos de Uso](#exemplos-de-uso)
- [API Utilizada](#api-utilizada)
- [Limitações e Considerações](#limitações-e-considerações)
- [Contribuição](#contribuição)
- [Licença](#licença)

## 🚀 Funcionalidades

### 🌐 Geolocalização de IPs
- **Suporte a IPv4 e IPv6**: Validação completa de endereços IP
- **Resolução de Domínios**: Converte domínios em IPs automaticamente
- **Detecção de IPs Reservados**: Identifica IPs privados e locais
- **Informações Geográficas**:
  - País, região e cidade
  - Código postal
  - Fuso horário
  - Coordenadas (latitude/longitude)
  - Links para Google Maps e OpenStreetMap
- **Informações de Rede**:
  - Provedor de Internet (ISP)
  - Organização
  - ASN (Sistema Autônomo)

### 🔍 Scanner de Portas
- **Multithreading**: Scan rápido com múltiplas threads
- **Portas Comuns**: Scan das 20 portas mais utilizadas
- **Scan Completo**: Portas 1-1024
- **Scan Personalizado**: Intervalo de portas definido pelo usuário
- **Identificação de Serviços**: Nome dos serviços para portas conhecidas

### 🛡️ Recursos de Segurança
- **Rate Limiting**: Limitação automática de requisições (1 requisição/segundo)
- **Validação de Entrada**: Verificação rigorosa de IPs e domínios
- **Tratamento de Erros**: Mensagens de erro claras e informativas
- **Timeout Configurável**: Prevenção de travamentos

## 📦 Instalação

### Pré-requisitos
- Python 3.7 ou superior
- Conexão com internet

### Passos de Instalação

1. **Clone o repositório** (se aplicável):
   ```bash
   git clone https://github.com/seu-usuario/ip-locator.git
   cd ip-locator
   ```

2. **Instale as dependências**:
   ```bash
   pip install requests
   ```

3. **Execute o script**:
   ```bash
   python iplocator.py
   ```

## 🎮 Uso

### Interface de Linha de Comando

Execute o script para acessar o menu interativo:

```bash
python iplocator.py
```

### Menu Principal

```
🌍 LOCALIZADOR DE IP GEOGRÁFICO + SCANNER DE PORTAS - FERRAMENTA OSINT
--------------------------------------------------------------------
[i] Digite 'sair' para encerrar
[i] Suporta IPs (IPv4/IPv6) e domínios (ex: google.com)
[i] Usando API HTTP (45 requisições/minuto)
[i] Scanner de portas com suporte a multithreading
--------------------------------------------------------------------

==============================
MENU PRINCIPAL
==============================
1. Localizar IP/Domínio
2. Scan de portas comuns
3. Scan completo de portas (1-1024)
4. Scan personalizado de portas
5. Sair
==============================
```

### Opções Disponíveis

1. **Localizar IP/Domínio**: Obtém informações geográficas de um IP ou domínio
2. **Scan de portas comuns**: Escaneia as 20 portas mais utilizadas
3. **Scan completo de portas**: Escaneia todas as portas de 1 a 1024
4. **Scan personalizado de portas**: Escaneia um intervalo específico de portas
5. **Sair**: Encerra o programa

## 🏗️ Classes e Métodos

### Classe `IPLocator`

Classe principal para geolocalização de IPs.

#### Métodos Principais:

- `__init__(use_https=False)`: Inicializa o localizador
- `validar_ip(ip)`: Valida endereços IPv4 e IPv6
- `is_ip_reservado(ip)`: Verifica se o IP é reservado/privado
- `resolver_dominio(dominio)`: Resolve domínio para IP
- `localizar(alvo)`: Localiza informações geográficas

### Classe `PortScanner`

Classe para escaneamento de portas.

#### Métodos Principais:

- `__init__(timeout=1.0, max_threads=50)`: Inicializa o scanner
- `testar_porta(host, porta)`: Testa uma porta específica
- `scan_porta(host, porta)`: Escaneia uma porta (usado por threads)
- `scan_intervalo(host, inicio=1, fim=1024)`: Escaneia um intervalo de portas
- `scan_portas_comuns(host)`: Escaneia portas comuns

### Funções Auxiliares

- `exibir_resultado(info)`: Exibe informações formatadas
- `menu()`: Interface de menu interativo

## 📝 Exemplos de Uso

### Exemplo 1: Localização de IP

```python
from iplocator import IPLocator

locator = IPLocator()
resultado = locator.localizar("8.8.8.8")

if isinstance(resultado, dict):
    print(f"País: {resultado.get('country')}")
    print(f"Cidade: {resultado.get('city')}")
    print(f"ISP: {resultado.get('isp')}")
else:
    print(f"Erro: {resultado}")
```

### Exemplo 2: Scanner de Portas

```python
from iplocator import PortScanner

scanner = PortScanner(timeout=0.5, max_threads=100)
portas_abertas = scanner.scan_portas_comuns("example.com")

print(f"Portas abertas: {portas_abertas}")
```

### Exemplo 3: Uso Programático Completo

```python
from iplocator import IPLocator, PortScanner, exibir_resultado

# Localizar IP
locator = IPLocator(use_https=True)
info = locator.localizar("google.com")

if isinstance(info, dict):
    exibir_resultado(info)
    
    # Scanner de portas no mesmo IP
    scanner = PortScanner()
    portas = scanner.scan_portas_comuns(info.get('query'))
    
    print(f"\nPortas abertas: {portas}")
```

## 🌐 API Utilizada

A ferramenta utiliza a API pública gratuita do [ip-api.com](https://ip-api.com/):

- **Limite**: 45 requisições por minuto (HTTP)
- **Campos incluídos**: query, status, country, countryCode, region, regionName, city, zip, lat, lon, timezone, isp, org, as
- **Precisão**: Nível de cidade
- **Suporte a HTTPS**: Opcional (use_https=True)

### Campos Retornados pela API

```json
{
  "query": "8.8.8.8",
  "status": "success",
  "country": "United States",
  "countryCode": "US",
  "region": "CA",
  "regionName": "California",
  "city": "Mountain View",
  "zip": "94043",
  "lat": 37.4056,
  "lon": -122.0775,
  "timezone": "America/Los_Angeles",
  "isp": "Google LLC",
  "org": "Google Public DNS",
  "as": "AS15169 Google LLC"
}
```

## ⚠️ Limitações e Considerações

### Limitações Técnicas

1. **Rate Limiting**: A API tem limite de 45 requisições por minuto
2. **Precisão**: A localização é em nível de cidade, não endereço exato
3. **IPv6**: Suporte limitado em algumas funcionalidades
4. **Portas Altas**: Scan acima da porta 1024 pode ser lento

### Considerações Éticas e Legais

⚠️ **AVISO IMPORTANTE**:

1. **Use Responsavelmente**: Esta ferramenta é para fins educacionais e de administração de redes
2. **Autorização**: Sempre obtenha permissão antes de escanear redes que não são suas
3. **Privacidade**: Respeite a privacidade dos outros
4. **Legalidade**: Verifique as leis locais sobre escaneamento de portas e coleta de informações
5. **Termos de Serviço**: Respeite os termos de serviço da API ip-api.com

### IPs Reservados/Privados

A ferramenta não permite localização de IPs reservados:
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16
- 127.0.0.1 (localhost)
- 0.0.0.0
- 255.255.255.255
- IPv6: ::1, ::, fe80::, fc00::/7

## 🛠️ Desenvolvimento

### Estrutura do Projeto

```
IP-Locator/
├── iplocator.py      # Código principal
├── README.md         # Esta documentação
└── .gitignore        # Arquivos ignorados pelo Git
```

### Dependências

- `requests`: Para requisições HTTP
- Bibliotecas padrão: `sys`, `re`, `socket`, `time`, `threading`, `typing`

### Testes

Para testar a ferramenta:

```bash
# Teste de localização
python -c "from iplocator import IPLocator; l = IPLocator(); print(l.localizar('8.8.8.8'))"

# Teste de validação de IP
python -c "from iplocator import IPLocator; l = IPLocator(); print(l.validar_ip('192.168.1.1'))"
```

## 🤝 Contribuição

Contribuições são bem-vindas! Siga estes passos:

1. Fork o repositório
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

### Áreas para Melhoria

- [ ] Interface gráfica (GUI)
- [ ] Exportação de resultados (JSON, CSV)
- [ ] Suporte a proxy
- [ ] Cache de resultados
- [ ] Mais APIs de geolocalização
- [ ] Detecção de serviços nas portas
- [ ] Integração com WHOIS

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 📞 Suporte

Para problemas, bugs ou sugestões:

1. Verifique a [documentação da API](https://ip-api.com/docs)
2. Revise os [exemplos de uso](#exemplos-de-uso)
3. Abra uma issue no repositório

## ⭐ Reconhecimentos

- [ip-api.com](https://ip-api.com/) pela API gratuita de geolocalização
- Comunidade Python pelos excelentes recursos e bibliotecas
- Contribuidores e testadores da ferramenta

---

**Nota**: Esta ferramenta é fornecida "como está", sem garantias de qualquer tipo. O autor não se responsabiliza pelo uso indevido desta ferramenta. Use com responsabilidade e sempre em conformidade com as leis aplicáveis.

**Última atualização**: Abril 2026