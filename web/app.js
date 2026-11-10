/*
 * Interface do IP-Locator — Vue 3 (build global, sem bundler).
 * Consome a API local servida por `python iplocator.py --serve`.
 */
(function () {
  'use strict';

  const alvo = document.getElementById('app');
  const Vue = window.Vue;

  if (!Vue || !Vue.createApp) {
    if (alvo) {
      alvo.removeAttribute('v-cloak');
      alvo.innerHTML =
        '<p class="alerta" style="margin:2rem">' +
        'Não foi possível carregar o Vue 3 (CDN indisponível). ' +
        'Sem internet, use a CLI: <code>python iplocator.py</code> ou execute ' +
        '<code>python iplocator.py --geo 8.8.8.8</code>.' +
        '</p>';
    }
    return;
  }

  /**
   * Base da API: mesma origem quando servida pelo Python, 127.0.0.1:8000
   * quando o arquivo é aberto via `file://`, e `?api=` como override.
   */
  function resolverApiBase() {
    const params = new URLSearchParams(window.location.search);
    const override = params.get('api');
    if (override) {
      return override.replace(/\/+$/, '');
    }
    if (window.location.protocol === 'file:') {
      return 'http://127.0.0.1:8000';
    }
    return '';
  }

  const API_BASE = resolverApiBase();
  const PROVEDORES_PADRAO = ['ip-api', 'ipwho.is', 'ipapi.co', 'ipinfo.io', 'freeipapi', 'geojs'];

  const CAMPOS_GEO = {
    country: 'País',
    countryCode: 'Código',
    regionName: 'Região',
    city: 'Cidade',
    zip: 'CEP',
    lat: 'Latitude',
    lon: 'Longitude',
    timezone: 'Fuso',
    isp: 'ISP',
    org: 'Organização',
    as: 'ASN'
  };

  const CAMPOS_WHOIS = {
    handles: 'Handle',
    nome: 'Nome',
    netname: 'Netname',
    organizacao: 'Organização',
    pais: 'País',
    tipo: 'Tipo',
    status: 'Status',
    intervalo: 'Intervalo',
    criado: 'Criado',
    atualizado: 'Atualizado',
    expira_em: 'Expira em',
    registrar: 'Registrar',
    abuse_contato: 'Contato de abuso',
    servidor: 'Servidor'
  };

  async function pedirJson(caminho, opcoes) {
    const resposta = await fetch(API_BASE + caminho, opcoes);
    let dados = null;
    try {
      dados = await resposta.json();
    } catch (erro) {
      dados = null;
    }
    if (!resposta.ok) {
      const mensagem =
        (dados && (dados.erro || dados.message)) || 'HTTP ' + resposta.status;
      throw new Error(mensagem);
    }
    if (!dados) {
      throw new Error('Resposta inválida da API');
    }
    return dados;
  }

  Vue.createApp({
    data() {
      return {
        apiBase: API_BASE,
        abas: [
          { id: 'geo', rotulo: 'Geolocalização' },
          { id: 'scan', rotulo: 'Portas' },
          { id: 'whois', rotulo: 'WHOIS' },
          { id: 'cache', rotulo: 'Cache' }
        ],
        abaAtiva: 'geo',
        apiOk: false,
        versao: '',
        aviso: '',
        exemplos: ['8.8.8.8', '1.1.1.1', 'github.com'],
        alvoGeo: '8.8.8.8',
        carregandoGeo: false,
        erroGeo: '',
        geo: null,
        geoErros: [],
        provedores: PROVEDORES_PADRAO.slice(),
        provedoresAtivos: PROVEDORES_PADRAO.slice(),
        alvoScan: '127.0.0.1',
        modoScan: 'comuns',
        inicioScan: 1,
        fimScan: 1024,
        servicosScan: true,
        carregandoScan: false,
        erroScan: '',
        scan: null,
        alvoWhois: '8.8.8.8',
        carregandoWhois: false,
        erroWhois: '',
        whois: null,
        cacheStats: null,
        carregandoCache: false,
        erroCache: ''
      };
    },

    computed: {
      camposGeoVisiveis() {
        const dados = this.geo || {};
        return Object.keys(CAMPOS_GEO)
          .filter((chave) => {
            const valor = dados[chave];
            return valor !== null && valor !== undefined && valor !== '';
          })
          .map((chave) => ({
            chave: chave,
            rotulo: CAMPOS_GEO[chave],
            valor: dados[chave]
          }));
      },
      geoFallbacks() {
        return this.geoErros || [];
      },
      camposWhoisVisiveis() {
        const dados = (this.whois && this.whois.dados) || {};
        const itens = [];
        Object.keys(CAMPOS_WHOIS).forEach((chave) => {
          let valor = dados[chave];
          if (valor === null || valor === undefined || valor === '') {
            return;
          }
          if (Array.isArray(valor)) {
            valor = valor.slice(0, 6).join(', ');
          } else if (typeof valor === 'object') {
            valor = Object.keys(valor)
              .filter((k) => valor[k])
              .map((k) => k + ': ' + valor[k])
              .join(' · ');
          }
          if (!valor) {
            return;
          }
          itens.push({ chave: chave, rotulo: CAMPOS_WHOIS[chave], valor: valor });
        });
        const eventos = dados.eventos || {};
        Object.keys(eventos).forEach((acao) => {
          itens.push({
            chave: 'evento-' + acao,
            rotulo: acao,
            valor: eventos[acao]
          });
        });
        return itens;
      },
      brutoWhois() {
        const dados = (this.whois && this.whois.dados) || {};
        if (!dados.bruto) {
          return '';
        }
        if (typeof dados.bruto === 'string') {
          return dados.bruto;
        }
        try {
          return JSON.stringify(dados.bruto, null, 2);
        } catch (erro) {
          return String(dados.bruto);
        }
      }
    },

    methods: {
      avisar(mensagem) {
        this.aviso = mensagem;
        window.clearTimeout(this._avisoTimer);
        this._avisoTimer = window.setTimeout(() => {
          this.aviso = '';
        }, 2500);
      },

      async verificarApi() {
        try {
          const dados = await pedirJson('/api/health');
          this.apiOk = !!dados.ok;
          this.versao = dados.versao || '';
          if (Array.isArray(dados.provedores) && dados.provedores.length) {
            this.provedores = dados.provedores;
            const mantidos = this.provedoresAtivos.filter((nome) =>
              this.provedores.includes(nome)
            );
            this.provedoresAtivos = mantidos.length
              ? mantidos
              : this.provedores.slice();
          }
        } catch (erro) {
          this.apiOk = false;
          this.versao = '';
        }
      },

      async consultarGeo() {
        const alvoConsulta = (this.alvoGeo || '').trim();
        if (!alvoConsulta) {
          this.erroGeo = 'Informe um IP ou domínio.';
          return;
        }
        this.carregandoGeo = true;
        this.erroGeo = '';
        this.geo = null;
        this.geoErros = [];
        try {
          const params = new URLSearchParams({ target: alvoConsulta });
          if (
            this.provedoresAtivos.length &&
            this.provedoresAtivos.length < this.provedores.length
          ) {
            params.set('providers', this.provedoresAtivos.join(','));
          }
          const dados = await pedirJson('/api/geo?' + params.toString());
          this.geo = dados.dados;
          this.geoErros = dados.erros || [];
          this.apiOk = true;
        } catch (erro) {
          this.erroGeo = erro.message;
        } finally {
          this.carregandoGeo = false;
        }
      },

      async escanear() {
        const alvoConsulta = (this.alvoScan || '').trim();
        if (!alvoConsulta) {
          this.erroScan = 'Informe um IP ou domínio.';
          return;
        }
        this.carregandoScan = true;
        this.erroScan = '';
        this.scan = null;
        try {
          const params = new URLSearchParams({
            target: alvoConsulta,
            mode: this.modoScan,
            services: this.servicosScan ? '1' : '0'
          });
          if (this.modoScan === 'intervalo') {
            params.set('start', String(this.inicioScan));
            params.set('end', String(this.fimScan));
          }
          this.scan = await pedirJson('/api/scan?' + params.toString());
          this.apiOk = true;
        } catch (erro) {
          this.erroScan = erro.message;
        } finally {
          this.carregandoScan = false;
        }
      },

      async consultarWhois() {
        const alvoConsulta = (this.alvoWhois || '').trim();
        if (!alvoConsulta) {
          this.erroWhois = 'Informe um IP ou domínio.';
          return;
        }
        this.carregandoWhois = true;
        this.erroWhois = '';
        this.whois = null;
        try {
          const params = new URLSearchParams({ target: alvoConsulta });
          this.whois = await pedirJson('/api/whois?' + params.toString());
          this.apiOk = true;
        } catch (erro) {
          this.erroWhois = erro.message;
        } finally {
          this.carregandoWhois = false;
        }
      },

      async carregarCache() {
        this.carregandoCache = true;
        this.erroCache = '';
        try {
          const dados = await pedirJson('/api/cache');
          this.cacheStats = dados.cache;
          this.apiOk = true;
        } catch (erro) {
          this.erroCache = erro.message;
        } finally {
          this.carregandoCache = false;
        }
      },

      async limparCache() {
        this.carregandoCache = true;
        this.erroCache = '';
        try {
          const dados = await pedirJson('/api/cache', { method: 'DELETE' });
          this.cacheStats = dados.cache;
          this.avisar('Cache limpo (' + dados.removidas + ' entrada(s)).');
        } catch (erro) {
          this.erroCache = erro.message;
        } finally {
          this.carregandoCache = false;
        }
      },

      async copiar(dados) {
        const texto = JSON.stringify(dados, null, 2);
        try {
          await navigator.clipboard.writeText(texto);
          this.avisar('JSON copiado para a área de transferência.');
        } catch (erro) {
          window.prompt('Copie o JSON abaixo:', texto);
        }
      }
    },

    watch: {
      abaAtiva(novo) {
        if (novo === 'cache') {
          this.carregarCache();
        }
      }
    },

    mounted() {
      this.verificarApi();
    }
  }).mount('#app');
})();

