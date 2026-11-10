"""Dublês e payloads compartilhados pelos testes (nenhuma chamada de rede)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class RespostaFalsa:
    """Imita ``requests.Response`` o suficiente para o código de produção."""

    def __init__(
        self,
        dados: Any = None,
        status: int = 200,
        erro_json: bool = False,
        texto: Optional[str] = None,
    ) -> None:
        self._dados = dados
        self.status_code = status
        self._erro_json = erro_json
        self.text = texto if texto is not None else json.dumps(dados or {})

    def json(self) -> Any:
        if self._erro_json:
            raise ValueError("JSON inválido")
        return self._dados


class SessaoFalsa:
    """Substitui ``requests.Session`` guardando as URLs consultadas."""

    def __init__(
        self,
        respostas: Optional[Dict[str, Any]] = None,
        excecao: Optional[BaseException] = None,
        status_padrao: int = 404,
    ) -> None:
        self.respostas = respostas or {}
        self.excecao = excecao
        self.status_padrao = status_padrao
        self.chamadas: List[str] = []
        self.headers: Dict[str, str] = {}

    def get(
        self, url: str, timeout: Any = None, headers: Any = None
    ) -> RespostaFalsa:
        self.chamadas.append(url)
        if self.excecao is not None:
            raise self.excecao
        for prefixo, resposta in self.respostas.items():
            if prefixo in url:
                if isinstance(resposta, RespostaFalsa):
                    return resposta
                return RespostaFalsa(resposta)
        return RespostaFalsa(
            {"status": "fail", "message": "sem rota"}, status=self.status_padrao
        )


# ----------------------------------------------------------------------
# Payloads de geolocalização (formato de cada provedor)
# ----------------------------------------------------------------------
PAYLOAD_IP_API: Dict[str, Any] = {
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
    "as": "AS15169 Google LLC",
    "query": "8.8.8.8",
}

PAYLOAD_IPWHOIS: Dict[str, Any] = {
    "ip": "8.8.8.8",
    "success": True,
    "type": "IPv4",
    "country": "United States",
    "country_code": "US",
    "region": "California",
    "city": "Mountain View",
    "latitude": 37.4056,
    "longitude": -122.0775,
    "postal": "94043",
    "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC"},
    "timezone": {"id": "America/Los_Angeles", "abbr": "PDT"},
}

PAYLOAD_IPAPI_CO: Dict[str, Any] = {
    "ip": "8.8.8.8",
    "city": "Mountain View",
    "region": "California",
    "region_code": "CA",
    "country_name": "United States",
    "country_code": "US",
    "postal": "94043",
    "latitude": 37.4056,
    "longitude": -122.0775,
    "timezone": "America/Los_Angeles",
    "asn": "AS15169",
    "org": "AS15169 GOOGLE",
}

PAYLOAD_IPINFO: Dict[str, Any] = {
    "ip": "8.8.8.8",
    "hostname": "dns.google",
    "city": "Mountain View",
    "region": "California",
    "country": "US",
    "loc": "37.4056,-122.0775",
    "org": "AS15169 Google LLC",
    "postal": "94043",
    "timezone": "America/Los_Angeles",
}

PAYLOAD_FREEIPAPI: Dict[str, Any] = {
    "ipVersion": 4,
    "ipAddress": "8.8.8.8",
    "latitude": 37.4056,
    "longitude": -122.0775,
    "countryName": "United States",
    "countryCode": "US",
    "cityName": "Mountain View",
    "regionName": "California",
    "timeZone": "America/Los_Angeles",
    "zipCode": "94043",
}

PAYLOAD_GEOJS: Dict[str, Any] = {
    "ip": "8.8.8.8",
    "country_name": "United States",
    "country_code2": "US",
    "region": "California",
    "city": "Mountain View",
    "latitude": "37.4056",
    "longitude": "-122.0775",
    "timezone": "America/Los_Angeles",
    "organization_name": "Google LLC",
    "organization": "AS15169 Google LLC",
    "asn": 15169,
}

#: URL (substring) -> payload, para montar uma sessão falsa completa.
RESPOSTAS_GEO: Dict[str, Any] = {
    "ip-api.com": PAYLOAD_IP_API,
    "ipwho.is": PAYLOAD_IPWHOIS,
    "ipapi.co": PAYLOAD_IPAPI_CO,
    "ipinfo.io": PAYLOAD_IPINFO,
    "freeipapi.com": PAYLOAD_FREEIPAPI,
    "get.geojs.io": PAYLOAD_GEOJS,
}


# ----------------------------------------------------------------------
# Payloads de WHOIS/RDAP
# ----------------------------------------------------------------------
PAYLOAD_RDAP_IP: Dict[str, Any] = {
    "handle": "NET-8-8-8-0-1",
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "ipVersion": "v4",
    "name": "GOGL",
    "type": "DIRECT ALLOCATION",
    "country": "US",
    "status": ["active"],
    "events": [
        {"eventAction": "registration", "eventDate": "2023-12-28T09:00:00-05:00"},
        {"eventAction": "last changed", "eventDate": "2024-01-02T10:00:00-05:00"},
    ],
    "entities": [
        {
            "handle": "GOGL",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]],
            ],
        },
        {
            "handle": "ABUSE5250-ARIN",
            "roles": ["abuse"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Abuse"],
                    ["email", {}, "text", "network-abuse@google.com"],
                ],
            ],
        },
    ],
    "remarks": [{"description": ["Google Public DNS"]}],
    "links": [{"href": "https://rdap.arin.net/registry/ip/8.8.8.8"}],
}

PAYLOAD_RDAP_DOMINIO: Dict[str, Any] = {
    "ldhName": "GITHUB.COM",
    "handle": "D1-COM",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "2007-10-09T00:00:00Z"},
    ],
    "entities": [
        {
            "handle": "GITHUB",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "GitHub, Inc."]],
            ],
        }
    ],
}

WHOIS_TEXTO: str = """\
% This is the RIPE Database query service.

inetnum:        8.8.8.0 - 8.8.8.255
netname:        GOGL
descr:          Google Public DNS
country:        US
org-name:       Google LLC
created:        2023-12-28T09:00:00Z
last-modified:  2024-01-02T10:00:00Z
abuse-mailbox:  network-abuse@google.com
source:         RIPE
"""

WHOIS_TEXTO_VAZIO: str = """\
% IANA WHOIS server
refer:        whois.arin.net

No match for "8.8.8.8".
"""

