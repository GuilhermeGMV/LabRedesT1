DEFAULT_SERVERS = [
    ("8.8.8.8", "Google Public DNS (sem filtragem)"),
    ("8.8.4.4", "Google Public DNS 2 (sem filtragem)"),
    ("1.1.1.1", "Cloudflare (sem filtragem)"),
    ("1.0.0.1", "Cloudflare 2 (sem filtragem)"),
    ("9.9.9.10", "Quad9 (sem filtro)"),
    ("64.6.64.6", "Verisign (sem filtragem)"),
    ("9.9.9.9", "Quad9 (segurança)"),
    ("208.67.222.222", "OpenDNS (segurança)"),
    ("185.228.168.9", "CleanBrowsing Security"),
    ("94.140.14.14", "AdGuard DNS"),
    ("1.1.1.3", "Cloudflare Family"),
    ("208.67.222.123", "OpenDNS FamilyShield"),
    ("185.228.168.168", "CleanBrowsing Family"),
    ("94.140.14.15", "AdGuard Family"),
    ("76.76.2.0", "Control D"),
    ("8.26.56.26", "Comodo Secure"),
    ("208.67.220.220", "OpenDNS 2"),
    ("9.9.9.11", "Quad9 ECS"),
    ("94.140.14.140", "AdGuard Unfiltered"),
    ("77.88.8.8", "Yandex"),
]

DOT_SERVERS = [
    ("dns.google", "Google DNS over TLS"),
    ("one.one.one.one", "Cloudflare DNS over TLS"),
    ("dns.quad9.net", "Quad9 DNS over TLS"),
]

TEST_DOMAINS = [
    ("www.example.com", "Controle: nenhum servidor deveria bloquear"),
    ("www.pucrs.br", "Controle regional"),
    ("internetbadguys.com", "Teste OpenDNS: bloqueado por filtros de segurança"),
    ("reddit.com", "Rede social: potencial bloqueio familiar"),
    ("tinder.com", "Aplicativo de encontros: potencial bloqueio familiar"),
    ("polymarket.com", "Mercado de previsões: bloqueio judicial no Brasil segundo o enunciado"),
    ("www.google.com", "Controle: nenhum servidor deveria bloquear"),
    ("www2.thepiratebay3.co", "Teste de bloqueio: potencial bloqueio por pirataria"),
    ("isitblocked.org", "Teste de bloqueio: potencial bloqueio por segurança ou judicial"),
]

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_MX = 15
QTYPE_AAAA = 28

TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    28: "AAAA",
}

QCLASS_IN = 1

BLOCKED_IPS = {"0.0.0.0", "127.0.0.1"}

DNS_PORT = 53
DOT_PORT = 853
TIMEOUT = 5
MIN_BENCHMARK_QUERIES = 10
