import argparse

from dns_analysis import detect_blocking
from dns_benchmark import benchmark_dot, benchmark_udp
from dns_clients import query_all_dot_servers, query_all_servers
from dns_config import (
    DEFAULT_SERVERS,
    DOT_SERVERS,
    MIN_BENCHMARK_QUERIES,
    QTYPE_A,
    QTYPE_AAAA,
    QTYPE_CNAME,
    QTYPE_MX,
    QTYPE_NS,
    QTYPE_SOA,
    TEST_DOMAINS,
    TIMEOUT,
)
from dns_display import display_benchmark, display_blocking_suite, display_full_benchmark, display_results, display_test_domains
from dns_utils import load_system_resolvers, parse_named_endpoint, parse_server_list


TYPE_MAP = {
    "A": QTYPE_A,
    "AAAA": QTYPE_AAAA,
    "CNAME": QTYPE_CNAME,
    "NS": QTYPE_NS,
    "MX": QTYPE_MX,
    "SOA": QTYPE_SOA,
}


def build_parser():
    parser = argparse.ArgumentParser(
        description="Ferramenta de análise de resolução DNS (UDP raw e DNS over TLS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Exemplos:
  %(prog)s www.google.com
  %(prog)s www.pucrs.br --include-system
  %(prog)s example.com --servers "1.1.1.1:Cloudflare,8.8.8.8:Google"
  %(prog)s example.com --timeout 3
  %(prog)s www.example.com --dot
  %(prog)s www.example.com --benchmark
  %(prog)s --test-suite --dot
""",
    )
    parser.add_argument("domain", nargs="?", help="Nome de domínio a consultar")
    parser.add_argument(
        "--servers", "-s",
        help="Lista de servidores DNS customizados (formato: ip:nome,ip:nome,...)",
    )
    parser.add_argument(
        "--dot", action="store_true",
        help="Consultar via DNS over TLS (TCP/TLS na porta 853)",
    )
    parser.add_argument(
        "--dot-servers",
        help="Lista de servidores DoT customizados (formato: host:nome,host:nome,...)",
    )
    parser.add_argument(
        "--insecure-dot", action="store_true",
        help="Desabilitar verificação do certificado TLS em consultas DoT",
    )
    parser.add_argument(
        "--include-system", action="store_true",
        help="Incluir servidores DNS do sistema (/etc/resolv.conf)",
    )
    parser.add_argument(
        "--timeout", "-t", type=float, default=TIMEOUT,
        help=f"Timeout em segundos para cada consulta (padrão: {TIMEOUT})",
    )
    parser.add_argument(
        "--type", dest="qtype", default="A",
        choices=list(TYPE_MAP),
        help="Tipo de registro DNS a consultar (padrão: A)",
    )
    parser.add_argument(
        "--benchmark", action="store_true",
        help="Comparar desempenho UDP vs DoT com pelo menos 10 consultas",
    )
    parser.add_argument(
        "--benchmark-count", type=int, default=MIN_BENCHMARK_QUERIES,
        help=f"Número de consultas no benchmark (mínimo: {MIN_BENCHMARK_QUERIES})",
    )
    parser.add_argument(
        "--udp-server", default="8.8.8.8:Google Public DNS",
        help="Servidor UDP para benchmark (formato: ip:nome)",
    )
    parser.add_argument(
        "--dot-host", default="dns.google:Google DNS over TLS",
        help="Servidor DoT para benchmark (formato: host:nome)",
    )
    parser.add_argument(
        "--full-scan", action="store_true",
        help="Varredura de bloqueios: todos os domínios de teste × todos os servidores, UDP e DoT",
    )
    parser.add_argument(
        "--full-benchmark", action="store_true",
        help="Benchmark completo: todos os domínios de teste × todos os servidores, UDP e DoT",
    )
    parser.add_argument(
        "--full-benchmark-count", type=int, default=MIN_BENCHMARK_QUERIES,
        help=f"Consultas por combinação no benchmark completo (padrão: {MIN_BENCHMARK_QUERIES})",
    )
    parser.add_argument(
        "--test-suite", action="store_true",
        help="Executar análise em todos os domínios de teste embutidos",
    )
    parser.add_argument(
        "--list-test-domains", action="store_true",
        help="Listar domínios de teste embutidos e sair se nenhum domínio for informado",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.list_test_domains:
        display_test_domains()
        if not args.domain and not args.test_suite:
            return

    if not args.domain and not args.test_suite and not args.full_benchmark and not args.full_scan:
        parser.error("informe um domínio ou use --test-suite / --full-benchmark / --full-scan")

    if args.full_scan and (args.benchmark or args.full_benchmark or args.test_suite or args.dot or args.domain):
        parser.error("--full-scan não pode ser combinado com outras opções de execução")

    if args.full_benchmark and (args.benchmark or args.test_suite or args.dot):
        parser.error("--full-benchmark não pode ser combinado com --benchmark, --test-suite ou --dot")

    if args.full_benchmark and args.full_benchmark_count < MIN_BENCHMARK_QUERIES:
        parser.error(f"--full-benchmark-count deve ser pelo menos {MIN_BENCHMARK_QUERIES}")

    if args.benchmark and args.test_suite:
        parser.error("--benchmark compara um único domínio; informe o domínio diretamente")

    if args.benchmark and args.benchmark_count < MIN_BENCHMARK_QUERIES:
        parser.error(f"--benchmark-count deve ser pelo menos {MIN_BENCHMARK_QUERIES}")

    qtype = TYPE_MAP[args.qtype]

    if args.full_scan:
        run_full_scan(args, qtype)
        return

    if args.full_benchmark:
        run_full_benchmark(args, qtype)
        return

    if args.benchmark:
        run_benchmark(args, qtype)
        return

    domains = [domain for domain, _purpose in TEST_DOMAINS] if args.test_suite else [args.domain]

    if args.dot:
        run_dot_analysis(parser, args, domains, qtype)
        return

    run_udp_analysis(parser, args, domains, qtype)


def run_full_scan(args, qtype):
    domains = [domain for domain, _ in TEST_DOMAINS]
    udp_servers = list(DEFAULT_SERVERS)
    dot_servers = list(DOT_SERVERS)

    total = len(domains) * (len(udp_servers) + len(dot_servers))
    print(f"\n  Varredura de bloqueios: {len(domains)} domínios × "
          f"{len(udp_servers)} servidores UDP + {len(dot_servers)} servidores DoT "
          f"({total} consultas)\n")

    data = []
    for domain in domains:
        print(f"  Consultando {domain}...", end="", flush=True)
        udp_results = query_all_servers(domain, udp_servers, qtype, args.timeout)
        dot_results = query_all_dot_servers(
            domain, dot_servers, qtype, args.timeout,
            verify_tls=not args.insecure_dot,
        )
        udp_alerts = detect_blocking(udp_results)
        dot_alerts = detect_blocking(dot_results)
        n_alerts = len(udp_alerts) + len(dot_alerts)
        print(f" {n_alerts} alerta(s)")
        data.append({
            "domain": domain,
            "udp_results": udp_results,
            "udp_alerts": udp_alerts,
            "dot_results": dot_results,
            "dot_alerts": dot_alerts,
        })

    display_blocking_suite(data, udp_servers, dot_servers)


def run_full_benchmark(args, qtype):
    count = max(args.full_benchmark_count, MIN_BENCHMARK_QUERIES)
    domains = [domain for domain, _ in TEST_DOMAINS]
    udp_servers = list(DEFAULT_SERVERS)
    dot_servers = list(DOT_SERVERS)

    total = len(udp_servers) * len(domains) + len(dot_servers) * len(domains)
    print(f"\n  Benchmark completo: {len(domains)} domínios, "
          f"{len(udp_servers)} servidores UDP + {len(dot_servers)} servidores DoT, "
          f"{count} consultas cada ({total * count} consultas no total)\n")

    udp_data = []
    for ip, name in udp_servers:
        for domain in domains:
            print(f"  [UDP] {name} × {domain}...", end="", flush=True)
            results = benchmark_udp(domain, ip, qtype, args.timeout, count)
            ok = sum(1 for r in results if r["success"])
            print(f" {ok}/{count}")
            udp_data.append((name, ip, domain, results))

    dot_data = []
    for host, name in dot_servers:
        for domain in domains:
            print(f"  [DoT] {name} × {domain}...", end="", flush=True)
            results = benchmark_dot(
                domain, host, qtype, args.timeout, count,
                verify_tls=not args.insecure_dot,
            )
            ok = sum(1 for r in results if r["success"])
            print(f" {ok}/{count}")
            dot_data.append((name, host, domain, results))

    display_full_benchmark(udp_data, dot_data, count)


def run_benchmark(args, qtype):
    udp_server = parse_named_endpoint(args.udp_server, "Servidor UDP")
    dot_server = parse_named_endpoint(args.dot_host, "Servidor DoT")
    udp_results = benchmark_udp(
        args.domain,
        udp_server[0],
        qtype,
        args.timeout,
        args.benchmark_count,
    )
    dot_results = benchmark_dot(
        args.domain,
        dot_server[0],
        qtype,
        args.timeout,
        args.benchmark_count,
        verify_tls=not args.insecure_dot,
    )
    display_benchmark(args.domain, udp_server, udp_results, dot_server, dot_results)


def run_dot_analysis(parser, args, domains, qtype):
    if args.servers or args.include_system:
        parser.error("em modo DoT, use --dot-servers em vez de --servers/--include-system")

    servers = parse_server_list(args.dot_servers) if args.dot_servers else list(DOT_SERVERS)
    for domain in domains:
        results = query_all_dot_servers(
            domain,
            servers,
            qtype,
            args.timeout,
            verify_tls=not args.insecure_dot,
        )
        alerts = detect_blocking(results)
        display_results(domain, results, alerts, protocol_label="DoT")


def run_udp_analysis(parser, args, domains, qtype):
    if args.dot_servers:
        parser.error("--dot-servers requer --dot")

    servers = build_udp_server_list(args)
    for domain in domains:
        results = query_all_servers(domain, servers, qtype, args.timeout)
        alerts = detect_blocking(results)
        display_results(domain, results, alerts, protocol_label="UDP")


def build_udp_server_list(args):
    servers = []
    if args.servers:
        servers.extend(parse_server_list(args.servers))
    if args.include_system:
        sys_resolvers = load_system_resolvers()
        existing_ips = {server[0] for server in servers}
        for ip, name in sys_resolvers:
            if ip not in existing_ips:
                servers.append((ip, name))
                existing_ips.add(ip)
    if not servers:
        servers = list(DEFAULT_SERVERS)
    return servers


if __name__ == "__main__":
    main()
