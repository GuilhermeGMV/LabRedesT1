import sys

from dns_benchmark import summarize_benchmark
from dns_config import (
    BLOCKED_IPS,
    DNS_PORT,
    DOT_PORT,
    QTYPE_A,
    QTYPE_CNAME,
    RCODE_NAMES,
    TEST_DOMAINS,
)

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GRAY = "\033[90m"

if not sys.stdout.isatty():
    RESET = BOLD = GREEN = RED = YELLOW = CYAN = GRAY = ""


def colored_rcode(rcode_num):
    name = RCODE_NAMES.get(rcode_num, f"RCODE={rcode_num}")
    if rcode_num == 0:
        return f"{GREEN}{name}{RESET}"
    if rcode_num in (3, 5):
        return f"{RED}{name}{RESET}"
    return f"{YELLOW}{name}{RESET}"


def print_separator(char="─", width=80):
    print(char * width)


def shorten_text(value, width):
    text = str(value)
    if len(text) <= width:
        return text
    return text[:max(0, width - 3)] + "..."


def format_ms(value):
    if value is None:
        return "—"
    return f"{value:.1f} ms"


def format_bytes(value):
    if value is None:
        return "—"
    return f"{value:.0f} B"


def display_results(domain, results, alerts, protocol_label="UDP"):
    """Exibe resultados de consultas DNS para um dominio."""
    print()
    print_separator("═")
    print(f"{BOLD}  DNS Analysis ({protocol_label}): {CYAN}{domain}{RESET}")
    print_separator("═")

    for result in results:
        print()
        print(
            f"  {BOLD}{result['server_name']}{RESET} "
            f"{GRAY}({result['server_ip']}){RESET}"
        )
        print_separator("─", 60)

        if not result["success"]:
            print(f"  Status:  {RED}FALHA — {result['error']}{RESET}")
            print(f"  Tempo:   {result['time_ms']:.1f} ms")
            continue

        response = result["response"]
        rcode = response["flags"]["rcode"]
        print(f"  RCODE:   {colored_rcode(rcode)}")
        print(f"  Tempo:   {result['time_ms']:.1f} ms")
        print(
            f"  Flags:   AA={response['flags']['aa']}  "
            f"TC={response['flags']['tc']}  RD={response['flags']['rd']}  "
            f"RA={response['flags']['ra']}"
        )

        a_records = [answer for answer in response["answers"] if answer["type"] == QTYPE_A]
        cname_records = [
            answer for answer in response["answers"] if answer["type"] == QTYPE_CNAME
        ]
        other_records = [
            answer
            for answer in response["answers"]
            if answer["type"] not in (QTYPE_A, QTYPE_CNAME)
        ]

        for record in cname_records:
            print(f"  CNAME:   {record['rdata']}  {GRAY}(TTL {record['ttl']}){RESET}")

        if a_records:
            for record in a_records:
                ip = record["rdata"]
                color = RED if ip in BLOCKED_IPS else GREEN
                print(f"  A:       {color}{ip}{RESET}  {GRAY}(TTL {record['ttl']}){RESET}")
        elif rcode == 0:
            print(f"  {GRAY}(nenhum registro A na resposta){RESET}")

        for record in other_records:
            print(
                f"  {record['type_name']:7s}  {record['rdata']}  "
                f"{GRAY}(TTL {record['ttl']}){RESET}"
            )

        if response["authority"]:
            print(f"  {GRAY}Authority:{RESET}")
            for record in response["authority"]:
                print(f"    {record['type_name']:7s}  {record['rdata']}")

    print()
    print_separator("═")
    print(f"{BOLD}  Análise de Bloqueio / Manipulação{RESET}")
    print_separator("═")

    if not alerts:
        print(f"  {GREEN}Nenhum indício de bloqueio detectado.{RESET}")
    else:
        for alert in alerts:
            if alert["type"] in ("NXDOMAIN", "REFUSED", "ENDEREÇO NULO", "IP DIVERGENTE"):
                color = RED
            else:
                color = YELLOW
            print(f"\n  {color}[{alert['type']}]{RESET} {BOLD}{alert['server']}{RESET}")
            print(f"    {alert['detail']}")

    print()
    print_separator("═")
    print(f"{BOLD}  Tabela Comparativa{RESET}")
    print_separator("═")
    print(f"  {'Servidor':<26} {'RCODE':<12} {'IPs':<36} {'Tempo':>8}")
    print_separator("─")

    for result in results:
        server = f"{result['server_name'][:20]} ({result['server_ip']})"
        if not result["success"]:
            rcode_str = shorten_text(result["error"], 12)
            ips_str = "—"
        else:
            rcode_num = result["response"]["flags"]["rcode"]
            rcode_str = RCODE_NAMES.get(rcode_num, str(rcode_num))
            ips = [
                answer["rdata"]
                for answer in result["response"]["answers"]
                if answer["type"] == QTYPE_A
            ]
            ips_str = ", ".join(ips) if ips else "—"

        time_str = f"{result['time_ms']:.1f} ms"
        print(f"  {server:<40} {rcode_str:<12} {ips_str:<36} {time_str:>8}")

    print_separator("═")
    print()


def display_benchmark(domain, udp_server, udp_results, dot_server, dot_results):
    """Exibe comparacao de desempenho entre UDP e DoT."""
    udp_summary = summarize_benchmark(udp_results)
    dot_summary = summarize_benchmark(dot_results)

    print()
    print_separator("═")
    print(f"{BOLD}  Benchmark UDP vs DoT: {CYAN}{domain}{RESET}")
    print_separator("═")
    print(f"  UDP: {udp_server[1]} ({udp_server[0]}:{DNS_PORT})")
    print(f"  DoT: {dot_server[1]} ({dot_server[0]}:{DOT_PORT})")
    print()
    print(
        f"  {'Protocolo':<10} {'Sucesso':<10} {'Média':>10} "
        f"{'Mediana':>10} {'Mín':>10} {'Máx':>10} {'DesvPad':>10} "
        f"{'Req app':>10} {'Resp app':>10}"
    )
    print_separator("─")

    for label, summary in (("UDP", udp_summary), ("DoT", dot_summary)):
        success = f"{summary['successes']}/{summary['total']}"
        print(
            f"  {label:<10} {success:<10} {format_ms(summary['avg']):>10} "
            f"{format_ms(summary['median']):>10} {format_ms(summary['min']):>10} "
            f"{format_ms(summary['max']):>10} {format_ms(summary['stdev']):>10} "
            f"{format_bytes(summary['query_bytes_avg']):>10} "
            f"{format_bytes(summary['response_bytes_avg']):>10}"
        )

    if udp_summary["avg"] is not None and dot_summary["avg"] is not None:
        delta = dot_summary["avg"] - udp_summary["avg"]
        ratio = dot_summary["avg"] / udp_summary["avg"] if udp_summary["avg"] > 0 else None
        ratio_str = f" ({ratio:.2f}x)" if ratio is not None else ""
        print()
        print(f"  Diferença média DoT - UDP: {delta:+.1f} ms{ratio_str}")

    print()
    print(f"  {'#':>2} {'UDP':>12} {'DoT':>12} {'Status UDP':<18} {'Status DoT':<18}")
    print_separator("─")
    for index in range(max(len(udp_results), len(dot_results))):
        udp = udp_results[index] if index < len(udp_results) else None
        dot = dot_results[index] if index < len(dot_results) else None
        udp_time = format_ms(udp["time_ms"]) if udp else "—"
        dot_time = format_ms(dot["time_ms"]) if dot else "—"
        udp_status = "OK" if udp and udp["success"] else (udp["error"] if udp else "—")
        dot_status = "OK" if dot and dot["success"] else (dot["error"] if dot else "—")
        print(
            f"  {index + 1:>2} {udp_time:>12} {dot_time:>12} "
            f"{udp_status[:18]:<18} {dot_status[:18]:<18}"
        )

    print()
    print_separator("═")
    print(f"{BOLD}  Notas para análise de tráfego{RESET}")
    print_separator("═")
    print("  UDP: a consulta e a resposta DNS aparecem em texto decodificável no Wireshark.")
    print("  DoT: o conteúdo DNS fica dentro do túnel TLS; normalmente são visíveis apenas IPs,")
    print("       porta 853, handshake TCP/TLS e metadados TLS, não o nome consultado.")
    print("  Pacotes/bytes reais devem ser medidos na captura, pois DoT inclui TCP + TLS +")
    print("  fechamento de conexão; a tabela acima mostra apenas bytes de aplicação DNS/DoT.")
    print()


def display_blocking_suite(data, udp_servers, dot_servers):
    """Exibe matriz de status de bloqueio para todos os domínios × servidores."""
    CELL_W = 6
    DOM_W = 28

    def _cell(result, divergent_labels):
        label = f"{result['server_name']} ({result['server_ip']})"
        is_div = label in divergent_labels

        if not result["success"]:
            if "Timeout" in result["error"]:
                return f"{YELLOW}{'TIME':<{CELL_W}}{RESET}"
            return f"{RED}{'ERR':<{CELL_W}}{RESET}"

        rcode = result["response"]["flags"]["rcode"]
        ips = [a["rdata"] for a in result["response"]["answers"] if a["type"] == QTYPE_A]

        if any(ip in BLOCKED_IPS for ip in ips):
            return f"{RED}{'BLKD':<{CELL_W}}{RESET}"
        if rcode == 3:
            return f"{RED}{'NXDM':<{CELL_W}}{RESET}"
        if rcode == 5:
            return f"{RED}{'RFSD':<{CELL_W}}{RESET}"
        if is_div:
            return f"{YELLOW}{'DIV':<{CELL_W}}{RESET}"
        if rcode == 0:
            return f"{GREEN}{'OK':<{CELL_W}}{RESET}"
        return f"{YELLOW}{f'R={rcode}':<{CELL_W}}{RESET}"

    print()
    print_separator("═")
    print(f"{BOLD}  Análise de Bloqueio — Todos os Domínios × Todos os Servidores{RESET}")
    print_separator("═")
    print(
        f"\n  {GRAY}Legenda: OK=sem bloqueio  NXDM=NXDOMAIN  RFSD=REFUSED  "
        f"BLKD=IP bloqueado  DIV=IP divergente  TIME=timeout  ERR=erro{RESET}"
    )

    for proto_label, servers, results_key, alerts_key, prefix in (
        ("UDP", udp_servers, "udp_results", "udp_alerts", "S"),
        ("DoT", dot_servers, "dot_results", "dot_alerts", "T"),
    ):
        print()
        print_separator("─")
        print(f"  {BOLD}{proto_label}{RESET}")
        print()
        for i, (ip, name) in enumerate(servers, 1):
            print(f"  {GRAY}{prefix}{i}{RESET} = {name} {GRAY}({ip}){RESET}")
        print()

        header = f"  {'Domínio':<{DOM_W}}"
        for i in range(1, len(servers) + 1):
            header += f" {(prefix + str(i)):<{CELL_W}}"
        print(header)
        print_separator("─", DOM_W + len(servers) * (CELL_W + 1) + 4)

        for entry in data:
            results = entry[results_key]
            alerts = entry[alerts_key]
            divergent_labels = {a["server"] for a in alerts if a["type"] == "IP DIVERGENTE"}

            domain_short = shorten_text(entry["domain"], DOM_W)
            row = f"  {domain_short:<{DOM_W}}"
            for result in results:
                row += " " + _cell(result, divergent_labels)
            print(row)

        print()

    print_separator("═")
    print(f"{BOLD}  Alertas Detectados{RESET}")
    print_separator("═")

    has_alerts = False
    for entry in data:
        domain_alerts = entry["udp_alerts"] + entry["dot_alerts"]
        if not domain_alerts:
            continue
        has_alerts = True
        print(f"\n  {BOLD}{CYAN}{entry['domain']}{RESET}")
        for alert in domain_alerts:
            color = RED if alert["type"] in (
                "NXDOMAIN", "REFUSED", "ENDEREÇO NULO", "IP DIVERGENTE"
            ) else YELLOW
            print(f"    {color}[{alert['type']}]{RESET} {alert['server']}")
            print(f"      {GRAY}{alert['detail']}{RESET}")

    if not has_alerts:
        print(f"\n  {GREEN}Nenhum indício de bloqueio detectado em nenhum servidor.{RESET}")

    print()
    print_separator("═")
    print()


def display_test_domains():
    """Lista os dominios de teste embutidos na ferramenta."""
    print()
    print_separator("═")
    print(f"{BOLD}  Domínios de Teste{RESET}")
    print_separator("═")
    for domain, purpose in TEST_DOMAINS:
        print(f"  {domain:<24} {purpose}")
    print()


def display_full_benchmark(udp_data, dot_data, count):
    """Exibe tabela resumida do benchmark completo (todos domínios × todos servidores)."""
    print()
    print_separator("═")
    print(f"{BOLD}  Benchmark Completo — todos os domínios × todos os servidores{RESET}")
    print(f"  {GRAY}{count} consultas por combinação domínio/servidor{RESET}")

    col_server = 36
    col_ok     = 9
    col_time   = 10

    def _print_row(label, summary, bold=False):
        ok = f"{summary['successes']}/{summary['total']}"
        prefix = BOLD if bold else ""
        print(
            f"  {prefix}{label:<{col_server}}{RESET}"
            f" {ok:>{col_ok}}"
            f" {format_ms(summary['min']):>{col_time}}"
            f" {format_ms(summary['avg']):>{col_time}}"
            f" {format_ms(summary['max']):>{col_time}}"
        )

    for protocol_label, data in (("UDP", udp_data), ("DoT", dot_data)):
        # agrupa todos os resultados por servidor
        per_server = {}
        for name, ip, _domain, results in data:
            key = (name, ip)
            if key not in per_server:
                per_server[key] = []
            per_server[key].extend(results)

        print()
        print_separator("═")
        print(f"  {BOLD}{protocol_label}{RESET}")
        print(
            f"  {'Servidor':<{col_server}}"
            f" {'Sucesso':>{col_ok}}"
            f" {'Mín':>{col_time}}"
            f" {'Média':>{col_time}}"
            f" {'Máx':>{col_time}}"
        )
        print_separator("─")

        all_results = []
        for (name, ip), results in per_server.items():
            summary = summarize_benchmark(results)
            all_results.extend(results)
            label = f"{name[:26]} ({ip})"
            _print_row(label, summary)

        print_separator("─")
        overall = summarize_benchmark(all_results)
        _print_row(f"TOTAL {protocol_label}", overall, bold=True)

    print()
    print_separator("═")
    print()
