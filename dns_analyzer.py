
import socket
import struct
import random
import time
import sys
import os

# ──────────────────────────────────────────────
# Servidores DNS padrão
# ──────────────────────────────────────────────
DEFAULT_SERVERS = [
    ("8.8.8.8",        "Google Public DNS"),
    ("8.8.4.4",        "Google Public DNS 2"),
    ("1.1.1.1",        "Cloudflare DNS"),
    ("1.0.0.1",        "Cloudflare DNS 2"),
    ("1.1.1.3",        "Cloudflare DNS (bloqueio malware)"),
    ("9.9.9.9",        "Quad9 DNS"),
    ("208.67.222.222", "OpenDNS"),
    ("208.67.220.220", "OpenDNS 2"),
]

# Códigos RCODE
RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

# Tipos de registro DNS
QTYPE_A     = 1
QTYPE_NS    = 2
QTYPE_CNAME = 5
QTYPE_SOA   = 6
QTYPE_MX    = 15
QTYPE_AAAA  = 28

TYPE_NAMES = {
    1:  "A",
    2:  "NS",
    5:  "CNAME",
    6:  "SOA",
    15: "MX",
    28: "AAAA",
}

# Classes
QCLASS_IN = 1

# IPs que indicam bloqueio/redirecionamento
BLOCKED_IPS = {"0.0.0.0", "127.0.0.1"}

DNS_PORT = 53
TIMEOUT  = 5  # segundos


def build_query(domain, qtype=QTYPE_A):
    """Constrói uma mensagem de consulta DNS em formato binário."""
    # Header (12 bytes) — RFC 1035 §4.1.1
    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # QR=0, OPCODE=0, RD=1 (recursion desired)
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    # Question section — RFC 1035 §4.1.2
    question = encode_domain_name(domain)
    question += struct.pack("!HH", qtype, QCLASS_IN)

    return tx_id, header + question


def encode_domain_name(domain):
    """Codifica um nome de domínio no formato DNS (labels com tamanho)."""
    parts = domain.rstrip(".").split(".") # separa o dominio em labels ["www", "google", "com"]
    result = b""
    for part in parts:
        encoded = part.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"Label muito longa: {part}")
        result += struct.pack("B", len(encoded)) + encoded
    result += b"\x00"  # terminador
    return result


def parse_response(data):
    """Interpreta uma resposta DNS binária completa."""
    if len(data) < 12:
        raise ValueError("Resposta muito curta")

    # Header
    (tx_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", data[:12])

    qr     = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa     = (flags >> 10) & 1
    tc     = (flags >> 9)  & 1
    rd     = (flags >> 8)  & 1
    ra     = (flags >> 7)  & 1
    rcode  = flags & 0xF

    offset = 12

    # Question section
    questions = []
    for _ in range(qdcount):
        qname, offset = decode_domain_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        questions.append({"name": qname, "type": qtype, "class": qclass})

    # Resource records
    answers     = parse_rr_section(data, offset, ancount)
    offset      = answers["next_offset"]
    authority   = parse_rr_section(data, offset, nscount)
    offset      = authority["next_offset"]
    additional  = parse_rr_section(data, offset, arcount)

    return {
        "tx_id":      tx_id,
        "flags": {
            "qr": qr, "opcode": opcode, "aa": aa,
            "tc": tc, "rd": rd, "ra": ra, "rcode": rcode,
        },
        "questions":  questions,
        "answers":    answers["records"],
        "authority":  authority["records"],
        "additional": additional["records"],
    }


def parse_rr_section(data, offset, count):
    """Faz o parse de uma seção de resource records."""
    records = []
    for _ in range(count):
        name, offset = decode_domain_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata_raw = data[offset:offset + rdlength]
        rdata = parse_rdata(data, offset, rtype, rdlength)
        offset += rdlength
        records.append({
            "name":    name,
            "type":    rtype,
            "class":   rclass,
            "ttl":     ttl,
            "rdlength": rdlength,
            "rdata":   rdata,
            "type_name": TYPE_NAMES.get(rtype, str(rtype)),
        })
    return {"records": records, "next_offset": offset}


def parse_rdata(data, offset, rtype, rdlength):
    """Interpreta o campo RDATA conforme o tipo de registro."""
    if rtype == QTYPE_A and rdlength == 4:
        return ".".join(str(b) for b in data[offset:offset + 4])
    elif rtype == QTYPE_AAAA and rdlength == 16:
        parts = struct.unpack("!8H", data[offset:offset + 16])
        return ":".join(f"{p:04x}" for p in parts)
    elif rtype == QTYPE_CNAME or rtype == QTYPE_NS:
        name, _ = decode_domain_name(data, offset)
        return name
    elif rtype == QTYPE_MX:
        preference = struct.unpack("!H", data[offset:offset + 2])[0]
        exchange, _ = decode_domain_name(data, offset + 2)
        return f"{preference} {exchange}"
    elif rtype == QTYPE_SOA:
        mname, off2 = decode_domain_name(data, offset)
        rname, off3 = decode_domain_name(data, off2)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[off3:off3 + 20])
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    else:
        return data[offset:offset + rdlength].hex()


def decode_domain_name(data, offset):
    """Decodifica um nome de domínio, tratando compressão de ponteiros (RFC 1035 §4.1.4)."""
    labels = []
    visited = set()
    original_offset = None

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            offset += 1
            break

        # Compressão: os dois bits mais significativos são 11
        if (length & 0xC0) == 0xC0:
            if original_offset is None:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if pointer in visited:
                raise ValueError("Loop de ponteiro detectado")
            visited.add(pointer)
            offset = pointer
            continue

        offset += 1
        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length

    final_offset = original_offset if original_offset is not None else offset
    return ".".join(labels), final_offset


def send_query(server_ip, domain, qtype=QTYPE_A, timeout=None):
    """Envia consulta DNS via UDP e retorna a resposta parseada + tempo."""
    if timeout is None:
        timeout = TIMEOUT
    tx_id, query = build_query(domain, qtype)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    start = time.time()
    try:
        sock.sendto(query, (server_ip, DNS_PORT))
        data, addr = sock.recvfrom(4096)
        elapsed = (time.time() - start) * 1000  # ms

        response = parse_response(data)

        # Verificar se o tx_id confere
        if response["tx_id"] != tx_id:
            return {
                "success": False,
                "error": "Transaction ID mismatch",
                "time_ms": elapsed,
            }

        return {
            "success": True,
            "response": response,
            "time_ms": elapsed,
        }
    except socket.timeout:
        elapsed = (time.time() - start) * 1000
        return {"success": False, "error": "Timeout", "time_ms": elapsed}
    except OSError as e:
        elapsed = (time.time() - start) * 1000
        return {"success": False, "error": str(e), "time_ms": elapsed}
    finally:
        sock.close()


def query_all_servers(domain, servers=None, qtype=QTYPE_A, timeout=TIMEOUT):
    """Consulta o domínio em todos os servidores e retorna resultados consolidados."""
    if servers is None:
        servers = DEFAULT_SERVERS

    results = []
    for ip, name in servers:
        result = send_query(ip, domain, qtype, timeout)
        result["server_ip"] = ip
        result["server_name"] = name
        results.append(result)

    return results


def detect_blocking(results):
    """Analisa os resultados e identifica possíveis bloqueios/manipulações."""
    alerts = []

    # Coletar todos os IPs retornados por cada servidor
    server_ips = {}
    rcodes = {}
    for r in results:
        key = f"{r['server_name']} ({r['server_ip']})"
        if not r["success"]:
            rcodes[key] = r["error"]
            continue

        rcode = r["response"]["flags"]["rcode"]
        rcodes[key] = RCODE_NAMES.get(rcode, f"RCODE={rcode}")

        ips = []
        for ans in r["response"]["answers"]:
            if ans["type"] == QTYPE_A:
                ips.append(ans["rdata"])
        server_ips[key] = ips

    # Contar quantos servidores responderam com sucesso (NOERROR + IPs)
    successful = {k: v for k, v in server_ips.items() if v}
    total_queried = len(results)

    # 1) NXDOMAIN enquanto maioria resolve
    nxdomain_servers = [k for k, v in rcodes.items() if v == "NXDOMAIN"]
    non_nxdomain = total_queried - len(nxdomain_servers)
    if nxdomain_servers and non_nxdomain > len(nxdomain_servers):
        for s in nxdomain_servers:
            alerts.append({
                "server": s,
                "type": "NXDOMAIN",
                "detail": "Resposta NXDOMAIN enquanto a maioria dos servidores resolve normalmente. Possível bloqueio.",
            })

    # 2) REFUSED
    refused_servers = [k for k, v in rcodes.items() if v == "REFUSED"]
    for s in refused_servers:
        alerts.append({
            "server": s,
            "type": "REFUSED",
            "detail": "O servidor recusou a consulta.",
        })

    # 3) Timeout / falhas
    failed_servers = [k for k, v in rcodes.items() if v == "Timeout"]
    for s in failed_servers:
        alerts.append({
            "server": s,
            "type": "TIMEOUT",
            "detail": "O servidor não respondeu dentro do tempo limite.",
        })

    # 4) Endereços nulos (0.0.0.0, 127.0.0.1)
    for server, ips in server_ips.items():
        blocked = [ip for ip in ips if ip in BLOCKED_IPS]
        if blocked:
            alerts.append({
                "server": server,
                "type": "ENDEREÇO NULO",
                "detail": f"Resposta contém IP(s) de bloqueio: {', '.join(blocked)}",
            })

    # 5) IP divergente — determinar consenso
    if len(successful) >= 2:
        # Contar frequência de conjuntos de IPs
        ip_sets = {}
        for server, ips in successful.items():
            key = tuple(sorted(ips))
            ip_sets.setdefault(key, []).append(server)

        if len(ip_sets) > 1:
            # Consenso = conjunto com mais servidores
            consensus_ips, consensus_servers = max(ip_sets.items(), key=lambda x: len(x[1]))
            for ip_set, servers_list in ip_sets.items():
                if ip_set != consensus_ips:
                    for s in servers_list:
                        alerts.append({
                            "server": s,
                            "type": "IP DIVERGENTE",
                            "detail": (
                                f"Retornou {', '.join(ip_set)} enquanto o consenso é "
                                f"{', '.join(consensus_ips)}. Possível redirecionamento."
                            ),
                        })

    return alerts


RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
GRAY   = "\033[90m"

# Desabilitar cores se não for terminal
if not sys.stdout.isatty():
    RESET = BOLD = GREEN = RED = YELLOW = CYAN = GRAY = ""


def colored_rcode(rcode_num):
    name = RCODE_NAMES.get(rcode_num, f"RCODE={rcode_num}")
    if rcode_num == 0:
        return f"{GREEN}{name}{RESET}"
    elif rcode_num == 3:
        return f"{RED}{name}{RESET}"
    elif rcode_num == 5:
        return f"{RED}{name}{RESET}"
    else:
        return f"{YELLOW}{name}{RESET}"


def print_separator(char="─", width=80):
    print(char * width)


def display_results(domain, results, alerts):
    """Exibe os resultados formatados no terminal."""
    print()
    print_separator("═")
    print(f"{BOLD}  DNS Analysis: {CYAN}{domain}{RESET}")
    print_separator("═")

    for r in results:
        print()
        print(f"  {BOLD}{r['server_name']}{RESET} {GRAY}({r['server_ip']}){RESET}")
        print_separator("─", 60)

        if not r["success"]:
            print(f"  Status:  {RED}FALHA — {r['error']}{RESET}")
            print(f"  Tempo:   {r['time_ms']:.1f} ms")
            continue

        resp = r["response"]
        rcode = resp["flags"]["rcode"]
        print(f"  RCODE:   {colored_rcode(rcode)}")
        print(f"  Tempo:   {r['time_ms']:.1f} ms")
        print(f"  Flags:   AA={resp['flags']['aa']}  TC={resp['flags']['tc']}  "
              f"RD={resp['flags']['rd']}  RA={resp['flags']['ra']}")

        # Answers
        a_records = [a for a in resp["answers"] if a["type"] == QTYPE_A]
        cname_records = [a for a in resp["answers"] if a["type"] == QTYPE_CNAME]
        other_records = [a for a in resp["answers"] if a["type"] not in (QTYPE_A, QTYPE_CNAME)]

        if cname_records:
            for rec in cname_records:
                print(f"  CNAME:   {rec['rdata']}  {GRAY}(TTL {rec['ttl']}){RESET}")

        if a_records:
            for rec in a_records:
                ip = rec["rdata"]
                color = RED if ip in BLOCKED_IPS else GREEN
                print(f"  A:       {color}{ip}{RESET}  {GRAY}(TTL {rec['ttl']}){RESET}")
        elif rcode == 0:
            print(f"  {GRAY}(nenhum registro A na resposta){RESET}")

        for rec in other_records:
            print(f"  {rec['type_name']:7s}  {rec['rdata']}  {GRAY}(TTL {rec['ttl']}){RESET}")

        # Authority
        if resp["authority"]:
            print(f"  {GRAY}Authority:{RESET}")
            for rec in resp["authority"]:
                print(f"    {rec['type_name']:7s}  {rec['rdata']}")

    # Alertas de bloqueio
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

    # Tabela comparativa
    print()
    print_separator("═")
    print(f"{BOLD}  Tabela Comparativa{RESET}")
    print_separator("═")
    print(f"  {'Servidor':<26} {'RCODE':<12} {'IPs':<36} {'Tempo':>8}")
    print_separator("─")

    for r in results:
        server = f"{r['server_name'][:20]} ({r['server_ip']})"
        if not r["success"]:
            rcode_str = r["error"]
            ips_str = "—"
        else:
            rcode_num = r["response"]["flags"]["rcode"]
            rcode_str = RCODE_NAMES.get(rcode_num, str(rcode_num))
            ips = [a["rdata"] for a in r["response"]["answers"] if a["type"] == QTYPE_A]
            ips_str = ", ".join(ips) if ips else "—"

        time_str = f"{r['time_ms']:.1f} ms"
        # Sem cores na tabela para alinhamento
        print(f"  {server:<40} {rcode_str:<12} {ips_str:<36} {time_str:>8}")

    print_separator("═")
    print()


def load_system_resolvers():
    """Tenta carregar servidores do /etc/resolv.conf (Linux)."""
    resolvers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    ip = line.split()[1]
                    resolvers.append((ip, f"Sistema ({ip})"))
    except (FileNotFoundError, PermissionError):
        pass
    return resolvers


def parse_server_list(spec):
    """Parseia uma lista de servidores no formato 'ip:nome,ip:nome,...'."""
    servers = []
    for entry in spec.split(","):
        entry = entry.strip()
        if ":" in entry:
            ip, name = entry.split(":", 1)
            servers.append((ip.strip(), name.strip()))
        else:
            servers.append((entry, entry))
    return servers

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Ferramenta de análise de resolução DNS (UDP raw, RFC 1035)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Exemplos:
  %(prog)s www.google.com
  %(prog)s www.pucrs.br --include-system
  %(prog)s example.com --servers "1.1.1.1:Cloudflare,8.8.8.8:Google"
  %(prog)s example.com --timeout 3
""",
    )
    parser.add_argument("domain", help="Nome de domínio a consultar")
    parser.add_argument(
        "--servers", "-s",
        help="Lista de servidores DNS customizados (formato: ip:nome,ip:nome,...)",
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
        choices=["A", "AAAA", "CNAME", "NS", "MX", "SOA"],
        help="Tipo de registro DNS a consultar (padrão: A)",
    )

    args = parser.parse_args()

    type_map = {
        "A": QTYPE_A, "AAAA": QTYPE_AAAA, "CNAME": QTYPE_CNAME,
        "NS": QTYPE_NS, "MX": QTYPE_MX, "SOA": QTYPE_SOA,
    }
    qtype = type_map[args.qtype]

    # Montar lista de servidores
    servers = []
    if args.servers:
        servers.extend(parse_server_list(args.servers))
    if args.include_system:
        sys_resolvers = load_system_resolvers()
        # Evitar duplicatas
        existing_ips = {s[0] for s in servers}
        for ip, name in sys_resolvers:
            if ip not in existing_ips:
                servers.append((ip, name))
                existing_ips.add(ip)
    if not servers:
        servers = list(DEFAULT_SERVERS)

    # Executar consultas
    results = query_all_servers(args.domain, servers, qtype, args.timeout)

    # Detectar bloqueios
    alerts = detect_blocking(results)

    # Exibir
    display_results(args.domain, results, alerts)


if __name__ == "__main__":
    main()
