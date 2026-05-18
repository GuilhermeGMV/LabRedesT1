from dns_config import BLOCKED_IPS, QTYPE_A, RCODE_NAMES


def detect_blocking(results):
    """Analisa resultados e identifica possiveis bloqueios ou manipulacoes."""
    alerts = []
    server_ips = {}
    rcodes = {}

    for result in results:
        key = f"{result['server_name']} ({result['server_ip']})"
        if not result["success"]:
            rcodes[key] = result["error"]
            continue

        rcode = result["response"]["flags"]["rcode"]
        rcodes[key] = RCODE_NAMES.get(rcode, f"RCODE={rcode}")

        ips = []
        for answer in result["response"]["answers"]:
            if answer["type"] == QTYPE_A:
                ips.append(answer["rdata"])
        server_ips[key] = ips

    successful = {server: ips for server, ips in server_ips.items() if ips}
    total_queried = len(results)

    nxdomain_servers = [server for server, rcode in rcodes.items() if rcode == "NXDOMAIN"]
    non_nxdomain = total_queried - len(nxdomain_servers)
    if nxdomain_servers and non_nxdomain > len(nxdomain_servers):
        for server in nxdomain_servers:
            alerts.append({
                "server": server,
                "type": "NXDOMAIN",
                "detail": (
                    "Resposta NXDOMAIN enquanto a maioria dos servidores resolve "
                    "normalmente. Possivel bloqueio."
                ),
            })

    refused_servers = [server for server, rcode in rcodes.items() if rcode == "REFUSED"]
    for server in refused_servers:
        alerts.append({
            "server": server,
            "type": "REFUSED",
            "detail": "O servidor recusou a consulta.",
        })

    failed_servers = [server for server, rcode in rcodes.items() if rcode == "Timeout"]
    for server in failed_servers:
        alerts.append({
            "server": server,
            "type": "TIMEOUT",
            "detail": "O servidor nao respondeu dentro do tempo limite.",
        })

    for server, ips in server_ips.items():
        blocked = [ip for ip in ips if ip in BLOCKED_IPS]
        if blocked:
            alerts.append({
                "server": server,
                "type": "ENDEREÇO NULO",
                "detail": f"Resposta contém IP(s) de bloqueio: {', '.join(blocked)}",
            })

    if len(successful) >= 2:
        ip_sets = {}
        for server, ips in successful.items():
            key = tuple(sorted(ips))
            ip_sets.setdefault(key, []).append(server)

        if len(ip_sets) > 1:
            consensus_ips, _consensus_servers = max(
                ip_sets.items(), key=lambda item: len(item[1])
            )
            for ip_set, servers_list in ip_sets.items():
                if ip_set == consensus_ips:
                    continue
                for server in servers_list:
                    alerts.append({
                        "server": server,
                        "type": "IP DIVERGENTE",
                        "detail": (
                            f"Retornou {', '.join(ip_set)} enquanto o consenso é "
                            f"{', '.join(consensus_ips)}. Possivel redirecionamento."
                        ),
                    })

    return alerts
