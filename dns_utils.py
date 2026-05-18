def load_system_resolvers():
    """Tenta carregar servidores DNS do /etc/resolv.conf em sistemas Linux."""
    resolvers = []
    try:
        with open("/etc/resolv.conf", "r") as resolv_conf:
            for line in resolv_conf:
                line = line.strip()
                if line.startswith("nameserver"):
                    ip = line.split()[1]
                    resolvers.append((ip, f"Sistema ({ip})"))
    except (FileNotFoundError, PermissionError):
        pass
    return resolvers


def parse_server_list(spec):
    """Parseia lista no formato 'host:nome,host:nome,...'."""
    servers = []
    for entry in spec.split(","):
        entry = entry.strip()
        if ":" in entry:
            host, name = entry.split(":", 1)
            servers.append((host.strip(), name.strip()))
        else:
            servers.append((entry, entry))
    return servers


def parse_named_endpoint(spec, default_name=None):
    """Parseia um endpoint no formato 'host:nome' ou apenas 'host'."""
    if ":" in spec:
        host, name = spec.split(":", 1)
        return host.strip(), name.strip()
    return spec.strip(), (default_name or spec).strip()
