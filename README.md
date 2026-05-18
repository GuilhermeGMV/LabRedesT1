# DNS Analyzer

Ferramenta de análise de resolução DNS via UDP e DNS over TLS (DoT).

## Requisitos

Python 3.8+, sem dependências externas.

## Uso básico

```bash
python3 dns_analyzer.py <domínio> [opções]
```

---

## Modos de execução

### Consulta UDP simples
Consulta um domínio em todos os servidores padrão via UDP (porta 53).
```bash
python3 dns_analyzer.py www.google.com
```

### Consulta DoT
Consulta via DNS over TLS (TCP/TLS, porta 853).
```bash
python3 dns_analyzer.py www.google.com --dot
```

### Benchmark UDP vs DoT
Executa N consultas (padrão: 10) e compara latência entre os dois protocolos.
```bash
python3 dns_analyzer.py www.google.com --benchmark
python3 dns_analyzer.py www.google.com --benchmark --benchmark-count 20
```

### Suíte de testes (domínios predefinidos)
Roda todos os domínios de teste embutidos, um por um, com análise de bloqueio.
```bash
python3 dns_analyzer.py --test-suite
python3 dns_analyzer.py --test-suite --dot
```

### Varredura de bloqueios — `--full-scan`
Roda **todos os domínios × todos os servidores** (UDP e DoT) uma vez e exibe uma matriz de status com detecção de bloqueios (NXDOMAIN, REFUSED, IP bloqueado, IP divergente, timeout).
```bash
python3 dns_analyzer.py --full-scan
```

### Benchmark completo — `--full-benchmark`
Roda **todos os domínios × todos os servidores** (UDP e DoT) N vezes e exibe mínimo, média e máximo de latência por servidor.
```bash
python3 dns_analyzer.py --full-benchmark
python3 dns_analyzer.py --full-benchmark --full-benchmark-count 20
```

---

## Opções gerais

| Opção | Descrição |
|---|---|
| `--timeout <s>` | Timeout por consulta em segundos (padrão: 5) |
| `--type <A\|AAAA\|MX\|NS\|CNAME\|SOA>` | Tipo de registro DNS (padrão: A) |
| `--servers "ip:nome,..."` | Servidores UDP customizados |
| `--dot-servers "host:nome,..."` | Servidores DoT customizados |
| `--include-system` | Inclui servidores de `/etc/resolv.conf` |
| `--insecure-dot` | Desabilita verificação do certificado TLS |
| `--list-test-domains` | Lista os domínios de teste embutidos |

---

## Exemplos

```bash
# Consulta simples
python3 dns_analyzer.py www.pucrs.br

# Usando servidores customizados
python3 dns_analyzer.py example.com --servers "1.1.1.1:Cloudflare,8.8.8.8:Google"

# Incluindo o DNS configurado no sistema
python3 dns_analyzer.py example.com --include-system

# Consulta DoT sem verificar certificado (para testes)
python3 dns_analyzer.py example.com --dot --insecure-dot

# Varredura completa de bloqueios com timeout de 10s
python3 dns_analyzer.py --full-scan --timeout 10

# Ver domínios de teste disponíveis
python3 dns_analyzer.py --list-test-domains
```
