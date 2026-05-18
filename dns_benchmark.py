import statistics

from dns_clients import send_dot_query, send_query
from dns_config import MIN_BENCHMARK_QUERIES, QTYPE_A, TIMEOUT


def benchmark_udp(domain, server_ip, qtype=QTYPE_A, timeout=TIMEOUT,
                  count=MIN_BENCHMARK_QUERIES):
    """Executa varias consultas UDP para medir desempenho."""
    return [send_query(server_ip, domain, qtype, timeout) for _ in range(count)]


def benchmark_dot(domain, server_host, qtype=QTYPE_A, timeout=TIMEOUT,
                  count=MIN_BENCHMARK_QUERIES, verify_tls=True):
    """Executa varias consultas DoT para medir desempenho."""
    return [
        send_dot_query(server_host, domain, qtype, timeout, verify_tls=verify_tls)
        for _ in range(count)
    ]


def summarize_benchmark(results):
    """Calcula estatisticas simples a partir dos tempos bem-sucedidos."""
    times = [result["time_ms"] for result in results if result["success"]]
    summary = {
        "total": len(results),
        "successes": len(times),
        "failures": len(results) - len(times),
        "avg": None,
        "median": None,
        "min": None,
        "max": None,
        "stdev": None,
        "query_bytes_avg": None,
        "response_bytes_avg": None,
    }
    if not times:
        return summary

    successful = [result for result in results if result["success"]]
    summary.update({
        "avg": statistics.mean(times),
        "median": statistics.median(times),
        "min": min(times),
        "max": max(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0.0,
        "query_bytes_avg": statistics.mean(
            result.get("dot_framed_query_bytes", result.get("query_bytes", 0))
            for result in successful
        ),
        "response_bytes_avg": statistics.mean(
            result.get("dot_framed_response_bytes", result.get("response_bytes", 0))
            for result in successful
        ),
    })
    return summary
