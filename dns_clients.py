import socket
import ssl
import struct
import time

from dns_config import DEFAULT_SERVERS, DNS_PORT, DOT_PORT, DOT_SERVERS, QTYPE_A, TIMEOUT
from dns_protocol import build_query, parse_response


def send_query(server_ip, domain, qtype=QTYPE_A, timeout=None):
    """Envia uma consulta DNS por UDP e retorna resposta parseada e tempo."""
    if timeout is None:
        timeout = TIMEOUT
    tx_id, query = build_query(domain, qtype)

    sock = None
    start = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (server_ip, DNS_PORT))
        data, _addr = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - start) * 1000

        response = parse_response(data)
        if response["tx_id"] != tx_id:
            return _failure(
                "Transaction ID mismatch",
                elapsed,
                len(query),
                response_bytes=len(data),
            )

        return {
            "success": True,
            "response": response,
            "time_ms": elapsed,
            "query_bytes": len(query),
            "response_bytes": len(data),
        }
    except socket.timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return _failure("Timeout", elapsed, len(query))
    except (OSError, ValueError, struct.error) as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return _failure(str(exc), elapsed, len(query))
    finally:
        if sock is not None:
            sock.close()


def recv_exact(sock, size):
    """Recebe exatamente size bytes de um socket TCP/TLS."""
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Conexao encerrada antes do fim da resposta")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_dot_query(server_host, domain, qtype=QTYPE_A, timeout=None,
                   port=DOT_PORT, verify_tls=True):
    """Envia consulta DNS over TLS usando TCP/TLS e prefixo de tamanho de 2 bytes."""
    if timeout is None:
        timeout = TIMEOUT
    tx_id, query = build_query(domain, qtype)
    framed_query = struct.pack("!H", len(query)) + query

    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    # pega o IP do servidor pra otimizar
    try:
        server_ip = socket.getaddrinfo(
            server_host, port, family=socket.AF_INET, proto=socket.IPPROTO_TCP
        )[0][4][0]
    except socket.gaierror:
        server_ip = server_host

    start = time.perf_counter()
    try:
        with socket.create_connection((server_ip, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            with context.wrap_socket(raw_sock, server_hostname=server_host) as tls_sock:
                tls_sock.settimeout(timeout)
                tls_sock.sendall(framed_query)
                length_raw = recv_exact(tls_sock, 2)
                response_length = struct.unpack("!H", length_raw)[0]
                if response_length == 0:
                    raise ValueError("Resposta DoT vazia")
                data = recv_exact(tls_sock, response_length)

        elapsed = (time.perf_counter() - start) * 1000
        response = parse_response(data)
        if response["tx_id"] != tx_id:
            return _failure(
                "Transaction ID mismatch",
                elapsed,
                len(query),
                response_bytes=len(data),
                dot_framed_query_bytes=len(framed_query),
                dot_framed_response_bytes=len(data) + 2,
            )

        return {
            "success": True,
            "response": response,
            "time_ms": elapsed,
            "query_bytes": len(query),
            "response_bytes": len(data),
            "dot_framed_query_bytes": len(framed_query),
            "dot_framed_response_bytes": len(data) + 2,
        }
    except socket.timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return _failure(
            "Timeout",
            elapsed,
            len(query),
            dot_framed_query_bytes=len(framed_query),
        )
    except (OSError, ssl.SSLError, ValueError, struct.error) as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return _failure(
            str(exc),
            elapsed,
            len(query),
            dot_framed_query_bytes=len(framed_query),
        )


def query_all_servers(domain, servers=None, qtype=QTYPE_A, timeout=TIMEOUT):
    """Consulta o dominio em todos os servidores UDP informados."""
    if servers is None:
        servers = DEFAULT_SERVERS

    results = []
    for ip, name in servers:
        result = send_query(ip, domain, qtype, timeout)
        result["server_ip"] = ip
        result["server_name"] = name
        result["protocol"] = "UDP"
        results.append(result)
    return results


def query_all_dot_servers(domain, servers=None, qtype=QTYPE_A, timeout=TIMEOUT,
                          verify_tls=True):
    """Consulta o dominio em todos os servidores DoT informados."""
    if servers is None:
        servers = DOT_SERVERS

    results = []
    for host, name in servers:
        result = send_dot_query(host, domain, qtype, timeout, verify_tls=verify_tls)
        result["server_ip"] = host
        result["server_name"] = name
        result["protocol"] = "DoT"
        results.append(result)
    return results


def _failure(error, elapsed, query_bytes, response_bytes=0,
             dot_framed_query_bytes=None, dot_framed_response_bytes=0):
    result = {
        "success": False,
        "error": error,
        "time_ms": elapsed,
        "query_bytes": query_bytes,
        "response_bytes": response_bytes,
    }
    if dot_framed_query_bytes is not None:
        result["dot_framed_query_bytes"] = dot_framed_query_bytes
        result["dot_framed_response_bytes"] = dot_framed_response_bytes
    return result
