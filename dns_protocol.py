import random
import struct

from dns_config import (
    QCLASS_IN,
    QTYPE_A,
    QTYPE_AAAA,
    QTYPE_CNAME,
    QTYPE_MX,
    QTYPE_NS,
    QTYPE_SOA,
    TYPE_NAMES,
)


def build_query(domain, qtype=QTYPE_A):
    """Constroi uma mensagem de consulta DNS em formato binario."""
    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    question = encode_domain_name(domain)
    question += struct.pack("!HH", qtype, QCLASS_IN)

    return tx_id, header + question


def encode_domain_name(domain):
    """Codifica um nome de dominio no formato DNS de labels com tamanho."""
    parts = domain.rstrip(".").split(".")
    result = b""
    for part in parts:
        encoded = part.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"Label muito longa: {part}")
        result += struct.pack("B", len(encoded)) + encoded
    result += b"\x00"
    return result


def parse_response(data):
    """Interpreta uma resposta DNS binaria completa."""
    if len(data) < 12:
        raise ValueError("Resposta muito curta")

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )

    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF

    offset = 12

    questions = []
    for _ in range(qdcount):
        qname, offset = decode_domain_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        questions.append({"name": qname, "type": qtype, "class": qclass})

    answers = parse_rr_section(data, offset, ancount)
    offset = answers["next_offset"]
    authority = parse_rr_section(data, offset, nscount)
    offset = authority["next_offset"]
    additional = parse_rr_section(data, offset, arcount)

    return {
        "tx_id": tx_id,
        "flags": {
            "qr": qr,
            "opcode": opcode,
            "aa": aa,
            "tc": tc,
            "rd": rd,
            "ra": ra,
            "rcode": rcode,
        },
        "questions": questions,
        "answers": answers["records"],
        "authority": authority["records"],
        "additional": additional["records"],
    }


def parse_rr_section(data, offset, count):
    """Faz o parse de uma secao de resource records."""
    records = []
    for _ in range(count):
        name, offset = decode_domain_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = parse_rdata(data, offset, rtype, rdlength)
        offset += rdlength
        records.append({
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "rdlength": rdlength,
            "rdata": rdata,
            "type_name": TYPE_NAMES.get(rtype, str(rtype)),
        })
    return {"records": records, "next_offset": offset}


def parse_rdata(data, offset, rtype, rdlength):
    """Interpreta o campo RDATA conforme o tipo de registro."""
    if rtype == QTYPE_A and rdlength == 4:
        return ".".join(str(b) for b in data[offset:offset + 4])
    if rtype == QTYPE_AAAA and rdlength == 16:
        parts = struct.unpack("!8H", data[offset:offset + 16])
        return ":".join(f"{p:04x}" for p in parts)
    if rtype in (QTYPE_CNAME, QTYPE_NS):
        name, _ = decode_domain_name(data, offset)
        return name
    if rtype == QTYPE_MX:
        preference = struct.unpack("!H", data[offset:offset + 2])[0]
        exchange, _ = decode_domain_name(data, offset + 2)
        return f"{preference} {exchange}"
    if rtype == QTYPE_SOA:
        mname, off2 = decode_domain_name(data, offset)
        rname, off3 = decode_domain_name(data, off2)
        serial, refresh, retry, expire, minimum = struct.unpack(
            "!IIIII", data[off3:off3 + 20]
        )
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    return data[offset:offset + rdlength].hex()


def decode_domain_name(data, offset):
    """Decodifica nomes DNS e trata compressao por ponteiros."""
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
