"""สร้างเหตุผลสั้นๆ ของ alert (rule-based จาก metadata + feature)

Isolation Forest อธิบายเหตุผลเองไม่ได้ จึงใช้กฎง่ายๆ ดูว่า packet นี้ "แปลก" เรื่องอะไร
"""
from __future__ import annotations

from .features import FEATURE_NAMES

_ICMP_NAMES = {
    0: "echo reply", 3: "destination unreachable", 5: "redirect",
    8: "echo request", 11: "time exceeded", 13: "timestamp request",
}


def explain(meta: dict, vector: list | None = None) -> str:
    feats = dict(zip(FEATURE_NAMES, vector)) if vector else {}
    proto = meta.get("proto")
    flags = meta.get("tcp_flags")

    if proto == "ICMP":
        t = meta.get("icmp_type")
        if t == 8:
            return "ICMP echo request (ping) - not seen in normal traffic"
        if t == 0:
            return "ICMP echo reply (ping response) - not seen in normal traffic"
        name = _ICMP_NAMES.get(t, f"type {t}")
        return f"Unusual ICMP {name} - not seen in normal traffic"

    unans = feats.get("ctx_unans_ports", 0)
    unans_long = feats.get("ctx_unans_ports_long", 0)
    if unans >= 10:
        return f"Port scan: {int(unans)} ports probed without reply within 5s"
    if unans_long >= 20:
        return f"Slow port scan: {int(unans_long)} ports probed without reply within 60s"

    # v4 (A-F): สัญญาณจากพฤติกรรม/ปริมาณที่ v3 ยังไม่ครอบ (threshold เป็นค่าประมาณ ปรับได้)
    same_endpoint = feats.get("ctx_same_endpoint", 0)
    if same_endpoint >= 15:
        return f"Brute force / repeated requests: {int(same_endpoint)} connections to the same endpoint within 5s"

    half_open = feats.get("ctx_half_open", 0)
    if half_open >= 8:
        return f"Possible slowloris: {int(half_open)} TCP connections held open without closing"

    beacon_cv = feats.get("ctx_beacon_cv")
    ctx_pkts = feats.get("ctx_pkts", 0)
    if beacon_cv is not None and beacon_cv < 0.12 and ctx_pkts >= 4:
        return "Possible periodic beacon (C2) - very regular timing to the same destination"

    dns_qlen = feats.get("dns_qlen", 0)
    if dns_qlen and dns_qlen >= 50:
        return f"Unusually long DNS query name ({int(dns_qlen)} chars) - possible DNS tunneling"

    dns_qrate = feats.get("ctx_dns_qrate", 0)
    if dns_qrate >= 20:
        return f"Unusually high DNS query rate: {int(dns_qrate)} queries within 5s - possible DNS tunneling"

    bytes_sum = feats.get("ctx_bytes", 0)
    if bytes_sum >= 2_000_000:
        return f"High-volume burst: {int(bytes_sum):,} bytes from this source within 5s"

    ports = feats.get("ctx_low_ports", 0)
    ips = feats.get("ctx_dst_ips", 0)
    if ports >= 15:
        return f"Port scan: {int(ports)} distinct service ports from this source within 5s"
    if ips >= 25:
        return f"Host scan: {int(ips)} distinct IPs contacted within 5s"

    if proto == "TCP" and flags is not None:
        if flags == 0:
            return "TCP NULL scan (no flags set)"
        if flags & 0x03 == 0x03:
            return "TCP SYN+FIN (invalid flag combination)"
        if flags & 0x29 == 0x29:
            return "TCP Xmas scan (FIN+PSH+URG)"

    if proto == "OTHER":
        return "Protocol not seen in normal traffic"
    return "Traffic pattern differs from normal baseline"
