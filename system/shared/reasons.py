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
