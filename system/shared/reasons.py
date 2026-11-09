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
            return "ICMP echo request (ping) ไม่พบใน traffic ปกติ"
        if t == 0:
            return "ICMP echo reply (ตอบ ping) ไม่พบใน traffic ปกติ"
        name = _ICMP_NAMES.get(t, f"type {t}")
        return f"ICMP {name} ผิดปกติ ไม่พบใน traffic ปกติ"

    ports = feats.get("ctx_low_ports", 0)
    ips = feats.get("ctx_dst_ips", 0)
    if ports >= 15:
        return f"สแกน port: src นี้ยิงไป {int(ports)} port ของ service ไม่ซ้ำภายใน 5 วินาที"
    if ips >= 25:
        return f"สแกน host: src นี้ติดต่อ {int(ips)} IP ไม่ซ้ำภายใน 5 วินาที"

    if proto == "TCP" and flags is not None:
        if flags == 0:
            return "TCP NULL scan (ไม่มี flag ใดเลย)"
        if flags & 0x03 == 0x03:
            return "TCP SYN+FIN (flag ผิดปกติ)"
        if flags & 0x29 == 0x29:
            return "TCP Xmas scan (FIN+PSH+URG)"

    if proto == "OTHER":
        return "โปรโตคอลที่ไม่พบใน traffic ปกติ"
    return "รูปแบบ traffic แตกต่างจาก baseline ปกติ"
