"""จำลอง packet ของการโจมตี/ping เพื่อทดสอบว่าโมเดลที่เทรนเสร็จยังจับได้อยู่ไหม
(แยกออกจาก common.py โดยตั้งใจ: ไฟล์นี้คือ "ชุดทดสอบ" ไม่ใช่ส่วนหนึ่งของการเทรนจริง —
run_training() ใน common.py เรียกใช้ไฟล์นี้แค่เพื่อรายงานผล ไม่ได้เอา packet พวกนี้ไปเทรนด้วย)
"""
from __future__ import annotations

import numpy as np

from training.pipeline.common import anomaly_scores, build_features


# ---------------------------------------------------------------- packet จำลองสำหรับทดสอบ
def _icmp(ts, src, dst, typ, ttl, length, iface):
    return {"ts": ts, "iface": iface, "src_ip": src, "dst_ip": dst, "src_port": None, "dst_port": None,
            "proto": "ICMP", "length": length, "ttl": ttl, "tcp_flags": None, "icmp_type": typ, "icmp_code": 0}


def _ping_sequence(src, dst, ttl_req, ttl_rep, length, iface, count=4, interval=1.0, t0=1_800_000_000.0):
    pkts = []
    for i in range(count):
        t = t0 + i * interval
        pkts.append(_icmp(t, src, dst, 8, ttl_req, length, iface))          # echo request
        pkts.append(_icmp(t + 0.001, dst, src, 0, ttl_rep, length, iface))  # echo reply
    return pkts


def _tcp(ts, src, dst, sport, dport, flags, length=44, ttl=64, iface="eth0"):
    return {"ts": ts, "iface": iface, "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "proto": "TCP", "length": length, "ttl": ttl, "tcp_flags": flags, "icmp_type": None, "icmp_code": None}


def _udp(ts, src, dst, sport, dport, length=28, ttl=64, iface="eth0"):
    return {"ts": ts, "iface": iface, "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "proto": "UDP", "length": length, "ttl": ttl, "tcp_flags": None, "icmp_type": None, "icmp_code": None}


def make_scenarios() -> dict[str, list[dict]]:
    """ชุด packet จำลอง (แต่ละชุดคำนวณ feature แยกกัน): ping รูปแบบต่างๆ + nmap หลายแบบ
    ขนาด/flag/TTL อิงพฤติกรรมของ nmap จริง: SYN scan = 44 byte, port เรียงสุ่ม, src port คงที่"""
    rng = np.random.default_rng(123)
    me, atk = "192.168.1.50", "192.168.1.99"
    t0 = 1_800_000_000.0
    top_ports = [int(x) for x in rng.choice(np.arange(1, 10001), size=1000, replace=False)]

    syn100 = [_tcp(t0 + i * 0.02, atk, me, 40000, p, 0x02) for i, p in enumerate(top_ports[:100])]
    syn1000 = [_tcp(t0 + i * 0.002, atk, me, 40000, p, 0x02, ttl=int(rng.integers(37, 65)))
               for i, p in enumerate(top_ports)]
    connect = [_tcp(t0 + i * 0.01, atk, me, 50000 + i, p, 0x02, length=60) for i, p in enumerate(top_ports[:200])]
    udp = [_udp(t0 + i * 0.02, atk, me, 50000, p) for i, p in enumerate(top_ports[:100])]
    sweep_ping = []        # nmap -sn: ต่อ host ส่ง echo + SYN 443 + ACK 80 + timestamp request
    for i in range(1, 101):
        dst, t = f"192.168.1.{i}", t0 + i * 0.03
        sweep_ping += [_icmp(t, atk, dst, 8, 64, 28, "eth0"), _tcp(t + 0.001, atk, dst, 51000, 443, 0x02),
                       _tcp(t + 0.002, atk, dst, 51000, 80, 0x10), _icmp(t + 0.003, atk, dst, 13, 64, 40, "eth0")]
    sweep_syn = [_tcp(t0 + i * 0.01, atk, f"192.168.1.{i}", 40000, 22, 0x02) for i in range(1, 101)]
    return {
        "ping ตัวเอง (loopback, Windows)": _ping_sequence(me, me, 128, 128, 60, "lo"),
        "ping จากเครื่อง Windows": _ping_sequence("192.168.1.31", me, 128, 128, 60, "eth0"),
        "ping จากเครื่อง Linux/Mac": _ping_sequence("192.168.1.32", me, 64, 64, 84, "eth0"),
        "ping รัว (flood เล็กน้อย)": _ping_sequence("192.168.1.33", me, 64, 64, 84, "eth0", count=30, interval=0.1),
        "nmap -sS 100 port": syn100,
        "nmap -sS 1000 port": syn1000,
        "nmap -sT (connect) 200 port": connect,
        "nmap -sU (UDP) 100 port": udp,
        "nmap -sS ไล่ host (port 22 x100)": sweep_syn,
        "nmap -sn ไล่ host (ping sweep)": sweep_ping,
    }


def is_ping_scenario(name: str) -> bool:
    return name.startswith("ping")


def is_scan_scenario(name: str) -> bool:
    return name.startswith("nmap")


# การสแกนต้องถูกจับได้ภายในกี่ packet แรก (nmap ยิงราว 50-500 packet/วินาที = ภายในประมาณ 1 วินาที)
SCAN_DETECT_WITHIN = 40


def scan_report(scenarios: dict[str, np.ndarray], thr: float) -> dict[str, dict]:
    """ต่อ scenario ของ nmap: packet แรกที่เกิน threshold คือตัวที่เท่าไร และกี่ % ของทั้งชุดที่ถูกจับ"""
    out = {}
    for name, sc in scenarios.items():
        if not is_scan_scenario(name):
            continue
        hit = np.nonzero(sc >= thr)[0]
        first = int(hit[0]) + 1 if len(hit) else None
        out[name] = {"first": first, "rate": float(np.mean(sc >= thr)),
                     "ok": first is not None and first <= SCAN_DETECT_WITHIN}
    return out


def score_scenarios(model, scaler, window_sec: float = 5.0) -> dict[str, np.ndarray]:
    return {name: anomaly_scores(model, scaler, build_features(pkts, window_sec))
            for name, pkts in make_scenarios().items()}


def ping_request_scores(model, scaler, window_sec: float = 5.0) -> np.ndarray:
    """score ของ ICMP echo request (ping ขาเข้า) ใน scenario ping จำลอง
    feature คำนวณจากทั้งลำดับ (รวม echo reply) แต่เลือกเฉพาะ request: reply เป็นแค่สิ่งที่เครื่องเราตอบกลับ
    ตัวที่ต้องแจ้งเตือนคือ request ที่อีกฝั่งยิงเข้ามา (alert-service แจ้ง "ICMP echo request (ping)")"""
    out = []
    for name, pkts in make_scenarios().items():
        if is_ping_scenario(name):
            s = anomaly_scores(model, scaler, build_features(pkts, window_sec))
            out.append(s[np.array([p.get("icmp_type") == 8 for p in pkts])])
    return np.concatenate(out)
