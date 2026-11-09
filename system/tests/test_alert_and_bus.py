"""ทดสอบ cooldown ของ alert-service, เหตุผลของ alert และ ZeroMQ bus"""
import io
import socket
import sqlite3
import time

from rich.console import Console

from services.alert_service.main import AlertManager
from shared.bus import Publisher, Subscriber
from shared.features import FEATURE_NAMES, N_FEATURES
from shared.reasons import explain
from shared.schemas import DetectionMsg


def det(src="192.168.1.30", ts=1000.0, typ=8, score=0.75):
    meta = {"ts": ts, "iface": "eth0", "src_ip": src, "dst_ip": "192.168.1.50", "src_port": None, "dst_port": None,
            "proto": "ICMP", "length": 84, "ttl": 64, "tcp_flags": None, "icmp_type": typ, "icmp_code": 0}
    return DetectionMsg(meta=meta, vector=[0.0] * N_FEATURES, score=score, is_anomaly=True, threshold=0.66)


def test_cooldown_merges_repeated_alerts_and_counts(tmp_path):
    now = [100.0]
    out = io.StringIO()
    mgr = AlertManager(tmp_path / "a.db", cooldown=10, console=Console(file=out, width=140), clock=lambda: now[0])
    mgr.handle(det(ts=1000.0))
    now[0] += 2
    mgr.handle(det(ts=1001.0, score=0.8))
    now[0] += 2
    mgr.handle(det(ts=1002.0))
    mgr.handle(det(src="192.168.1.31"))                  # src อื่น -> alert ใหม่แยกกัน
    rows = mgr.db.execute("SELECT src_ip, count, score FROM alerts ORDER BY id").fetchall()
    assert rows == [("192.168.1.30", 3, 0.8), ("192.168.1.31", 1, 0.75)]
    assert out.getvalue().count("ALERT") == 2            # พิมพ์ 2 ครั้ง ไม่ใช่ 4
    now[0] += 20                                          # หมด cooldown
    mgr.handle(det(ts=1030.0))
    assert mgr.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 3
    assert "รวม alert" in out.getvalue()                 # มีบรรทัดสรุปจำนวนครั้งที่ถูกรวม
    mgr.close()
    assert sqlite3.connect(tmp_path / "a.db").execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 3


def test_same_src_different_destinations_get_own_lines_but_are_bounded(tmp_path):
    out = io.StringIO()
    mgr = AlertManager(tmp_path / "b.db", cooldown=10, console=Console(file=out, width=140), clock=lambda: 100.0)
    for i in range(20):                                   # src เดียว ping 20 ปลายทาง
        d = det()
        d.meta["dst_ip"] = f"192.168.1.{100 + i}"
        mgr.handle(d)
    assert out.getvalue().count("ALERT") == AlertManager.MAX_DST_PER_SRC + 1   # 5 ปลายทาง + กลุ่มรวม "*"
    assert mgr.db.execute("SELECT SUM(count) FROM alerts").fetchone()[0] == 20
    mgr.close()


def test_reasons():
    ping = det().meta
    assert "echo request" in explain(ping, [0.0] * N_FEATURES)
    assert "echo reply" in explain({**ping, "icmp_type": 0}, None)
    vec = [0.0] * N_FEATURES
    vec[FEATURE_NAMES.index("ctx_low_ports")] = 40
    tcp = {**ping, "proto": "TCP", "tcp_flags": 2, "icmp_type": None}
    assert "สแกน port" in explain(tcp, vec)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_bus_roundtrip():
    port = free_port()
    pub = Publisher(port, "packets")
    sub = Subscriber(port, "packets")
    got = []
    try:
        deadline = time.time() + 5
        while not got and time.time() < deadline:    # รอ subscriber connect เสร็จ (slow joiner)
            pub.send({"hello": "สวัสดี"})
            got = sub.recv_many(100)
    finally:
        sub.close()
        pub.close()
    assert got and got[0] == {"hello": "สวัสดี"}
