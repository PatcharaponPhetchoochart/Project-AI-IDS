"""ทดสอบ feature extraction (shared/features.py)"""
import numpy as np

from shared.features import FEATURE_NAMES, N_FEATURES, FeatureExtractor, port_bucket


def pkt(**kw):
    base = dict(ts=1000.0, iface="eth0", src_ip="10.0.0.2", dst_ip="10.0.0.9", src_port=50000, dst_port=443,
                proto="TCP", length=60, ttl=64, tcp_flags=0x10, icmp_type=None, icmp_code=None)
    base.update(kw)
    return base


def as_dict(vec):
    assert len(vec) == N_FEATURES
    return dict(zip(FEATURE_NAMES, vec))


def feats(**kw):
    """feature ของ packet เดียว (ใช้ extractor ใหม่ = ไม่มี state ค้าง)"""
    return as_dict(FeatureExtractor().extract(pkt(**kw)))


def test_feature_names_unique_and_count():
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES) == N_FEATURES


def test_port_bucket_boundaries():
    assert port_bucket(None) == 0
    assert port_bucket(0) == 1 and port_bucket(1023) == 1
    assert port_bucket(1024) == 2 and port_bucket(49151) == 2
    assert port_bucket(49152) == 3 and port_bucket(65535) == 3


def test_tcp_syn_ack_flags_split_into_bits():
    f = feats(tcp_flags=0x12)          # SYN+ACK
    assert f["proto_tcp"] == 1 and f["proto_udp"] == 0 and f["proto_icmp"] == 0
    assert f["flag_syn"] == 1 and f["flag_ack"] == 1
    assert f["flag_fin"] == f["flag_rst"] == f["flag_psh"] == 0
    assert f["port_wellknown"] == 1 and f["port_dynamic"] == 0
    assert f["length"] == 60 and f["ttl"] == 64


def test_icmp_echo_request_features():
    f = feats(proto="ICMP", src_port=None, dst_port=None, tcp_flags=None,
              icmp_type=8, icmp_code=0, length=84)
    assert f["proto_icmp"] == 1 and f["proto_tcp"] == 0
    assert f["icmp_type"] == 8
    assert f["port_none"] == 1 and f["port_wellknown"] == 0
    assert all(f[f"flag_{n}"] == 0 for n in ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"))


def test_nan_and_none_are_treated_as_zero():
    f = feats(proto="UDP", tcp_flags=float("nan"), icmp_type=None, dst_port=53)
    assert f["proto_udp"] == 1 and f["flag_ack"] == 0 and f["icmp_type"] == 0


def test_context_window_counts_ports_and_ips():
    ex = FeatureExtractor(window_sec=5.0)
    out = []
    for i in range(4):   # src เดียวกันยิงไป 4 port, 2 IP ภายใน 1 วินาที
        out.append(as_dict(ex.extract(pkt(ts=1000.0 + i * 0.25, dst_port=80 + i, dst_ip=f"10.0.0.{9 + i % 2}"))))
    assert [o["ctx_pkts"] for o in out] == [1, 2, 3, 4]
    assert [o["ctx_dst_ports"] for o in out] == [1, 2, 3, 4]
    assert [o["ctx_dst_ips"] for o in out] == [1, 2, 2, 2]


def test_low_ports_ignore_ephemeral_and_ratio():
    ex = FeatureExtractor()
    # src ตอบกลับ client หลายตัว (dst port สูง = ephemeral) ไม่นับเป็น low port
    for i in range(5):
        f = as_dict(ex.extract(pkt(src_ip="10.0.0.1", ts=1000.0 + i * 0.1, dst_ip=f"10.0.0.{20 + i}", dst_port=50000 + i)))
    assert f["ctx_dst_ports"] == 5 and f["ctx_low_ports"] == 0 and f["ctx_ip_ratio"] == 1.0
    # src อีกตัวไล่ยิง port ของ service 3 port (port เดิมซ้ำไม่นับ)
    for port in (22, 80, 443, 80):
        g = as_dict(ex.extract(pkt(src_ip="10.0.0.99", ts=1001.0, dst_port=port)))
    assert g["ctx_low_ports"] == 3 and g["ctx_pkts"] == 4 and g["ctx_ip_ratio"] == 0.25


def test_low_port_counter_decrements_when_window_expires():
    ex = FeatureExtractor(window_sec=5.0)
    for i, port in enumerate((22, 80, 443)):
        ex.extract(pkt(ts=1000.0 + i, dst_port=port))
    f = as_dict(ex.extract(pkt(ts=1020.0, dst_port=8080)))
    assert f["ctx_low_ports"] == 1


def test_context_window_expires_old_packets():
    ex = FeatureExtractor(window_sec=5.0)
    for i in range(3):
        ex.extract(pkt(ts=1000.0 + i, dst_port=1000 + i))
    f = as_dict(ex.extract(pkt(ts=1010.0, dst_port=2000)))      # ห่างเกิน 5 วินาที -> เหลือแค่ตัวเอง
    assert (f["ctx_pkts"], f["ctx_dst_ports"], f["ctx_dst_ips"]) == (1, 1, 1)


def test_context_is_per_source_ip():
    ex = FeatureExtractor()
    ex.extract(pkt(src_ip="10.0.0.2"))
    f = as_dict(ex.extract(pkt(src_ip="10.0.0.3")))
    assert f["ctx_pkts"] == 1


# ----------------------------------------------------------------- v4 feature A-F
def test_same_endpoint_counts_repeated_connections_to_one_port():
    """feature A: brute force / dir-enum ยิงรัวไป endpoint (dst_ip,dst_port) เดิมซ้ำๆ"""
    ex = FeatureExtractor()
    out = []
    for i in range(5):
        out.append(as_dict(ex.extract(pkt(ts=1000.0 + i * 0.05, dst_ip="10.0.0.9", dst_port=22))))
    assert [o["ctx_same_endpoint"] for o in out] == [1, 2, 3, 4, 5]
    # endpoint อื่น (คนละ port) ของ src เดียวกัน นับแยก ไม่ปนกับตัวแรก
    f = as_dict(ex.extract(pkt(ts=1000.3, dst_ip="10.0.0.9", dst_port=80)))
    assert f["ctx_same_endpoint"] == 1


def test_half_open_connections_for_slowloris():
    """feature B: handshake เสร็จ (เห็น ACK) แต่ไม่ปิด (ไม่มี FIN/RST) ค้างเกิน min_age -> นับเป็น half-open"""
    ex = FeatureExtractor()
    attacker = "10.0.0.50"
    t = 1000.0
    for i, port in enumerate(range(80, 85)):   # เปิด 5 connection, SYN แล้วตามด้วย ACK ทันที ไม่ปิดเลย
        ex.extract(pkt(ts=t, src_ip=attacker, dst_ip="10.0.0.1", src_port=40000 + i, dst_port=port, tcp_flags=0x02))
        ex.extract(pkt(ts=t + 0.01, src_ip=attacker, dst_ip="10.0.0.1", src_port=40000 + i, dst_port=port,
                       tcp_flags=0x10))
        t += 0.02
    f = as_dict(ex.extract(pkt(ts=t + 3.0, src_ip=attacker, dst_ip="10.0.0.1",
                              src_port=40099, dst_port=86, tcp_flags=0x02)))
    assert f["ctx_half_open"] == 5                 # ครบ min_age (2s) ทั้ง 5 connection
    # ปิดไปทีละตัวด้วย FIN -> นับลดลง
    ex.extract(pkt(ts=t + 3.1, src_ip=attacker, dst_ip="10.0.0.1", src_port=40000, dst_port=80, tcp_flags=0x11))
    g = as_dict(ex.extract(pkt(ts=t + 3.2, src_ip=attacker, dst_ip="10.0.0.1",
                              src_port=40098, dst_port=87, tcp_flags=0x02)))
    assert g["ctx_half_open"] == 4


def test_bytes_sum_accumulates_and_expires():
    """feature C: ผลรวม byte ใน window -> flood / exfil burst"""
    ex = FeatureExtractor(window_sec=5.0)
    f = None
    for i in range(3):
        f = as_dict(ex.extract(pkt(ts=1000.0 + i * 0.1, length=1000)))
    assert f["ctx_bytes"] == 3000
    f2 = as_dict(ex.extract(pkt(ts=1010.0, length=500)))     # ห่างเกิน window -> เหลือแค่ตัวเอง
    assert f2["ctx_bytes"] == 500


def test_beacon_cv_low_for_regular_timing_high_default_otherwise():
    """feature D: จังหวะสม่ำเสมอ (C2 beacon) -> CV ต่ำ / ข้อมูลไม่พอ -> ค่าเริ่มต้น"""
    ex = FeatureExtractor()
    f = as_dict(ex.extract(pkt(ts=1000.0, dst_ip="8.8.8.8")))
    assert f["ctx_beacon_cv"] == 2.0                          # BeaconTracker.DEFAULT_CV: ข้อมูลไม่พอ

    ex2 = FeatureExtractor()
    f = None
    for i in range(10):                                        # เคาะจังหวะเท่ากันทุก 2 วินาทีเป๊ะ ไปยัง dst เดิม
        f = as_dict(ex2.extract(pkt(ts=1000.0 + i * 2.0, dst_ip="8.8.8.8", dst_port=443)))
    assert f["ctx_beacon_cv"] < 0.05                          # แทบไม่มีความแปรปรวนเลย = คล้าย beacon


def test_dns_qlen_feature_passes_through_metadata():
    """feature E: ความยาวชื่อ DNS query ส่งผ่านจาก meta ตรงๆ (capture-service เป็นคนคำนวณ)"""
    ex = FeatureExtractor()
    f = as_dict(ex.extract(pkt(proto="UDP", dst_port=53, dns_qlen=42)))
    assert f["dns_qlen"] == 42
    g = as_dict(ex.extract(pkt(proto="UDP", dst_port=53)))     # ไม่มี dns_qlen ใน meta -> default 0
    assert g["dns_qlen"] == 0


def test_dns_query_rate_counts_only_queries_to_port_53():
    """feature E: ctx_dns_qrate นับเฉพาะ UDP:53 ไม่รวม UDP port อื่น"""
    ex = FeatureExtractor()
    f = None
    for i in range(4):
        f = as_dict(ex.extract(pkt(ts=1000.0 + i * 0.1, proto="UDP", dst_port=53, src_port=50000 + i)))
    assert f["ctx_dns_qrate"] == 4
    g = as_dict(ex.extract(pkt(ts=1000.5, proto="UDP", dst_port=12345)))   # UDP ธรรมดา ไม่ใช่ DNS
    assert g["ctx_dns_qrate"] == 4                              # ยังนับแค่ 4 query ก่อนหน้า ไม่เพิ่มจาก packet นี้


def test_resp_ports_counts_low_source_port_responses_separately():
    """feature F: ทิศทาง "ตอบกลับจาก port ต่ำ" แยกจาก ctx_low_ports (ทิศทางเปิดการเชื่อมต่อใหม่)"""
    ex = FeatureExtractor()
    server = "10.0.0.1"
    f = None
    for i in range(3):   # server ตอบกลับ client หลายตัวจาก src_port 80 เดิม (เว็บ server ปกติ)
        f = as_dict(ex.extract(pkt(ts=1000.0 + i * 0.1, src_ip=server, src_port=80,
                                   dst_ip=f"10.0.0.{10 + i}", dst_port=50000 + i)))
    assert f["ctx_resp_ports"] == 1       # ใช้ src_port 80 ซ้ำทุกครั้ง -> distinct ต่ำ = 1
    assert f["ctx_low_ports"] == 0        # ทิศทางนี้ dst_port สูง ไม่ถูกนับเป็น low_ports ปกติ


def test_extract_many_matches_extract():
    pkts = [pkt(ts=1000.0 + i * 0.1, dst_port=80 + i % 3) for i in range(10)]
    a = FeatureExtractor().extract_many(pkts)
    ex = FeatureExtractor()
    b = np.array([ex.extract(p) for p in pkts])
    assert a.shape == (10, N_FEATURES) and np.array_equal(a, b)


def _pkt(ts, src, dst, sport, dport, proto="TCP", flags=None, iface="eth0"):
    return {"ts": ts, "iface": iface, "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "proto": proto, "length": 60, "ttl": 64, "tcp_flags": flags, "icmp_type": None, "icmp_code": None}


def test_unanswered_ports_counts_scan_but_not_answered_traffic():
    """ctx_unans_ports: port ที่ยิงไปแล้วไม่มีใครตอบ (สแกน) สูง / การเชื่อมต่อที่ได้รับการตอบ (เว็บ, DNS) ต่ำ"""
    i_short, i_long = FEATURE_NAMES.index("ctx_unans_ports"), FEATURE_NAMES.index("ctx_unans_ports_long")
    # สแกน: SYN 50 port ไม่มีการตอบกลับ (หรือได้ RST = ปฏิเสธ)
    scan = []
    for i in range(50):
        scan.append(_pkt(1.0 + i * 0.01, "10.0.0.9", "10.0.0.1", 40000, 1 + i, flags=0x02))
        if i % 2:
            scan.append(_pkt(1.0 + i * 0.01 + 0.001, "10.0.0.1", "10.0.0.9", 1 + i, 40000, flags=0x14))  # RST+ACK
    X = FeatureExtractor(5.0).extract_many(scan)
    assert X[-2, i_short] == 50 and X[-2, i_long] == 50
    # UDP scan เงียบๆ
    udp = [_pkt(1.0 + i * 0.02, "10.0.0.9", "10.0.0.1", 50000, 1 + i, proto="UDP") for i in range(30)]
    assert FeatureExtractor(5.0).extract_many(udp)[-1, i_short] == 30
    # เว็บ: SYN -> SYN/ACK ทุกครั้ง + DNS query -> answer: ไม่ค้างเลย
    normal, t = [], 1.0
    for i in range(30):
        normal += [_pkt(t, "192.168.1.5", "1.1.1.1", 50000 + i, 53, proto="UDP"),
                   _pkt(t + 0.01, "1.1.1.1", "192.168.1.5", 53, 50000 + i, proto="UDP"),
                   _pkt(t + 0.02, "192.168.1.5", "142.250.1.1", 51000 + i, 443, flags=0x02),
                   _pkt(t + 0.03, "142.250.1.1", "192.168.1.5", 443, 51000 + i, flags=0x12)]
        t += 0.1
    X = FeatureExtractor(5.0).extract_many(normal)
    assert X[:, i_short].max() <= 2                 # ค้างได้ชั่วครู่แค่ระหว่างรอคำตอบ
    assert X[-1, i_short] == 0
    # DNS server ตอบหลาย client ต่าง port = การตอบกลับ ไม่ใช่การยิงใหม่
    server = []
    for i in range(40):
        server += [_pkt(1.0 + i * 0.01, f"192.168.1.{10 + i}", "192.168.1.1", 40000 + i, 53, proto="UDP"),
                   _pkt(1.0 + i * 0.01 + 0.001, "192.168.1.1", f"192.168.1.{10 + i}", 53, 40000 + i, proto="UDP")]
    X = FeatureExtractor(5.0).extract_many(server)
    assert X[1::2, i_short].max() == 0

