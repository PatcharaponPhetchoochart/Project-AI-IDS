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


def test_extract_many_matches_extract():
    pkts = [pkt(ts=1000.0 + i * 0.1, dst_port=80 + i % 3) for i in range(10)]
    a = FeatureExtractor().extract_many(pkts)
    ex = FeatureExtractor()
    b = np.array([ex.extract(p) for p in pkts])
    assert a.shape == (10, N_FEATURES) and np.array_equal(a, b)
