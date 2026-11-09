"""ทดสอบการให้คะแนน: ping ต้องแปลก, traffic ปกติต้องไม่แปลก (เทรนโมเดลเล็กๆ ใน fixture ไม่ต้องดัก network)"""
import numpy as np
import pytest

from training.common import (SCAN_DETECT_WITHIN, anomaly_scores, build_features, is_ping_scenario, is_scan_scenario,
                             make_scenarios, recommend_threshold, scan_report, train_model)
from training.generate_data import generate


@pytest.fixture(scope="module")
def trained():
    # ใช้ขนาดข้อมูล/พารามิเตอร์เดียวกับ config จริง (IF ต้องการข้อมูลพอสมควรจึงแยก ICMP ออกมาได้)
    train = generate(8000, seed=42)
    scaler, model = train_model(build_features(train), n_estimators=200, seed=42)
    hold = [p for p in generate(4000, seed=43) if p["proto"] != "ICMP"]
    s_hold = anomaly_scores(model, scaler, build_features(hold))
    pings = np.concatenate([anomaly_scores(model, scaler, build_features(v))
                            for k, v in make_scenarios().items() if is_ping_scenario(k)])
    thr, _ = recommend_threshold(s_hold, pings, 0.998)
    return model, scaler, s_hold, pings, thr


def test_synthetic_training_data_has_no_icmp_echo():
    pk = generate(3000, seed=1)
    assert not [p for p in pk if p["proto"] == "ICMP" and p["icmp_type"] in (0, 8)]


def test_ping_scores_higher_than_normal_traffic(trained):
    _, _, s_hold, pings, _ = trained
    assert np.median(pings) > np.quantile(s_hold, 0.99)
    assert pings.min() > np.median(s_hold)


def test_every_ping_flagged_at_recommended_threshold(trained):
    _, _, _, pings, thr = trained
    assert (pings >= thr).all()


def test_normal_traffic_rarely_flagged(trained):
    _, _, s_hold, _, thr = trained
    assert np.mean(s_hold >= thr) < 0.02


def test_single_ping_from_other_host_flagged_and_https_not(trained):
    model, scaler, _, _, thr = trained
    ping = [{"ts": 1.0, "iface": "eth0", "src_ip": "192.168.1.77", "dst_ip": "192.168.1.50", "src_port": None,
             "dst_port": None, "proto": "ICMP", "length": 84, "ttl": 64, "tcp_flags": None,
             "icmp_type": 8, "icmp_code": 0}]
    https = [{"ts": 1.0, "iface": "eth0", "src_ip": "192.168.1.10", "dst_ip": "142.250.1.1", "src_port": 51234,
              "dst_port": 443, "proto": "TCP", "length": 52, "ttl": 128, "tcp_flags": 0x10,
              "icmp_type": None, "icmp_code": None}]
    assert anomaly_scores(model, scaler, build_features(ping))[0] >= thr
    assert anomaly_scores(model, scaler, build_features(https))[0] < thr


def test_nmap_scans_detected_within_first_packets(trained):
    """nmap หลายแบบ (SYN/connect/UDP/ไล่ host/ping sweep) ต้องถูกจับได้ภายในไม่กี่ packet แรก"""
    model, scaler, _, _, thr = trained
    scores = {k: anomaly_scores(model, scaler, build_features(v)) for k, v in make_scenarios().items()
              if is_scan_scenario(k)}
    assert len(scores) >= 5
    rep = scan_report(scores, thr)
    bad = {k: r for k, r in rep.items() if not r["ok"]}
    assert not bad, f"จับไม่ทันภายใน {SCAN_DETECT_WITHIN} packet: {bad}"
