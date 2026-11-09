"""ทดสอบตัวแปลง pcap -> CSV, การติด label จาก labels.csv และการคำนวณ TP/FP/TN/FN + metric"""
import numpy as np
import pytest

from training import evaluate as ev
from training.generate_data import load_packets_csv


def test_pcap_roundtrip_matches_capture_format(tmp_path):
    from shared.utils import scapy_env
    scapy_env()
    from scapy.all import ICMP, IP, TCP, UDP, Ether, wrpcap

    from training.pcap_to_csv import convert, convert_folder

    pkts = [Ether() / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) / TCP(sport=50000, dport=443, flags="S"),
            Ether() / IP(src="10.0.0.2", dst="10.0.0.1", ttl=128) / UDP(sport=53, dport=50001),
            Ether() / IP(src="10.0.0.3", dst="10.0.0.1", ttl=64) / ICMP(type=8)]
    for i, p in enumerate(pkts):
        p.time = 1000.0 + i
    src = tmp_path / "in"
    src.mkdir()
    wrpcap(str(src / "a.pcap"), pkts)

    stats = convert([src / "a.pcap"], tmp_path / "a.csv")
    assert stats["written"] == 3
    rows = load_packets_csv(tmp_path / "a.csv")
    assert [r["proto"] for r in rows] == ["TCP", "UDP", "ICMP"]
    assert rows[0]["tcp_flags"] == 0x02 and rows[0]["dst_port"] == 443 and rows[0]["ttl"] == 64
    assert rows[2]["icmp_type"] == 8 and rows[2]["dst_port"] is None
    assert rows[0]["ts"] == pytest.approx(1000.0)

    outs = convert_folder(src, tmp_path / "out")             # แปลงทั้งโฟลเดอร์ + cache
    assert len(outs) == 1 and outs[0].exists()
    mtime = outs[0].stat().st_mtime
    convert_folder(src, tmp_path / "out")                    # รอบสองต้องไม่แปลงซ้ำ
    assert outs[0].stat().st_mtime == mtime


def test_label_rules(tmp_path):
    f = tmp_path / "labels.csv"
    f.write_text("# comment\nlabel,src_ip,dst_ip,start,end,both_directions,note\n"
                 "PortScan,10.9.9.9,,100,200,0,x\n"
                 "DoS,,10.0.0.5,2017-07-07T13:55:00-03:00,,1,y\n", encoding="utf-8")
    rules = ev.load_label_rules(f)
    assert len(rules) == 2 and rules[1]["start"] == pytest.approx(1499446500.0)
    p = lambda ts, s, d: {"ts": ts, "src_ip": s, "dst_ip": d}  # noqa: E731
    names = ev.label_packets([
        p(150, "10.9.9.9", "1.1.1.1"),          # ผู้โจมตีในช่วงเวลา -> PortScan
        p(250, "10.9.9.9", "1.1.1.1"),          # นอกช่วงเวลา -> normal
        p(150, "1.1.1.1", "10.9.9.9"),          # ขาตอบกลับ แต่ both_directions=0 -> normal
        p(1499446600, "10.0.0.5", "8.8.8.8"),   # ขาตอบกลับของ DoS และ both=1 -> DoS
    ], rules)
    assert names == ["PortScan", "normal", "normal", "DoS"]


def test_binary_metrics_known_values():
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1, 1, 0])
    y_pred = np.array([0, 0, 0, 1, 1, 1, 1, 0, 0, 0])
    m = ev.binary_metrics(y_true, y_pred)
    assert (m["TP"], m["FP"], m["TN"], m["FN"]) == (3, 1, 4, 2)
    assert m["Accuracy"] == pytest.approx(0.7)
    assert m["Precision"] == pytest.approx(0.75)
    assert m["Recall (TPR)"] == pytest.approx(0.6)
    assert m["F1"] == pytest.approx(2 * 0.75 * 0.6 / 1.35)
    assert m["FPR"] == pytest.approx(0.2)


def test_metrics_without_any_attack_do_not_crash():
    m = ev.binary_metrics(np.zeros(5, int), np.zeros(5, int))
    assert m["TN"] == 5 and m["Recall (TPR)"] == 0.0
    assert ev.auc(np.zeros(5, int), np.arange(5.0)) is None


def test_simulated_test_set_has_both_classes():
    X, y, names = ev.blocks_to_xy(ev.simulated_test_set(500, 9))
    assert X.shape[0] == len(y) == len(names)
    assert 0 < y.sum() < len(y)
    assert set(names[y == 0]) == {"normal"}
