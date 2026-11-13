"""ฟังก์ชันที่ใช้ร่วมกันระหว่าง train.py และ train.ipynb (ไม่พึ่ง pandas)"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT, ROOT / "system"):          # shared/, services/ อยู่ใน system/
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from shared.config import load_config, resolve_path  # noqa: E402
from shared.features import FEATURE_NAMES, FEATURE_VERSION, FeatureExtractor  # noqa: E402
from training.generate_data import generate, load_packets_csv  # noqa: E402


def build_features(packets: list[dict], window_sec: float = 5.0) -> np.ndarray:
    """metadata ดิบ -> เมทริกซ์ feature ผ่าน shared/features.py (ใช้ extractor ใหม่ = state สะอาด)"""
    return FeatureExtractor(window_sec).extract_many(packets)


def train_model(X: np.ndarray, n_estimators: int = 200, seed: int = 42):
    """StandardScaler + Isolation Forest
    contamination='auto' เพราะเราใช้ score + threshold เองแทน predict() ของ sklearn"""
    scaler = StandardScaler().fit(X)
    model = IsolationForest(
        # ให้ทุก tree เห็นข้อมูลเกือบทั้งหมด: ICMP ในข้อมูลปกติมีน้อยมาก ถ้า subsample เล็ก
        # หลาย tree จะไม่เห็น ICMP เลย ทำให้ ping ไม่ถูกแยกออกมา
        n_estimators=n_estimators, max_samples=min(8192, len(X)),
        contamination="auto", random_state=seed, n_jobs=1,
    ).fit(scaler.transform(X))
    return scaler, model


def anomaly_scores(model, scaler, X: np.ndarray) -> np.ndarray:
    """anomaly score: ยิ่งสูงยิ่งแปลก (= -score_samples ช่วงประมาณ 0.3-0.8)"""
    return -model.score_samples(scaler.transform(X))


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


def recommend_threshold(normal_scores: np.ndarray, ping_scores: np.ndarray, quantile: float = 0.998,
                        gap_frac: float = 0.25) -> tuple[float, str]:
    """เลือก threshold: ต้องสูงกว่า score ปกติ (quantile ที่กำหนด) แต่ต่ำกว่า ping ที่ต่ำที่สุด
    ถ้าแยกกันได้ วางไว้ที่ gap_frac ของช่องว่างนับจากฝั่งปกติ (0.5 = กึ่งกลาง) — ค่าเริ่มต้น 0.25
    เพราะ ping มีระยะห่างเหลือเฟือ แต่การสแกนบางแบบ (เช่นไล่ host) ได้ score ต่ำกว่า ping จึงต้องเผื่อให้
    ถ้าแยกไม่ได้ ใช้ quantile ของ traffic ปกติและเตือน"""
    p_norm = float(np.quantile(normal_scores, quantile))
    ping_min = float(np.min(ping_scores))
    if ping_min > p_norm:
        return p_norm + gap_frac * (ping_min - p_norm), \
            f"OK: แยก ping ออกจาก traffic ปกติได้ (วางที่ {gap_frac:.0%} ของช่องว่างจากฝั่งปกติ)"
    return p_norm, ("คำเตือน: ping บางตัวมี score ต่ำกว่า quantile ของ traffic ปกติ — "
                    "ใช้ค่า quantile ของ traffic ปกติ (ping อาจหลุดบางตัว) ลองเพิ่มข้อมูล/ปรับ fp_quantile")


# ---------------------------------------------------------------- pipeline หลัก
def is_icmp_echo(p: dict) -> bool:
    return p["proto"] == "ICMP" and p.get("icmp_type") in (0, 8)


def run_training(cfg: dict | None = None, packets_csv=None, verbose: bool = True,
                 drop_icmp_echo: bool = True) -> dict:
    """โหลดข้อมูล -> เทรน -> ประเมิน -> คืนผลทุกอย่างเป็น dict (ยังไม่เขียนไฟล์)

    packets_csv: path เดียว หรือ list ของหลายไฟล์ (เช่น synthetic + traffic จริง)
      แต่ละไฟล์คำนวณ feature แยกกัน (sliding window ไม่ข้ามไฟล์) แล้วค่อยรวมเป็นชุดเทรนเดียว
    drop_icmp_echo: ตัด ping (ICMP echo) ออกจากข้อมูลเทรน — ถ้าไม่ตัด โมเดลจะเรียนว่า ping เป็นเรื่องปกติ"""
    cfg = cfg or load_config()
    tcfg = cfg["training"]
    window = cfg["feature"]["window_sec"]
    if not packets_csv:
        packets_csv = [resolve_path(tcfg["packets_csv"])]
    elif isinstance(packets_csv, (str, Path)):
        packets_csv = [packets_csv]
    paths = [Path(p) for p in packets_csv]
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"ไม่พบ {path} — รัน python training/generate_data.py ก่อน (หรือบันทึกด้วย capture mode csv)")
    packets, blocks, dropped = [], [], 0
    for path in paths:
        pk = load_packets_csv(path)
        if drop_icmp_echo:
            n = len(pk)
            pk = [p for p in pk if not is_icmp_echo(p)]
            dropped += n - len(pk)
        pk.sort(key=lambda p: p["ts"])
        packets += pk
        blocks.append(build_features(pk, window))
    X = np.vstack(blocks)
    if verbose and dropped:
        print(f"ตัด ICMP echo (ping) ออกจากข้อมูลเทรน {dropped} packets")
    scaler, model = train_model(X, tcfg["n_estimators"], tcfg["seed"])

    # ชุดปกติที่ model ไม่เคยเห็น (seed ต่างกัน) ไว้ประเมิน false positive
    holdout = generate(4000, tcfg["seed"] + 1)
    s_train = anomaly_scores(model, scaler, X)
    s_hold = anomaly_scores(model, scaler, build_features(holdout, window))
    hold_icmp = np.array([p["proto"] == "ICMP" for p in holdout])
    scen = score_scenarios(model, scaler, window)
    ping_all = ping_request_scores(model, scaler, window)          # เฉพาะ echo request (ping ขาเข้า)
    # ICMP error ที่ฝังไว้ในข้อมูลปกติมีหน้าที่แค่ให้โมเดลรู้จักมิติ ICMP -- IF แยกมันจาก echo ไม่ได้
    # จึงไม่นับเป็น "traffic ปกติ" ตอนเลือก threshold (รายงาน false positive แยกให้)
    thr, note = recommend_threshold(s_hold[~hold_icmp], ping_all, tcfg["fp_quantile"])
    return {
        "packets": packets, "X": X, "scaler": scaler, "model": model, "s_train": s_train, "s_hold": s_hold,
        "scenarios": scen, "ping_scores": ping_all, "threshold": thr, "note": note, "source": ", ".join(str(p) for p in paths),
        "fp_rate_holdout": float(np.mean(s_hold[~hold_icmp] >= thr)),
        "icmp_err_flag_rate": float(np.mean(s_hold[hold_icmp] >= thr)) if hold_icmp.any() else 0.0,
        "s_hold_non_icmp": s_hold[~hold_icmp],
        "ping_detect_rate": float(np.mean(ping_all >= thr)),
        "scan_report": scan_report(scen, thr),
    }


def save_artifacts(model, scaler, threshold: float, n_samples: int, source: str,
                   cfg: dict | None = None, extra: dict | None = None) -> dict[str, Path]:
    """บันทึกโมเดล + scaler + meta.json ไปที่ path ใน config (detection-service โหลดจากที่นี่)
    ใช้ร่วมกันทั้ง train.py และ train.ipynb"""
    cfg = cfg or load_config()
    dcfg = cfg["detection"]
    paths = {k: resolve_path(dcfg[k]) for k in ("model_path", "scaler_path", "meta_path")}
    paths["model_path"].parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, paths["model_path"])
    joblib.dump(scaler, paths["scaler_path"])
    meta = {
        "feature_names": FEATURE_NAMES,
        "feature_version": FEATURE_VERSION,
        "recommended_threshold": round(float(threshold), 5),
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "n_samples": int(n_samples),
        "source": source,
        **(extra or {}),
    }
    paths["meta_path"].write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return paths


def save_model(res: dict, cfg: dict | None = None) -> dict[str, Path]:
    qs = [0.5, 0.9, 0.99, 0.998, 1.0]
    extra = {
        "normal_score_quantiles": {str(q): round(float(np.quantile(res["s_hold"], q)), 5) for q in qs},
        "ping_score_min": round(float(res["ping_scores"].min()), 5),
        "fp_rate_holdout": round(res["fp_rate_holdout"], 5),
    }
    return save_artifacts(res["model"], res["scaler"], res["threshold"], len(res["X"]), res["source"], cfg, extra)


def print_report(res: dict) -> None:
    print(f"ข้อมูลเทรน: {len(res['X'])} packets จาก {res['source']}")
    q = np.quantile(res["s_hold_non_icmp"], [0.5, 0.99, 0.998, 1.0])
    print(f"score ของ traffic ปกติ ไม่นับ ICMP (hold-out): median={q[0]:.3f}  p99={q[1]:.3f}  p99.8={q[2]:.3f}  max={q[3]:.3f}")
    for name, sc in res["scenarios"].items():
        extra = ""
        if name in res["scan_report"]:
            r = res["scan_report"][name]
            extra = f"  จับ packet แรกที่ตัวที่ {r['first']}" if r["first"] else "  จับไม่ได้เลย"
            extra += "  [ผ่าน]" if r["ok"] else "  [ไม่ผ่าน]"
        print(f"  {name:<34} min={sc.min():.3f}  max={sc.max():.3f}  จับได้ {np.mean(sc >= res['threshold']) * 100:3.0f}%{extra}")
    print(f"threshold แนะนำ = {res['threshold']:.4f}  | {res['note']}")
    print(f"false positive (hold-out ปกติ ไม่นับ ICMP) = {res['fp_rate_holdout'] * 100:.2f}%  |  ping จับได้ {res['ping_detect_rate'] * 100:.0f}%")
    print(f"ICMP error ที่ปนอยู่ในข้อมูลปกติ ถูกมองว่าแปลก {res['icmp_err_flag_rate'] * 100:.0f}% (ยอมรับได้: ICMP หายากในบ้านอยู่แล้ว)")


def plot_scores(res: dict, out: str | Path | None = None, show: bool = False):
    """กราฟกระจาย score: traffic ปกติ vs ping vs port scan พร้อมเส้น threshold"""
    import matplotlib
    if not show:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.hist(res["s_hold"], bins=60, color="tab:gray", alpha=0.8, label="ปกติ (hold-out)")
    ymax = ax.get_ylim()[1]
    colors = ["tab:red", "tab:orange", "tab:pink", "tab:purple", "tab:blue", "tab:cyan", "tab:green",
              "tab:olive", "tab:brown", "magenta"]
    for (name, sc), c in zip(res["scenarios"].items(), colors):
        ax.scatter(sc, np.full(len(sc), ymax * 0.05) + np.random.default_rng(0).uniform(0, ymax * 0.1, len(sc)),
                   s=14, color=c, alpha=0.7, label=name)
    ax.axvline(res["threshold"], color="k", ls="--", label=f"threshold {res['threshold']:.3f}")
    ax.set_xlabel("anomaly score (สูง = แปลก)")
    ax.set_ylabel("จำนวน packet")
    ax.set_title("Score distribution")
    ax.legend(fontsize=8)
    fig.tight_layout()
    if out:
        fig.savefig(out, dpi=120)
    return fig
