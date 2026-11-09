"""วัดผลโมเดล: ติด label ให้ packet, คำนวณ confusion matrix (TP/FP/TN/FN) และ metric ต่างๆ

ใช้ใน training/train.ipynb (ไม่พึ่ง pandas)
label: 0 = normal, 1 = attack (โจมตี/ผิดปกติ)
"""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, roc_auc_score, roc_curve

from shared.features import FeatureExtractor
from training.common import is_ping_scenario, make_scenarios
from training.generate_data import generate

NORMAL = "normal"


# ------------------------------------------------------------------ label จากไฟล์ labels.csv
def parse_time(v) -> float | None:
    """'' -> None, ตัวเลข -> epoch, ข้อความ -> ISO 8601 (ควรมี timezone เช่น -03:00)"""
    v = (v or "").strip()
    if not v:
        return None
    try:
        return float(v)
    except ValueError:
        return datetime.fromisoformat(v).timestamp()


def load_label_rules(path: Path) -> list[dict]:
    """อ่าน labels.csv (ข้ามบรรทัดที่ขึ้นต้นด้วย #)"""
    path = Path(path)
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    rules = []
    for row in csv.DictReader(lines):
        if not (row.get("label") or "").strip():
            continue
        rules.append({
            "label": row["label"].strip(),
            "src_ip": (row.get("src_ip") or "").strip() or None,
            "dst_ip": (row.get("dst_ip") or "").strip() or None,
            "start": parse_time(row.get("start")),
            "end": parse_time(row.get("end")),
            "both": (row.get("both_directions") or "0").strip() in ("1", "true", "yes"),
        })
    return rules


def _match(p: dict, r: dict) -> bool:
    if r["start"] is not None and p["ts"] < r["start"]:
        return False
    if r["end"] is not None and p["ts"] > r["end"]:
        return False
    fwd = (r["src_ip"] in (None, p["src_ip"])) and (r["dst_ip"] in (None, p["dst_ip"]))
    if fwd:
        return True
    return r["both"] and (r["src_ip"] in (None, p["dst_ip"])) and (r["dst_ip"] in (None, p["src_ip"]))


def label_packets(packets: list[dict], rules: list[dict]) -> list[str]:
    """คืนชื่อ label ต่อ packet ('normal' หรือชื่อการโจมตีจากกฎข้อแรกที่ตรง)"""
    out = []
    for p in packets:
        name = NORMAL
        for r in rules:
            if _match(p, r):
                name = r["label"]
                break
        out.append(name)
    return out


# ------------------------------------------------------------------ ชุดทดสอบจำลอง (ใช้ได้เสมอแม้ไม่มี pcap)
def simulated_test_set(n_normal: int = 4000, seed: int = 4242, window_sec: float = 5.0):
    """traffic ปกติจำลอง (seed ต่างจากชุดเทรน) + การโจมตีจำลอง (ping, nmap หลายแบบ)
    คืน list ของ block: (ชื่อ, packets, label names) — แต่ละ block คำนวณ feature แยกกัน"""
    blocks = []
    normal = generate(n_normal, seed)
    blocks.append(("ปกติ (จำลอง)", normal, [NORMAL] * len(normal)))
    for name, pkts in make_scenarios().items():
        kind = "ping" if is_ping_scenario(name) else "nmap"
        blocks.append((name, pkts, [f"{kind}: {name}"] * len(pkts)))
    return blocks


def blocks_to_xy(blocks, window_sec: float = 5.0):
    """แปลง block -> X (feature), y (0/1), names (ชื่อ label ต่อแถว)"""
    Xs, names = [], []
    for _, pkts, labels in blocks:
        if not pkts:
            continue
        Xs.append(FeatureExtractor(window_sec).extract_many(pkts))
        names += labels
    X = np.vstack(Xs)
    names = np.array(names, dtype=object)
    y = (names != NORMAL).astype(int)
    return X, y, names


# ------------------------------------------------------------------ metric
def binary_metrics(y_true, y_pred) -> dict:
    """TP/FP/TN/FN + Accuracy, Precision, Recall, F1, FPR, Specificity"""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    tp, fp, tn, fn = int(tp), int(fp), int(tn), int(fn)
    div = lambda a, b: a / b if b else 0.0  # noqa: E731
    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Accuracy": div(tp + tn, tp + tn + fp + fn),
        "Precision": precision,
        "Recall (TPR)": recall,
        "F1": div(2 * precision * recall, precision + recall),
        "FPR": div(fp, fp + tn),
        "Specificity (TNR)": div(tn, tn + fp),
        "Balanced Acc": (recall + div(tn, tn + fp)) / 2,
    }


def auc(y_true, scores) -> float | None:
    return float(roc_auc_score(y_true, scores)) if len(set(np.asarray(y_true).tolist())) == 2 else None


def threshold_sweep(y_true, scores, thresholds) -> list[dict]:
    rows = []
    for t in thresholds:
        m = binary_metrics(y_true, (scores >= t).astype(int))
        rows.append({"threshold": float(t), **m})
    return rows


def best_f1_threshold(y_true, scores, n: int = 200) -> float:
    ts = np.quantile(scores, np.linspace(0.5, 0.9999, n))
    rows = threshold_sweep(y_true, scores, np.unique(ts))
    return max(rows, key=lambda r: r["F1"])["threshold"]


def per_label_table(names, y_pred) -> list[dict]:
    """แต่ละ label: มีกี่ packet, ถูกมองว่าแปลกกี่ตัว (normal -> FP rate, attack -> detection rate)"""
    rows = []
    for lab in sorted(set(names.tolist()), key=lambda s: (s != NORMAL, s)):
        m = names == lab
        flagged = int(y_pred[m].sum())
        rows.append({"label": lab, "packets": int(m.sum()), "ถูกมองว่าแปลก": flagged,
                     "อัตรา": flagged / int(m.sum())})
    return rows


# ------------------------------------------------------------------ แสดงผล
def md_table(rows: list[dict], floatfmt: str = ".4f") -> str:
    """list[dict] -> ตาราง Markdown (ใช้กับ IPython.display.Markdown)"""
    if not rows:
        return "_(ไม่มีข้อมูล)_"
    cols = list(rows[0].keys())
    fmt = lambda v: format(v, floatfmt) if isinstance(v, float) else str(v)  # noqa: E731
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(fmt(r[c]) for c in cols) + " |" for r in rows]
    return "\n".join(lines)


def metrics_md(m: dict) -> str:
    keys = ["Accuracy", "Precision", "Recall (TPR)", "F1", "FPR", "Specificity (TNR)", "Balanced Acc"]
    rows = [{"metric": k, "ค่า": m[k]} for k in keys]
    if m.get("ROC-AUC") is not None:
        rows.append({"metric": "ROC-AUC", "ค่า": m["ROC-AUC"]})
    return md_table(rows)


def plot_confusion(m: dict, ax, title: str = "Confusion Matrix"):
    cm = np.array([[m["TN"], m["FP"]], [m["FN"], m["TP"]]])
    ax.imshow(cm, cmap="Blues")
    names = [["TN", "FP"], ["FN", "TP"]]
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{names[i][j]}\n{cm[i, j]:,}", ha="center", va="center", fontsize=12,
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    ax.set_xticks([0, 1], ["ทำนาย: ปกติ", "ทำนาย: โจมตี"])
    ax.set_yticks([0, 1], ["จริง: ปกติ", "จริง: โจมตี"])
    ax.set_title(title)


def plot_roc(y_true, scores, ax):
    fpr, tpr, _ = roc_curve(y_true, scores)
    ax.plot(fpr, tpr, label=f"AUC = {auc(y_true, scores):.4f}")
    ax.plot([0, 1], [0, 1], "k--", lw=0.8)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate (Recall)")
    ax.set_title("ROC curve")
    ax.legend(loc="lower right")


def plot_score_hist(y_true, scores, threshold, ax):
    bins = np.linspace(scores.min(), scores.max(), 60)
    ax.hist(scores[y_true == 0], bins=bins, alpha=0.7, color="tab:gray", label="ปกติ")
    ax.hist(scores[y_true == 1], bins=bins, alpha=0.7, color="tab:red", label="โจมตี")
    ax.axvline(threshold, color="k", ls="--", label=f"threshold {threshold:.4f}")
    ax.set_yscale("log")
    ax.set_xlabel("anomaly score (สูง = แปลก)")
    ax.set_ylabel("จำนวน packet (log)")
    ax.set_title("การกระจายของ score")
    ax.legend()
