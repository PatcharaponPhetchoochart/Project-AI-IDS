"""detection-service: subscribe `features` -> ให้คะแนน anomaly (Isolation Forest) -> publish `detections`

ทุก packet ถูก publish ออกไป (พร้อม score และ is_anomaly) ให้ alert/monitor เลือกใช้เอง
รันเดี่ยว:  python system/services/detection_service/main.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared.bus import Publisher, Subscriber
from shared.config import bus_port, load_config, resolve_path
from shared.features import FEATURE_NAMES, FEATURE_VERSION
from shared.schemas import TOPIC_DETECTIONS, TOPIC_FEATURES, DetectionMsg
from shared.utils import setup_logging

SERVICE = "detection"


def load_model(dcfg: dict, log):
    """โหลด model + scaler + meta จาก models/ — ถ้าไม่มีให้บอกชัดเจนว่าต้องเทรนก่อน"""
    import joblib

    model_p = resolve_path(dcfg["model_path"])
    scaler_p = resolve_path(dcfg["scaler_path"])
    meta_p = resolve_path(dcfg["meta_path"])
    missing = [str(p) for p in (model_p, scaler_p, meta_p) if not p.exists()]
    if missing:
        log.error("model files not found: %s", ", ".join(missing))
        log.error("train the model first: open training/train.ipynb and Run All (or: python training/train.py)")
        sys.exit(2)
    model = joblib.load(model_p)
    scaler = joblib.load(scaler_p)
    meta = json.loads(meta_p.read_text(encoding="utf-8"))
    if meta.get("feature_names") != FEATURE_NAMES or meta.get("feature_version") != FEATURE_VERSION:
        log.error("model features do not match shared/features.py - retrain the model (training/train.ipynb)")
        sys.exit(2)
    return model, scaler, meta


def resolve_threshold(dcfg: dict, meta: dict) -> float:
    th = dcfg.get("threshold", "auto")
    if isinstance(th, str) and th.strip().lower() == "auto":
        return float(meta["recommended_threshold"])
    return float(th)


def is_icmp_echo(meta: dict) -> bool:
    """ping = ICMP echo request (type 8) หรือ echo reply (type 0)"""
    return meta.get("proto") == "ICMP" and meta.get("icmp_type") in (0, 8)


def decide(score: float, threshold: float, meta: dict, ping_only: bool) -> bool:
    """ตัดสินว่าแปลกไหม: score >= threshold
    ping_only=True (โหมดทดสอบ ping) -> นับเฉพาะ ping ส่วน traffic อื่นที่ score สูงถือว่าปกติ (ตัด alert หลอกทิ้ง)"""
    if ping_only and not is_icmp_echo(meta):
        return False
    return bool(score >= threshold)


def main() -> None:
    log = setup_logging(SERVICE)
    cfg = load_config()
    dcfg = cfg["detection"]
    host = cfg["bus"]["host"]

    import numpy as np

    model, scaler, meta = load_model(dcfg, log)
    threshold = resolve_threshold(dcfg, meta)
    log.info("model loaded (trained %s, %s samples)", meta.get("trained_at"), meta.get("n_samples"))
    log.info("threshold = %.4f (%s)", threshold, "from system/models/meta.json" if str(dcfg.get("threshold")).lower() == "auto" else "from config")

    sub = Subscriber(bus_port(cfg, TOPIC_FEATURES), TOPIC_FEATURES, host)
    pub = Publisher(bus_port(cfg, TOPIC_DETECTIONS), TOPIC_DETECTIONS, host)
    log.info("subscribed to '%s' at %s", TOPIC_FEATURES, sub.endpoint)
    log.info("publishing '%s' at %s", TOPIC_DETECTIONS, pub.endpoint)

    ping_only = bool(dcfg.get("ping_only", False))
    if ping_only:
        log.info("ping_only mode: alerting on ping (ICMP echo) only - other traffic is never flagged")
    batch = int(dcfg.get("batch_size", 256))
    total = anomalies = 0
    last_log, last_total = time.time(), 0
    try:
        while True:
            msgs = sub.recv_many(100, batch)
            if msgs:
                X = np.asarray([m["vector"] for m in msgs], dtype=float)
                # score = -score_samples: ยิ่งสูงยิ่งแปลก (ช่วงประมาณ 0.3 - 0.8)
                scores = -model.score_samples(scaler.transform(X))
                for m, s in zip(msgs, scores):
                    is_anom = decide(float(s), threshold, m["meta"], ping_only)
                    anomalies += is_anom
                    pub.send(DetectionMsg(meta=m["meta"], vector=m["vector"], score=round(float(s), 5),
                                          is_anomaly=is_anom, threshold=threshold).to_dict())
                total += len(msgs)
            now = time.time()
            if now - last_log >= 30:
                log.info("scored %d packets total (+%d), anomalies %d", total, total - last_total, anomalies)
                last_log, last_total = now, total
    except KeyboardInterrupt:
        log.info("shutting down ...")
    finally:
        sub.close()
        pub.close()
        log.info("stopped")


if __name__ == "__main__":
    main()
