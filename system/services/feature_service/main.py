"""feature-service: subscribe `packets` -> คำนวณ feature -> publish `features`

ใช้ shared/features.py ตัวเดียวกับตอนเทรน (feature ต้องเหมือนกันเป๊ะ)
รันเดี่ยว:  python system/services/feature_service/main.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared.bus import Publisher, Subscriber
from shared.config import bus_port, load_config
from shared.features import FEATURE_VERSION, FeatureExtractor
from shared.schemas import TOPIC_FEATURES, TOPIC_PACKETS, FeatureMsg
from shared.utils import setup_logging

SERVICE = "feature"


def main() -> None:
    log = setup_logging(SERVICE)
    cfg = load_config()
    host = cfg["bus"]["host"]

    sub = Subscriber(bus_port(cfg, TOPIC_PACKETS), TOPIC_PACKETS, host)
    pub = Publisher(bus_port(cfg, TOPIC_FEATURES), TOPIC_FEATURES, host)
    extractor = FeatureExtractor(cfg["feature"]["window_sec"])
    log.info("subscribed to '%s' at %s", TOPIC_PACKETS, sub.endpoint)
    log.info("publishing '%s' at %s (window=%ss)", TOPIC_FEATURES, pub.endpoint, cfg["feature"]["window_sec"])

    total = 0
    last_log, last_total = time.time(), 0
    try:
        while True:
            for meta in sub.recv_many(200, 512):
                try:
                    vec = extractor.extract(meta)
                except Exception as e:  # noqa: BLE001
                    log.warning("feature extraction failed: %s (%s)", e, meta)
                    continue
                pub.send(FeatureMsg(meta=meta, vector=vec, feature_version=FEATURE_VERSION).to_dict())
                total += 1
            now = time.time()
            if now - last_log >= 30:
                log.info("processed %d packets total (+%d)", total, total - last_total)
                last_log, last_total = now, total
    except KeyboardInterrupt:
        log.info("shutting down ...")
    finally:
        sub.close()
        pub.close()
        log.info("stopped")


if __name__ == "__main__":
    main()
