"""โครงสร้าง message ที่ส่งระหว่าง service (JSON ผ่าน ZeroMQ)

topic `packets`    -> PacketMsg      (capture  -> feature)
topic `features`   -> FeatureMsg     (feature  -> detection)
topic `detections` -> DetectionMsg   (detection -> alert, monitor)

ทุก message เป็น dict ธรรมดาตอนส่ง (ใช้ to_dict / from_dict แปลง)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

TOPIC_PACKETS = "packets"
TOPIC_FEATURES = "features"
TOPIC_DETECTIONS = "detections"


@dataclass
class PacketMsg:
    ts: float                         # epoch seconds
    iface: str
    src_ip: str
    dst_ip: str
    proto: str                        # TCP | UDP | ICMP | OTHER
    length: int                       # ขนาด IP packet ทั้งหมด (byte)
    ttl: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[int] = None   # bitmask (FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32 ECE=64 CWR=128)
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PacketMsg":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__ if k in d})


@dataclass
class FeatureMsg:
    meta: dict                        # PacketMsg ต้นฉบับ
    vector: list = field(default_factory=list)   # ลำดับตาม shared.features.FEATURE_NAMES
    feature_version: int = 1

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "FeatureMsg":
        return cls(meta=d["meta"], vector=d["vector"], feature_version=d.get("feature_version", 1))


@dataclass
class DetectionMsg:
    meta: dict
    vector: list
    score: float                      # anomaly score ยิ่งสูงยิ่งแปลก
    is_anomaly: bool
    threshold: float

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DetectionMsg":
        return cls(meta=d["meta"], vector=d["vector"], score=float(d["score"]),
                   is_anomaly=bool(d["is_anomaly"]), threshold=float(d.get("threshold", 0.0)))
