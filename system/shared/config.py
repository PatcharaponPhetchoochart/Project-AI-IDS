"""โหลด config กลาง (config/config.yaml) ให้ทุก service ใช้ร่วมกัน"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

# โฟลเดอร์รากของโปรเจกต์ (มี config/, data/, training/, system/)
ROOT = Path(__file__).resolve().parents[2]
# โฟลเดอร์ของระบบ (shared/, services/, models/, tests/ ...)
SYSTEM_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config" / "config.yaml"


def load_config(path: str | os.PathLike | None = None) -> dict:
    """อ่าน config — ใช้ตัวแปรสภาพแวดล้อม NIDS_CONFIG ได้ถ้าอยากชี้ไปไฟล์อื่น"""
    cfg_path = Path(path or os.environ.get("NIDS_CONFIG") or DEFAULT_CONFIG)
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    return cfg


def resolve_path(p: str | os.PathLike) -> Path:
    """path แบบ relative ให้อิงจากรากโปรเจกต์ (ไม่ขึ้นกับ cwd ที่รัน)"""
    p = Path(p)
    return p if p.is_absolute() else ROOT / p


def bus_port(cfg: dict, topic: str) -> int:
    return int(cfg["bus"]["ports"][topic])
