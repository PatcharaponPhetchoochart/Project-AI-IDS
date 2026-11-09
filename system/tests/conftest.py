import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # รากโปรเจกต์ (มี training/)
for p in (ROOT, ROOT / "system"):                   # system/ มี shared/, services/
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
