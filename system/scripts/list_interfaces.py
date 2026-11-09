"""แสดงรายชื่อ network interface ที่ Scapy มองเห็น (ใช้เลือกค่า capture.interfaces ใน config)

รัน:  python system/scripts/list_interfaces.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.utils import force_utf8, scapy_env  # noqa: E402

force_utf8()
scapy_env()

from scapy.all import conf  # noqa: E402

print(f"loopback ของระบบ (ใช้ชื่อ 'loopback' ใน config ได้): {conf.loopback_name}")
print(f"interface หลักของ Scapy (ใช้ชื่อ 'default' ได้):     {getattr(conf.iface, 'name', conf.iface)}\n")
print(conf.ifaces)
if sys.platform.startswith("win"):
    print("\nหมายเหตุ: ถ้าไม่เห็น Npcap Loopback Adapter ให้ติดตั้ง Npcap ใหม่และติ๊ก "
          "'Support loopback traffic' (ดู README)")
