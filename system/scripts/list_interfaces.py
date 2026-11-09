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

print(f"system loopback (use 'loopback' in config): {conf.loopback_name}")
print(f"Scapy default interface (use 'default'):    {getattr(conf.iface, 'name', conf.iface)}\n")
print(conf.ifaces)
if sys.platform.startswith("win"):
    print("\nNote: if NPF_Loopback is missing, reinstall Npcap with "
          "'Support loopback traffic' checked (see README)")
