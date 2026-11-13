# Baseline v1 — โมเดลเดิม (ก่อนเทรนด้วย CIC-IDS2017 + traffic บ้าน)

สำรองไว้ที่ `C:\Project_AI\models_backup_v1`

## การเทรน (2026-11-12 16:08, `python training\train.py`)
- ข้อมูลเทรน: synthetic `data/normal_packets.csv` 8,000 packets
- threshold = **0.6308** (recommended)
- false positive (hold-out ปกติ ไม่นับ ICMP) = **0.10%**
- ping จำลอง: จับได้ 100% ทุกแบบ (ตัวเอง/Windows/Linux/flood)

| scenario จำลอง | จับได้ | packet แรกที่จับ |
|---|---|---|
| nmap -sS 100 port | 94% | 1 |
| nmap -sS 1000 port | 99% | 1 |
| nmap -sT 200 port | 97% | 1 |
| nmap -sU 100 port | 73% | 28 |
| nmap -sS ไล่ host (port 22 x100) | 93% | 8 |
| nmap -sn ping sweep | 68% | 1 |

## ทดสอบสดบนเครื่องจริง (Windows, Ethernet 192.168.1.36)

| # | การทดสอบ | เวลา | ผล | score |
|---|---|---|---|---|
| 1 | ping ตัวเอง `ping 192.168.1.36` (ping_only) | 16:10 | ✅ ALERT ทุก packet (iface=loopback) | 0.63–0.76 |
| 2 | ping จาก iPhone 192.168.1.34 (ping_only) | 16:31 | ✅ ALERT ทุก packet (iface=Ethernet) | 0.74–0.78 |
| 3 | ใช้งานปกติ ~4 นาที (ping_only: false) | 16:37–16:41 | ⚠️ alert หลอก 3 จาก 702 packets (~0.4%) — HTTPS ขาออก | 0.638–0.646 |
| 4 | port scan จาก iPhone ด้วย Fing "Find open ports" | 16:44 | ✅ ALERT 61 ครั้ง ใน 10 วิ (พอร์ต 206→510+) แต่ score เกิน threshold นิดเดียว / พอร์ตต้นๆ อาจหลุด / เหตุผลเป็นแบบทั่วไป ไม่บอกว่า scan | 0.632–0.670 |
| 5 | alert หลอกระหว่างทดสอบ (QUIC/UDP 443, SSDP 1900, HTTPS) | 16:42–16:44 | ⚠️ score ซ้อนกับช่วงของ scan | 0.648–0.658 |

**สรุป:** ping แยกจาก traffic ปกติได้ชัด แต่ port scan จริงกับ traffic ปกติของบ้านมี score ซ้อนกัน (~0.63–0.67) → เทรนใหม่ด้วย traffic จริง
