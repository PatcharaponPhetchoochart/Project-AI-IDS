# ทดสอบสด — โมเดล v3 (train_20261112_220654, threshold 0.6427)

session 22:28:01–22:33:49 (~6 นาที) บันทึกทุก packet ที่ `data/home_session3.csv` | ping_only: false | เปิด Discord voice ตลอด

| # | การทดสอบ | เวลา | ผล | score |
|---|---|---|---|---|
| 1 | traffic ปกติ + Discord (208,591 packets: UDP 161,211 / TCP 47,380, Discord ~160k) | ทั้ง session | ✅ **alert หลอก 0 ครั้ง** | — |
| 2 | Fing "Find open ports" (TCP SYN 806 packets → 280 ports ใน 14 วิ) | 22:29:20–22:29:34 | ✅ ALERT 796/806 (98.8%) | 0.734–0.735 |
| 3 | ping จาก iPhone | 22:29:38–22:30:02 | ✅ ALERT 12/12 (100%) | 0.720–0.724 |
| 4 | mDNS ของ iPhone ระหว่างสแกน (UDP 5353 → 224.0.0.251) | 22:29:28 | ALERT 1 ครั้ง เหตุผล "Port scan: 158 distinct service ports" (มาจาก source ที่กำลังสแกน) | 0.728 |

## เทียบทุกเวอร์ชัน (ทดสอบสดบนเครื่องจริง)

| | v1 (synthetic) | v2 (+CIC +บ้าน) | **v3 (+Discord, ICMP 1%)** |
|---|---|---|---|
| ping จาก iPhone | ✅ 100% (0.74–0.78) | ✅ 100% (0.735–0.748) | ✅ 100% (0.720–0.724) |
| Fing port scan | ⚠️ จับได้แต่ score 0.632–0.670 (ห่าง threshold นิดเดียว) | ✅ 98.7% (~0.73) | ✅ 98.8% (~0.73) |
| alert หลอก ใช้งานปกติ | ⚠️ ~0.4% (HTTPS ขาออก) | ⚠️ ~8% ตอนคุย Discord | ✅ **0 / 208,591** |
| threshold | 0.6308 | 0.6464 | 0.6427 |
