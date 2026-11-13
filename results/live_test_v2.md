# ทดสอบสด — โมเดล v2 (train_20261112_205214, threshold 0.6464)

เครื่อง Windows 192.168.1.36 (Ethernet) | iPhone 192.168.1.34 (Fing) | ping_only: false

| # | การทดสอบ | เวลา | ผล | score |
|---|---|---|---|---|
| 1 | ping จาก iPhone | 21:24 / 21:35 | ✅ ALERT ครบ 12/12 ทั้ง 2 รอบ | 0.735–0.748 |
| 2 | Fing "Find open ports" (SYN 952 packets → 320 ports ใน 16 วิ) | 21:36:30–21:36:46 | ✅ ALERT 940/952 (98.7%) ตั้งแต่ packet แรก | ~0.73 |
| 3 | ใช้งานปกติ + คุย Discord | 21:17–21:23, 21:30–21:36 | ❌ alert หลอก ~12,000–17,000 packets: Discord voice UDP → 104.29.140.171:19335 (Cloudflare, ช่วง 19294–19344) | 0.646–0.656 |
| 4 | alert หลอกอื่น (ไม่นับ Discord) | ทั้ง session | ✅ 1 ครั้ง/session (UDP 212.102.63.139:27056) | 0.647 |

หมายเหตุ: รอบแรก (21:24) ไม่มี alert ของ scan เลย — ตอนนั้นสรุปผิดว่าโมเดลพลาด แต่ session2 (21:36) จับได้ 98.7% จึงน่าจะเป็นเพราะ scan รอบแรกไม่ได้เกิดขณะที่ run_all.py ทำงานอยู่

## เทียบ baseline v1
- Fing scan: v1 จับได้แต่ score 0.632–0.670 (เกิน threshold นิดเดียว) → v2 score ~0.73 ชัดกว่า
- alert หลอก HTTPS ปกติ: v1 ~1 ครั้ง/1–2 นาที → v2 แทบไม่มี (ยกเว้น Discord)

## สิ่งที่แก้ต่อ (v3)
- เพิ่ม Discord session (21:30–21:33) เข้าข้อมูลเทรน → `data/home_discord_normal.csv`
- ICMP_MIN_FRAC 0.003 → 0.01 (ping จำลองกลับเป็น 100%)
- ทดลองในเครื่อง (ข้อมูลชุดเดียวกัน, ทดสอบด้วย session2 หลัง 21:33): alert หลอกบ้าน/Discord 0%, ping 100%, Fing scan 98.9%
