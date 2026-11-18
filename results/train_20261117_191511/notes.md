# บันทึก: เทรนรอบ 1 บน branch ter-work (feature 40 ตัว, FEATURE_VERSION 5)

เทรนเมื่อ 2026-11-17 ด้วยโค้ดของ ter-work (b7a1198) ใช้ feature 40 ตัวตามเดิม ไม่ตัดออก
ข้อมูลเทรน: synthetic v5 (สร้างใหม่) + CIC Monday (แปลงใหม่ให้มี field v5 → data/pcap_csv_v5)
ไม่ได้ใช้ข้อมูลบ้านชุดเก่า (soak_*, home_*) เพราะไม่มี field v5 (tcp_window ฯลฯ) → ค่าจะเป็น 0 ทั้งหมด

## ผลรวม (threshold recommended = 0.6284)
- CIC Friday PortScan จับได้ 75.8% (README ระบุโมเดลเดิมของเพื่อน Recall 0.5877)
- ROC-AUC 0.989, FPR 0.92% (~6,800 alert หลอก/ชม. บน Friday)

## เกณฑ์ README: ❌ ไม่ผ่าน
- ping request: 0% ทุกแบบ (Windows, Linux/Mac, loopback, flood)
- nmap ภายใน 40 packet แรก: 0/6
  - -sS 100 port: packet ที่ 65 (จับได้ 32%)
  - -sS 1000 port: packet ที่ 60 (จับได้ 94%)
  - -sT 200 port: packet ที่ 68 (จับได้ 65%)
  - -sU, ไล่ host port 22, ping sweep: จับไม่ได้เลย

## สาเหตุ (จากการทดลองตัด feature ก่อนหน้า)
feature ที่มีค่าเฉพาะใน SYN (tcp_mss, tcp_wscale, tcp_sack_ok, tcp_ts_present)
ทำให้ SYN ปกติดู "แปลก" → หาง score ของ traffic ปกติสูงขึ้น → threshold ต้องสูงตาม
→ ping (score ต่ำกว่า quantile ของ traffic ปกติ) หลุดหมด
จากข้อมูลจำลอง: 40 ตัว ping ~17% / 36 ตัว (ตัด 4 ตัวนี้) ping 100% + nmap 6/6

## สถานะโมเดล
โมเดลนี้อยู่ใน system/models แต่ไม่ควรใช้จริง (ไม่ผ่านเกณฑ์)
โมเดล v5 เดิมของ Thitiwat (FEATURE_VERSION 3) สำรองไว้ที่ models_backup_v5 แต่ใช้กับโค้ด ter-work ไม่ได้ (feature version ไม่ตรง)
