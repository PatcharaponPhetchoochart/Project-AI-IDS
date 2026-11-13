# สรุปรอบเทรน 2026-11-12 19:28 (v2: synthetic + CIC Monday + traffic บ้าน)

**ผล: ไม่ใช้ — ping หลุด 100%** (กลับไปใช้ models_backup_v1)

- PortScan (CIC Friday 13:50–~14:15): จับได้ 75.5% ที่ threshold 0.6711 | ROC-AUC 0.983
- alert หลอกบน traffic ปกติของ CIC Friday: 1.77%
- nmap จำลอง: -sS/-sT 92–99% (ใกล้ baseline) แต่ -sU 44% (เดิม 73%), -sn 34.5% (เดิม 68%)
- **ping จำลองทุกแบบ: 0%** (baseline 100%)

## สาเหตุ
- Monday 1,999,994 packets = 98% ของข้อมูลเทรน กลบ synthetic (8,000) และบ้าน (33,160)
- ICMP ในข้อมูลเทรนเหลือ 27/2,041,154 (~0.001%) → Isolation Forest (max_samples 8192) แทบไม่เคยแบ่งตาม ICMP → ping ไม่ดูแปลก (ตรงกับ README sec 4: ICMP ต้องมี ~0.3%)
- 2M packets แรกของ Monday ครอบคลุมแค่ 08:56–09:21

## แก้รอบหน้า
- คุมสัดส่วนแหล่งข้อมูล (สุ่ม Monday ลงให้ไม่กลบข้อมูลอื่น)
- รักษาสัดส่วน ICMP ที่ไม่ใช่ ping ~0.3%
