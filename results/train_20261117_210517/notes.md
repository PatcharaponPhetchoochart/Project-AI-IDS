# บันทึก: เทรนชุดเทียบ 36 feature (FEATURE_VERSION 6)

เหมือนรอบ 40 ตัว (results/train_20261117_191511) ทุกอย่าง ทั้งข้อมูล ค่าตั้ง และ seed
ต่างกันแค่ตัด tcp_mss, tcp_wscale, tcp_sack_ok, tcp_ts_present ออกจาก FEATURE_NAMES
(ยังเก็บใน CSV เหมือนเดิม) และ test ของ system/tests ผ่าน 36 ข้อ (รวม test ping ที่ตกตอน 40 ตัว)

## เทียบ 40 vs 36 (แต่ละชุดใช้ threshold recommended ของตัวเอง)

| | 40 feature (v5) | 36 feature (v6) |
|---|---|---|
| threshold | 0.6284 (fallback: ping แยกจากปกติไม่ได้) | 0.5714 (แยก ping ได้) |
| ping request (4 แบบ) | 0% | 100% |
| nmap จับได้ภายใน 40 packet | 0/6 | 5/6 |
| CIC PortScan จับได้ | 75.8% | 94.5% |
| Precision / Recall / F1 | 0.954 / 0.757 / 0.844 | 0.935 / 0.944 / 0.940 |
| FPR (alert หลอก) | 0.92% | 1.64% |
| ROC-AUC | 0.989 | 0.995 |

ข้อสังเกต: FPR ของ 36 สูงกว่าเพราะ threshold ต่ำกว่า ถ้าเลื่อน threshold ของ 36 ไปที่ 0.59
FPR = 0.73% (ต่ำกว่า 40) และ PortScan ยังจับได้ 92% แต่ต้องเช็กว่า ping ยังผ่าน

## ที่ยังไม่ผ่าน
- nmap -sS ไล่ host (port 22 x100): จับได้ครั้งแรกที่ packet 61 (เกณฑ์ ≤40) จับได้รวม 40%
- เกณฑ์อื่นผ่านหมด

## สรุป
การตัด 4 feature ที่มีค่าเฉพาะใน SYN ทำให้ดีขึ้นแทบทุกด้าน เหลือจุดเดียวคือการไล่ host
ยังไม่ผ่านเกณฑ์ README ครบ จึงยังไม่ควรใช้จริง
โมเดล 40 ตัวสำรองไว้ที่ C:\Project_AI\models_backup_ter40
