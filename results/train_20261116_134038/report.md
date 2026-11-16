# ผลการเทรน 2026-11-16 13:40:38

ข้อมูลเทรน: 289027 packets จาก data\normal_packets.csv, data\captured_full_v5.csv
score ของ traffic ปกติ ไม่นับ ICMP (hold-out): median=0.563  p99=0.716  p99.8=0.733  max=0.750
  ping ตัวเอง (loopback, Windows)    min=0.536  max=0.601  จับได้   0%
  ping จากเครื่อง Windows            min=0.547  max=0.601  จับได้   0%
  ping จากเครื่อง Linux/Mac          min=0.556  max=0.613  จับได้   0%
  ping รัว (flood เล็กน้อย)          min=0.556  max=0.613  จับได้   0%
  nmap -sS 100 port                  min=0.657  max=0.734  จับได้  21%  จับ packet แรกที่ตัวที่ 77  [ไม่ผ่าน]
  nmap -sS 1000 port                 min=0.657  max=0.746  จับได้  84%  จับ packet แรกที่ตัวที่ 45  [ไม่ผ่าน]
  nmap -sT (connect) 200 port        min=0.658  max=0.737  จับได้  55%  จับ packet แรกที่ตัวที่ 77  [ไม่ผ่าน]
  nmap -sU (UDP) 100 port            min=0.631  max=0.715  จับได้   0%  จับไม่ได้เลย  [ไม่ผ่าน]
  nmap -sS ไล่ host (port 22 x100)   min=0.618  max=0.644  จับได้   0%  จับไม่ได้เลย  [ไม่ผ่าน]
  nmap -sn ไล่ host (ping sweep)     min=0.489  max=0.671  จับได้   0%  จับไม่ได้เลย  [ไม่ผ่าน]
threshold แนะนำ = 0.7335  | คำเตือน: ping บางตัวมี score ต่ำกว่า quantile ของ traffic ปกติ — ใช้ค่า quantile ของ traffic ปกติ (ping อาจหลุดบางตัว) ลองเพิ่มข้อมูล/ปรับ fp_quantile
false positive (hold-out ปกติ ไม่นับ ICMP) = 0.20%  |  ping จับได้ 0%
ICMP error ที่ปนอยู่ในข้อมูลปกติ ถูกมองว่าแปลก 0% (ยอมรับได้: ICMP หายากในบ้านอยู่แล้ว)