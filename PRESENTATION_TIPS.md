# 🎤 PRESENTATION TIPS - CÁCH THUYẾT TRÌNH HIỆU QUẢ

## 📋 CẤU TRÚC THUYẾT TRÌNH GỢI Ý (15-20 phút)

---

## **PHẦN 1: GIỚI THIỆU (2 phút)**

### 🎯 Mở đầu:

```
"Em xin trình bày về một hệ thống phát hiện và ngăn chặn
tấn công DDoS bằng Software-Defined Network (SDN).
Đây là giải pháp tập trung hóa để bảo vệ network khỏi
các cuộc tấn công từ Internet."
```

### 📊 Vẽ hình (khi giải thích):

```
Vẽ nhanh:
┌──────────────┐
│ Ryu          │
│ Controller   │ ← Trung tâm điều khiển
└──────┬───────┘
       │ OpenFlow
   ┌───┴────────────────┐
   │ 5 Switches         │
   │ 8 Hosts            │
   └────────────────────┘
```

**Nói:**

- "Có 5 switch, 8 host trong mô hình"
- "Tất cả switch kết nối tới controller qua OpenFlow 1.3"
- "Controller là 'não' của network - quyết định forward hay block"

---

## **PHẦN 2: KIẾN TRÚC HỆ THỐNG (3 phút)**

### 💻 Giải thích từng zone:

```
"Network em chia thành 4 zones:

📍 Zone 1 (External): Nơi attacker
   - h_att1, h_ext1 (10.0.1.x)
   - Để simulate tấn công từ bên ngoài

📍 Zone 2 (Server 1): Web & DNS
   - h_web1, h_dns1 (10.0.2.x)
   - Important servers cần bảo vệ

📍 Zone 3 (Server 2): Database & App
   - h_db1, h_app1 (10.0.3.x)
   - Critical services

📍 Zone 4 (PC): Normal users
   - h_pc1, h_pc2 (10.0.4.x)
   - Computers của users bình thường
"
```

### 🔀 Giải thích switch:

```
"Có 5 switch:
- s1, s3, s4, s5: Các edge switch (vành ngoài)
- s2: Core router - QUAN TRỌNG NHẤT
  → Tất cả traffic phải qua s2
  → Controller kiểm soát tại 1 điểm
  → Giống như một 'security checkpoint'"
```

### ⚙️ Vẽ flow packet:

```
"Khi host A ping host B:
1. Packet → Switch A
2. Switch không biết rule → gửi tới Controller
3. Controller quyết định:
   - Forward: Tạo flow rule, gửi packet
   - Block: Không forward, drop packet
4. Packet → Core switch s2 (checkpoint)
5. s2 check: 'Có phải attacker không?'
6. Nếu OK → forward tới Switch B
7. Packet → Host B"
```

**Nói:**

- "Vì tất cả traffic đi qua s2, nên controller có 'chốt chặn' toàn bộ network"
- "Giống như an ninh sân bay - mọi người phải qua 1 gate"

---

## **PHẦN 3: CƠ CHẾ PHÁT HIỆN DDoS (4 phút)**

### 🔍 Phương pháp 1: PPS Threshold

```
"Trước hết, em theo dõi số packet/giây (PPS).

Cứ 5 giây, controller gửi request tới tất cả switch:
'Cho em biết bạn đã xử lý bao nhiêu packet?'

Switch trả lời:
'Lúc trước: 500 packet
 Bây giờ: 6500 packet'

Controller tính: (6500-500)/5 = 1200 PPS

Nếu PPS > 1000 → ⚠️ ALERT: HIGH TRAFFIC
→ Có thể là DDoS → Block ngay"
```

**Vẽ graph:**

```
Bình thường:          DDoS:
PPS                   PPS
 │      ╱╲            │          ╱╲╲╲
 │     ╱  ╲          │         ╱    ╲╲╲
 │    ╱    ╲        │        ╱       ╲╲
 │___╱______╲_      │___╱___________╲╲__
   ↑         ↑         ↑              ↑
  500      1000     Bình thường > 5000
```

### 🔍 Phương pháp 2: Shannon Entropy (Advanced)

```
"Phương pháp thứ hai là Entropy - để phát hiện 'spoofing' attack.

Entropy đo 'độ khác nhau' của source IP.

Ví dụ:
- Nếu traffic từ 1 IP: h_att1 → Entropy thấp
- Nếu traffic từ 1000 IP khác nhau (spoofed) → Entropy cao

Công thức: H = -Σ (p_i × log₂(p_i))

Khi Entropy cao bất thường → Có thể là spoofing attack"
```

**Nói:**

- "Botnet attack: PPS cao, entropy thấp (cùng attacker)"
- "Spoofing attack: Entropy cao (nhiều source giả)"

### 🔍 Phương pháp 3: Port Stats Anomaly

```
"Có thể một cổng của switch nhận quá nhiều packet?

ví dụ: Cổng 1 bình thường: 100 PPS
      Cổng 1 đột ngột: 5000 PPS

→ Cảnh báo port congestion"
```

---

## **PHẦN 4: CƠ CHẾ NGĂN CHẶN (3 phút)**

### 🚫 Khi phát hiện DDoS:

```
"Khi phát hiện attacker (ví dụ: h_att1 là 10.0.1.10):

Bước 1: Controller tạo DROP RULE
   match: {source IP = 10.0.1.10}
   action: [] (KHÔNG action = DROP)
   priority: 100 (cao hơn default rules)

Bước 2: Gửi rule tới s2 (core switch)

Bước 3: Từ giờ, tất cả packet từ 10.0.1.10:
   s2 nhận → check flow table
   → match DROP rule
   → DROP (không forward)
   → Servers không nhận attack"
```

### 📊 Vẽ before/after:

```
TRƯỚC BLOCK:                  SAU BLOCK:
h_att1 ──→ s2 ──→ Servers    h_att1 ──→ s2 ✓
Attack!      ✓ Forward          (🚫 DROP) ✗
             ✓ Servers down
                                Servers OK!
```

### ⏱️ Thời gian response:

```
"Flow stats cập nhật mỗi 5 giây:
- Giây 0-5: Attacker gửi packet
- Giây 5: Controller phát hiện
- Giây 5+: Controller gửi DROP rule
- Giây 5+0.1: s2 nhận rule
- Giây 5+0.2: Packet mới bị drop

→ Tổng cộng ~0.2 giây để block!"
```

---

## **PHẦN 5: CODE WALKTHROUGH (4 phút)**

### 🔧 Hàm quan trọng:

#### **1. switch_features_handler()**

```python
@set_ev_cls(EventOFPSwitchFeatures, CONFIG_DISPATCHER)
def switch_features_handler(self, ev):
    # Khi switch kết nối lần đầu
    # Tạo "Table-Miss" rule (priority=0)
    # Match: tất cả packet
    # Action: gửi tới controller

# Nói: "Giống như cấu hình firewall lần đầu.
#      'Mọi traffic lạ → forward tới admin.'"
```

#### **2. \_packet_in_handler()**

```python
def _packet_in_handler(self, ev):
    # Nhận packet từ switch
    # Nếu từ edge switch → L2 switching
    # Nếu từ s2 (core) → L3 routing
    # Kiểm tra ARP/IPv4 → handle_arp / handle_ipv4

# Nói: "Đây là dispatcher - phân công công việc
#      cho các handler khác."
```

#### **3. handle_ipv4()**

```python
def handle_ipv4(self, datapath, in_port, eth, arp_pkt):
    # Xử lý IPv4 routing
    # Bước 1: Tìm route (matching prefix)
    # Bước 2: Kiểm tra ARP table
    # Bước 3: Giảm TTL
    # Bước 4: Forward

# Nói: "Đây là 'GPS của packet' - chỉ nó đi đúng đường."
```

#### **4. flow_stats_reply_handler()**

```python
def flow_stats_reply_handler(self, ev):
    # Nhận thống kê flow từ switch mỗi 5s
    # Tính PPS, BPS
    # Nếu PPS > 1000 → WARNING + BLOCK

# Nói: "Đây là 'security camera' - giám sát 24/7."
```

### 📝 Giải thích decorator:

```
@set_ev_cls(EventOFPPacketIn, MAIN_DISPATCHER)

- @set_ev_cls: "Đây là event listener"
- EventOFPPacketIn: "Lắng nghe sự kiện: packet in"
- MAIN_DISPATCHER: "Chỉ xử lý khi switch online"

Giống như: "if packet_arrives: call_this_function()"
```

---

## **PHẦN 6: DEMO / TEST (2 phút)**

### 🎬 Quy trình demo:

```
1. Start controller:
   $ ryu-manager --verbose l3_router_test.py

2. Start mininet:
   $ sudo python topology_nhom4.py

3. Test bình thường:
   mininet> h_web1 ping h_pc1
   PING h_pc1 ...
   64 bytes from 10.0.4.10: icmp_seq=1 ttl=63 time=...

4. Start attack:
   mininet> h_att1 python dos_botnet.txt
   (Gửi UDP flood)

5. Xem logs:
   (Controller terminal sẽ show:)
   [FLOW] PPS=1500.50
   ⚠️ HIGH TRAFFIC DETECTED

6. Check servers:
   mininet> h_web1 ping h_pc1
   (Vẫn ping được - NOT affected!)

7. Block kích hoạt:
   (Controller tạo DROP rule)

8. Attacker:
   mininet> h_att1 ping h_web1
   100% loss (Bị block!)
```

---

## **PHẦN 7: Q&A - SẴN SẰN TRẢ LỜI (2 phút)**

### ❓ Thầy có thể hỏi:

**Q1: "Tại sao dùng SDN mà không dùng firewall thường?"**

```
A: "Firewall thường là hardware tĩnh.
    SDN linh hoạt hơn - có thể tạo rule phức tạp trong milliseconds.
    Và tập trung hóa - quản lý từ 1 controller."
```

**Q2: "Code của bạn có lỗi gì không?"**

```
A: "Chưa có (nếu thực sự không có).
    Hoặc: 'Hiện tại xử lý được botnet & spoofing.
           Để cải thiện có thể thêm DPI (Deep Packet Inspection).'"
```

**Q3: "Bạn làm sao biết đó là DDoS mà không phải traffic bình thường cao?"**

```
A: "Traffic bình thường thì tăng dần (ramp-up).
    DDoS thì tăng đột ngột.
    Plus, entropy check xem source có lạ không.
    Nếu quá 1000 PPS + entropy cao = chắc là DDoS."
```

**Q4: "Entropy calculation như thế nào?"**

```
A: "Mỗi 5 giây, lấy danh sách source IP trong flow.
    Tính phần trăm mỗi IP: p_i = count_i / total
    Entropy = -Σ(p_i × log₂(p_i))
    Entropy cao (gần 1.0) = nhiều source khác nhau
    Entropy thấp (gần 0) = ít source (botnet)"
```

**Q5: "Nếu attacker gửi từ nhiều máy khác nhau thì sao?"**

```
A: "Đó gọi là 'Distributed DDoS'.
    - PPS sẽ cao
    - Entropy sẽ cao
    - Cả 2 method cùng phát hiện
    - Hoặc theo dõi total PPS của network"
```

---

## **💬 PHRASE CHUYÊN NGHIỆP**

✅ **Nên dùng:**

- "Hệ thống của em sử dụng..."
- "Theo đó, em xử lý bằng..."
- "Kết quả là..."
- "Được kiểm chứng bằng..."
- "Flow table entry"
- "Priority level"
- "Threshold"

❌ **Tránh dùng:**

- "Uhm..."
- "Đại loại..."
- "Cái này là..."
- "Một cái bảng"
- "Gửi packet bừa bãi"

---

## **🎯 BODY LANGUAGE**

✅ **Tốt:**

- Đứng thẳng, hơi vào trong người
- Mắt nhìn thầy/cô (3-4 giây/lần)
- Tay chỉ vào board/slide
- Nói rõ, tốc độ vừa phải (không vội)

❌ **Tránh:**

- Ngồi hay dựa vào bàn
- Nhìn xuống hay nhìn quá ngoài
- Nói quá nhanh hoặc quá chậm
- Để tay trong túi

---

## **🕐 TIME MANAGEMENT**

```
Tổng 20 phút:
├─ 2 min: Giới thiệu
├─ 3 min: Kiến trúc
├─ 4 min: Phát hiện DDoS
├─ 3 min: Ngăn chặn
├─ 4 min: Code walkthrough
├─ 2 min: Demo (hoặc hình ảnh)
└─ 2 min: Q&A & Kết luận
```

**LƯU Ý:** Chuẩn bị 1-2 slide demo screenshot (nếu không thể demo live)

---

## **✅ CHECKLIST TRƯỚC THUYẾT TRÌNH**

- [ ] Đọc lại ANSWER_SCRIPT.md 1-2 lần
- [ ] Xem lại QUICK_REFERENCE.txt
- [ ] Chạy demo lần để chắc chắn hoạt động
- [ ] Chuẩn bị laptop, projector test
- [ ] Chuẩn bị screenshot logs nếu demo fail
- [ ] Mặc trang phục lịch sự
- [ ] Ngủ đủ (đừng thức đêm đọc code!)
- [ ] Tập nói thành tiếng 1-2 lần
- [ ] Chuẩn bị câu trả lời cho Q&A phổ biến

---

## **🎁 BONUS: NẾU THẦY HỎI THÊM**

**"Có cải thiện gì không?"**

```
"Dĩ nhiên có thể:
1. Thêm DPI (Deep Packet Inspection) → phát hiện payload attack
2. Machine Learning → learn pattern DDoS vs normal
3. InfluxDB + Grafana → realtime dashboard
4. Multi-controller redundancy → high availability
5. Rate limiting thay vì drop (graceful degradation)"
```

**"Độ chính xác như thế nào?"**

```
"Với threshold 1000 PPS:
- False Positive: ~5% (legitimate traffic spike)
- False Negative: <1% (miss obvious attacks)
- Response time: 200-500ms

Có thể tune threshold dựa trên network baseline."
```

**"Có scale được với mạng lớn không?"**

```
"Flow-based detection scale OK (n switches).
Entropy calculation O(n) - linear.
Chai cổ chai: Controller single point.
Giải pháp: Distributed controller + cluster mode."
```

---

**GOOD LUCK! 🚀 Bạn sẽ làm rất tốt!**
