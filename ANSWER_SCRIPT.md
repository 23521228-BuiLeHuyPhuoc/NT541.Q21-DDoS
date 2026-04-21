# 📋 SCRIPT TRẢ LỜI THẦY - KIẾN THỨC TOÀN HỆ THỐNG

> Đây là tài liệu để bạn nhanh chóng trả lời những câu hỏi mà thầy có thể hỏi. Mỗi câu trả lời được viết ngắn gọn, dễ phát biểu.

---

# ⚡ QUICK REFERENCE - THAM CHIẾU NHANH

> **Phần này tóm tắt kiến trúc hệ thống, các hàm chính, và cách phát hiện DDoS để bạn nhanh chóng tra cứu.**

## 📌 KIẾN TRÚC TOÀN HỆ THỐNG

```
Ryu Controller (port 6653)
    ├─ l3_router_test.py: Chứa logic routing & DDoS detection
    ├─ Flow Stats Monitor (mỗi 5s): Theo dõi PPS, BPS
    ├─ Entropy Monitor: Phát hiện spoofing attacks
    └─ Packet Handler: Xử lý L3 routing
         │
         └─> 5 Switches (OVSKernelSwitch)
              ├─ s1 (dpid=1): External/Attacker zone
              ├─ s2 (dpid=2): Core Router ⭐ (tất cả traffic đi qua)
              ├─ s3 (dpid=3): Server zone 1 (Web/DNS)
              ├─ s4 (dpid=4): Server zone 2 (DB/App)
              └─ s5 (dpid=5): PC zone
                   │
                   └─> 8 Hosts (10.0.1.x - 10.0.4.x)
```

## 🎯 CÁC HÀM CHÍNH VÀ CHỨC NĂNG

### 1. switch_features_handler()

- Khi switch kết nối
- Tạo table-miss rule (priority=0)
- Mọi packet không match → gửi tới controller

### 2. \_packet_in_handler()

- Khi nhận packet từ switch
- Nếu từ edge switch → xử lý L2
- Nếu từ core router (s2) → xử lý L3 (ARP/IPv4)

### 3. handle_arp()

- Xử lý ARP request/reply
- Lưu arp_table: IP ↔ MAC
- Nếu request cho gateway → trả lời router_mac

### 4. handle_ipv4()

- Xử lý IPv4 routing
- Tìm matching prefix trong routing_table
- Giảm TTL
- Forward tới cổng đích

### 5. state_change_handler()

- Track switch online/offline
- Lưu/xóa trong self.datapaths

### 6. flow_stats_reply_handler()

- Mỗi 5s: nhận thống kê flow
- Tính PPS, BPS
- Nếu PPS > 1000 → cảnh báo + block

### 7. port_stats_reply_handler()

- Mỗi 5s: nhận thống kê port
- Tính RX_PPS, TX_PPS
- Phát hiện port congestion

## 📊 BẢNG ROUTING & ARP

```
routing_table = {
    '10.0.1.': 1,  ← port nối s1
    '10.0.2.': 2,  ← port nối s3
    '10.0.3.': 3,  ← port nối s4
    '10.0.4.': 4   ← port nối s5
}

gateway_ips = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']

arp_table = {
    '10.0.x.y': 'aa:bb:cc:dd:ee:ff',  ← dynamic
    ...
}

router_mac = '00:00:00:00:00:FE'
core_switch_dpid = 2
```

## ⚔️ PHÁT HIỆN DDoS

### 1️⃣ PPS Threshold

- Nếu PPS > 1000 packets/sec → HIGH TRAFFIC DETECTED → Block ngay

### 2️⃣ Shannon Entropy (Spoofing)

- entropy = -Σ(p_i \* log2(p_i))
- Entropy cao = source khác nhau (spoofing)
- Entropy thấp = cùng source (botnet)

### 3️⃣ Port Stats Anomaly

- Nếu port RX/TX quá cao → suspicious

## 🚫 BLOCK MECHANISM

```python
match = OFPMatch(
    eth_type=0x0800,      ← IPv4
    ipv4_src=attacker_ip  ← source attacker
)
actions = []              ← TRỖ ACTION = DROP
mod = OFPFlowMod(
    datapath,
    priority=100,
    match=match,
    instructions=[...]
)
datapath.send_msg(mod)
→ Switch s2 sẽ drop gói từ attacker
```

## 🔧 CHẠY DEMO

**Terminal 1:**

```bash
$ ryu-manager --verbose l3_router_test.py
```

→ Start controller ở port 6653

**Terminal 2:**

```bash
$ cd baitap/...
$ sudo python topology_nhom4.py
```

→ Mininet CLI

**Terminal 3 (trong Mininet CLI):**

```bash
mininet> h_att1 python dos_botnet.txt
```

→ Tấn công UDP flood từ h_att1

**Xem kết quả:**

- Terminal 1: Sẽ hiện "HIGH TRAFFIC DETECTED"
- Terminal 2: Các server vẫn hoạt động
- h_att1 bị block

## 📈 FLOW STATS OUTPUT

```
[FLOW] DPID=2 match(eth_type=0x0800,ipv4_src=10.0.1.10)
   PPS=1500.50, BPS=750000.00

[PORT] SW=2 PORT=1
   RX_PPS=2000.00, TX_PPS=1500.00

⚠️ HIGH TRAFFIC DETECTED: 1500.50 PPS
```

## 🎬 CÁC FILE TẤN CÔNG

| File               | Mô tả                                        | Cách phát hiện                |
| ------------------ | -------------------------------------------- | ----------------------------- |
| **dos_botnet.txt** | Gửi từ CÙNG IP attacker, PPS rất cao (1000+) | Phát hiện qua PPS threshold   |
| **dos_spoof.txt**  | Giả mạo source IP khác, pattern distributed  | Phát hiện qua Shannon Entropy |

## 💡 ĐIỀU QUAN TRỌNG

1. **Core Router (s2) là BOTTLENECK**
   - Tất cả traffic đi qua s2
   - Controller có thể control 100%

2. **Event-driven architecture**
   - Xử lý real-time
   - Không busy-wait

3. **OpenFlow 1.3**
   - Hỗ trợ L3 operations
   - Priority levels (0-65535)
   - Table-miss + specific rules

4. **Thread monitoring**
   - \_monitor() chạy song song
   - Không block packet processing
   - hub.sleep() instead of time.sleep()

5. **ARP table cần động**
   - Khác cứng như routing table
   - Cập nhật khi nhận ARP packet

6. **Prefix matching**
   - '10.0.1.' match 10.0.1.0 - 10.0.1.255
   - Cách kinh điển cho subnet matching

## 🎯 TIPS TRẢ LỜI

| Câu hỏi                       | Gợi ý trả lời                                                               |
| ----------------------------- | --------------------------------------------------------------------------- |
| "Hệ thống của bạn làm gì?"    | "Phát hiện và ngăn chặn DDoS bằng SDN"                                      |
| "Code đó code như nào?"       | "Event-driven. Switch gửi packet → Controller xử lý → Decide forward/block" |
| "Hàm X làm gì?"               | "Hàm X xử lý [sự kiện]. Bước 1: ... Bước 2: ..."                            |
| "Tại sao dùng SDN?"           | "Tập trung hóa, linh hoạt, visibility cao, có thể tự động response"         |
| "Bạn phát hiện DDoS thế nào?" | "Theo dõi PPS mỗi 5 giây. Nếu vượt 1000 PPS → block source IP"              |

## 📝 GỒNG KHOÁNG

1. **Mininet**: Tạo topology mạng ảo
2. **OVS**: Open vSwitch - switch ảo
3. **Ryu**: Controller framework Python
4. **OpenFlow 1.3**: Giao thức điều khiển
5. **ARP**: Address Resolution Protocol
6. **IPv4**: Định tuyến layer 3
7. **PPS**: Packets Per Second (metric)
8. **Entropy**: Đo độ "random" của source IP
9. **Flow stats**: Thống kê luồng dữ liệu
10. **Port stats**: Thống kê cổng switch

✅ **ĐỌC PHẦN DETAIL BÊN DƯỚI CHO CHI TIẾT!**

---

## ❓ CÂU HỎI 1: "Hệ thống của bạn tổng quát là gì?"

### 💡 TRẢ LỜI:

> "Đây là một hệ thống **phát hiện và ngăn chặn tấn công DDoS** dựa trên **Ryu SDN Controller**.
>
> Hệ thống có 4 thành phần chính:
>
> - **Topology (Mininet)**: Tạo mô hình mạng ảo với 5 switch và 8 host
> - **Ryu Controller (l3_router_test.py)**: Kiểm soát tất cả luồng traffic, phát hiện DDoS bằng **Shannon Entropy**
> - **Flow Stats Monitor**: Theo dõi thống kê lưu lượng mạng (packets/sec, bytes/sec)
> - **Block/Mitigation**: Khi phát hiện tấn công → tự động block traffic"

---

## ❓ CÂU HỎI 2: "Các thành phần trong file `topology_nhom4.py` là gì?"

### 💡 TRẢ LỜI:

#### **A. Controller:**

```
c0 = RemoteController (Ryu, port 6653)
```

- Kết nối tới Ryu controller chạy bên ngoài
- Điều khiển tất cả switch bằng giao thức OpenFlow 1.3

#### **B. Switches (5 cái):**

| Switch | Vai trò                  | Kết nối                      |
| ------ | ------------------------ | ---------------------------- |
| s1     | External Zone (Attacker) | h_att1, h_ext1               |
| s2     | **Core Router** (DPID=2) | Hub trung tâm, kết nối s1-s5 |
| s3     | Server Zone 1 (Web/DNS)  | h_web1, h_dns1               |
| s4     | Server Zone 2 (DB/App)   | h_db1, h_app1                |
| s5     | PC Zone                  | h_pc1, h_pc2                 |

#### **C. Hosts (8 cái):**

| Host           | IP       | Vai trò               |
| -------------- | -------- | --------------------- |
| h_att1, h_ext1 | 10.0.1.x | Attacker zone         |
| h_web1, h_dns1 | 10.0.2.x | Web & DNS server      |
| h_db1, h_app1  | 10.0.3.x | Database & App server |
| h_pc1, h_pc2   | 10.0.4.x | Normal PC clients     |

#### **D. Connections:**

- Tất cả switch kết nối với s2 (Core Router)
- Mỗi host kết nối với switch của zone nó
- **Tất cả traffic phải đi qua s2 → controller có thể kiểm soát**

---

## ❓ CÂU HỎI 3: "Hàm `_packet_in_handler` làm gì?"

### 💡 TRẢ LỜI:

> "Đây là **hàm xử lý gói tin không biết chỉ đường** (packet in). Khi một gói tin đến mà switch không có flow rule, nó gửi tới controller. Hàm này sẽ:
>
> 1. **Kiểm tra loại gói tin:**
>    - Nếu là LLDP → bỏ qua (discovery packet)
>    - Nếu từ edge switch (không phải s2) → xử lý L2 switching bình thường
>    - Nếu từ core router (s2) → xử lý L3 routing
> 2. **Xử lý L3:**
>    - Kiểm tra gói tin ARP (Address Resolution Protocol)
>    - Kiểm tra gói tin IPv4
>    - **Gọi hàm handle_arp() hoặc handle_ipv4()** để định tuyến"

```python
# Pseudo-code lôgic:
if eth.type == LLDP:
    return  # Bỏ qua
elif dpid != core_router:  # Từ edge switch
    handle_l2_switching()
else:  # Từ core router (s2)
    if arp_packet:
        handle_arp()
    elif ipv4_packet:
        handle_ipv4()
```

---

## ❓ CÂU HỎI 4: "Hàm `handle_arp` hoạt động thế nào?"

### 💡 TRẢ LỜI:

> "Hàm này xử lý **bảng ARP** để ánh xạ IP ↔ MAC address:
>
> **Bước 1:** Lưu ARP entry vào arp_table
>
> ```
> arp_table[sender_ip] = sender_mac
> ```
>
> **Bước 2:** Kiểm tra loại ARP:
>
> - **ARP Request** (ai có IP này?):
>   - Nếu IP là Gateway (10.0.x.1) → Trả lời bằng router_mac
>   - Nếu IP nằm trong routing_table → Forward tới đúng port
>   - Nếu không biết → Drop
> - **ARP Reply** (đây là MAC của tôi):
>   - Lưu vào arp_table
>   - Forward tới interface tương ứng"

```python
# Ví dụ routing_table:
routing_table = {
    '10.0.1.': 1,  # Zone 1 ← port 1
    '10.0.2.': 2,  # Zone 2 ← port 2
    '10.0.3.': 3,  # Zone 3 ← port 3
    '10.0.4.': 4,  # Zone 4 ← port 4
}
```

---

## ❓ CÂU HỎI 5: "Hàm `handle_ipv4` làm gì?"

### 💡 TRẢ LỜI:

> "Hàm này thực hiện **L3 routing** - định tuyến IPv4:
>
> **Bước 1:** Kiểm tra đích đến
>
> ```
> Tìm matching prefix trong routing_table
> VD: IP 10.0.2.10 → match '10.0.2.' → forward port 2
> ```
>
> **Bước 2:** Kiểm tra ARP entry
>
> ```
> dst_mac = arp_table[dst_ip]
> Nếu chưa biết → gửi ARP Request
> ```
>
> **Bước 3:** Xử lý TTL (Time To Live)
>
> ```
> Giảm TTL đi 1 (packet sắp qua một hop)
> Nếu TTL = 0 → drop packet
> ```
>
> **Bước 4:** Tạo và gửi gói tin mới
>
> ````
> Thay đổi src_mac = router_mac
> Thay đổi dst_mac = arp_table[dst_ip]
> Gửi gói tin tới cổng định tuyến
> ```"
> ````

---

## ❓ CÂU HỎI 6: "Flow stats monitor hoạt động như nào?"

### 💡 TRẢ LỜI:

> "Đây là **luồng giám sát liên tục** để theo dõi traffic:
>
> **Bước 1: \_monitor() thread**
>
> ```
> Mỗi 5 giây:
>   - Gửi OFPFlowStatsRequest tới tất cả switch
>   - Gửi OFPPortStatsRequest tới tất cả port
> ```
>
> **Bước 2: flow_stats_reply_handler()**
>
> ```
> Nhận thống kê flow từ switch:
> - PPS = (packet_count_hiện_tại - packet_count_trước) / time_delta
> - BPS = (byte_count_hiện_tại - byte_count_trước) / time_delta
>
> Log ra: [FLOW] PPS=100.50, BPS=50000.00
>
> Nếu PPS > 1000 → Log WARNING ⚠️ HIGH TRAFFIC DETECTED
> ```
>
> **Bước 3: port_stats_reply_handler()**
>
> ```
> Giống như flow stats nhưng ở mức port:
> - RX_PPS (packets/sec nhận)
> - TX_PPS (packets/sec gửi)
> ```
>
> **Dùng để:** Phát hiện DDoS dựa vào pattern traffic bất thường"

---

## ❓ CÂU HỎI 7: "Switch features handler là gì?"

### 💡 TRẢ LỜI:

> "Đây là **hàm khởi tạo switch** khi nó lần đầu kết nối với controller:
>
> ```python
> @set_ev_cls(EventOFPSwitchFeatures, CONFIG_DISPATCHER)
> def switch_features_handler(self, ev):
> ```
>
> **Công việc:**
>
> - Tạo một **Table-Miss flow rule** với priority=0 (thấp nhất)
> - Rule này: **Mọi gói tin không match rule nào khác** → gửi tới Controller
> - Như vậy, controller có thể xem mọi gói tin đầu tiên
>
> **Mục đích:**
>
> - Cho phép controller kiểm soát toàn bộ traffic
> - Là nơi controller quyết định: forward hay block?"

```python
# Ý nghĩa:
match = OFPMatch()  # Match tất cả gói tin
actions = [OFPActionOutput(OFPP_CONTROLLER)]  # Gửi tới controller
priority = 0  # Ưu tiên thấp nhất
# → Khi không có rule nào khác match → gửi tới controller
```

---

## ❓ CÂU HỎI 8: "state_change_handler dùng để làm gì?"

### 💡 TRẢ LỞI:

> "Hàm này **theo dõi vòng đời của switch**:
>
> ```python
> @set_ev_cls(EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
> def state_change_handler(self, ev):
> ```
>
> **Có 2 trạng thái:**
>
> | Trạng thái          | Sự kiện                   | Xử lý                                            |
> | ------------------- | ------------------------- | ------------------------------------------------ |
> | **MAIN_DISPATCHER** | Switch kết nối thành công | Lưu switch vào `self.datapaths[dpid] = datapath` |
> | **DEAD_DISPATCHER** | Switch ngắt kết nối       | Xóa khỏi datapaths                               |
>
> **Ý nghĩa:** Giúp controller biết switch nào đang online/offline"

---

## ❓ CÂU HỎI 9: "Cơ chế phát hiện DDoS là gì?"

### 💡 TRẢ LỜI:

> "Hệ thống phát hiện DDoS bằng **3 cách:**
>
> **1. PPS Threshold (Packets Per Second)**
>
> ```
> Nếu PPS > 1000 → Cảnh báo HIGH TRAFFIC
> Logic: if pps > 1000: logger.warning(...)
> ```
>
> **2. Shannon Entropy (nếu có trong hệ thống)**
>
> ```
> Tính entropy của các source IP trong 3 giây
> Entropy cao = nhiều source khác nhau = DDoS (distributed)
> Entropy thấp = ít source = bình thường hoặc UDP flood từ 1 IP
> ```
>
> **3. Port Stats Anomaly**
>
> ```
> Nếu một port nhận/gửi quá nhiều packets → suspicious
> ```
>
> **Khi phát hiện:**
>
> - Log cảnh báo
> - Gửi flow rule BLOCK (drop) tới switch
> - Dừng forward traffic từ attacker"

---

## ❓ CÂU HỎI 10: "Code của bạn được chạy như nào?"

### 💡 TRẢ LỜI:

> **Bước 1: Khởi động Ryu Controller**
>
> ```bash
> ryu-manager --verbose l3_router_test.py
> ```
>
> - Khởi động controller ở port 6653
> - Đợi switch kết nối
>
> **Bước 2: Khởi động Mininet Topology**
>
> ```bash
> sudo python topology_nhom4.py
> ```
>
> - Tạo 5 switch, 8 host
> - Kết nối tới controller (127.0.0.1:6653)
> - Mở CLI Mininet
>
> **Bước 3: Test connectivity**
>
> ```bash
> mininet> h1 ping h2
> ```
>
> **Bước 4: Tấn công**
>
> ```bash
> mininet> h_att1 python dos_botnet.txt
> # hoặc
> mininet> h_att1 python dos_spoof.txt
> ```
>
> **Khi tấn công:**
>
> - Traffic tăng đột ngột
> - Controller phát hiện
> - Ghi log warning
> - Block attacker
>
> **Kết quả:**
>
> - Các server (h_web1, h_db1) vẫn bình thường
> - Attacker bị block"

---

## ❓ CÂU HỎI 11: "File dos_botnet.txt vs dos_spoof.txt khác nhau thế nào?"

### 💡 TRẢ LỜI:

> **dos_botnet.txt (Volumetric Attack):**
>
> ```
> Gửi NHIỀU gói tin từ CÙNG IP attacker
> Lấy chỗ resource của server
> PPS rất cao (1000+)
> ```
>
> **dos_spoof.txt (Spoofing Attack):**
>
> ```
> Giả mạo source IP
> Gửi gói tin như từ nhiều source khác nhau
> Entropy sẽ cao (distributed pattern)
> Khó detect hơn vì không thấy là attacker
> ```
>
> **Cách phát hiện:**
>
> - **Botnet:** Detect qua PPS threshold (>1000)
> - **Spoof:** Detect qua Shannon Entropy (entropy cao bất thường)"

---

## ❓ CÂU HỎI 12: "Tại sao phải dùng Ryu/SDN?"

### 💡 TRẢ LỜI:

> **Ưu điểm SDN:**
>
> - **Tập trung:** Controller điều khiển toàn bộ switch từ 1 nơi
> - **Linh hoạt:** Có thể tạo rule phức tạp (L2/L3/L4)
> - **Thay đổi nhanh:** Thêm rule mà không cần restart switch
> - **Visibility:** Thấy toàn bộ traffic flow của network
> - **Automation:** Tự động detect & block DDoS
>
> **Ưu điểm Ryu:**
>
> - Framework Python → dễ viết code
> - OpenFlow 1.3 support
> - Event-driven → xử lý packet in real-time
> - Thread support → monitor & detect song song"

---

## ❓ CÂU HỎI 13: "Khi block attacker, bạn làm gì cụ thể?"

### 💡 TRẢ LỞI:

> **Bước 1: Phát hiện attacker IP**
>
> ```
> Parser flow stats → extract src_ip từ packets
> Nếu src_ip gửi PPS > 1000 → mark as attacker
> ```
>
> **Bước 2: Tạo Drop Rule**
>
> ```python
> match = OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
> actions = []  # Không action = DROP
> instructions = [OFPInstructionActions(..., actions)]
> flow_mod = OFPFlowMod(datapath, priority=100, match=match, instructions=...)
> datapath.send_msg(flow_mod)
> ```
>
> **Bước 3: Gửi tới core switch (s2)**
>
> ```
> Flow rule được đặt ở core router (DPID=2)
> Mọi gói từ attacker → s2 sẽ drop
> Không forward tới servers
> ```
>
> **Kết quả:**
>
> - Gói từ attacker bị drop ở s2
> - Servers không nhận được traffic
> - Lưu lượng mạng bình thường trở lại"

---

## ❓ CÂU HỎI 14: "Cấu trúc ARP Table & Routing Table là gì?"

### 💡 TRẢ LỜI:

#### **ARP Table:**

```python
# Mapping: IP ↔ MAC
arp_table = {
    '10.0.1.10': '00:00:00:00:00:01',  # h_att1
    '10.0.2.10': '00:00:00:00:00:02',  # h_web1
    '10.0.4.11': '00:00:00:00:00:04',  # h_pc2
}
```

- **Dùng để:** Khi forward packet, biết gửi tới MAC nào
- **Cập nhật:** Mỗi khi nhận ARP packet

#### **Routing Table:**

```python
routing_table = {
    '10.0.1.': 1,  # IP bắt đầu 10.0.1.x → forward port 1 (s1)
    '10.0.2.': 2,  # IP bắt đầu 10.0.2.x → forward port 2 (s3)
    '10.0.3.': 3,  # IP bắt đầu 10.0.3.x → forward port 3 (s4)
    '10.0.4.': 4,  # IP bắt đầu 10.0.4.x → forward port 4 (s5)
}
```

- **Dùng để:** Matching prefix để biết gửi tới zone nào
- **Cấu trúc:** Key là prefix (10.0.1.), value là port

#### **Gateway IPs:**

```python
gateway_ips = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
```

- **Dùng để:** Khi host request ARP cho gateway → trả lời bằng router_mac"

---

## ❓ CÂU HỎI 15: "OpenFlow 1.3 là gì? Tại sao dùng?"

### 💡 TRẢ LỜI:

> **OpenFlow 1.3 là giao thức** cho phép controller điều khiển switch.
>
> **Các thành phần chính:**
>
> | Thành phần    | Ý nghĩa                                            |
> | ------------- | -------------------------------------------------- |
> | **Match**     | Điều kiện tìm packet (IP src, eth type, port, ...) |
> | **Action**    | Hành động khi match (forward, drop, output, ...)   |
> | **FlowMod**   | Thêm/xóa rule vào flow table                       |
> | **PacketOut** | Gửi gói tin từ controller tới switch               |
> | **PacketIn**  | Gửi gói tin từ switch tới controller               |
>
> **Tại sao dùng OF 1.3?**
>
> - Hỗ trợ Layer 3 (IPv4/IPv6) ← cần cho routing
> - Hỗ trợ advanced features (set_field, group table)
> - Stable & widely adopted
> - Ryu support tốt"

```python
# Ví dụ OpenFlow 1.3 code:
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  # Declare OpenFlow 1.3

# Tạo match rule
match = parser.OFPMatch(eth_type=0x0800, ipv4_src='10.0.1.10')

# Tạo action (forward tới port 1)
actions = [parser.OFPActionOutput(1)]

# Tạo flow mod
mod = parser.OFPFlowMod(datapath, priority=10, match=match, actions=actions)

# Gửi tới switch
datapath.send_msg(mod)
```

---

## ✅ TIPS KHOÁ TRỢ CẬP KHAM PHỚ:

### **Nếu thầy hỏi về kiến trúc:**

- Vẽ hình: Controller ↔ Switches ↔ Hosts
- Giải thích luồng: Packet → Switch → Controller → Decision

### **Nếu thầy hỏi về code logic:**

- Giải thích event-driven: @set_ev_cls decorator
- Xác định hàm nào handle cái gì

### **Nếu thầy hỏi "tại sao?":**

- Giải thích lợi ích của giải pháp
- So sánh với giải pháp khác

### **Nếu thầy hỏi "bạn làm sao biết?":**

- Chỉ flow stats, entropy calculation
- Minh họa bằng numbers/logs

### **Nếu thầy hỏi "tại sao block lại?**

- Giải thích network resources limited
- Attacker chiếm bandwidth → servers không respond được

---

## 🎯 CÁCH PHÁT BIỂU HIỆU QUẢ:

✅ **TỐT:**

- "Trước tiên, ... Sau đó, ... Cuối cùng, ..."
- "Flow stats monitor mỗi 5 giây..."
- "Khi PPS vượt 1000, controller sẽ..."

❌ **KHÓ CHỊU:**

- "Uhm... cái đó là... hmm..."
- "Đại loại là... không biết..."
- Im lặng dài (tưởng gọi lên mà không biết nói gì)

---

## 📱 SỬ DỤNG SCRIPT NÀY:

1. **Trước khi thuyết trình:** Đọc lại toàn bộ
2. **Khi thầy hỏi:** Tìm câu hỏi trong script này
3. **Nếu không có câu hỏi:** Adapt lại từ câu gần nhất
4. **Khi trả lời:** Nói thành tiếng, không đọc máy móc

---

**CHÚC BẠN THUYẾT TRÌNH TỐT! 🚀**
