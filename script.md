# 📋 SCRIPT THUYẾT TRÌNH — Phát hiện & Giảm thiểu tấn công DoS trong SDN bằng Shannon Entropy

> **Ghi chú**: Script này ánh xạ 1:1 với từng slide trong file `dos_sdn_presentation.pptx`.  
> Mỗi phần đều kèm **lý thuyết nền** + **code tương ứng** trong `l3_router_test.py` để bạn hiểu sâu và trả lời câu hỏi.

---

## 📌 SLIDE 1 — Trang bìa

**Nói:**

> Xin chào thầy/cô và các bạn. Hôm nay nhóm 4 sẽ trình bày đề tài **"Phát hiện và giảm thiểu tấn công DoS trong mạng SDN bằng phương pháp Ngưỡng Entropy"**.
>
> Hệ thống được xây dựng trên môi trường **Mininet** với **Ryu SDN Controller** và trực quan hóa bằng **Grafana**.

---

## 📌 SLIDE 2 — Nội dung trình bày

**Nói:**

> Bài trình bày gồm 7 phần chính:
> 1. **Đặt vấn đề** — Tại sao DoS nguy hiểm trong SDN
> 2. **Cơ sở lý thuyết** — Shannon Entropy là gì
> 3. **Kiến trúc hệ thống** — Mô hình mạng 4 vùng
> 4. **Cơ chế phát hiện** — Thuật toán & ngưỡng cảnh báo
> 5. **Cơ chế ngăn chặn** — Flow-Mod, Lockdown & Whitelist
> 6. **Demo & Kết quả** — Thực nghiệm Mininet
> 7. **Kết luận** — Ưu nhược điểm & hướng phát triển

---

## 📌 SLIDE 3 — Đặt vấn đề

### 💡 Lý thuyết nền

**SDN (Software-Defined Networking)** là kiến trúc mạng trong đó:
- **Control Plane** (bộ não — Ryu Controller): quyết định gói tin đi đâu
- **Data Plane** (Switch): chỉ chuyển tiếp gói theo lệnh từ Controller
- Hai lớp giao tiếp qua **OpenFlow Protocol**

**Lợi ích**: quản lý tập trung, linh hoạt lập trình, giám sát toàn cục.

**Điểm yếu**: Controller là **single point of failure** → bị DoS là sập toàn mạng.

**2 kiểu tấn công chính:**
1. **Packet-In Flooding**: Kẻ tấn công gửi hàng loạt gói với IP giả mạo → Switch không có flow rule → liên tục gửi Packet-In lên Controller → Controller quá tải
2. **Flow Table Overflow**: Mỗi IP mới tạo 1 flow entry trên Switch → đầy bộ nhớ TCAM (rất đắt, chỉ có vài nghìn entry) → Switch tê liệt

**Nói:**

> Trong mạng truyền thống, tấn công DoS chỉ ảnh hưởng 1 thiết bị. Nhưng trong SDN, do kiến trúc tập trung, nếu Controller bị sập thì **toàn bộ mạng** tê liệt.
>
> Có 2 hình thức chính: **Packet-In Flooding** — gửi quá nhiều gói mới lạ khiến Controller quá tải; và **Flow Table Overflow** — nhồi đầy bảng luật trên Switch.
>
> Vì vậy, chúng ta cần một cơ chế phát hiện nhanh, nhẹ, chạy ngay trên Controller để bảo vệ mạng.

---

## 📌 SLIDE 4 — Cơ sở lý thuyết: Shannon Entropy

### 💡 Lý thuyết nền

**Shannon Entropy** (1948) đo độ **hỗn loạn / ngẫu nhiên** của một tập dữ liệu:

```
H = −∑ pᵢ · log₂(pᵢ)
```

Trong đó:
- `pᵢ` = tỷ lệ xuất hiện của IP nguồn thứ `i` trong cửa sổ
- `n` = số IP nguồn duy nhất
- `H` = entropy (đơn vị: bit)

**Ví dụ trực quan:**
| Tình huống | Phân bố IP | Entropy |
|---|---|---|
| **Bình thường** | 10 IP, mỗi IP chiếm ~10% | H ≈ 3.3 (trung bình) |
| **Flood (IP cố định)** | 1 IP chiếm 95%, 9 IP chiếm 5% | H ≈ 0.5 (**rất thấp**) |
| **Spoofing (IP giả mạo)** | 1000 IP khác nhau, mỗi IP 1 lần | H ≈ 10.0 (**rất cao**) |

**Trực giác:**
- **H thấp** = ít đa dạng = 1 nguồn flood cố định
- **H cao** = quá đa dạng = IP giả mạo liên tục đổi
- **H trung bình** = lưu lượng bình thường, đa dạng tự nhiên

### 🔗 Code tương ứng (`l3_router_test.py`, dòng 86–93)

```python
if window_size >= 100:
    ip_counts = Counter(self.src_ip_window)  # đếm số lần xuất hiện mỗi IP
    total = len(self.src_ip_window)

    for count in ip_counts.values():
        p = count / total       # xác suất pᵢ
        entropy -= p * math.log2(p)  # công thức Shannon
```

**Nói:**

> Shannon Entropy là công thức đo độ hỗn loạn. Chúng ta áp dụng nó lên **tập hợp IP nguồn** trong cửa sổ trượt.
>
> Khi lưu lượng bình thường, các host gửi gói cân bằng → entropy ở mức trung bình, ổn định.
>
> Khi bị tấn công **Flood từ IP cố định**, chỉ 1 IP gửi lượng lớn → phân bố cực lệch → entropy **giảm sâu**.
>
> Ngược lại, khi bị tấn công **Spoofing**, liên tục xuất hiện IP mới lạ → cực kỳ hỗn loạn → entropy **tăng vọt**.
>
> Tài liệu tham khảo chính là bài báo của **Feinstein & Schnackenberg, DARPA/Boeing, DISCEX'03**.

---

## 📌 SLIDE 5 — Cơ chế Sliding Window

### 💡 Lý thuyết nền

**Sliding Window** là kỹ thuật giữ lại **W gói tin gần nhất** để tính toán, thay vì tích lũy vô hạn:

- Window giữ tối đa **W = 1000** IP nguồn
- Khi có gói mới: thêm vào cuối, nếu vượt W thì bỏ gói cũ nhất
- Mỗi **3 giây**, Controller tính entropy trên toàn bộ window

**Tại sao dùng Sliding Window?**
- Phản ánh **tình trạng hiện tại** của mạng (không bị pha loãng bởi dữ liệu cũ)
- Kẻ tấn công bắt đầu → window nhanh chóng bị lấp đầy bởi IP tấn công → entropy thay đổi rõ rệt
- Khi tấn công dừng → window dần hồi phục với IP bình thường

### 🔗 Code tương ứng (`l3_router_test.py`)

**Thêm IP vào window (dòng 226–229):**

```python
# Trong _packet_in_handler, khi nhận gói IPv4:
if p_ip.src not in self.gateways and p_ip.src not in self.WHITELIST_SRC:
    self.src_ip_window.append(p_ip.src)      # thêm IP nguồn vào cuối
    if len(self.src_ip_window) > self.WINDOW_SIZE:  # WINDOW_SIZE = 1000
        self.src_ip_window.pop(0)             # bỏ gói cũ nhất
```

> **Lưu ý**: Code dùng `list` + `pop(0)` (không phải `deque`). `pop(0)` trên list là O(n) nhưng với W=1000 thì hoàn toàn chấp nhận được.
>
> Chỉ IP **không thuộc gateway** và **không thuộc whitelist** mới được đưa vào window → tránh nhiễu từ traffic hợp lệ.

**Tính entropy mỗi 3 giây (dòng 76–78, 86–93):**

```python
def _monitor_entropy(self):
    while True:
        hub.sleep(3)  # mỗi 3 giây tính 1 lần
        ...
        if window_size >= 100:  # cần tối thiểu 100 mẫu
            ip_counts = Counter(self.src_ip_window)  # O(n)
            # tính entropy...
```

**Nói:**

> Chúng ta dùng **Sliding Window** kích thước 1000 gói tin. Mỗi lần Controller nhận Packet-In, IP nguồn (không thuộc whitelist) được thêm vào window.
>
> Cứ mỗi **3 giây**, một thread riêng sẽ tính entropy trên toàn bộ window. Điều kiện tối thiểu là phải có **100 mẫu** trong window để kết quả có ý nghĩa thống kê.
>
> Bài báo gốc dùng W = 10.000, nhưng trong môi trường Mininet nhỏ (9 hosts) ta scale down còn 1.000.

---

## 📌 SLIDE 6 — Kiến trúc hệ thống: Mô hình 4 vùng mạng

### 💡 Lý thuyết nền

Mô hình mạng gồm **5 switch** và **8 host**, chia thành 4 vùng:

```
                 c0 (Ryu Controller)
                       │ OpenFlow
                    ┌──s2 (Core Router)──┐
                    │    │    │           │
                   s1   s3   s4          s5
              Internet  DMZ  Internal   Campus
              Zone      Zone DC Zone    Zone
```

| Vùng | Switch | Hosts | Subnet | Mô tả |
|---|---|---|---|---|
| **Internet** | s1 | h_att1 (10.0.1.10), h_ext1 (10.0.1.20) | 10.0.1.0/24 | Kẻ tấn công + user ngoài |
| **DMZ** | s3 | h_web1 (10.0.2.10), h_dns1 (10.0.2.11) | 10.0.2.0/24 | Web server, DNS server |
| **Internal DC** | s4 | h_db1 (10.0.3.10), h_app1 (10.0.3.11) | 10.0.3.0/24 | Database, App server |
| **Campus** | s5 | h_pc1 (10.0.4.10), h_pc2 (10.0.4.11) | 10.0.4.0/24 | PC nội bộ |

**s2 là Core Router** (dpid=2): chỉ switch này mới xử lý routing Layer 3. Các switch khác (s1, s3, s4, s5) hoạt động như L2 switch thông thường.

### 🔗 Code tương ứng

**Topology (`topology_nhom4.py`, dòng 27–48):**

```python
s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='1')  # External zone
s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='2')  # Router trung tam
s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='3')  # Server zone 1
s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='4')  # Server zone 2
s5 = net.addSwitch('s5', cls=OVSKernelSwitch, dpid='5')  # PC zone

h_att1 = net.addHost('h_att1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
h_ext1 = net.addHost('h_ext1', ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')
# ... (tương tự cho các host khác)
```

**Router config (`l3_router_test.py`, dòng 22–26):**

```python
self.mac = '00:00:00:00:00:FE'       # MAC ảo của Router
self.routes = {
    '10.0.1.': 1,   # subnet 10.0.1.x → port 1 (tới s1)
    '10.0.2.': 2,   # subnet 10.0.2.x → port 2 (tới s3)
    '10.0.3.': 3,   # subnet 10.0.3.x → port 3 (tới s4)
    '10.0.4.': 4    # subnet 10.0.4.x → port 4 (tới s5)
}
self.gateways = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
```

**Nói:**

> Mạng được chia thành 4 vùng, kết nối qua Core Router s2. 
>
> **Internet Zone** có kẻ tấn công `h_att1` và user hợp lệ `h_ext1`. Mục tiêu tấn công thường là **h_web1** ở DMZ Zone.
>
> Switch s2 hoạt động như **Layer 3 Router**: nhận gói, tra bảng routing theo subnet, thay MAC rồi chuyển tiếp. Các switch còn lại chỉ chuyển mạch L2.
>
> Controller c0 kết nối tới tất cả switch qua OpenFlow, nhưng logic phát hiện DoS chỉ chạy trên traffic đi qua s2.

---

## 📌 SLIDE 7 — Cơ chế Giám sát (Monitoring)

### 💡 Lý thuyết nền

Luồng giám sát:

```
Gói tin đến → Controller nhận (Packet-In) → Đưa IP nguồn vào Window
→ Mỗi 3 giây: Tính Entropy H → So sánh với ngưỡng → Kích hoạt cảnh báo
```

**Bảng tham số:**

| Tham số | Giá trị | Ý nghĩa |
|---|---|---|
| `WINDOW_SIZE` | 1.000 gói | Kích thước cửa sổ trượt (bài báo gốc: 10.000) |
| `ENTROPY_LOW` | < 1.5 | Ngưỡng phát hiện Flood IP cố định |
| `ENTROPY_HIGH` | > 8.0 | Ngưỡng phát hiện Spoofing IP ngẫu nhiên |
| `Packet Rate` | gói/giây | Kết hợp để tránh báo động giả |
| `Block threshold` | IP chiếm > 20% | Ngưỡng block IP trong chế độ Flood |
| `Chu kỳ tính H` | Mỗi 3 giây | Cần tối thiểu 100 mẫu trong window |

### ❓ Tại sao chọn các ngưỡng này?

- **ENTROPY_LOW = 1.5**: Trong Mininet 9 hosts, traffic bình thường entropy khoảng 2.5–3.5. Dưới 1.5 nghĩa là 1 IP áp đảo → chắc chắn flood.
- **ENTROPY_HIGH = 8.0**: Với 1000 gói mà entropy > 8.0 nghĩa là có hàng trăm IP duy nhất → rõ ràng IP giả mạo (9 hosts thật không thể tạo ra entropy cao như vậy).
- **20% threshold**: Nếu 1 IP chiếm > 20% traffic trong window 1000 gói (tức > 200 gói), đó là bất thường.

### 🔗 Code tương ứng (`l3_router_test.py`, dòng 28–35)

```python
self.WINDOW_SIZE = 1000
self.ENTROPY_HIGH = 8.0
self.ENTROPY_LOW = 1.5
self.attack_status = 0  # 0=bình thường, 1=flood, 2=spoofing
```

**Whitelist — các IP không bị giám sát (dòng 37–42):**

```python
self.WHITELIST_SRC = {
    '10.0.2.10', '10.0.2.11',   # web server, DNS server
    '10.0.3.10', '10.0.3.11',   # DB, App server
    '10.0.4.10', '10.0.4.11',   # PC nội bộ
    '10.0.1.20'                  # user hợp lệ từ Internet
}
```

> **Tại sao có whitelist?** Vì các server nội bộ gửi response → nếu đưa vào window sẽ làm nhiễu entropy. `h_ext1` (10.0.1.20) là user hợp lệ, cũng được whitelist.

**Nói:**

> Controller giám sát traffic thông qua 2 cơ chế song song:
>
> Thứ nhất, **Entropy monitoring**: mỗi 3 giây tính entropy trên window. Nếu H < 1.5 → phát hiện Flood. Nếu H > 8.0 → phát hiện Spoofing.
>
> Thứ hai, **Flow stats monitoring**: gửi FlowStatsRequest tới switch mỗi 3 giây, tính PPS (gói/giây) cho từng flow. Nếu IP nào vượt 500 PPS → block ngay.
>
> Các IP nội bộ và user hợp lệ được đưa vào **whitelist** để không bị block nhầm.

---

## 📌 SLIDE 8 — Cơ chế Ngăn chặn (Mitigation)

### 💡 Lý thuyết nền

Hệ thống có **2 kịch bản phản ứng** tùy theo loại tấn công:

### ⚡ Kịch bản 1: Entropy THẤP (H < 1.5) — Flood IP cố định

```
1. Controller phát hiện H < 1.5
2. Quét window: tìm các IP chiếm > 20% traffic
3. Bỏ qua IP thuộc whitelist
4. Đẩy Flow-Mod DROP xuống TẤT CẢ switch (priority=100, hard_timeout=60s)
5. Sau 61 giây → tự động unblock IP
6. Xóa window → tính lại từ đầu
```

### 🎲 Kịch bản 2: Entropy CAO (H > 8.0) — Spoofing IP ngẫu nhiên

```
1. Controller phát hiện H > 8.0
2. Không thể block từng IP (vì IP liên tục đổi)
3. Kích hoạt LOCKDOWN: DROP TẤT CẢ IPv4 (priority=40, hard_timeout=10s)
4. Đồng thời ALLOW whitelist IPs (priority=60, hard_timeout=10s)
5. Sau 10 giây → lockdown tự hết hạn → hệ thống kiểm tra lại
6. Xóa window → tính lại từ đầu
```

### 🔑 Giải thích Priority trong OpenFlow

| Priority | Rule | Ý nghĩa |
|---|---|---|
| **0** | Table-miss | Gửi lên Controller (mặc định) |
| **10** | Routing flow | Forward gói tin bình thường |
| **40** | DROP all IPv4 | Lockdown khi spoofing |
| **60** | ALLOW whitelist | Cho phép IP hợp lệ qua lockdown |
| **100** | DROP specific IP | Block IP tấn công cụ thể |

> Priority cao hơn được ưu tiên xử lý trước. Khi lockdown, rule DROP all (pri=40) chặn mọi thứ, nhưng whitelist (pri=60) được ưu tiên hơn nên vẫn đi qua.

### 🔗 Code tương ứng

**Kịch bản 1 — Block IP cố định (`l3_router_test.py`, dòng 96–105):**

```python
if entropy < self.ENTROPY_LOW:
    self.attack_status = 1
    self.logger.warning("[CANH BAO] Flood! Entropy = %.2f", entropy)
    for ip, count in ip_counts.items():
        if (count / total) > 0.20 and ip not in self.blocked_ips:
            if ip in self.WHITELIST_SRC:
                continue  # KHÔNG block whitelist
            self._block_ip(ip)
    self.src_ip_window.clear()  # reset window
```

**Hàm block IP (dòng 147–161):**

```python
def _block_ip(self, bad_ip):
    self.blocked_ips.add(bad_ip)
    for dp in self.dps.values():
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=bad_ip)
        inst = [parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, [])]  # actions rỗng = DROP
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=100, match=match,
            instructions=inst, hard_timeout=60))  # tự hết sau 60s

    def unblock():
        hub.sleep(61)
        self.blocked_ips.discard(bad_ip)
    hub.spawn(unblock)  # tự unblock sau 61s
```

**Kịch bản 2 — Lockdown (dòng 107–124):**

```python
elif entropy > self.ENTROPY_HIGH:
    self.attack_status = 2
    self.logger.warning("[CANH BAO] Spoofing! Entropy = %.2f", entropy)
    for dp in self.dps.values():
        parser = dp.ofproto_parser

        # DROP tất cả IPv4 — priority 40
        match_all = parser.OFPMatch(eth_type=0x0800)
        inst_drop = [parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=40, match=match_all,
            instructions=inst_drop, hard_timeout=10))

        # ALLOW whitelist — priority 60 (cao hơn → ưu tiên)
        for wl_ip in self.WHITELIST_SRC:
            match_wl = parser.OFPMatch(eth_type=0x0800, ipv4_src=wl_ip)
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=60, match=match_wl,
                instructions=[], hard_timeout=10))
    self.src_ip_window.clear()
```

### 🔗 Cơ chế bổ sung: Flow Stats PPS Monitoring (dòng 172–194)

```python
# Mỗi 3 giây gửi FlowStatsRequest tới switch
# Khi nhận reply, tính PPS cho mỗi flow:
if pps > 500 and src not in self.blocked_ips:
    self._block_ip(src)  # Block ngay IP có tốc độ > 500 PPS
```

> Đây là lớp bảo vệ thứ 2: ngay cả khi entropy chưa phát hiện, nếu 1 IP gửi > 500 gói/giây qua switch (đo bằng flow stats), nó vẫn bị block.

**Nói:**

> Khi phát hiện **Flood**, hệ thống tìm IP chiếm hơn 20% window rồi **tạo flow rule DROP** trên tất cả switch với priority 100 và timeout 60 giây. Sau đó IP tự động được unblock.
>
> Khi phát hiện **Spoofing**, không thể block từng IP vì chúng liên tục đổi. Hệ thống kích hoạt **LOCKDOWN**: DROP tất cả IPv4 ở priority 40, đồng thời ALLOW các IP whitelist ở priority 60 (cao hơn nên được ưu tiên). Lockdown tự hết sau 10 giây.
>
> Ngoài ra còn có cơ chế **Flow Stats**: nếu 1 IP nào đó gửi hơn 500 gói/giây qua switch, nó bị block ngay lập tức, bất kể entropy.

---

## 📌 SLIDE 9 — So sánh tham số: Nghiên cứu vs. Mininet

**Nói:**

> Slide này so sánh tham số giữa bài báo gốc (Feinstein et al.) và hệ thống của chúng ta. Việc điều chỉnh tham số là hoàn toàn có cơ sở:
>
> - **Window size**: 10.000 → 1.000 (vì Mininet chỉ có 9 hosts, traffic ít hơn)
> - **ENTROPY_LOW**: 1.5 (giữ nguyên — ngưỡng phát hiện flood)
> - **ENTROPY_HIGH**: 8.0 (cao hơn bài báo vì cần tránh false positive trong môi trường nhỏ)
> - **Chu kỳ**: bài báo tính liên tục, ta tính mỗi 3 giây (đủ nhanh cho Mininet)

---

## 📌 SLIDE 10 — Môi trường triển khai

### Các công cụ sử dụng

| Công cụ | Vai trò | Chi tiết |
|---|---|---|
| **Mininet** | Giả lập mạng SDN | 8 hosts, 5 switches, chạy trên VM Ubuntu |
| **Ryu SDN** | Controller | Framework OpenFlow, chạy thuật toán entropy |
| **hping3** | Công cụ tấn công | TCP SYN Flood, `--rand-source` để spoof IP |
| **InfluxDB** | Time-series DB | Lưu entropy, packet rate, attack status realtime |
| **Grafana** | Dashboard | Trực quan hóa biểu đồ entropy, cảnh báo |
| **Python** | Ngôn ngữ | Ryu App, Counter, entropy, flow stats monitoring |

### 🔗 Code kết nối InfluxDB (`l3_router_test.py`, dòng 44–56)

```python
self.influx_client = InfluxDBClient(
    host='localhost', port=8086, database='sdn_monitor')
self.influx_client.create_database('sdn_monitor')
```

**Gửi dữ liệu mỗi 3 giây (dòng 131–145):**

```python
self.influx_client.write_points([{
    "measurement": "network_traffic",
    "fields": {
        "packet_rate": int(current_rate),
        "total_pps": int(current_pps),
        "entropy": round(float(entropy), 4),
        "attack_status": int(self.attack_status),
        "blocked_ip_count": int(len(self.blocked_ips)),
        "window_fill": int(window_size)
    }
}])
```

**Nói:**

> Hệ thống chạy trên máy ảo Ubuntu với Mininet. Ryu Controller thực thi thuật toán. Mỗi 3 giây, dữ liệu entropy, packet rate, trạng thái tấn công được ghi vào **InfluxDB** và hiển thị realtime trên **Grafana**.
>
> Công cụ tấn công là **hping3** — có thể tạo TCP SYN Flood với tùy chọn `--rand-source` để giả mạo IP.

---

## 📌 SLIDE 11 — Demo 1: Tấn công IP cố định (Flood)

### 💡 Kịch bản tấn công

**Lệnh thực thi (từ file `dos_botnet.txt`):**

```bash
# 1. Khởi động web server trên h_web1
h_web1 pkill iperf
h_web1 iperf -s -p 80 &

# 2. User hợp lệ h_ext1 truy cập bình thường (traffic nền)
h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &

# 3. Kẻ tấn công h_att1 flood SYN
h_att1 hping3 -S -p 80 --flood 10.0.2.10
```

**Diễn biến:**
1. Ban đầu: chỉ có traffic h_ext1 → h_web1, entropy bình thường (~2–3)
2. h_att1 bắt đầu flood → IP 10.0.1.10 chiếm phần lớn window
3. Entropy **giảm mạnh** xuống dưới 1.5
4. Controller phát hiện, log cảnh báo Flood
5. Tìm thấy IP 10.0.1.10 chiếm > 20% → **block** (priority=100, 60s)
6. h_att1 bị drop tại switch, **h_ext1 vẫn truy cập bình thường**
7. Sau 60 giây → tự unblock

**Nói:**

> Trong demo 1, chúng ta mô phỏng kẻ tấn công `h_att1` dùng **hping3 flood** gửi SYN liên tục vào web server.
>
> Entropy giảm xuống dưới 1.5, Controller phát hiện IP 10.0.1.10 chiếm hơn 20% traffic và **tự động block** nó trên tất cả switch.
>
> Điểm quan trọng: user hợp lệ `h_ext1` thuộc whitelist nên **không bị ảnh hưởng**, vẫn truy cập bình thường.

---

## 📌 SLIDE 12 — Demo 2: Tấn công giả mạo IP (Spoofing)

### 💡 Kịch bản tấn công

**Lệnh thực thi (từ file `dos_spoof.txt`):**

```bash
# 1. Khởi động web server
h_web1 pkill iperf
h_web1 iperf -s -p 80 &

# 2. Traffic nền hợp lệ
h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &

# 3. Tấn công với IP giả mạo ngẫu nhiên
h_att1 hping3 -S -p 80 --flood --rand-source 10.0.2.10
```

> Khác biệt duy nhất: thêm `--rand-source` → mỗi gói SYN có **IP nguồn ngẫu nhiên khác nhau**.

**Diễn biến:**
1. Ban đầu: traffic bình thường, entropy ổn định
2. h_att1 flood với `--rand-source` → hàng trăm IP lạ xuất hiện trong window
3. Entropy **tăng vọt** trên 8.0
4. Controller phát hiện Spoofing, không thể block từng IP
5. Kích hoạt **LOCKDOWN**: DROP all IPv4 (priority=40, 10s) + ALLOW whitelist (priority=60, 10s)
6. Sau 10 giây → lockdown hết hạn, kiểm tra lại
7. Nếu tấn công vẫn tiếp tục → lockdown lại

**Nói:**

> Demo 2 dùng `--rand-source` — mỗi gói có IP nguồn ngẫu nhiên. Controller thấy entropy tăng vượt 8.0 và kích hoạt **LOCKDOWN**.
>
> Toàn bộ IPv4 bị drop ở priority 40, nhưng các IP trong whitelist được allow ở priority 60 (cao hơn) nên vẫn đi qua.
>
> Lockdown chỉ kéo dài 10 giây rồi tự hết. Nếu tấn công vẫn tiếp tục, entropy vẫn cao → lockdown được kích hoạt lại.

---

## 📌 SLIDE 13 — Trực quan hóa Grafana Dashboard

**Nói:**

> Đây là Grafana Dashboard hiển thị realtime. Các panel bao gồm:
>
> - **Source IP Entropy**: biểu đồ entropy theo thời gian, có đường ngưỡng threshold
> - **Packet Rate/s**: số gói/giây qua controller
> - **Status**: trạng thái hiện tại — bình thường hoặc ATTACK DETECTED
> - **Blocked IPs Log**: danh sách IP đã bị block và lý do
>
> Dữ liệu được ghi vào InfluxDB mỗi 3 giây từ Controller, Grafana query và hiển thị realtime.

---

## 📌 SLIDE 14 — Kết luận

**Nói:**

> Tóm lại, đề tài đã thực hiện được:
>
> ✅ Xây dựng hệ thống giám sát **Entropy thời gian thực** trên Ryu Controller
>
> ✅ Phát hiện **2 kiểu tấn công**: Flood (entropy thấp) và Spoofing (entropy cao)
>
> ✅ **Tự động** thực thi Flow-Mod block IP và Lockdown, không cần can thiệp thủ công
>
> ✅ Trực quan hóa toàn bộ qua **Grafana Dashboard**
>
> **Ưu điểm:**
> - Thuật toán nhẹ, tính entropy mỗi 3 giây
> - Phản ứng nhanh, tự động hoàn toàn
> - Phù hợp kiến trúc SDN tập trung
>
> **Hạn chế:**
> - Cần tuning ngưỡng cho từng môi trường cụ thể
> - Kẻ tấn công nếu biết ngưỡng có thể lẩn tránh
> - Chưa xử lý được tấn công tốc độ thấp (low-rate DoS)

---

## 📌 SLIDE 15 — Cảm ơn & Q&A

**Nói:**

> Trên đây là toàn bộ nội dung trình bày của nhóm 4. Xin cảm ơn thầy/cô và các bạn đã lắng nghe.
>
> Mời thầy/cô đặt câu hỏi ạ.

---

## 🛡️ PHỤ LỤC: CÁC CÂU HỎI THƯỜNG GẶP

### ❓ Q1: "Tại sao dùng Entropy mà không dùng Machine Learning?"

> Entropy là phương pháp **thống kê nhẹ**, không cần training data, không cần GPU, chạy trực tiếp trên Controller.
> ML tuy chính xác hơn nhưng cần dataset lớn, training offline, và tốn tài nguyên tính toán. Trong môi trường SDN realtime, entropy phù hợp hơn.

### ❓ Q2: "Nếu kẻ tấn công gửi đúng entropy bình thường thì sao?"

> Đúng, đó là hạn chế. Nếu attacker biết ngưỡng và điều chỉnh tốc độ + số IP giả mạo sao cho entropy nằm trong dải bình thường, hệ thống sẽ không phát hiện.
> Đó là lý do cần kết hợp thêm **Flow Stats PPS monitoring** — nếu 1 IP vượt 500 PPS vẫn bị block.

### ❓ Q3: "hard_timeout 60 giây có quá ngắn không?"

> 60 giây là thời gian ban đầu. Nếu sau khi unblock, IP đó tiếp tục tấn công → entropy lại giảm → **bị block lại**. Cơ chế này tự lặp cho đến khi tấn công dừng.

### ❓ Q4: "Tại sao dùng list mà không dùng deque?"

> `list + pop(0)` đơn giản hơn. Với W=1000, `pop(0)` mất khoảng 1μs — hoàn toàn không đáng kể. `deque` tối ưu hơn nhưng không cần thiết ở scale này.

### ❓ Q5: "Whitelist có bị lợi dụng không?"

> Nếu attacker spoof IP thuộc whitelist (ví dụ 10.0.2.10) thì gói đó **không bị đưa vào window** → không ảnh hưởng entropy. Tuy nhiên, flow stats vẫn có thể phát hiện nếu traffic bất thường. Đây là điểm có thể cải thiện.

### ❓ Q6: "Tại sao chỉ giám sát trên s2 (Core Router)?"

> Vì s2 là bottleneck — tất cả traffic cross-subnet đều phải đi qua s2. Giám sát tại đây là đủ để thấy toàn bộ traffic giữa các zone. Code kiểm tra `if dp.id != 2: return super()._packet_in_handler(ev)` — tức switch khác chỉ chạy L2 switching bình thường.

### ❓ Q7: "Lockdown 10 giây có đủ không?"

> 10 giây là đủ để hệ thống "thở". Sau khi lockdown hết hạn, nếu tấn công vẫn tiếp tục → window lại đầy IP giả → entropy lại cao → **lockdown lại**. Chu kỳ này lặp liên tục cho đến khi attacker dừng.

---

## 📂 CẤU TRÚC CODE TỔNG QUAN

```
NT541.Q21-DDoS/
├── topology_nhom4.py       # Tạo topology Mininet (8 hosts, 5 switches)
├── l3_router_test.py       # Ryu App chính: L3 Router + Entropy Detection + Mitigation
├── l3_router.py            # Phiên bản Router gốc (không có detection — để so sánh)
├── dos_botnet.txt          # Lệnh tấn công Flood (IP cố định)
├── dos_spoof.txt           # Lệnh tấn công Spoofing (IP ngẫu nhiên)
└── dos_sdn_presentation.pptx  # Slide thuyết trình
```

### Luồng chạy:

```bash
# Terminal 1: Khởi động Ryu Controller
ryu-manager l3_router_test.py

# Terminal 2: Khởi động Mininet
sudo python topology_nhom4.py

# Terminal 3 (trong Mininet CLI): Chạy kịch bản tấn công
source dos_botnet.txt   # hoặc dos_spoof.txt
```

---

## 🧠 TÓM TẮT KIẾN THỨC CỐT LÕI

| Khái niệm | Giải thích ngắn |
|---|---|
| **SDN** | Mạng lập trình được, tách Control Plane khỏi Data Plane |
| **OpenFlow** | Giao thức giao tiếp giữa Controller và Switch |
| **Packet-In** | Gói tin Switch không biết xử lý → gửi lên Controller |
| **Flow-Mod** | Lệnh từ Controller xuống Switch: "thêm/sửa/xóa flow rule" |
| **Shannon Entropy** | Đo độ hỗn loạn: H = −∑ pᵢ log₂(pᵢ) |
| **Sliding Window** | Giữ W gói gần nhất để tính toán realtime |
| **Flood Attack** | Gửi nhiều gói từ 1 IP → entropy thấp |
| **Spoofing Attack** | Gửi gói với IP nguồn giả → entropy cao |
| **Lockdown** | Chặn toàn bộ IPv4, chỉ cho whitelist qua |
| **hard_timeout** | Flow rule tự xóa sau N giây |
| **Priority** | Số ưu tiên của flow rule, cao hơn = xử lý trước |
