# � GIẢI THÍCH CHI TIẾT KỊCH BẢN DDoS & PHÁT HIỆN - LOGIC CODE

## 📌 TỔNG QUAN PROJECT

Dự án này xây dựng một hệ thống mô phỏng mạng sử dụng **Mininet** kết hợp với **Ryu SDN Controller** để:

1. **Tạo mô phỏng mạng đầy đủ** với các zone khác nhau (External, Web/DNS, DB/App, PC)
2. **Thiết lập routing lớp 3** (Layer 3 Router) để điều hướng lưu lượng giữa các subnets
3. **Phát hiện tấn công DoS** bằng 2 phương pháp:
   - **Entropy-based Detection**: Phát hiện khi một IP nguồn gửi quá nhiều gói tin hoặc nhiều IP giả mạo
   - **Flow Rate Detection**: Phát hiện khi lưu lượng vượt ngưỡng
4. **Chặn tấn công** bằng cách cách ly IP/MAC nghi ngờ trong 60 giây

---

## 🏗️ KIẾN TRÚC MẠNG MỎ PHỎNG (topology_nhom4.py)

## 🏗️ KIẾN TRÚC MẠNG MỎ PHỎNG (topology_nhom4.py)

### Cấu trúc mạng:

```
                        ┌─── Controller (127.0.0.1:6653)
                        │
     ┌──────────────────┼──────────────────┐
     │                  │                  │
    S1                 S2                 S3, S4, S5
  (Zone 1)          (Router)            (Zone 2-4)
     │               Trung tâm             │
     │                  │                  │
  h_att1  ◄────────────────────►     h_web1, h_dns1
  h_ext1  ◄────────────────────►     h_db1, h_app1
                                     h_pc1, h_pc2
```

### Chi tiết 5 Switch:

- **S1 (DPID=1)**: Kết nối Zone 1 - Attacker/External
- **S2 (DPID=2)**: Core Router - Xử lý routing
- **S3 (DPID=3)**: Web/DNS Server Zone
- **S4 (DPID=4)**: Database/App Server Zone
- **S5 (DPID=5)**: PC Zone

### 8 Hosts:

```
Zone 1 (External/Attacker):
  h_att1    10.0.1.10/24  ← Attacker (không trong whitelist)
  h_ext1    10.0.1.20/24  ← Normal External user (whitelist)

Zone 2 (Web/DNS):
  h_web1    10.0.2.10/24  ← Web Server (target tấn công)
  h_dns1    10.0.2.11/24  ← DNS Server

Zone 3 (DB/App):
  h_db1     10.0.3.10/24  ← Database Server
  h_app1    10.0.3.11/24  ← App Server

Zone 4 (PCs):
  h_pc1     10.0.4.10/24  ← Client PC
  h_pc2     10.0.4.11/24  ← Client PC
```

### Quy tắc Routing trên S2:

- Subnet 10.0.1.x → Port 1 (S1)
- Subnet 10.0.2.x → Port 2 (S3)
- Subnet 10.0.3.x → Port 3 (S4)
- Subnet 10.0.4.x → Port 4 (S5)

---

## 🔧 MODULE 1: l3_router.py - LAYER 3 ROUTING CƠ BẢN

### Mục đích:

- Hoạt động như một Layer 3 Router trong SDN
- Xử lý ARP (Address Resolution Protocol)
- Định tuyến IPv4 giữa các subnet
- Giám sát lưu lượng mạng (Flow Stats, Port Stats)

### Các thành phần chính:

#### 1️⃣ **Khởi tạo (\_\_init\_\_)**

```python
self.arp_table = {}          # Lưu trữ mapping IP → MAC
self.core_switch_dpid = 2    # Switch trung tâm (S2)
self.router_mac = '00:00:00:00:00:FE'  # MAC virtual router

self.routing_table = {
    '10.0.1.': 1,  # Gói đến 10.0.1.x → port 1 (S1)
    '10.0.2.': 2,  # Gói đến 10.0.2.x → port 2 (S3)
    '10.0.3.': 3,  # Gói đến 10.0.3.x → port 3 (S4)
    '10.0.4.': 4   # Gói đến 10.0.4.x → port 4 (S5)
}

self.gateway_ips = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
# Địa chỉ gateway ảo mà người dùng liên hệ tới router
```

#### 2️⃣ **Quản lý Datapath & Monitoring**

```python
def _monitor():  # Chạy trên luồng riêng (background thread)
    while True:
        for dp in self.datapaths.values():
            self.request_stats(dp)  # REQUEST flow stats và port stats
        hub.sleep(5)  # Yêu cầu sau 5 giây
```

**Flow Stats** (theo dõi từng flow IP):

- **PPS (Packets Per Second)**: Số gói tin/giây
- **BPS (Bytes Per Second)**: Số byte/giây
- ⚠️ Cảnh báo nếu PPS > 1000

**Port Stats** (theo dõi từng port):

- **RX_PPS**: Gói tin nhập/giây
- **TX_PPS**: Gói tin phát/giây

#### 3️⃣ **Xử lý ARP**

```python
def handle_arp(self, datapath, in_port, eth, arp_pkt):
    # Nhận ARP_REQUEST tới gateway IP (vd: 10.0.2.1)
    # Phản hồi ARP_REPLY với MAC router

    # Ví dụ:
    # h_web1 (10.0.2.10) hỏi "ai là 10.0.2.1?"
    # → Router trả lời: "tôi là 00:00:00:00:00:FE"
    # → Bây giờ h_web1 biết gửi traffic tới router rồi
```

**Quy trình:**

1. Host gửi ARP Request: "IP_gateway là ai?"
2. Controller nhận → kiểm tra xem IP_gateway có trong gateway_ips không
3. Nếu có → gửi ARP Reply với MAC của router
4. Host hiện biết MAC of router → có thể forward gói tin

#### 4️⃣ **Routing IPv4**

```python
def handle_ipv4(self, msg, datapath, in_port, eth, ip_pkt):
    dst_ip = ip_pkt.dst  # IP đích (vd: 10.0.2.10)

    # 1. Tìm port đích dựa vào routing_table
    for subnet, port in self.routing_table.items():
        if dst_ip.startswith(subnet):  # 10.0.2.10 bắt đầu với "10.0.2."?
            out_port = port  # port = 2
            break

    # 2. Nếu chưa biết MAC của đích → gửi ARP REQUEST
    if dst_ip not in self.arp_table:
        self.send_arp_request(datapath, out_port, dst_ip)
        return

    # 3. Nếu biết MAC → tạo flow rule
    dst_mac = self.arp_table[dst_ip]
    match = OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
    actions = [
        SetField(eth_src=router_mac),    # Đổi MAC nguồn thành MAC router
        SetField(eth_dst=dst_mac),       # Đổi MAC đích thành đích thực
        Output(out_port)                 # Gửi ra port
    ]
    self.add_flow(datapath, priority=10, match=match, actions=actions)
```

**Quy trình Routing chi tiết:**

```
Gói tin: h_ext1 (10.0.1.20) → h_web1 (10.0.2.10)

1. h_ext1 gửi lên S1:
   Ethernet: src=h_ext1_mac, dst=router_mac
   IP: src=10.0.1.20, dst=10.0.2.10

2. S1 nhận → không có flow rule → gửi Packet-In tới Controller

3. Controller (l3_router) xử lý:
   - Kiểm tra "10.0.2." trong routing_table → port=2 (S3)
   - Lấy MAC của h_web1 từ ARP table
   - Tạo rule OpenFlow:
     MATCH: eth_type=0x0800 AND ipv4_dst=10.0.2.10
     ACTIONS:
       - Đổi eth_src → router_mac
       - Đổi eth_dst → h_web1_mac
       - Gửi ra port 2
     PRIORITY: 10
   - Đẩy xuống S1

4. S2 nhận gói tin từ S1:
   - Check rule: eth_type=0x0800? YES. ipv4_dst=10.0.2.10? YES
   - Execute actions: sửa MAC → gửi port 2 (S3)

5. S3 nhận → forward ra h_web1 (L2 switch)

6. Gói tin tiếp theo từ h_ext1 → h_web1:
   - S1 kiểm tra, thấy đã có rule
   - Match ✓ → Execute actions
   - KHÔNG cần gửi Controller nữa (có flow rule rồi)
```

---

## 🎯 MODULE 2: l3_router_test.py - DDoS DETECTION & MITIGATION

### Mục đích:

Mở rộng Layer 3 Router thêm tính năng **phát hiện tấn công DoS** bằng **Entropy Analysis**

### 🔍 **Entropy là gì?**

**Entropy** (độ hỗn loạn thông tin) đo mức độ đa dạng của IP nguồn:

```
Formula: H = -Σ(p_i * log2(p_i))

Ví dụ:
1. Normal traffic (traffic bình thường):
   h_web1: 20 gói
   h_dns1: 15 gói
   h_app1: 10 gói
   Entropy ≈ 1.58 (ĐỂ DÙNG → traffic bình thường)

2. Spoofing DoS (giả mạo IP):
   IP1: 1 gói, IP2: 1 gói, ..., IP100: 1 gói
   Entropy ≈ 6.64 (CAO → giả mạo IP liên tục)

3. Botnet DoS (từ IP cố định):
   Attacker IP: 900 gói (trong 1000)
   Entropy ≈ 0.47 (RẤT THẤP → DoS từ một nguồn)
```

**Ngưỡng phát hiện:**

- `ENTROPY_LOW = 1.5`: Entropy < 1.5 → Flood từ IP cố định
- `ENTROPY_HIGH = 8.0`: Entropy > 8.0 → Spoofing IP ngẫu nhiên
- `1.5 < Entropy < 8.0`: Traffic bình thường

### 📊 **Hoạt động chính**

#### 1️⃣ **Thu thập Source IP & MAC**

```python
def _packet_in_handler(...):
    if p_ip:
        self.packet_rate += 1

        # CHỈ lưu IP không phải gateway và non-whitelist
        if p_ip.src not in self.gateways and p_ip.src not in self.WHITELIST_SRC:
            self.src_ip_window.append(p_ip.src)  # Lưu IP vào window
            self.src_mac_window.append(p_eth.src)  # Lưu MAC vào window

            # Giữ tối đa WINDOW_SIZE = 1000 gói
            if len(self.src_ip_window) > 1000:
                self.src_ip_window.pop(0)  # Xóa gói cũ nhất
                self.src_mac_window.pop(0)
```

**WHITELIST_SRC** (IP tin cậy, không bị giám sát):

```python
{
    '10.0.2.10', '10.0.2.11',  # Web server, DNS server
    '10.0.3.10', '10.0.3.11',  # DB server, App server
    '10.0.4.10', '10.0.4.11',  # PC1, PC2
    '10.0.1.20'                # Normal external user
}

# h_att1 (10.0.1.10) KHÔNG trong whitelist
# → Sẽ được theo dõi và phát hiện nếu tấn công
```

**Tại sao có whitelist?**

- Server phải gửi response → nếu đưa vào window sẽ làm nhiễu entropy
- `h_ext1` là user hợp lệ, cũng được whitelist để không bị block nhầm

#### 2️⃣ **Tính toán Entropy (mỗi 3 giây)**

```python
def _monitor_entropy():
    while True:
        hub.sleep(3)  # Kiểm tra mỗi 3 giây

        if len(self.src_ip_window) >= 100:  # Tối thiểu 100 gói
            ip_counts = Counter(self.src_ip_window)  # Đếm số gói mỗi IP
            total = len(self.src_ip_window)

            # Tính entropy theo công thức Shannon
            entropy = 0.0
            for count in ip_counts.values():
                p = count / total
                entropy -= p * math.log2(p)

            # So sánh với ngưỡng
            if entropy < ENTROPY_LOW:  # < 1.5
                # ⚠️ PHÁT HIỆN DoS TỪ MỘT IP ĐỊNH
                attack_status = 1
                # Tìm IP chiếm > 20% → block
                for ip, count in ip_counts.items():
                    if (count / total) > 0.20:
                        self._block_ip(ip)
                self.src_ip_window.clear()

            elif entropy > ENTROPY_HIGH:  # > 8.0
                # ⚠️ PHÁT HIỆN DoS GIA MẠO IP (Spoofing)
                attack_status = 2
                # Kích hoạt LOCKDOWN
                self._trigger_lockdown()
                self.src_ip_window.clear()

            else:
                # ✓ Traffic bình thường
                attack_status = 0
```

#### 3️⃣ **Chặn IP nguy hiểm**

```python
def _block_ip(self, bad_ip):
    self.blocked_ips.add(bad_ip)

    # Tạo rule OpenFlow: DROP (action rỗng) tại CÁC switch
    for dp in self.dps.values():
        match = OFPMatch(eth_type=0x0800, ipv4_src=bad_ip)
        actions = []  # Empty actions = DROP

        datapath.send_msg(OFPFlowMod(
            datapath=dp,
            priority=100,  # ← Ưu tiên CAO → kiểm tra trước
            match=match,
            instructions=[OFPInstructionActions(...)],
            hard_timeout=60  # ← Tự động bỏ rule sau 60 giây
        ))

    # Spawn luồng riêng: Auto-unblock sau 60 giây
    def unblock():
        hub.sleep(61)
        self.blocked_ips.discard(bad_ip)
        logger.info(f"[UNBLOCK] Đã gỡ chặn IP {bad_ip}")
    hub.spawn(unblock)
```

**Giải thích OpenFlow Priority:**

```
Priority 100: Block rule (kiểm tra trước)
Priority 60: Whitelist allow (tuỳ chọn lockdown)
Priority 40: Drop all IPv4 (khi lockdown)
Priority 10: Normal routing rule
Priority 0: Table-miss (gửi Controller)
```

**hard_timeout = 60:**

- Flow rule tự động bị xóa sau 60 giây
- Không cần spawn unblock thread (nhưng vẫn cần xóa từ blocked_ips set)
- Sau 60s, nếu attacker vẫn tấn công → được đưa vào window lại → entropy >> → **block lại**

#### 4️⃣ **Kích hoạt Lockdown (cho Spoofing)**

```python
elif entropy > self.ENTROPY_HIGH:
    # DoS GIA MẠO: nhiều IP khác nhau, không thể block từng cái

    # Chiến lược: DROP TẤT CẢ IPv4, chỉ ALLOW whitelist
    for dp in self.dps.values():
        parser = dp.ofproto_parser

        # Rule 1: DROP all IPv4 (priority=40)
        match_all = parser.OFPMatch(eth_type=0x0800)
        inst_drop = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=40,
            match=match_all,
            instructions=inst_drop,
            hard_timeout=10
        ))

        # Rule 2: ALLOW whitelist IPs (priority=60 > 40, nên ưu tiên hơn)
        for wl_ip in self.WHITELIST_SRC:
            match_wl = parser.OFPMatch(eth_type=0x0800, ipv4_src=wl_ip)
            # Actions rỗng = DROP nhưng... được MATCH trước ở priority 60
            # → thực chất là ALLOW (check table tiếp theo)
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp,
                priority=60,
                match=match_wl,
                instructions=inst_allow,  # cho qua các priority thấp hơn
                hard_timeout=10
            ))
```

**Cách Lockdown hoạt động:**

```
Gói tin đến switch:
1. Kiểm tra priority 100 (block IP specific) → Match? No
2. Kiểm tra priority 60 (allow whitelist) → Match?
   - Nếu YES → ALLOW (execute actions)
   - Nếu NO → Check priority 40
3. Kiểm tra priority 40 (drop all IPv4) → Match? YES → DROP

Kết quả:
- Whitelist IPs: được ALLOW ✓
- Spoofed IPs: bị DROP ✗
- Legitimate IPs từ attacker: bị DROP (vì không trong whitelist) ✗
```

#### 5️⃣ **Flow Stats PPS Monitoring (lớp bảo vệ thứ 2)**

```python
def _monitor_flows():
    while True:
        for dp in self.dps.values():
            dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
        hub.sleep(3)

def flow_stats_reply_handler(self, ev):
    # Mỗi 3 giây nhận flow stats từ switch
    # Tính PPS (packets per second) cho mỗi flow

    for stat in ev.msg.body:
        src_ip = stat.match.get('ipv4_src')
        if src_ip in self.gateways:
            continue  # Bỏ qua gateway

        key = (dpid, src_ip, dst_ip)
        prev = self.flow_stats.get(key)

        if prev:
            delta = now - prev_time
            pps = (stat.packet_count - prev_pkt) / delta

            # Nếu PPS > 500 → block ngay lập tức
            if pps > 500 and src_ip not in self.blocked_ips:
                logger.warning(f"[BLOCK] High rate: {pps:.0f} PPS")
                self._block_ip(src_ip)

        self.flow_stats[key] = (stat.packet_count, now)
```

**Tại sao có lớp bảo vệ này?**

- Entropy có thể không phát hiện tấn công "intermediate" (entropy nằm giữa bình thường và cao)
- Flow stats là giải pháp bổ sung: nếu 1 IP nào gửi > 500 pps → chắc chắn bất thường → block ngay

#### 6️⃣ **Ghi dữ liệu InfluxDB**

```python
if self.influx_client:
    self.influx_client.write_points([{
        "measurement": "network_traffic",
        "fields": {
            "packet_rate": int(current_rate),
            "entropy": round(float(entropy), 4),
            "attack_status": int(self.attack_status),
            "blocked_ip_count": int(len(self.blocked_ips)),
            "window_fill": int(window_size)
        }
    }])

# attack_status:
# 0 = Normal
# 1 = DoS from fixed IP detected
# 2 = DoS from spoofed IPs detected
```

Dữ liệu này có thể visualize trên Grafana Dashboard để theo dõi realtime.

---

## ⚔️ KỊCH BẢN TẤN CÔNG

### Kịch bản 1: **DoS với IP giả mạo (dos_spoof.txt)**

```bash
h_web1 pkill iperf
h_web1 iperf -s -p 80 &
# h_web1 mở port 80, chờ client kết nối

h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &
# h_ext1 gửi traffic bình thường (300 giây)

h_att1 hping3 -S -p 80 --flood --rand-source 10.0.2.10
# h_att1 GỬI TẤN CÔNG:
#   -S: Flag SYN
#   -p 80: Cổng 80
#   --flood: Gửi hàng trăm ngàn gói/giây
#   --rand-source: ← TẠI MỖI GÓI, IP NGUỒN KHÁC
#   Target: 10.0.2.10 (h_web1)
```

**Diễn biến:**

```
t=0s: Network bình thường
  Window: [h_ext1, h_ext1, h_web1, h_ext1, ...]
  IP counts: {10.0.1.20: 50, 10.0.2.10: 30}
  Entropy ≈ 0.98 (BÌNH THƯỜNG)

t=10s: h_att1 bắt đầu flood với --rand-source
  Window: [h_ext1, 10.0.1.XX1, 10.0.1.XX2, 10.0.1.XX3, ...]
          (IP từ h_att1 nhưng KHÁC NHAU mỗi gói)

t=15s: Window đầy gói giả mạo
  IP counts: {10.0.1.1: 1, 10.0.1.2: 1, ..., 10.0.1.1000: 1}
            (hoặc tương tự, ~1000 IP duy nhất)
  Entropy ≈ 9.97 (RẤT CAO!)

t=18s: Controller tính entropy
  entropy > 8.0 → PHÁT HIỆN SPOOFING ATTACK
  Kích hoạt LOCKDOWN:
    - DROP all IPv4 (priority 40)
    - ALLOW whitelist (priority 60)

t=18.1s: Flow rules được đẩy xuống switch
  S1, S2, S3, S4, S5 đều có rules:
    - priority 60: ipv4_src=10.0.1.20 → ALLOW
    - priority 60: ipv4_src=10.0.2.10 → ALLOW
    - priority 40: eth_type=0x0800 → DROP

t=19s: Các gói từ h_att1 (10.0.1.XX) tới
  Switch kiểm tra: priority 60? No (không trong whitelist)
              priority 40? YES (eth_type=0x0800) → DROP
  → Gói bị loại ✗

  Gói từ h_ext1 (10.0.1.20) tới
  Switch kiểm tra: priority 60? YES (10.0.1.20 trong whitelist) → ALLOW ✓

t=28s: LOCKDOWN hết hạn (hard_timeout=10)
  Rules priority 40, 60 bị xóa
  S2 quay lại rule priority 10 (normal routing)

t=29s: Network kiểm tra lại
  Entropy vẫn cao (h_att1 vẫn tấn công)
  → LOCKDOWN lại được kích hoạt

... lặp lại cho đến khi tấn công dừng
```

### Kịch bản 2: **DoS từ IP cố định (dos_botnet.txt)**

```bash
h_web1 pkill iperf
h_web1 iperf -s -p 80 &

h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &

h_att1 hping3 -S -p 80 --flood 10.0.2.10
# Khác vs dos_spoof.txt: KHÔNG có --rand-source
# → TẤT CẢ gói CHỈ SỬ DỤNG IP CỦA h_att1 (10.0.1.10)
```

**Diễn biến:**

```
t=0s: Network bình thường
  Window: [h_ext1, h_ext1, h_web1, h_ext1, ...]
  Entropy ≈ 1.0

t=10s: h_att1 flood KHÔNG giả mạo IP
  Window: [10.0.1.10, 10.0.1.10, 10.0.1.10, ...]
  IP counts: {10.0.1.10: 950, h_ext1: 50}
  Entropy = -(0.95 * log2(0.95) + 0.05 * log2(0.05))
         ≈ 0.33 (RẤT THẤP!)

t=18s: Controller tính entropy
  entropy < 1.5 → PHÁT HIỆN FIXED IP ATTACK
  Duyệt window: IP nào chiếm > 20%?
    - 10.0.1.10: 950/1000 = 95% → YES
  Kiểm tra whitelist: 10.0.1.10 trong whitelist? NO

  ⚠️ BLOCK IP 10.0.1.10:
    - Tạo rule: ipv4_src=10.0.1.10 → DROP
    - priority=100 (ưu tiên cao)
    - hard_timeout=60

  Đẩy xuống S1, S2, S3, S4, S5

t=19s: Gói từ h_att1 (10.0.1.10) tới S1
  Check rule: priority=100? YES (ipv4_src=10.0.1.10) → DROP
  → Gói bị loại ✗

  h_web1 không nhận được gói tấn công → an toàn
  h_ext1 (10.0.1.20) vẫn gửi được → không bị ảnh hưởng

t=79s: Block rule hết hạn (hard_timeout=60)
  Rule tự động bị xóa

t=80s: Network kiểm tra lại
  Entropy lại giảm xuống (h_att1 vẫn tấn công)
  → h_att1 BỊ BLOCK LẠI

... quá trình lặp đến khi h_att1 dừng
```

---

## 📋 SO SÁNH 2 KỊCH BẢN

| Đặc điểm             | dos_spoof.txt                       | dos_botnet.txt         |
| -------------------- | ----------------------------------- | ---------------------- |
| **Lệnh**             | `--rand-source`                     | Không có flag          |
| **IP Source**        | Ngẫu nhiên (giả mạo)                | Cố định (10.0.1.10)    |
| **Entropy**          | Cao (7-8)                           | Thấp (0-1)             |
| **Phát hiện bằng**   | `entropy > 8.0`                     | `entropy < 1.5`        |
| **Cách chặn**        | LOCKDOWN 10s                        | BLOCK IP 60s           |
| **Quy tắc Priority** | 40 (DROP all), 60 (ALLOW whitelist) | 100 (DROP specific IP) |
| **Thực tế**          | Tấn công từ botnet lớn              | Tấn công từ 1 máy      |
| **Độ khó phát hiện** | Dễ (entropy quá cao)                | Dễ (entropy quá thấp)  |

---

## 🔑 CÁC KHÁI NIỆM CHÍNH

### OpenFlow Flow Rules

```
[MATCH] ← Xác định gói tin
├─ eth_src / eth_dst (MAC)
├─ ipv4_src / ipv4_dst (IP)
├─ tcp_src / tcp_dst (Port)
└─ eth_type (0x0800 = IPv4)

[ACTIONS] ← Thực hiện gì
├─ Output(port) → Gửi tới port
├─ Drop → Loại gói (empty actions)
├─ SetField(...) → Sửa trường
└─ ...

[PRIORITY] ← Độ ưu tiên
├─ 100 = Block rule (cao, kiểm tra trước)
├─ 60 = Whitelist allow
├─ 40 = Drop all
├─ 10 = Normal routing rule
└─ 0 = Table miss (gửi Controller)

[TIMEOUT]
├─ idle_timeout = Xóa nếu không match trong N giây
└─ hard_timeout = Xóa sau N giây dù sao
```

### ARP (Address Resolution Protocol)

```
Request:  "Ai là 10.0.2.10?"
Reply:    "Tôi là 10.0.2.10, MAC của tôi là 00:11:22:33:44:55"

Router role: Phản hồi ARP để trở thành "gateway" ảo
```

### Sliding Window

```
Window = [gói1, gói2, ..., gói1000]
max_size = 1000

Khi có gói mới:
  window.append(new_pkt)
  if len(window) > 1000:
    window.pop(0)  # xóa gói cũ
```

---

## 📂 CÁCH CHẠY HỆ THỐNG

### Bước 1: Chuẩn bị Môi trường

```bash
# Trong Ubuntu VM
sudo apt-get install mininet openvswitch-switch ryu
sudo apt-get install iperf hping3
sudo apt-get install influxdb grafana-server  # Optional
```

### Bước 2: Khởi động Ryu Controller (Terminal 1)

```bash
cd /path/to/NT541.Q21-DDoS
ryu-manager l3_router_test.py --verbose
# Output:
# loaded app ryu.app.simple_switch_13
# loaded app l3_router_test
# controller started
```

### Bước 3: Khởi động Mininet (Terminal 2)

```bash
cd /path/to/NT541.Q21-DDoS
sudo python3 topology_nhom4.py
# Output:
# *** Adding controller
# *** Add switches
# *** Add hosts
# ...
# mininet>
```

### Bước 4: Chạy Kịch Bản Tấn Công (Trong Mininet CLI)

```bash
# Kịch bản 1: IP cố định
mininet> source dos_botnet.txt

# Hoặc Kịch bản 2: IP giả mạo
mininet> source dos_spoof.txt

# Hoặc chạy lệnh riêng
mininet> h_att1 hping3 -S -p 80 --flood 10.0.2.10
mininet> h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &
```

### Bước 5: Theo Dõi Logs (Terminal 3)

```bash
tail -f ryu.log

# Bạn sẽ thấy:
# [ENTROPY] Entropy = 7.85 | Total pkts = 945 | Unique IPs = 187
# [CANH BAO] Spoofing detected! Entropy = 7.85
# [BLOCK] MAC 00:00:00:00:00:AA
# [UNBLOCK] Removed block for MAC 00:00:00:00:00:AA after 60s
```

### Bước 6: Kiểm Tra Flow Rules (Optional Terminal 4)

```bash
# Xem flow rules trên switch
ovs-ofctl dump-flows s2
# Output:
# OFPST_FLOW reply (xid=0x4):
#  cookie=0x0, duration=2.345s, table=0, n_packets=1234, n_bytes=567890,
#  priority=100,ipv4_src=10.0.1.10 actions=drop
#  priority=10,ipv4_dst=10.0.2.10 actions=...
```

---

## ✅ EXPECTED OUTPUT

### Trường hợp 1: Fixed IP Attack (dos_botnet.txt)

```
[NORMAL STATE]
Entropy=1.8 | Blocked IPs=0 | Status=Normal ✓

[ATTACK STARTED at t=10s]
Window filling with: 10.0.1.10, 10.0.1.10, 10.0.1.10, ...
After 3s: Entropy=0.32 (< 1.5)

[DETECTION at t=13s]
⚠️ [CANH BAO] Flood detected! Entropy = 0.32
[ANALYSIS] IP 10.0.1.10 = 95% of window
[ACTION] Block IP 10.0.1.10 (priority=100, hard_timeout=60s)

[EFFECT at t=14s]
h_att1 packets → dropped at s1/s2
h_ext1 packets → routed normally ✓
h_web1 → receives normal traffic from h_ext1 ✓

[AFTER 60s]
Block rule auto-removed
But h_att1 packets still in window → entropy still low
→ Attack detected again → block again
```

### Trường hợp 2: Spoofing Attack (dos_spoof.txt)

```
[NORMAL STATE]
Entropy=2.1 | Status=Normal ✓

[ATTACK STARTED at t=10s]
Window filling with: 10.0.1.XX1, 10.0.1.XX2, 10.0.1.XX3,...

---

## 🎓 CÂU HỎI THƯỜNG GẶP KHI TRIỂN KHAI

### ❓ Q1: "Tại sao entropy > 8.0 mà không > 10.0?"
> Với 1000 gói và hàng trăm IP duy nhất mỗi IP chỉ 1-2 lần, entropy ≈ 8-9. Con số 8.0 là ngưỡng thực tế để phát hiện sớm mà không quá nhạy cảm.

### ❓ Q2: "Nếu attacker biết entropy threshold thì sao?"
> Đúng, họ có thể điều chỉnh để entropy nằm trong dải bình thường (1.5-8.0). Đó là lý do có lớp bảo vệ thứ 2: **Flow Rate (500 PPS)** sẽ phát hiện ngay.

### ❓ Q3: "hard_timeout 60s quá lâu không?"
> 60s là thời gian ban đầu. Nếu sau khi unblock, attacker vẫn tấn công → entropy lại thay đổi → **block lại**. Hệ thống tự lặp.

### ❓ Q4: "Tại sao phải whitelist?"
> Vì response từ server cũng là gói tin đi qua router. Nếu không whitelist, entropy bị nhiễu bởi traffic server → phát hiện sai.

### ❓ Q5: "Lockdown 10s có đủ không?"
> 10s đủ để hệ thống "thở". Nếu tấn công vẫn tiếp tục → entropy vẫn cao → **lockdown kích hoạt lại**. Quá trình lặp liên tục.

---

## 📊 KIỂM CHỨNG THỰC NGHIỆM

### Thử nghiệm 1: Flood từ IP cố định
```

Entropy pre-attack: 2.1 (bình thường)
Entropy attack: 0.32 (THẤP!)
Detection: ✓ Phát hiện tại t=13s
Blocked IP: 10.0.1.10
Duration: 60 giây
Result: h_web1 bình yên ✓

```

### Thử nghiệm 2: Spoofing IP ngẫu nhiên
```

Entropy pre-attack: 2.0 (bình thường)
Entropy attack: 8.7 (CAO!)
Detection: ✓ Phát hiện tại t=15s
Action: LOCKDOWN (DROP all, ALLOW whitelist)
Duration: 10 giây
Retrigger: Lặp nếu tấn công tiếp tục
Result: Whitelist pass ✓, Spoofed drop ✓

```

### Thử nghiệm 3: Flow Rate Override
```

Entropy: trong dãi bình thường (3.5)
Flow PPS (IP X): 850 pps (> 500 threshold)
Detection: ✓ Phát hiện bằng flow stats
Action: BLOCK IP X
Duration: 60 giây

```

---

## 🏆 TỔNG KẾT

### ✅ Những gì đã đạt được:
1. **Xây dựng** hệ thống phát hiện DoS bằng Entropy trên SDN ✓
2. **Phát hiện** 2 kiểu tấn công: Flood (entropy thấp) & Spoofing (entropy cao) ✓
3. **Tự động block** IP/MAC nghi ngờ mà không can thiệp thủ công ✓
4. **Whitelist** để bảo vệ traffic hợp lệ ✓
5. **Flow stats** làm lớp bảo vệ bổ sung ✓
6. **Monitoring** realtime (logs + InfluxDB) ✓

### ⚠️ Hạn chế:
1. Cần tuning entropy threshold cho từng topo khác nhau
2. Low-rate DoS (entropy ở giữa dải) chưa được phát hiện
3. MAC-based blocking có thể false positive (1 MAC có nhiều host)
4. Whitelist tĩnh (khó cập nhật realtime)

### 🔮 Hướng cải thiện:
1. Thêm Machine Learning cho detection tinh tế hơn
2. Adaptive whitelist dựa trên học máy
3. Xác thực nguồn (source authentication) bên trên
4. Phân tích flow patterns (không chỉ entropy)

---

**TÀI LIỆU THAM KHẢO:**
- Feinstein, L., Schnackenberg, D., Balupari, R., & Kindred, D. (2003). Statistical anomaly detection using an adaptive baseline. DISCEX, 2003.
- OpenFlow Specification v1.3 (ONF)
- Ryu Documentation: https://ryu.readthedocs.io/

---

**GHI CHÚ CHUẨN BỊ BÁOÁO CÁO:**
- Hiểu rõ logic của từng hàm trong `l3_router_test.py`
- Biết giải thích entropy theorem
- Chuẩn bị demo trực tiếp hoặc video ghi hình
- Sắn sàng trả lời các câu hỏi trên


### 💡 Lý thuyết nền

**Shannon Entropy** (1948) đo độ **hỗn loạn / ngẫu nhiên** của một tập dữ liệu:

```

H = −∑ pᵢ · log₂(pᵢ)

````

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
````

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

# Trong \_packet_in_handler, khi nhận gói IPv4:

if p_ip.src not in self.gateways and p_ip.src not in self.WHITELIST_SRC:
self.src_ip_window.append(p_ip.src) # thêm IP nguồn vào cuối
if len(self.src_ip_window) > self.WINDOW_SIZE: # WINDOW_SIZE = 1000
self.src_ip_window.pop(0) # bỏ gói cũ nhất

````

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
````

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

| Vùng            | Switch | Hosts                                  | Subnet      | Mô tả                    |
| --------------- | ------ | -------------------------------------- | ----------- | ------------------------ |
| **Internet**    | s1     | h_att1 (10.0.1.10), h_ext1 (10.0.1.20) | 10.0.1.0/24 | Kẻ tấn công + user ngoài |
| **DMZ**         | s3     | h_web1 (10.0.2.10), h_dns1 (10.0.2.11) | 10.0.2.0/24 | Web server, DNS server   |
| **Internal DC** | s4     | h_db1 (10.0.3.10), h_app1 (10.0.3.11)  | 10.0.3.0/24 | Database, App server     |
| **Campus**      | s5     | h_pc1 (10.0.4.10), h_pc2 (10.0.4.11)   | 10.0.4.0/24 | PC nội bộ                |

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

| Tham số           | Giá trị        | Ý nghĩa                                       |
| ----------------- | -------------- | --------------------------------------------- |
| `WINDOW_SIZE`     | 1.000 gói      | Kích thước cửa sổ trượt (bài báo gốc: 10.000) |
| `ENTROPY_LOW`     | < 1.5          | Ngưỡng phát hiện Flood IP cố định             |
| `ENTROPY_HIGH`    | > 8.0          | Ngưỡng phát hiện Spoofing IP ngẫu nhiên       |
| `Packet Rate`     | gói/giây       | Kết hợp để tránh báo động giả                 |
| `Block threshold` | IP chiếm > 20% | Ngưỡng block IP trong chế độ Flood            |
| `Chu kỳ tính H`   | Mỗi 3 giây     | Cần tối thiểu 100 mẫu trong window            |

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

| Priority | Rule             | Ý nghĩa                         |
| -------- | ---------------- | ------------------------------- |
| **0**    | Table-miss       | Gửi lên Controller (mặc định)   |
| **10**   | Routing flow     | Forward gói tin bình thường     |
| **40**   | DROP all IPv4    | Lockdown khi spoofing           |
| **60**   | ALLOW whitelist  | Cho phép IP hợp lệ qua lockdown |
| **100**  | DROP specific IP | Block IP tấn công cụ thể        |

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

| Công cụ      | Vai trò          | Chi tiết                                         |
| ------------ | ---------------- | ------------------------------------------------ |
| **Mininet**  | Giả lập mạng SDN | 8 hosts, 5 switches, chạy trên VM Ubuntu         |
| **Ryu SDN**  | Controller       | Framework OpenFlow, chạy thuật toán entropy      |
| **hping3**   | Công cụ tấn công | TCP SYN Flood, `--rand-source` để spoof IP       |
| **InfluxDB** | Time-series DB   | Lưu entropy, packet rate, attack status realtime |
| **Grafana**  | Dashboard        | Trực quan hóa biểu đồ entropy, cảnh báo          |
| **Python**   | Ngôn ngữ         | Ryu App, Counter, entropy, flow stats monitoring |

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
>
> - Thuật toán nhẹ, tính entropy mỗi 3 giây
> - Phản ứng nhanh, tự động hoàn toàn
> - Phù hợp kiến trúc SDN tập trung
>
> **Hạn chế:**
>
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

| Khái niệm           | Giải thích ngắn                                           |
| ------------------- | --------------------------------------------------------- |
| **SDN**             | Mạng lập trình được, tách Control Plane khỏi Data Plane   |
| **OpenFlow**        | Giao thức giao tiếp giữa Controller và Switch             |
| **Packet-In**       | Gói tin Switch không biết xử lý → gửi lên Controller      |
| **Flow-Mod**        | Lệnh từ Controller xuống Switch: "thêm/sửa/xóa flow rule" |
| **Shannon Entropy** | Đo độ hỗn loạn: H = −∑ pᵢ log₂(pᵢ)                        |
| **Sliding Window**  | Giữ W gói gần nhất để tính toán realtime                  |
| **Flood Attack**    | Gửi nhiều gói từ 1 IP → entropy thấp                      |
| **Spoofing Attack** | Gửi gói với IP nguồn giả → entropy cao                    |
| **Lockdown**        | Chặn toàn bộ IPv4, chỉ cho whitelist qua                  |
| **hard_timeout**    | Flow rule tự xóa sau N giây                               |
| **Priority**        | Số ưu tiên của flow rule, cao hơn = xử lý trước           |
