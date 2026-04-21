# 🔬 HƯỚNG DẪN DEMO & GIẢI THÍCH KỸ THUẬT CHI TIẾT

> Tài liệu này giải thích **toàn bộ luồng hoạt động** từ khi khởi động hệ thống, tới khi tấn công xảy ra, và cách hệ thống tự phục hồi. Mỗi dòng code đều được giải thích.

---

# MỤC LỤC

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Giải thích chi tiết topology_nhom4.py](#2-giải-thích-chi-tiết-topology_nhom4py)
3. [Giải thích chi tiết l3_router_test.py](#3-giải-thích-chi-tiết-l3_router_testpy)
4. [Giải thích file tấn công .txt](#4-giải-thích-file-tấn-công-txt)
5. [Luồng hoạt động toàn hệ thống](#5-luồng-hoạt-động-toàn-hệ-thống)
6. [Thuật toán phát hiện: Shannon Entropy](#6-thuật-toán-phát-hiện-shannon-entropy)
7. [Cơ chế ngăn chặn chi tiết](#7-cơ-chế-ngăn-chặn-chi-tiết)
8. [Kịch bản Demo 1: Flood Attack](#8-kịch-bản-demo-1-flood-attack)
9. [Kịch bản Demo 2: Spoofing Attack](#9-kịch-bản-demo-2-spoofing-attack)
10. [Cơ chế phục hồi sau tấn công](#10-cơ-chế-phục-hồi-sau-tấn-công)
11. [Bảng tổng hợp tất cả Flow Rules](#11-bảng-tổng-hợp-tất-cả-flow-rules)
12. [Các lệnh demo thực tế](#12-các-lệnh-demo-thực-tế)

---

# 1. TỔNG QUAN KIẾN TRÚC

## Sơ đồ hệ thống

```
┌─────────────────────────────────────────────────────────────────┐
│                    Ryu Controller (c0)                          │
│              l3_router_test.py (port 6653)                     │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ Entropy  │  │ Flow     │  │ Packet   │  │ InfluxDB     │   │
│  │ Monitor  │  │ Stats    │  │ Handler  │  │ Writer       │   │
│  │ (3s)     │  │ (3s)     │  │          │  │ (3s)         │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │
└────────────────────────┬────────────────────────────────────────┘
                         │ OpenFlow 1.3
          ┌──────────────┼──────────────────┐
          │              │                  │
     ┌────┴───┐    ┌─────┴────┐       ┌────┴────┐
     │ s1     │    │ s2       │       │ s3-s5   │
     │ Edge   │────│ Core     │───────│ Edge    │
     │ Switch │    │ Router   │       │ Switches│
     └────┬───┘    │ (dpid=2) │       └────┬────┘
          │        └──────────┘            │
   ┌──────┴──────┐              ┌──────────┴──────────┐
   │ h_att1      │              │ h_web1, h_dns1,     │
   │ h_ext1      │              │ h_db1, h_app1,      │
   │ (Internet)  │              │ h_pc1, h_pc2        │
   └─────────────┘              └─────────────────────┘
```

## Luồng dữ liệu tổng quát

```
Gói tin mạng → Switch (s1-s5) → Packet-In → Controller
                                                │
                                    ┌───────────┼───────────┐
                                    │           │           │
                               L3 Routing   Entropy     Flow Stats
                               (forward)    (detect)    (PPS check)
                                    │           │           │
                                    ▼           ▼           ▼
                               PacketOut    Cảnh báo    Block nếu
                               + FlowMod   + Block     PPS > 500
                                    │           │           │
                                    └───────────┼───────────┘
                                                │
                                                ▼
                                           InfluxDB
                                               │
                                               ▼
                                           Grafana
```

---

# 2. GIẢI THÍCH CHI TIẾT `topology_nhom4.py`

File này tạo mô hình mạng ảo trong Mininet.

## 2.1. Import và khởi tạo

```python
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
```

- `Mininet`: class chính tạo mạng ảo
- `RemoteController`: cho phép kết nối tới Ryu controller đang chạy bên ngoài (không dùng controller mặc định của Mininet)
- `OVSKernelSwitch`: Open vSwitch chạy trong kernel — hiệu năng cao hơn userspace switch
- `CLI`: giao diện dòng lệnh tương tác sau khi mạng khởi động

## 2.2. Tạo Controller

```python
net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

c0 = net.addController(name='c0',
    controller=RemoteController,
    ip='127.0.0.1',      # Controller chạy trên cùng máy
    protocol='tcp',
    port=6653)            # Port chuẩn OpenFlow 1.3
```

**Giải thích:**

- `topo=None, build=False`: không dùng topology tự động, tự tay xây dựng
- `ipBase='10.0.0.0/8'`: dải IP cơ sở cho toàn mạng
- `RemoteController` trỏ tới `127.0.0.1:6653` — nơi Ryu đang lắng nghe
- **Quan trọng**: Ryu **phải được khởi động TRƯỚC** khi chạy topology này

## 2.3. Tạo 5 Switch

```python
s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='1')  # Internet zone
s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='2')  # Core Router
s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='3')  # DMZ zone
s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='4')  # Internal DC
s5 = net.addSwitch('s5', cls=OVSKernelSwitch, dpid='5')  # Campus zone
```

**Giải thích:**

- `dpid` (Datapath ID): mã định danh duy nhất của mỗi switch trong OpenFlow
- **s2 (dpid=2)** là trung tâm — toàn bộ code detection trong `l3_router_test.py` chỉ xử lý trên switch có `dp.id == 2`
- s1, s3, s4, s5 là edge switch — chỉ làm L2 switching (học MAC, forward frame)

## 2.4. Tạo 8 Host

```python
# Zone 1 — Internet (mạng ngoài)
h_att1 = net.addHost('h_att1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
h_ext1 = net.addHost('h_ext1', ip='10.0.1.20/24', defaultRoute='via 10.0.1.1')

# Zone 2 — DMZ (dịch vụ công khai)
h_web1 = net.addHost('h_web1', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
h_dns1 = net.addHost('h_dns1', ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')

# Zone 3 — Internal DC (bảo mật cao)
h_db1  = net.addHost('h_db1',  ip='10.0.3.10/24', defaultRoute='via 10.0.3.1')
h_app1 = net.addHost('h_app1', ip='10.0.3.11/24', defaultRoute='via 10.0.3.1')

# Zone 4 — Campus (nội bộ)
h_pc1 = net.addHost('h_pc1', ip='10.0.4.10/24', defaultRoute='via 10.0.4.1')
h_pc2 = net.addHost('h_pc2', ip='10.0.4.11/24', defaultRoute='via 10.0.4.1')
```

**Bảng tổng hợp:**

| Host     | IP        | Subnet      | Zone     | Vai trò               | Whitelist? |
| -------- | --------- | ----------- | -------- | --------------------- | ---------- |
| `h_att1` | 10.0.1.10 | 10.0.1.0/24 | Internet | **Kẻ tấn công**       | ❌ KHÔNG   |
| `h_ext1` | 10.0.1.20 | 10.0.1.0/24 | Internet | User ngoài hợp lệ     | ✅ CÓ      |
| `h_web1` | 10.0.2.10 | 10.0.2.0/24 | DMZ      | Web Server (mục tiêu) | ✅ CÓ      |
| `h_dns1` | 10.0.2.11 | 10.0.2.0/24 | DMZ      | DNS Server            | ✅ CÓ      |
| `h_db1`  | 10.0.3.10 | 10.0.3.0/24 | Internal | Database Server       | ✅ CÓ      |
| `h_app1` | 10.0.3.11 | 10.0.3.0/24 | Internal | App Server            | ✅ CÓ      |
| `h_pc1`  | 10.0.4.10 | 10.0.4.0/24 | Campus   | PC nội bộ 1           | ✅ CÓ      |
| `h_pc2`  | 10.0.4.11 | 10.0.4.0/24 | Campus   | PC nội bộ 2           | ✅ CÓ      |

> **Chú ý**: `h_att1` (10.0.1.10) là host DUY NHẤT **không có** trong whitelist → chỉ nó bị giám sát entropy.

**`defaultRoute='via 10.0.1.1'`**: cấu hình default gateway. Khi host muốn gửi gói tới subnet khác, nó gửi tới gateway IP → switch gửi ARP lên controller → controller trả lời bằng MAC ảo `00:00:00:00:00:FE`.

## 2.5. Kết nối (Links)

```python
# Kết nối switch edge tới Core Router (s2)
net.addLink(s1, s2)    # s1:port1 ↔ s2:port1
net.addLink(s3, s2)    # s3:port1 ↔ s2:port2
net.addLink(s4, s2)    # s4:port1 ↔ s2:port3
net.addLink(s5, s2)    # s5:port1 ↔ s2:port4

# Kết nối host tới switch edge
net.addLink(s1, h_att1)  # s1:port2 ↔ h_att1
net.addLink(s1, h_ext1)  # s1:port3 ↔ h_ext1
net.addLink(s3, h_web1)  # s3:port2 ↔ h_web1
net.addLink(s3, h_dns1)  # s3:port3 ↔ h_dns1
net.addLink(s4, h_db1)   # s4:port2 ↔ h_db1
net.addLink(s4, h_app1)  # s4:port3 ↔ h_app1
net.addLink(s5, h_pc1)   # s5:port2 ↔ h_pc1
net.addLink(s5, h_pc2)   # s5:port3 ↔ h_pc2
```

**Topology dạng cây (Star):**

```
                    s2 (Core Router)
                   / |  |  \
                 /   |  |    \
              s1    s3  s4    s5
             / \   / \  / \   / \
        att1 ext1 web dns db app pc1 pc2
```

**Mapping port trên s2** (rất quan trọng — phải khớp với `self.routes` trong code):

| Port trên s2 | Kết nối tới   | Subnet      |
| ------------ | ------------- | ----------- |
| Port 1       | s1 (Internet) | 10.0.1.0/24 |
| Port 2       | s3 (DMZ)      | 10.0.2.0/24 |
| Port 3       | s4 (Internal) | 10.0.3.0/24 |
| Port 4       | s5 (Campus)   | 10.0.4.0/24 |

Đây chính là lý do bảng routing trong code là:

```python
self.routes = {'10.0.1.': 1, '10.0.2.': 2, '10.0.3.': 3, '10.0.4.': 4}
```

## 2.6. Khởi động mạng

```python
net.build()                          # Tạo các interface, namespace
for controller in net.controllers:
    controller.start()               # Kết nối tới Ryu Controller

net.get('s1').start([c0])            # Switch s1 kết nối controller c0
net.get('s2').start([c0])            # Switch s2 kết nối controller c0
# ... tương tự s3, s4, s5

CLI(net)   # Mở Mininet CLI — chờ lệnh người dùng
net.stop() # Dọn dẹp khi thoát
```

**Khi `start()` được gọi**: mỗi switch thiết lập kết nối TCP tới Ryu trên port 6653 → gửi `OFPHello` → handshake OpenFlow → Ryu gửi `OFPSwitchFeatures` request → switch trả về → event `EventOFPStateChange(MAIN_DISPATCHER)` được trigger trong Ryu.

---

# 3. GIẢI THÍCH CHI TIẾT `l3_router_test.py`

Đây là file **cốt lõi** — Ryu App kết hợp 3 chức năng:

1. **L3 Router**: định tuyến giữa các subnet
2. **Entropy-based DoS Detection**: phát hiện tấn công
3. **Automatic Mitigation**: tự động ngăn chặn

## 3.1. Class và kế thừa (dòng 1–17)

```python
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
from collections import Counter
import math
import time

class SimpleRouterEntropy(simple_switch_13.SimpleSwitch13):
```

**Giải thích từng import:**

- `simple_switch_13`: class L2 switch mẫu của Ryu — app kế thừa từ đây để switch s1, s3, s4, s5 vẫn hoạt động L2 bình thường
- `ofp_event`: các event OpenFlow (Packet-In, FlowStats, StateChange...)
- `MAIN_DISPATCHER`: trạng thái switch đã handshake xong, sẵn sàng nhận lệnh
- `DEAD_DISPATCHER`: switch ngắt kết nối
- `set_ev_cls`: decorator đăng ký handler cho event
- `hub`: green thread library của Ryu — tạo thread nhẹ (coroutine), KHÔNG phải OS thread
- `Counter`: đếm tần suất xuất hiện mỗi IP trong window
- `math.log2`: tính logarit cơ số 2 cho entropy

**Kế thừa `SimpleSwitch13`**: Nhờ kế thừa, app tự động có chức năng L2 switching. Khi gói tới switch s1/s3/s4/s5 (không phải s2), gọi `super()._packet_in_handler(ev)` → xử lý L2 bình thường (học MAC, forward).

## 3.2. Khởi tạo `__init__` (dòng 18–63)

### 3.2.1. Cấu hình mạng (dòng 21–26)

```python
self.mac = '00:00:00:00:00:FE'
self.arp_table = {}
self.routes = {'10.0.1.': 1, '10.0.2.': 2, '10.0.3.': 3, '10.0.4.': 4}
self.gateways = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
self.dps = {}
```

| Biến             | Kiểu   | Ý nghĩa                                                             |
| ---------------- | ------ | ------------------------------------------------------------------- |
| `self.mac`       | string | MAC ảo của router — tất cả gói qua router đều dùng MAC này làm src  |
| `self.arp_table` | dict   | Bảng ARP: `{IP → MAC}` — học từ ARP request/reply                   |
| `self.routes`    | dict   | Bảng routing: `{subnet_prefix → port_number}` — tra cứu port output |
| `self.gateways`  | list   | 4 gateway IP — router trả lời ARP cho các IP này                    |
| `self.dps`       | dict   | `{dpid → datapath}` — lưu tham chiếu tới tất cả switch đang kết nối |

**Router MAC ảo (`00:00:00:00:00:FE`)**: Trong mạng thật, router có MAC riêng trên mỗi interface. Ở đây đơn giản hóa: dùng 1 MAC duy nhất. Khi host gửi ARP hỏi gateway IP, controller trả lại MAC này → host gửi frame tới MAC này → switch gửi lên controller (Packet-In) → controller routing rồi đổi MAC đích thành MAC thật của host đích.

### 3.2.2. Cấu hình Entropy Detection (dòng 28–42)

```python
self.WINDOW_SIZE = 1000        # Kích thước cửa sổ trượt
self.src_ip_window = []         # List chứa IP nguồn gần nhất
self.blocked_ips = set()        # Tập IP đang bị block
self.packet_rate = 0            # Đếm gói Packet-In trong 3 giây
self.ENTROPY_HIGH = 8.0         # Ngưỡng phát hiện Spoofing
self.ENTROPY_LOW = 1.5          # Ngưỡng phát hiện Flood
self.attack_status = 0          # 0=bình thường, 1=flood, 2=spoofing

self.WHITELIST_SRC = {
    '10.0.2.10', '10.0.2.11',  # web, dns server
    '10.0.3.10', '10.0.3.11',  # db, app server
    '10.0.4.10', '10.0.4.11',  # PC nội bộ
    '10.0.1.20'                 # user hợp lệ từ Internet
}
```

**Tại sao `src_ip_window` là `list` chứ không phải `deque`?**

- `list` đơn giản, dễ hiểu
- `pop(0)` trên list 1000 phần tử chỉ mất ~1μs — không đáng lo về performance
- `Counter(list)` hoạt động tốt trên cả list lẫn deque

**Tại sao có WHITELIST?**

- Server nội bộ (web, dns, db, app) gửi response → nếu đưa vào window sẽ "pha loãng" dữ liệu tấn công → entropy bình thường hóa → không phát hiện được
- `h_ext1` (10.0.1.20) là user hợp lệ — cũng exclude khỏi window
- **Chỉ có `h_att1` (10.0.1.10)** là IP duy nhất KHÔNG trong whitelist → traffic của nó bị giám sát

### 3.2.3. InfluxDB Connection (dòng 44–56)

```python
self.influx_client = None
if HAS_INFLUX:
    try:
        self.influx_client = InfluxDBClient(
            host='localhost', port=8086, database='sdn_monitor')
        self.influx_client.create_database('sdn_monitor')
        # Test ghi thử
        self.influx_client.write_points(
            [{"measurement": "test", "fields": {"ok": 1}}])
    except Exception as e:
        self.influx_client = None
```

**Giải thích:**

- Kiểm tra thư viện `influxdb` có cài không (try/except import)
- Kết nối InfluxDB trên `localhost:8086`
- Tạo database `sdn_monitor` nếu chưa có
- Ghi 1 data point test để verify kết nối
- Nếu fail → `influx_client = None` → tiếp tục chạy mà không ghi metrics (graceful degradation)

### 3.2.4. Flow Stats & Thread (dòng 58–63)

```python
self.flow_stats = {}   # Lưu {(dpid, src, dst) → (packet_count, timestamp)}
self.total_pps = 0     # Tổng PPS hiện tại

hub.spawn(self._monitor_entropy)   # Thread 1: tính entropy mỗi 3s
hub.spawn(self._monitor_flows)     # Thread 2: query flow stats mỗi 3s
```

**`hub.spawn`** tạo **green thread** (eventlet coroutine) — không phải OS thread:

- Rất nhẹ, không cần lock
- Dùng cooperative scheduling — chỉ chuyển context khi gặp `hub.sleep()` hoặc I/O
- Tổng cộng có **2 background thread** chạy song song

## 3.3. Switch State Management (dòng 65–71)

```python
@set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
def _state_change(self, ev):
    dp = ev.datapath
    if ev.state == MAIN_DISPATCHER:       # Switch vừa kết nối thành công
        self.dps[dp.id] = dp              # Lưu tham chiếu
    elif dp.id in self.dps:               # Switch ngắt kết nối
        del self.dps[dp.id]               # Xóa tham chiếu
```

**Giải thích:**

- `MAIN_DISPATCHER`: switch đã hoàn tất handshake OpenFlow, sẵn sàng nhận FlowMod
- `DEAD_DISPATCHER`: switch mất kết nối
- `self.dps` luôn chứa danh sách switch đang "sống" → dùng khi gửi FlowMod tới **tất cả** switch

**Khi nào event này trigger?**

- Khi chạy `topology_nhom4.py` → 5 switch kết nối → 5 lần `MAIN_DISPATCHER` → `self.dps = {1: dp1, 2: dp2, 3: dp3, 4: dp4, 5: dp5}`

## 3.4. PACKET-IN HANDLER — Logic chính (dòng 199–258)

Đây là hàm được gọi **mỗi khi switch gửi gói tin lên controller**.

### 3.4.1. Bước 1: Parse gói tin (dòng 200–208)

```python
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def _packet_in_handler(self, ev):
    msg = ev.msg                            # OpenFlow message
    dp = msg.datapath                       # Switch gửi gói
    in_port = msg.match['in_port']          # Port nhận gói

    pkt = packet.Packet(msg.data)           # Parse raw bytes thành packet
    p_eth = pkt.get_protocol(ethernet.ethernet)
    if p_eth.ethertype == 0x88CC:           # Bỏ qua LLDP (dùng cho topology discovery)
        return
```

### 3.4.2. Bước 2: Phân loại switch (dòng 210–211)

```python
if dp.id != 2:    # Nếu KHÔNG phải Core Router (s2)
    return super(SimpleRouterEntropy, self)._packet_in_handler(ev)
    # → Chuyển cho SimpleSwitch13 xử lý L2 (học MAC, forward)
```

**Đây là điểm then chốt**: Chỉ switch s2 (dpid=2) mới đi vào logic L3 routing + detection. Các switch khác (s1, s3, s4, s5) xử lý L2 bình thường bằng code của SimpleSwitch13 (mac_to_port table).

### 3.4.3. Bước 3: Xử lý ARP (dòng 213–221)

```python
p_arp = pkt.get_protocol(arp.arp)
p_ip = pkt.get_protocol(ipv4.ipv4)

if p_arp:
    # Học source IP → MAC
    self.arp_table[p_arp.src_ip] = p_arp.src_mac

    # Nếu host hỏi ARP cho gateway IP → trả lời bằng MAC ảo
    if p_arp.opcode == arp.ARP_REQUEST and p_arp.dst_ip in self.gateways:
        self._send_arp(dp, in_port, p_eth.src, arp.ARP_REPLY,
                       self.mac, p_arp.dst_ip, p_arp.src_mac, p_arp.src_ip)
    return
```

**Luồng ARP khi host muốn gửi gói cross-subnet:**

```
h_att1 (10.0.1.10) muốn gửi tới h_web1 (10.0.2.10):
1. h_att1 thấy 10.0.2.10 không cùng subnet → cần gửi qua gateway 10.0.1.1
2. h_att1 gửi ARP Request: "Ai có IP 10.0.1.1?"
3. s1 forward ARP lên s2 → s2 gửi Packet-In lên Controller
4. Controller thấy dst_ip = 10.0.1.1 ∈ gateways[]
5. Controller trả ARP Reply: "10.0.1.1 có MAC = 00:00:00:00:00:FE"
6. h_att1 gửi IP packet với dst_mac = 00:00:00:00:00:FE
7. s1 không biết MAC này → Packet-In lại → lần này vào logic IPv4
```

### 3.4.4. Bước 4: Xử lý IPv4 — Routing + Detection (dòng 223–258)

```python
if p_ip:
    # ====== DETECTION: đếm gói và ghi vào window ======
    self.packet_rate += 1    # Đếm tổng gói qua controller trong 3s

    # Chỉ thêm vào window nếu IP KHÔNG phải gateway và KHÔNG phải whitelist
    if p_ip.src not in self.gateways and p_ip.src not in self.WHITELIST_SRC:
        self.src_ip_window.append(p_ip.src)
        if len(self.src_ip_window) > self.WINDOW_SIZE:
            self.src_ip_window.pop(0)    # Giữ window tối đa 1000

    # ====== ROUTING: tìm port output ======
    out_port = None
    for net, port in self.routes.items():
        if p_ip.dst.startswith(net):     # Tra bảng routing theo prefix
            out_port = port
            break
    if not out_port:
        return    # Không tìm thấy route → drop

    # ====== ARP RESOLUTION: tìm MAC đích ======
    if p_ip.dst not in self.arp_table:
        # Chưa biết MAC của IP đích → gửi ARP Request
        self._send_arp(dp, out_port, 'ff:ff:ff:ff:ff:ff', arp.ARP_REQUEST,
                       self.mac, '0.0.0.0', '00:00:00:00:00:00', p_ip.dst)
        return    # Chờ ARP reply, gói hiện tại bị drop (stateless)

    # ====== FORWARDING: đổi MAC và chuyển tiếp ======
    parser = dp.ofproto_parser
    actions = [
        parser.OFPActionSetField(eth_src=self.mac),              # Đổi src MAC thành router MAC
        parser.OFPActionSetField(eth_dst=self.arp_table[p_ip.dst]),  # Đổi dst MAC thành MAC thật
        parser.OFPActionOutput(out_port)                          # Gửi ra port tương ứng
    ]

    # ====== FLOW RULE: chỉ cài flow cho whitelist ======
    if p_ip.src in self.WHITELIST_SRC:
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst)
        self.add_flow(dp, 10, match, actions, idle_timeout=30)

    # Gửi gói hiện tại ra
    dp.send_msg(parser.OFPPacketOut(
        datapath=dp, buffer_id=msg.buffer_id,
        in_port=in_port, actions=actions, data=msg.data))
```

**Điểm cực kỳ quan trọng — Flow Rule chỉ cho Whitelist:**

```python
if p_ip.src in self.WHITELIST_SRC:
    self.add_flow(dp, 10, match, actions, idle_timeout=30)
```

- **Whitelist IP** (h_ext1, h_web1, ...): cài flow rule trên switch → gói sau đi thẳng qua switch mà KHÔNG lên controller → **giảm tải controller**
- **Non-whitelist IP** (h_att1): **KHÔNG** cài flow rule → **MỌI gói** đều đi lên controller qua Packet-In → controller đếm được vào window → **phát hiện được tấn công**

> Đây là thiết kế then chốt: nếu cài flow rule cho tất cả IP, gói tấn công sẽ đi thẳng qua switch mà controller không thấy → không phát hiện được!

### 3.4.5. Hàm `_send_arp` (dòng 267–275)

```python
def _send_arp(self, dp, port, eth_dst, opcode, s_mac, s_ip, d_mac, d_ip):
    pkt = packet.Packet()
    pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=eth_dst, src=self.mac))
    pkt.add_protocol(arp.arp(opcode=opcode, src_mac=s_mac, src_ip=s_ip,
                              dst_mac=d_mac, dst_ip=d_ip))
    pkt.serialize()
    dp.send_msg(dp.ofproto_parser.OFPPacketOut(
        datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
        in_port=dp.ofproto.OFPP_CONTROLLER,
        actions=[dp.ofproto_parser.OFPActionOutput(port)], data=pkt.data))
```

**Giải thích:**

- Tạo gói ARP từ controller và gửi ra switch qua PacketOut
- `in_port=OFPP_CONTROLLER`: gói được tạo bởi controller (không phải từ port vật lý)
- Dùng cho 2 trường hợp:
  1. Trả lời ARP Request từ host → `opcode=ARP_REPLY`
  2. Hỏi MAC của IP đích chưa biết → `opcode=ARP_REQUEST` + `eth_dst=broadcast`

### 3.4.6. Hàm `add_flow` (dòng 260–265)

```python
def add_flow(self, datapath, priority, match, actions, idle_timeout=0, **kwargs):
    parser = datapath.ofproto_parser
    inst = [parser.OFPInstructionActions(
        datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
    datapath.send_msg(parser.OFPFlowMod(
        datapath=datapath, priority=priority, match=match,
        instructions=inst, idle_timeout=idle_timeout))
```

- **FlowMod**: lệnh từ controller → switch: "thêm flow rule này vào flow table"
- **priority**: số ưu tiên — flow có priority cao hơn được match trước
- **idle_timeout**: flow tự xóa nếu không có gói nào match trong N giây (0 = vĩnh viễn)
- **OFPIT_APPLY_ACTIONS**: thực thi actions ngay lập tức (không buffer)

## 3.5. ENTROPY MONITOR — Thread 1 (dòng 76–145)

### 3.5.1. Vòng lặp chính

```python
def _monitor_entropy(self):
    while True:
        hub.sleep(3)    # Ngủ 3 giây

        current_rate = self.packet_rate    # Lưu tạm
        self.packet_rate = 0               # Reset đếm
        entropy = 0.0
        current_pps = self.total_pps       # PPS từ flow stats
        window_size = len(self.src_ip_window)
```

**Mỗi 3 giây**, thread thức dậy và:

1. Lưu `packet_rate` (số Packet-In từ lần tính trước) rồi reset về 0
2. Lấy `total_pps` (tổng PPS từ flow stats — tính riêng)
3. Kiểm tra window đủ 100 mẫu chưa

### 3.5.2. Tính Entropy (dòng 86–93)

```python
if window_size >= 100:
    ip_counts = Counter(self.src_ip_window)
    # Ví dụ: Counter({'10.0.1.10': 800, '10.0.5.33': 1, '10.0.7.88': 1, ...})
    total = len(self.src_ip_window)  # Ví dụ: 1000

    for count in ip_counts.values():
        p = count / total            # xác suất: 800/1000 = 0.8
        entropy -= p * math.log2(p)  # -0.8 * log2(0.8) = 0.258
```

**Ví dụ tính toán thực tế:**

| Tình huống  | Window                     | IP counts                                         | Entropy |
| ----------- | -------------------------- | ------------------------------------------------- | ------- |
| Bình thường | 1000 gói từ 7 host         | {A:150, B:140, C:145, D:135, E:130, F:155, G:145} | ≈ 2.80  |
| Flood       | 1000 gói, 950 từ h_att1    | {10.0.1.10: 950, others: 50}                      | ≈ 0.35  |
| Spoofing    | 1000 gói, 980 IP khác nhau | {rand1:1, rand2:1, ...}                           | ≈ 9.94  |

### 3.5.3. Phát hiện Flood (dòng 96–105)

```python
if entropy < self.ENTROPY_LOW:          # H < 1.5
    self.attack_status = 1               # Đánh dấu: flood
    # Log cảnh báo
    for ip, count in ip_counts.items():
        if (count / total) > 0.20:       # IP chiếm > 20% window
            if ip not in self.blocked_ips:  # Chưa bị block
                if ip in self.WHITELIST_SRC:
                    continue              # Bỏ qua whitelist
                self._block_ip(ip)        # BLOCK!
    self.src_ip_window.clear()            # Reset window
```

**Logic:**

1. Entropy dưới 1.5 → chắc chắn có flood
2. Quét từng IP trong window, tìm IP nào chiếm > 20% (> 200 gói trên 1000)
3. Nếu IP đó thuộc whitelist → bỏ qua (tránh block server)
4. Nếu IP đó chưa bị block → gọi `_block_ip()`
5. Xóa toàn bộ window → chu kỳ tiếp theo tính lại từ đầu

### 3.5.4. Phát hiện Spoofing (dòng 107–124)

```python
elif entropy > self.ENTROPY_HIGH:       # H > 8.0
    self.attack_status = 2               # Đánh dấu: spoofing
    for dp in self.dps.values():         # Gửi tới TẤT CẢ switch
        parser = dp.ofproto_parser

        # Rule 1: DROP tất cả IPv4 — priority 40
        match_all = parser.OFPMatch(eth_type=0x0800)
        inst_drop = [parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, [])]      # actions=[] → DROP
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=40, match=match_all,
            instructions=inst_drop, hard_timeout=10))  # Tự hết sau 10s

        # Rule 2: ALLOW whitelist — priority 60 (cao hơn → ưu tiên)
        for wl_ip in self.WHITELIST_SRC:
            match_wl = parser.OFPMatch(eth_type=0x0800, ipv4_src=wl_ip)
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=60, match=match_wl,
                instructions=[], hard_timeout=10))     # instructions=[] → table-miss → controller
    self.src_ip_window.clear()
```

**Giải thích chi tiết LOCKDOWN:**

```
Flow Table trong switch khi Lockdown:
┌────────────┬─────────────────────────────┬──────────┬────────────┐
│ Priority   │ Match                       │ Action   │ Timeout    │
├────────────┼─────────────────────────────┼──────────┼────────────┤
│ 100        │ ipv4_src=10.0.1.10 (nếu có) │ DROP     │ 60s        │
│ 60         │ ipv4_src=10.0.2.10          │ → Ctrl   │ 10s        │
│ 60         │ ipv4_src=10.0.2.11          │ → Ctrl   │ 10s        │
│ 60         │ ipv4_src=10.0.3.10          │ → Ctrl   │ 10s        │
│ 60         │ ...mỗi whitelist IP         │ → Ctrl   │ 10s        │
│ 40         │ eth_type=0x0800 (ALL IPv4)  │ DROP     │ 10s        │
│ 10         │ ipv4_src=..., ipv4_dst=...  │ Forward  │ idle 30s   │
│ 0          │ (any)                       │ → Ctrl   │ permanent  │
└────────────┴─────────────────────────────┴──────────┴────────────┘
```

**Luồng xử lý khi Lockdown:**

- Gói từ IP giả mạo → match rule priority 40 → **DROP**
- Gói từ IP whitelist (ví dụ 10.0.2.10) → match rule priority 60 → **gửi lên controller** → controller routing bình thường
- Sau 10 giây → cả 2 rule (40 và 60) hết hạn → mọi thứ trở về bình thường

### 3.5.5. Trạng thái bình thường (dòng 125–126)

```python
else:
    self.attack_status = 0    # 1.5 ≤ H ≤ 8.0 → bình thường
```

### 3.5.6. Ghi metrics vào InfluxDB (dòng 130–145)

```python
if self.influx_client:
    self.influx_client.write_points([{
        "measurement": "network_traffic",
        "fields": {
            "packet_rate": int(current_rate),       # Gói qua controller / 3s
            "total_pps": int(current_pps),          # Tổng PPS từ flow stats
            "entropy": round(float(entropy), 4),    # Giá trị entropy
            "attack_status": int(self.attack_status),  # 0/1/2
            "blocked_ip_count": int(len(self.blocked_ips)),
            "window_fill": int(window_size)         # Số gói trong window
        }
    }])
```

**6 metrics** được ghi mỗi 3 giây → Grafana query để vẽ biểu đồ realtime.

## 3.6. BLOCK IP (dòng 147–161)

```python
def _block_ip(self, bad_ip):
    self.blocked_ips.add(bad_ip)                    # Ghi nhớ IP đã block

    for dp in self.dps.values():                     # Gửi tới TẤT CẢ switch
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=bad_ip)
        inst = [parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, [])]     # Actions rỗng = DROP
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=100, match=match,  # Priority cao nhất
            instructions=inst, hard_timeout=60))      # Tự hết sau 60s

    def unblock():
        hub.sleep(61)                                # Đợi 61 giây
        self.blocked_ips.discard(bad_ip)             # Xóa khỏi blocked set
        self.logger.info("[UNBLOCK] Da go chan IP %s sau 60 giay", bad_ip)
    hub.spawn(unblock)      # Tạo thread riêng để unblock
```

**Chi tiết mechanism:**

1. **Thêm vào `blocked_ips`**: tránh gửi FlowMod trùng lặp nếu IP vẫn nằm trong window
2. **FlowMod DROP** với `priority=100`: cao hơn mọi rule khác → mọi gói từ IP này bị drop tại switch, KHÔNG đi lên controller
3. **`hard_timeout=60`**: switch tự xóa rule sau 60 giây (không cần controller can thiệp)
4. **`unblock()` thread**: sau 61 giây (chắc chắn rule đã hết trên switch), xóa IP khỏi `blocked_ips` → nếu IP vẫn tấn công → entropy lại giảm → block lại

**Tại sao `hard_timeout=60` chứ không phải `idle_timeout`?**

- `hard_timeout`: xóa sau N giây **bất kể** có traffic hay không
- `idle_timeout`: xóa sau N giây **không có** traffic
- Kẻ tấn công vẫn gửi gói liên tục → `idle_timeout` sẽ không bao giờ hết → dùng `hard_timeout` để đảm bảo unblock

## 3.7. FLOW STATS MONITOR — Thread 2 (dòng 166–194)

### 3.7.1. Gửi FlowStatsRequest (dòng 166–170)

```python
def _monitor_flows(self):
    while True:
        for dp in self.dps.values():
            dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
        hub.sleep(3)
```

Mỗi 3 giây, gửi request tới TẤT CẢ switch → switch trả về danh sách tất cả flow rules và counter (packet_count, byte_count).

### 3.7.2. Xử lý FlowStatsReply (dòng 172–194)

```python
@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
def flow_stats_reply_handler(self, ev):
    now = time.time()
    sum_pps = 0

    for stat in ev.msg.body:           # Duyệt từng flow rule
        if stat.priority == 0:          # Bỏ qua table-miss
            continue
        src = stat.match.get('ipv4_src')
        if not src:                     # Bỏ flow không có ipv4_src
            continue
        if src in self.gateways or src in self.WHITELIST_SRC:
            continue                    # Bỏ gateway và whitelist

        key = (ev.msg.datapath.id, src, stat.match.get('ipv4_dst'))
        prev = self.flow_stats.get(key)

        if prev:
            delta = now - prev[1]       # Thời gian giữa 2 lần đo
            if delta > 0:
                pps = (stat.packet_count - prev[0]) / delta   # PPS
                if pps > 0:
                    sum_pps += pps
                # BLOCK nếu PPS > 500
                if pps > 500 and src not in self.blocked_ips:
                    self._block_ip(src)

        self.flow_stats[key] = (stat.packet_count, now)    # Lưu cho lần sau
    self.total_pps = int(sum_pps)
```

**Giải thích PPS (Packets Per Second):**

```
Lần đo 1 (t=10s): flow {src=10.0.1.10} có packet_count = 1000
Lần đo 2 (t=13s): flow {src=10.0.1.10} có packet_count = 2500

delta = 13 - 10 = 3 giây
PPS = (2500 - 1000) / 3 = 500 gói/giây
```

**Tại sao cần cả entropy VÀ flow stats?**

- **Entropy**: phát hiện pattern tấn công (nhiều gói từ 1 IP, hoặc nhiều IP lạ)
- **Flow stats PPS**: phát hiện tốc độ bất thường — ngay cả khi entropy chưa trigger (ví dụ: entropy ở mức 2.0 nhưng 1 IP gửi 600 PPS → vẫn bị block)
- **Kết hợp 2 lớp** → giảm false negative

---

# 4. GIẢI THÍCH FILE TẤN CÔNG .TXT

## 4.1. `dos_botnet.txt` — Tấn công Flood IP cố định

```bash
h_web1 pkill iperf              # ① Dọn dẹp iperf cũ trên web server
h_web1 iperf -s -p 80 &         # ② Chạy iperf server lên port 80 (TCP)
h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &   # ③ Traffic nền hợp lệ
h_att1 hping3 -S -p 80 --flood 10.0.2.10    # ④ TẤN CÔNG!
```

**Giải thích từng lệnh:**

| #   | Lệnh                                       | Ý nghĩa                                                                                                                          |
| --- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| ①   | `h_web1 pkill iperf`                       | Kill mọi process iperf cũ trên h_web1 (dọn dẹp)                                                                                  |
| ②   | `h_web1 iperf -s -p 80 &`                  | Chạy TCP server trên h_web1, lắng nghe port 80. `&` = chạy nền                                                                   |
| ③   | `h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &` | h_ext1 kết nối TCP tới h_web1:80, gửi data 300 giây. Đây là **traffic bình thường** để chứng minh user hợp lệ không bị ảnh hưởng |
| ④   | `h_att1 hping3 -S -p 80 --flood 10.0.2.10` | **FLOOD ATTACK**: gửi SYN liên tục tới 10.0.2.10:80, tốc độ tối đa. `-S` = cờ SYN, `--flood` = không chờ reply, gửi liên tục     |

**Tham số hping3:**

- `-S`: đặt cờ TCP SYN (giả lập bước 1 của 3-way handshake)
- `-p 80`: port đích = 80
- `--flood`: chế độ flood — gửi nhanh nhất có thể, không hiển thị output
- **IP nguồn**: mặc định là IP thật của h_att1 = 10.0.1.10 (IP CỐ ĐỊNH)

**Kết quả:** Hàng nghìn gói SYN/s từ **cùng 1 IP** (10.0.1.10) → window bị lấp đầy → entropy giảm mạnh → trigger Flood detection.

## 4.2. `dos_spoof.txt` — Tấn công Spoofing IP ngẫu nhiên

```bash
h_web1 pkill iperf
h_web1 iperf -s -p 80 &
h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &
h_att1 hping3 -S -p 80 --flood --rand-source 10.0.2.10
```

**Khác biệt duy nhất**: `--rand-source`

| Tham số        | dos_botnet.txt      | dos_spoof.txt      |
| -------------- | ------------------- | ------------------ |
| IP nguồn       | 10.0.1.10 (cố định) | **Random mỗi gói** |
| Entropy effect | Giảm mạnh (< 1.5)   | Tăng vọt (> 8.0)   |
| Detection      | `ENTROPY_LOW`       | `ENTROPY_HIGH`     |
| Mitigation     | Block IP cụ thể     | LOCKDOWN toàn mạng |

**`--rand-source`**: hping3 tạo IP nguồn ngẫu nhiên cho MỖI gói tin. Ví dụ:

```
Gói 1: src=172.16.84.33  → 10.0.2.10
Gói 2: src=10.255.7.201  → 10.0.2.10
Gói 3: src=192.168.33.5  → 10.0.2.10
... cứ thế, mỗi gói 1 IP khác
```

→ Window chứa hàng trăm IP duy nhất → entropy cực cao → trigger Spoofing detection.

---

# 5. LUỒNG HOẠT ĐỘNG TOÀN HỆ THỐNG

## Giai đoạn 1: KHỞI ĐỘNG RYU CONTROLLER

```bash
$ ryu-manager l3_router_test.py
```

**Những gì xảy ra bên trong:**

```
1. Ryu load file l3_router_test.py
2. Tạo instance SimpleRouterEntropy
3. __init__() chạy:
   a. Khởi tạo routing table, ARP table, gateway list
   b. Khởi tạo entropy detection: window=[], blocked=set(), thresholds
   c. Khởi tạo whitelist
   d. Kết nối InfluxDB (nếu có)
   e. Spawn 2 green threads:
      - _monitor_entropy: ngủ 3s → tính entropy → ngủ 3s → ...
      - _monitor_flows: ngủ 3s → gửi FlowStatsRequest → ngủ 3s → ...
4. Ryu bắt đầu lắng nghe TCP port 6653
5. Console hiển thị: "listening on 0.0.0.0:6653"
```

**Lúc này:** Controller sẵn sàng, 2 monitor thread chạy nhưng `self.dps = {}` (chưa có switch nào).

## Giai đoạn 2: KHỞI ĐỘNG MININET TOPOLOGY

```bash
$ sudo python topology_nhom4.py
```

**Những gì xảy ra:**

```
1. Mininet tạo 5 switch (OVS) và 8 host (network namespace)
2. Tạo virtual link giữa chúng
3. Mỗi switch bắt đầu TCP handshake tới Ryu (127.0.0.1:6653)

--- Với MỖI switch (s1 → s5): ---
4. OpenFlow Handshake:
   Switch → Controller: OFPHello
   Controller → Switch: OFPHello
   Controller → Switch: OFPFeaturesRequest
   Switch → Controller: OFPFeaturesReply (chứa dpid)

5. Event MAIN_DISPATCHER trigger:
   → _state_change() gọi: self.dps[dp.id] = dp
   → Ryu log: "switch connected: dpid=0001"

6. SimpleSwitch13.switch_features_handler() (từ class cha):
   → Cài table-miss rule: priority=0, match=any → OFPP_CONTROLLER
   → MỌI gói tin không match flow nào → gửi lên controller

--- Sau khi tất cả 5 switch kết nối: ---
7. self.dps = {1: dp1, 2: dp2, 3: dp3, 4: dp4, 5: dp5}
8. _monitor_flows bắt đầu gửi FlowStatsRequest tới 5 switch
9. _monitor_entropy tính entropy — nhưng window rỗng → bỏ qua
10. Mininet CLI hiện "mininet>" — sẵn sàng nhận lệnh
```

## Giai đoạn 3: TRAFFIC BÌNH THƯỜNG (trước tấn công)

```bash
mininet> h_ext1 ping h_web1
```

**Luồng chi tiết cho gói ICMP đầu tiên (h_ext1 → h_web1):**

```
Bước 1: h_ext1 muốn gửi tới 10.0.2.10 (khác subnet)
        → Cần gửi qua gateway 10.0.1.1
        → h_ext1 chưa biết MAC của 10.0.1.1
        → Gửi ARP Request broadcast: "Who has 10.0.1.1?"

Bước 2: ARP Request đi qua s1 → s2 → Packet-In lên Controller
        Controller nhận ARP:
        - Học: arp_table['10.0.1.20'] = MAC(h_ext1)
        - dst_ip=10.0.1.1 ∈ gateways → trả ARP Reply
        - Reply: "10.0.1.1 has MAC 00:00:00:00:00:FE"

Bước 3: h_ext1 nhận ARP Reply, biết gateway MAC = 00:00:00:00:00:FE
        → Gửi ICMP: src_mac=MAC(h_ext1), dst_mac=00:00:00:00:00:FE
                     src_ip=10.0.1.20, dst_ip=10.0.2.10

Bước 4: Gói ICMP tới s1 → Packet-In (s1 chưa biết MAC 00:00:00:00:FE)
        Controller (SimpleSwitch13) xử lý L2 cho s1:
        - Học MAC(h_ext1) → port 3
        - Flood gói ra tất cả port → gói đến s2

Bước 5: Gói tới s2 → Packet-In (dp.id == 2 → vào logic L3)
        Controller xử lý IPv4:
        a. packet_rate += 1
        b. src=10.0.1.20 ∈ WHITELIST_SRC → KHÔNG thêm vào window
        c. Tra routing: dst=10.0.2.10 starts with '10.0.2.' → out_port=2
        d. dst=10.0.2.10 chưa có trong arp_table → gửi ARP Request:
           Controller → PacketOut → s2:port2 → s3 → broadcast
           "Who has 10.0.2.10?"

Bước 6: h_web1 nhận ARP Request → trả ARP Reply
        Reply qua s3 → s2 → Packet-In
        Controller học: arp_table['10.0.2.10'] = MAC(h_web1)
        (gói ICMP ban đầu bị drop — stateless, h_ext1 sẽ retry)

Bước 7: h_ext1 retry ICMP → s1 → s2 → Packet-In
        Lần này arp_table có 10.0.2.10 → xử lý routing:
        actions = [
            SetField(eth_src=00:00:00:00:00:FE),    # Router MAC
            SetField(eth_dst=MAC(h_web1)),            # MAC thật
            Output(port 2)                            # Tới s3
        ]
        Vì src=10.0.1.20 ∈ WHITELIST:
        → add_flow(priority=10, match={src=10.0.1.20, dst=10.0.2.10}, idle=30)
        → PacketOut: gói ICMP đi ra port 2 → s3 → h_web1

Bước 8: CÁC GÓI SAU từ h_ext1 → h_web1:
        → Match flow rule priority=10 trên s2
        → Switch tự forward, KHÔNG lên controller
        → Controller không thấy → không ảnh hưởng entropy
        (flow tự xóa sau 30 giây idle)
```

## Giai đoạn 4: TẤN CÔNG XẢY RA

**Xem chi tiết ở phần [Kịch bản Demo 1](#8-kịch-bản-demo-1-flood-attack) và [Demo 2](#9-kịch-bản-demo-2-spoofing-attack).**

## Giai đoạn 5: PHỤC HỒI SAU TẤN CÔNG

**Xem chi tiết ở phần [Cơ chế phục hồi](#10-cơ-chế-phục-hồi-sau-tấn-công).**

---

# 6. THUẬT TOÁN PHÁT HIỆN: SHANNON ENTROPY

## 6.1. Công thức toán học

```
         n
H = − Σ  pᵢ × log₂(pᵢ)
        i=1

Trong đó:
  n = số IP nguồn duy nhất trong window
  pᵢ = frequency(IPᵢ) / total_packets
  H = entropy (bit)
```

## 6.2. Tính chất toán học

| Tính chất                   | Giải thích                                           |
| --------------------------- | ---------------------------------------------------- |
| `H ≥ 0`                     | Entropy luôn không âm                                |
| `H = 0`                     | Chỉ khi tất cả gói từ 1 IP duy nhất (p=1, log₂(1)=0) |
| `H = log₂(n)`               | Khi mọi IP xuất hiện cùng tần suất (phân bố đều)     |
| `H_max = log₂(1000) ≈ 9.97` | Maximum khi 1000 gói có 1000 IP khác nhau            |

## 6.3. Ví dụ tính tay

**Trường hợp Flood:**

```
Window = [10.0.1.10, 10.0.1.10, 10.0.1.10, ..., 10.0.1.20, 10.0.1.20]
                     900 lần                         100 lần
Total = 1000

p₁ = 900/1000 = 0.9    → −0.9 × log₂(0.9) = −0.9 × (−0.152) = 0.137
p₂ = 100/1000 = 0.1    → −0.1 × log₂(0.1) = −0.1 × (−3.322) = 0.332

H = 0.137 + 0.332 = 0.469

H = 0.469 < 1.5 (ENTROPY_LOW) → PHÁT HIỆN FLOOD ✅
```

**Trường hợp Spoofing:**

```
Window = [ip_1, ip_2, ip_3, ..., ip_950, ip_repeat1, ip_repeat2, ...]
              950 IP duy nhất              50 IP lặp lại

p{mỗi IP unique} ≈ 1/1000     → có 950 IP
p{mỗi IP repeat} ≈ 2/1000     → có ~25 IP

H = 950 × (−0.001 × log₂(0.001)) + 25 × (−0.002 × log₂(0.002))
  = 950 × 0.001 × 9.97 + 25 × 0.002 × 8.97
  = 9.47 + 0.45
  = 9.92

H = 9.92 > 8.0 (ENTROPY_HIGH) → PHÁT HIỆN SPOOFING ✅
```

**Trường hợp bình thường:**

```
Window = [10.0.1.10, 10.0.1.10, ..., ext_ip1, ext_ip2, ...]
Chỉ có vài IP thật (không whitelist), phân bố tự nhiên

Giả sử: h_att1 gửi bình thường (không flood), chỉ có 1 IP trong window
H = 0 (chỉ 1 IP) → nhưng vì traffic ít, window chưa đủ 100 → bỏ qua
Hoặc mix traffic: H ≈ 2-3 → bình thường
```

## 6.4. Flowchart thuật toán

```
                    ┌─────────────┐
                    │ Ngủ 3 giây  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Window      │
                    │ >= 100 mẫu? │
                    └──────┬──────┘
                     No    │    Yes
                    ┌──────┘──────┐
                    │             │
                    ▼             ▼
              Bỏ qua       ┌──────────────┐
              (ghi 0.0      │ Counter(window)│
               vào InfluxDB)│ Tính entropy H │
                            └──────┬───────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
               H < 1.5      1.5 ≤ H ≤ 8.0    H > 8.0
                    │              │              │
                    ▼              ▼              ▼
              ┌─────────┐   ┌─────────┐   ┌─────────────┐
              │ FLOOD!  │   │ NORMAL  │   │ SPOOFING!   │
              │ status=1│   │ status=0│   │ status=2    │
              └────┬────┘   └─────────┘   └──────┬──────┘
                   │                             │
                   ▼                             ▼
           ┌──────────────┐              ┌──────────────────┐
           │ Quét IP >20% │              │ LOCKDOWN:        │
           │ Block non-WL │              │ DROP all IPv4    │
           │ Priority=100 │              │ (pri=40, 10s)    │
           │ Timeout=60s  │              │ ALLOW whitelist  │
           └──────┬───────┘              │ (pri=60, 10s)    │
                  │                      └────────┬─────────┘
                  │                               │
                  └───────────┬───────────────────┘
                              │
                       ┌──────▼──────┐
                       │ Clear window│
                       │ Ghi InfluxDB│
                       └──────┬──────┘
                              │
                       ┌──────▼──────┐
                       │ Lặp lại     │
                       └─────────────┘
```

---

# 7. CƠ CHẾ NGĂN CHẶN CHI TIẾT

## 7.1. So sánh 2 kịch bản

| Thuộc tính        | Flood (H < 1.5)         | Spoofing (H > 8.0)     |
| ----------------- | ----------------------- | ---------------------- |
| **Phương pháp**   | Block từng IP cụ thể    | LOCKDOWN toàn mạng     |
| **Flow priority** | 100 (cao nhất)          | 40 (DROP) + 60 (ALLOW) |
| **Timeout**       | `hard_timeout=60s`      | `hard_timeout=10s`     |
| **Scope**         | Chỉ IP tấn công         | Tất cả IPv4            |
| **Whitelist**     | Skip khi quét           | Cho phép qua lockdown  |
| **Unblock**       | Thread riêng sau 61s    | Tự hết sau 10s         |
| **Trigger**       | 1 IP chiếm > 20% window | Quá nhiều IP duy nhất  |

## 7.2. Priority System giải thích

```
                         Gói tin IPv4 đến Switch
                                │
                    ┌───────────▼───────────┐
                    │ Tra cứu Flow Table    │
                    │ theo priority CAO → thấp│
                    └───────────┬───────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         │                      │                      │
    Priority 100           Priority 60            Priority 40
    Block IP cụ thể?      Whitelist IP?           DROP all IPv4?
    (hard_timeout=60s)     (hard_timeout=10s)      (hard_timeout=10s)
         │                      │                      │
    Match: ipv4_src=      Match: ipv4_src=        Match: eth_type=
    bad_ip                whitelist_ip             0x0800 (any IPv4)
         │                      │                      │
         ▼                      ▼                      ▼
       DROP               → Controller              DROP
                          (routing bình thường)
         │                      │                      │
    Nếu không match ────────────┼──────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │ Priority 10           │
                    │ Routing flow          │
                    │ (idle_timeout=30s)    │
                    │ Match: src+dst IP     │
                    │ → Forward             │
                    └───────────┬───────────┘
                                │
                    Nếu không match
                                │
                    ┌───────────▼───────────┐
                    │ Priority 0            │
                    │ Table-miss            │
                    │ → Gửi lên Controller  │
                    └───────────────────────┘
```

---

# 8. KỊCH BẢN DEMO 1: FLOOD ATTACK

## 8.1. Chuẩn bị

```bash
# Terminal 1: Ryu Controller
$ ryu-manager l3_router_test.py

# Terminal 2: Mininet
$ sudo python topology_nhom4.py
```

## 8.2. Tạo traffic nền (bình thường)

```bash
mininet> h_web1 pkill iperf
mininet> h_web1 iperf -s -p 80 &
mininet> h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &
```

**Quan sát trên Ryu console:**

```
[ENTROPY] Gia tri entropy = 0.00 | Tong goi = 0 | So IP duy nhat = 0
```

(Window chưa đủ 100 mẫu vì h_ext1 thuộc whitelist → không thêm vào window)

## 8.3. Bắt đầu tấn công

```bash
mininet> h_att1 hping3 -S -p 80 --flood 10.0.2.10
```

## 8.4. Timeline chi tiết

```
T=0s:  h_att1 bắt đầu flood
       → Mỗi gói SYN: src=10.0.1.10, dst=10.0.2.10
       → Gói đi: h_att1 → s1 → s2 (Packet-In vì non-whitelist)
       → Controller:
         packet_rate += 1
         src_ip_window.append('10.0.1.10')
         → forward gói tới h_web1 (PacketOut)

T=0~3s: Window lấp dần:
        src_ip_window = ['10.0.1.10', '10.0.1.10', ..., '10.0.1.10']
        Có thể hàng nghìn gói trong 3 giây → window đạt 1000 nhanh chóng

T=3s:  _monitor_entropy thức dậy
       window_size = 1000 >= 100 ✅
       ip_counts = Counter({'10.0.1.10': 1000})
       H = −(1.0 × log₂(1.0)) = 0.0

       0.0 < 1.5 (ENTROPY_LOW) → FLOOD DETECTED!

       Quét window:
       - IP '10.0.1.10': count=1000, ratio=100% > 20% ✅
       - 10.0.1.10 ∉ WHITELIST_SRC ✅
       - 10.0.1.10 ∉ blocked_ips ✅
       → _block_ip('10.0.1.10')

       Block:
       - blocked_ips.add('10.0.1.10')
       - Gửi FlowMod tới s1, s2, s3, s4, s5:
         match: eth_type=0x0800, ipv4_src=10.0.1.10
         actions: [] (DROP)
         priority: 100
         hard_timeout: 60
       - Spawn unblock thread (đợi 61s)
       - Clear window

       Ghi InfluxDB:
       {entropy: 0.0, attack_status: 1, blocked_ip_count: 1}

T=3s+: MỌI gói từ 10.0.1.10 bị DROP tại switch (priority 100)
       → KHÔNG lên controller
       → h_att1 vẫn gửi nhưng gói đều bị drop
       → h_ext1 vẫn truy cập bình thường (whitelist, có flow rule)

T=6s:  _monitor_entropy thức dậy
       window rỗng (đã clear) → window_size < 100 → bỏ qua
       Ghi InfluxDB: {entropy: 0.0, attack_status: 1}

T=63s: hard_timeout hết trên switch → flow rule DROP bị xóa
T=64s: unblock() thread thức dậy
       blocked_ips.discard('10.0.1.10')
       Log: "[UNBLOCK] Da go chan IP 10.0.1.10 sau 60 giay"

       Nếu h_att1 VẪN flood:
       → Gói lại lên controller
       → Window lại đầy 10.0.1.10
       → Entropy lại giảm < 1.5
       → Block lại!

       Nếu h_att1 DỪNG:
       → Không có traffic non-whitelist
       → Window rỗng/ít → entropy bình thường
       → attack_status = 0
```

## 8.5. Kết quả mong đợi trên Grafana

```
Entropy:     ████████████████╲__________ (giảm đột ngột → 0)
                              ↑ Phát hiện flood
Packet Rate: ████████████████╲__________ (giảm sau khi block)
Status:      ────────────────█████────── (1 = flood detected)
Blocked IPs: ────────────────█████────── (1 = có IP bị block)
```

---

# 9. KỊCH BẢN DEMO 2: SPOOFING ATTACK

## 9.1. Bắt đầu tấn công

```bash
mininet> h_att1 hping3 -S -p 80 --flood --rand-source 10.0.2.10
```

## 9.2. Timeline chi tiết

```
T=0s:  h_att1 flood với --rand-source
       Mỗi gói có src IP khác nhau: 172.x.x.x, 10.x.x.x, 192.x.x.x...

       Controller nhận Packet-In từ s2:
       → Mỗi IP ngẫu nhiên KHÔNG thuộc whitelist
       → Thêm vào window: ['172.16.5.33', '10.44.88.2', '192.168.1.55', ...]

T=0~3s: Window lấp đầy:
        src_ip_window = [IP_1, IP_2, IP_3, ..., IP_1000]
        (hầu hết là IP duy nhất)

T=3s:  _monitor_entropy thức dậy
       ip_counts = Counter({IP_1: 1, IP_2: 1, ..., IP_980: 1, ...})
       ~980 IP duy nhất trong 1000 gói

       H = −Σ(1/1000 × log₂(1/1000)) × 980 + ...
       H ≈ 9.9 (gần maximum)

       9.9 > 8.0 (ENTROPY_HIGH) → SPOOFING DETECTED!

       LOCKDOWN activation:
       Gửi tới TẤT CẢ switch (s1-s5):

       Rule 1: DROP all IPv4
         match: eth_type=0x0800
         actions: [] (DROP)
         priority: 40
         hard_timeout: 10

       Rule 2: ALLOW mỗi whitelist IP (7 rules)
         match: eth_type=0x0800, ipv4_src=10.0.2.10
         instructions: [] (→ table-miss → controller)
         priority: 60
         hard_timeout: 10
         (lặp cho 10.0.2.11, 10.0.3.10, 10.0.3.11, 10.0.4.10, 10.0.4.11, 10.0.1.20)

       Clear window
       Ghi InfluxDB: {entropy: 9.9, attack_status: 2}

T=3s+: LOCKDOWN hiệu lực:
       ┌────────────────────────────────────────────────┐
       │ Gói từ IP giả mạo (ví dụ 172.16.5.33):        │
       │ → Match pri=40 (DROP all IPv4) → DROP ✅       │
       │                                                │
       │ Gói từ h_ext1 (10.0.1.20):                     │
       │ → Match pri=60 (whitelist) → gửi lên controller│
       │ → Controller routing bình thường → forward ✅  │
       │                                                │
       │ Gói từ h_web1 (10.0.2.10, response):           │
       │ → Match pri=60 (whitelist) → controller → OK ✅│
       └────────────────────────────────────────────────┘

T=13s: hard_timeout=10 hết → CẢ HAI loại rule (40 và 60) bị xóa
       Mạng trở về trạng thái bình thường
       → Gói tấn công lại lên controller
       → Window lại đầy IP giả
       → Entropy lại > 8.0
       → LOCKDOWN LẠI (chu kỳ lặp)

T=13~16s: Lockdown lần 2
T=26s:    Lockdown hết → lần 3...
          (Lặp cho đến khi attacker dừng)

Khi attacker DỪNG:
       → Lockdown cuối cùng hết sau 10s
       → Không có gói tấn công mới
       → Window rỗng hoặc ít
       → Entropy bình thường
       → attack_status = 0
```

## 9.3. Kết quả mong đợi trên Grafana

```
Entropy:      ────────████████████████── (tăng vọt > 8.0)
                      ↑ Spoofing detected
Packet Rate:  ────────████╲───████╲──── (giảm mỗi lockdown, tăng lại)
Status:       ────────████████████████── (2 = spoofing, nhấp nháy theo lockdown cycle)
```

---

# 10. CƠ CHẾ PHỤC HỒI SAU TẤN CÔNG

## 10.1. Phục hồi sau Flood Attack

```
Attacker dừng → không có gói non-whitelist → window rỗng
                                                │
                                    ┌───────────▼───────────┐
                                    │ _monitor_entropy      │
                                    │ window < 100          │
                                    │ → entropy = 0.0       │
                                    │ → attack_status giữ   │
                                    │   (không reset vì     │
                                    │    vào nhánh else:pass)│
                                    └───────────┬───────────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │ hard_timeout=60s hết  │
                                    │ → Flow rule DROP xóa  │
                                    │ → unblock() chạy      │
                                    │ → blocked_ips.discard  │
                                    └───────────┬───────────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │ Mạng hoạt động        │
                                    │ bình thường            │
                                    │ (h_att1 cũng có thể   │
                                    │  truy cập lại)        │
                                    └───────────────────────┘
```

**Thời gian phục hồi**: ~61–64 giây sau khi attacker dừng
(60s hard_timeout + 1s unblock thread + vài giây buffer)

## 10.2. Phục hồi sau Spoofing Attack

```
Attacker dừng → lockdown cuối cùng hết sau 10s
                          │
              ┌───────────▼───────────┐
              │ hard_timeout=10s hết  │
              │ → Rules (pri 40 + 60) │
              │   tự xóa              │
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │ Không có gói tấn công │
              │ → Window rỗng/ít     │
              │ → Entropy bình thường │
              │ → attack_status = 0  │
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │ Mạng hoạt động       │
              │ bình thường           │
              └───────────────────────┘
```

**Thời gian phục hồi**: ~10–13 giây sau khi attacker dừng
(10s hard_timeout + 3s chu kỳ entropy)

## 10.3. Cơ chế tự lặp (Self-healing loop)

```
Tấn công tiếp tục → Window lại đầy
                        │
              ┌─────────▼─────────┐
              │ Entropy bất thường │──── Flood: block lại IP
              │ (< 1.5 hoặc > 8.0)│──── Spoofing: lockdown lại
              └─────────┬─────────┘
                        │
              ┌─────────▼─────────┐
              │ Clear window      │
              │ Timeout hết       │
              │ Kiểm tra lại      │
              └─────────┬─────────┘
                        │
                   Tấn công dừng?
                   /           \
                 Yes            No
                  │              │
            Phục hồi      Lặp block/lockdown
```

Hệ thống **KHÔNG CẦN can thiệp thủ công**. Nó tự:

1. Phát hiện → block/lockdown
2. Timeout → kiểm tra lại
3. Vẫn tấn công → block/lockdown lại
4. Hết tấn công → phục hồi tự động

---

# 11. BẢNG TỔNG HỢP TẤT CẢ FLOW RULES

| Priority | Match                                      | Action           | Timeout   | Ai tạo               | Khi nào                       |
| -------- | ------------------------------------------ | ---------------- | --------- | -------------------- | ----------------------------- |
| **0**    | `(any)`                                    | → Controller     | Permanent | `SimpleSwitch13`     | Khi switch kết nối            |
| **10**   | `eth_type=0x0800, ipv4_src=WL, ipv4_dst=X` | Set MAC + Output | idle 30s  | `_packet_in_handler` | Khi whitelist IP gửi gói      |
| **40**   | `eth_type=0x0800` (all IPv4)               | DROP             | hard 10s  | `_monitor_entropy`   | Khi H > 8.0 (Spoofing)        |
| **60**   | `eth_type=0x0800, ipv4_src=WL_IP`          | → Controller     | hard 10s  | `_monitor_entropy`   | Khi H > 8.0 (cùng lúc pri 40) |
| **100**  | `eth_type=0x0800, ipv4_src=BAD_IP`         | DROP             | hard 60s  | `_block_ip()`        | Khi H < 1.5 hoặc PPS > 500    |

---

# 12. CÁC LỆNH DEMO THỰC TẾ

## 12.1. Demo cơ bản — kiểm tra kết nối

```bash
# Trong Mininet CLI:

# Ping cùng subnet
mininet> h_att1 ping -c 3 h_ext1

# Ping cross-subnet (qua router s2)
mininet> h_att1 ping -c 3 h_web1

# Ping all (kiểm tra tất cả kết nối)
mininet> pingall
```

## 12.2. Demo Flood Attack

```bash
# Bước 1: Tạo server + traffic nền
mininet> h_web1 iperf -s -p 80 &
mininet> h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &

# Bước 2: Kiểm tra h_ext1 truy cập OK
mininet> h_ext1 ping -c 3 h_web1
# → Phải thành công

# Bước 3: BẮT ĐẦU TẤN CÔNG
mininet> h_att1 hping3 -S -p 80 --flood 10.0.2.10

# → Quan sát Ryu console: "[CANH BAO] Flood!", "[BLOCK] Chan IP 10.0.1.10"

# Bước 4: KIỂM TRA user hợp lệ vẫn OK (mở terminal Mininet khác)
mininet> h_ext1 ping -c 3 h_web1
# → Phải vẫn thành công (h_ext1 thuộc whitelist)

# Bước 5: Dừng tấn công
# Ctrl+C trên h_att1

# Bước 6: Đợi 61 giây → h_att1 được unblock
mininet> h_att1 ping -c 3 h_web1
# → Lại thành công
```

## 12.3. Demo Spoofing Attack

```bash
# Bước 1: Tạo server + traffic nền (giống trên)
mininet> h_web1 iperf -s -p 80 &
mininet> h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &

# Bước 2: BẮT ĐẦU TẤN CÔNG
mininet> h_att1 hping3 -S -p 80 --flood --rand-source 10.0.2.10

# → Quan sát Ryu console: "[CANH BAO] Spoofing!", entropy > 8.0
# → LOCKDOWN kích hoạt

# Bước 3: KIỂM TRA whitelist
mininet> h_ext1 ping -c 3 h_web1
# → Có thể bị delay nhưng vẫn đi qua (whitelist được ALLOW)

# Bước 4: Dừng tấn công
# Ctrl+C

# Bước 5: Đợi ~10-15 giây → mạng tự phục hồi
mininet> h_att1 ping -c 3 h_web1
# → Thành công (lockdown đã hết)
```

## 12.4. Kiểm tra flow table trên switch

```bash
# Xem flow table của s2 (Core Router)
mininet> dpctl dump-flows -O OpenFlow13

# Hoặc từ terminal host:
$ sudo ovs-ofctl dump-flows s2 -O OpenFlow13
```

**Output mẫu khi đang block IP:**

```
cookie=0x0, priority=100, hard_timeout=60, eth_type=0x0800,
  nw_src=10.0.1.10 actions=drop

cookie=0x0, priority=10, idle_timeout=30, eth_type=0x0800,
  nw_src=10.0.1.20, nw_dst=10.0.2.10
  actions=set_field:00:00:00:00:00:fe->eth_src,
          set_field:xx:xx:xx:xx:xx:xx->eth_dst, output:2

cookie=0x0, priority=0 actions=CONTROLLER:65535
```

**Output mẫu khi LOCKDOWN:**

```
cookie=0x0, priority=60, hard_timeout=10, eth_type=0x0800,
  nw_src=10.0.2.10 actions=<none>    ← gửi lên controller (table-miss)

cookie=0x0, priority=60, hard_timeout=10, eth_type=0x0800,
  nw_src=10.0.1.20 actions=<none>

cookie=0x0, priority=40, hard_timeout=10, eth_type=0x0800
  actions=drop                        ← DROP all IPv4

cookie=0x0, priority=0 actions=CONTROLLER:65535
```

## 12.5. Kiểm tra Grafana

```
Truy cập: http://localhost:3000
Database: sdn_monitor
Measurement: network_traffic
Fields: entropy, packet_rate, total_pps, attack_status, blocked_ip_count, window_fill
```

## 12.6. Script Tấn Công - DOS_BOTNET.TXT

**File:** `dos_botnet.txt` - Tấn công SYN Flood từ 1 IP

```bash
h_web1 pkill iperf
h_web1 iperf -s -p 80 &
h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &
h_att1 hping3 -S -p 80 --flood 10.0.2.10
```

**Giải thích:**

- `h_web1 pkill iperf`: Dừng các iperf cũ trên web server
- `h_web1 iperf -s -p 80 &`: Khởi động iperf server ở port 80 (tạo normal traffic)
- `h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &`: Client thường kết nối tới server (khác hành vi bình thường)
- `h_att1 hping3 -S -p 80 --flood 10.0.2.10`: **Attacker gửi SYN packet liên tục tới server** (botnet attack)

**Dấu hiệu DDoS:**

- PPS từ h_att1 lên tới 1000+ packets/sec
- Shannon Entropy thấp vì toàn từ 1 IP (h_att1 = 10.0.1.10)
- Flow stats: PPS > 500 → trigger block
- Kết quả: h_att1 bị block, h_web1 vẫn hoạt động bình thường

## 12.7. Script Tấn Công - DOS_SPOOF.TXT

**File:** `dos_spoof.txt` - Tấn công IP Spoofing (giả mạo nguồn)

```bash
h_web1 pkill iperf
h_web1 iperf -s -p 80 &
h_ext1 iperf -c 10.0.2.10 -p 80 -t 300 &
h_att1 hping3 -S -p 80 --flood --rand-source 10.0.2.10
```

**Giải thích:**

- Giống như trên, nhưng thêm flag `--rand-source`
- **`--rand-source`**: Giả mạo source IP mỗi gói (random từ range 0-255)

**Dấu hiệu DDoS:**

- PPS cao tương tự (1000+)
- **Nhưng Shannon Entropy TĂNG** vì source IP khác nhau nhiều
- Entropy cao → chỉ báo spoofing attack → **lockdown toàn mạng** (all traffic blocked)
- Recovery: h_att1 bị block + vào blacklist lâu dài
- Kết quả: h_web1 và h_ext1 không thể kết nối cho tới khi lockdown timeout

---

# 📝 TÓM TẮT CHO THUYẾT TRÌNH

> **Khi thầy hỏi "code hoạt động thế nào?":**
>
> Hệ thống có 3 luồng chạy song song:
>
> 1. **Packet-In Handler**: mỗi gói đi qua core router s2, controller nhận, routing (đổi MAC, forward), đồng thời ghi IP nguồn vào sliding window
> 2. **Entropy Monitor (3s)**: tính Shannon Entropy trên window. H thấp → flood → block IP. H cao → spoofing → lockdown toàn mạng
> 3. **Flow Stats Monitor (3s)**: query PPS từ switch. IP nào > 500 PPS → block ngay
>
> Whitelist IP (server + user hợp lệ) được bảo vệ: không bị đưa vào window, không bị block, vẫn đi qua lockdown.
>
> Sau timeout, mọi thứ tự phục hồi. Nếu tấn công tiếp → block/lockdown lại. Chu kỳ lặp tự động.

> **Khi thầy hỏi "tại sao dùng cách này?":**
>
> Shannon Entropy là phương pháp thống kê nhẹ, không cần training data, chạy trực tiếp trên controller. Bài báo gốc của Feinstein & Schnackenberg (DARPA/Boeing, DISCEX'03) đã chứng minh entropy hiệu quả phân biệt traffic bình thường vs. DoS. Kết hợp thêm flow stats PPS tạo lớp phòng thủ thứ 2.
