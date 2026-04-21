# 📚 GLOSSARY - TỪ ĐIỂN KỸ THUẬT

## A

**ARP (Address Resolution Protocol)**

- Giao thức để ánh xạ IP address ↔ MAC address
- Ví dụ: "Tìm MAC address của 10.0.2.10" → gửi ARP request
- Hệ thống em dùng ARP table để track devices

**ARP Table**

- Bảng mapping: IPv4 → MAC address
- Dùng để biết gửi Ethernet frame tới cái MAC nào
- VD: arp_table['10.0.2.10'] = '00:00:00:00:00:02'

---

## B

**BPS (Bytes Per Second)**

- Số byte dữ liệu truyền/giây
- Khác với Mbps (megabits per second)
- Công thức: bytes / seconds
- Thường log ra như: BPS=750000.00

**Botnet**

- Mạng lưới máy tính bị hack → kiểm soát từ xa
- Dùng để gửi tấn công DDoS
- Thường từ 1 IP (botnet master) → nhận lệnh
- Entropy thấp vì traffic từ ít source

**Block Rule**

- Flow rule có action = [] (rỗng)
- Khi packet match → DROP (không forward)
- VD: match(ipv4_src=10.0.1.10) → drop

---

## C

**CONFIG_DISPATCHER**

- State của switch: "đang cấu hình"
- Dùng @set_ev_cls(EventOFPSwitchFeatures, CONFIG_DISPATCHER)
- Lúc này controller gửi initial flow rules

**Controller**

- "Não" của network
- Quyết định: forward packet hay block packet
- Ryu controller chạy ở 127.0.0.1:6653

**Core Router**

- Switch s2 (dpid=2) trong topology
- Tất cả traffic phải qua đây
- Là bottleneck → nơi best để detect/block

---

## D

**DPID (DataPath ID)**

- ID duy nhất của switch
- VD: s1 có dpid=1, s2 có dpid=2
- Controller dùng DPID để identify switch

**DDoS (Distributed Denial of Service)**

- Tấn công từ nhiều nguồn → "làm tắc" server
- Server không thể xử lý quá nhiều request
- VD: gửi 1 tỷ UDP packet/giây → server crash

---

## E

**Edge Switch**

- Switch ở "vành ngoài" - kết nối các host
- VD: s1, s3, s4, s5
- Đối lập: Core switch (s2)

**Entropy (Shannon Entropy)**

- Đo "độ khác nhau" / "độ random"
- Formula: H = -Σ(p_i × log₂(p_i))
- Entropy cao = nhiều source khác nhau (spoofing)
- Entropy thấp = ít source (botnet)
- Range: 0.0 (cùng 1 IP) → 1.0 (hoàn toàn random)

**Ethernet Type (eth_type)**

- Loại gói Ethernet
- 0x0800 = IPv4
- 0x0806 = ARP
- 0x86DD = IPv6
- Dùng trong OpenFlow match rules

**Event Dispatcher**

- State của controller
- CONFIG_DISPATCHER: switch cấu hình
- MAIN_DISPATCHER: switch online & bình thường
- DEAD_DISPATCHER: switch đã disconnect

---

## F

**Flow**

- Một "luồng" packets với cùng criteria
- VD: tất cả packets từ 10.0.1.10 → 10.0.2.10 = 1 flow
- Controller quản lý flow thông qua flow table

**Flow Rule / Flow Entry**

- Entry trong flow table của switch
- Gồm: match + actions + priority
- VD: "if src_ip=10.0.1.10 then drop"

**Flow Stats**

- Thống kê của flow
- packet_count: tổng packet đã xử lý
- byte_count: tổng byte đã xử lý
- Controller request stats mỗi 5 giây

**Flow Table**

- Bảng quy tắc của switch
- Entries được sort theo priority (cao trước)
- Nếu packet match rule → thực hiện action
- Nếu không match → table-miss → gửi controller

**Flood Attack**

- Gửi quá nhiều packet tới server
- Server resources (bandwidth, CPU) bị cạn kiệt
- Server không thể respond user legitimate requests

---

## G

**Gateway IP**

- IP address của router trong subnet
- VD: 10.0.1.1 là gateway của 10.0.1.x
- Host trong subnet sử dụng gateway để forward packets ra ngoài

**Gateway MAC**

- MAC address của gateway router
- router_mac = '00:00:00:00:00:FE' trong hệ thống em

---

## H

**Host**

- End device (máy tính, server)
- VD: h_att1, h_web1, h_db1
- Trong mininet: virtual host

**Hub Switch**

- Switch mà broadcast packets tới tất cả port
- Khác từ intelligent switch
- Hệ thống em dùng smart switches (s1-s5) với rules

---

## I

**Instance / Datapath Instance**

- Một kết nối tới một switch
- self.datapaths[dpid] = datapath (instance)
- Dùng để gửi message tới switch

**IPv4**

- Internet Protocol version 4
- Địa chỉ 32-bit (VD: 10.0.1.10)
- Layer 3 (Network layer)

**InfluxDB**

- Time-series database
- Dùng để lưu flow stats history
- Sau đó visualize bằng Grafana

---

## J

**JSON**

- Format dữ liệu (JavaScript Object Notation)
- Dùng trong API requests
- VD: {"dpid": 2, "match": {...}}

---

## K

**Kernel Module**

- OVSKernelSwitch: switch chạy trong kernel
- Hiệu năng cao hơn userspace
- Sử dụng Linux kernel's packet processing

---

## L

**L2 / Layer 2**

- Data Link Layer
- Dùng MAC address
- Switching dựa vào MAC table

**L3 / Layer 3**

- Network Layer
- Dùng IP address
- Routing dựa vào routing table

**L4 / Layer 4**

- Transport Layer
- TCP, UDP protocols

**LLDP (Link Layer Discovery Protocol)**

- Giao thức để discover network topology
- Hệ thống em ignore LLDP packets (return early)

---

## M

**MAC Address**

- Media Access Control address (48-bit)
- VD: 00:00:00:00:00:01
- Dùng trong Ethernet frame header
- Scope: local network segment

**Mininet**

- Network simulator dùng virtual hosts & switches
- Chạy trên 1 máy
- Dùng để test network code trước deploy thực

**Match**

- Điều kiện trong OpenFlow flow rule
- VD: match(eth_type=0x0800, ipv4_src=10.0.1.10)
- Nếu packet match → execute action

**MAIN_DISPATCHER**

- State: switch online & sẵn sàng nhận lệnh
- Dùng trong @set_ev_cls(event, MAIN_DISPATCHER)

---

## N

**Network Prefix**

- Phần đầu của subnet
- VD: 10.0.1.0/24 → prefix là 10.0.1
- Hệ thống em dùng prefix matching: '10.0.1.' → port 1

---

## O

**OpenFlow**

- Giao thức giữa controller & switch
- Cho phép controller điều khiển packet forwarding
- Version: 1.0, 1.3, 1.4, etc

**OpenFlow 1.3**

- Version hiện đại hơn 1.0
- Hỗ trợ IPv6, MPLS, group tables
- Hệ thống em dùng version này

**OVS / OpenVswitch**

- Open Virtual Switch
- Software switch implementation
- Hỗ trợ OpenFlow

---

## P

**Packet-In**

- Event: switch gửi packet tới controller
- Khi packet không match rule nào
- VD: "Em không biết xử lý packet này, thầy ơi!"

**Packet-Out**

- Message: controller gửi packet tới switch
- Để forward packet ra port nào đó

**Port**

- Connection point của switch
- VD: switch s2 có port 1, 2, 3, 4
- Mỗi port nối tới 1 switch/host khác

**Port Stats**

- Thống kê của port
- RX_packets: packet nhận
- TX_packets: packet gửi

**PPS (Packets Per Second)**

- Số packet truyền/giây
- Khác với packets total
- Dùng để detect traffic spike
- Threshold: 1000 PPS → alert

**Priority**

- Độ ưu tiên flow rule
- Range: 0 (thấp nhất) - 65535 (cao nhất)
- Controller check priority cao trước

---

## Q

**QoS (Quality of Service)**

- Đảm bảo chất lượng dịch vụ
- VD: bandwidth guarantee, latency limit
- Hệ thống em không implement QoS

---

## R

**Routing**

- Quyết định đường đi của packet
- Dựa vào destination IP
- VD: packet tới 10.0.2.10 → forward port 2 (s3)

**Routing Table**

- Bảng mapping: IP prefix → port
- VD: '10.0.1.' → port 1
- Hệ thống em dùng prefix matching

**RemoteController**

- Controller chạy ở remote (bên ngoài mininet)
- VD: Ryu controller chạy ở 127.0.0.1:6653
- Mininet kết nối tới nó

---

## S

**Shannon Entropy**

- Khái niệm từ information theory
- Đo độ "disorder" / "randomness"
- Dùng để phát hiện spoofing attacks
- Công thức: H = -Σ(p_i × log₂(p_i)) với p_i = count_i/total

**Source IP**

- IP address của sender
- VD: 10.0.1.10 gửi packet
- Dùng trong match rules để phát hiện attacker

**Spoofing**

- Giả mạo source IP
- VD: packet từ 10.0.1.10 nhưng thực ra từ attacker IP khác
- Entropy cao khi nhiều IP khác nhau

**Subnet**

- Phân chia mạng lớn thành mạng nhỏ
- VD: 10.0.1.0/24 là 1 subnet
- Bao gồm 256 addresses (10.0.1.0 - 10.0.1.255)

**Switch**

- Network device kết nối devices khác
- Forward packet dựa vào MAC/IP
- VD: OVSKernelSwitch trong mininet

---

## T

**Table-Miss**

- Flow rule default (priority=0)
- Match tất cả packets
- Action: gửi packet tới controller
- Dùng để controller thấy tất cả packets

**Thread**

- Process chạy song song
- Hub.spawn(self.\_monitor) → spawn thread monitor
- Không block main thread

**Topology**

- Hình dạng / cấu trúc mạng
- VD: 5 switch + 8 host kết nối sao
- File topology_nhom4.py định nghĩa topology

**Traffic**

- Luồng dữ liệu qua network
- VD: "Traffic từ zone 1 tới zone 2 cao"
- DDoS làm traffic tăng đột ngột

**TTL (Time To Live)**

- Số hop mà packet có thể đi
- Giảm 1 sau mỗi hop
- Khi TTL=0 → drop packet (prevent loop)

---

## U

**UDP (User Datagram Protocol)**

- Transport layer protocol (Layer 4)
- Không connection-oriented (khác TCP)
- File dos_botnet.txt dùng UDP flood
- Nhanh nhưng không reliable

**UDP Flood**

- Tấn công gửi quá nhiều UDP packets
- VD: dos_botnet.txt gửi UDP packets
- Server không thể xử lý → crash

---

## V

**Virtual Network**

- Network chạy trên 1 máy vật lý
- Mininet tạo virtual switches & hosts
- Ưu điểm: dễ test, không cần hardware

---

## W

---

## X

---

## Y

---

## Z

**Zone**

- Phân chia network thành vùng logic
- Zone 1: External (attacker)
- Zone 2: Web/DNS server
- Zone 3: DB/App server
- Zone 4: PCs
- Mỗi zone có subnet riêng

---

## 🔑 FREQUENTLY USED TERMS

| Term                          | Short   | Example                  |
| ----------------------------- | ------- | ------------------------ |
| Packets Per Second            | PPS     | PPS=1500                 |
| Bytes Per Second              | BPS     | BPS=750KB                |
| Internet Protocol v4          | IPv4    | 10.0.1.10                |
| Data Link Layer               | L2      | MAC switching            |
| Network Layer                 | L3      | IP routing               |
| Address Resolution Protocol   | ARP     | resolve IP→MAC           |
| Open Virtual Switch           | OVS     | s1-s5 switches           |
| Network Simulator             | Mininet | virtual topology         |
| Source IP                     | src_ip  | attacker identification  |
| Destination IP                | dst_ip  | target server            |
| Media Access Control          | MAC     | 00:00:00:00:00:01        |
| Software Defined Network      | SDN     | controller+OpenFlow      |
| Distributed Denial of Service | DDoS    | attack from multiple IPs |
| Time To Live                  | TTL     | hop limit                |

---

## 💡 ACRONYM REFERENCE

```
API - Application Programming Interface
ARP - Address Resolution Protocol
BPS - Bytes Per Second
DPID - DataPath ID
DDoS - Distributed Denial of Service
DNS - Domain Name System
OVS - OpenVSwitch
OF - OpenFlow
IP - Internet Protocol
IPv4 - IP version 4
LLDP - Link Layer Discovery Protocol
L2 - Layer 2 (Data Link)
L3 - Layer 3 (Network)
L4 - Layer 4 (Transport)
MAC - Media Access Control
PPS - Packets Per Second
QoS - Quality of Service
SDN - Software Defined Network
TCP - Transmission Control Protocol
TTL - Time To Live
UDP - User Datagram Protocol
```

---

## 🎯 KHI NÀO SỬ DỤNG TỪNG TERM

**Khi nói về cấu trúc:**

- "Topology gồm 5 switches..."
- "Core router (s2) là hub..."

**Khi nói về xử lý gói tin:**

- "Packet-in từ switch"
- "Packet-out từ controller"
- "Match rule trên IPv4"

**Khi nói về DDoS:**

- "PPS tăng từ 100 → 1500"
- "Entropy cao = spoofing"
- "UDP flood attack"

**Khi nói về phòng chống:**

- "Block rule được đặt ở core router"
- "Drop action thay vì forward"
- "Match source IP = attacker"

---

**Happy Learning! 🎓**
