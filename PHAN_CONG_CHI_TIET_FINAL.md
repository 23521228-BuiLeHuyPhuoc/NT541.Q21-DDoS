# PHÂN CÔNG CHI TIẾT V3 FINAL - Phát hiện DoS bằng SDN có cơ sở khoa học

**Đặc điểm V3:**

- ✅ **Kế thừa code**: topology_nhom4.py + l3_router.py (phát triển)
- ✅ **Cơ sở khoa học**: 20-25 papers IEEE/ACM/Springer
- ✅ **Phương pháp cụ thể**: Entropy + Statistical methods (không trùng lặp)
- ✅ **Mitigation nâng cao**: DQoS, traffic shaping, multi-level filtering
- ✅ **Song song hóa**: 3 dòng độc lập (Data, Detection, Mitigation)
- ✅ **Timeline**: 3-4 tuần, 5 người

---

## 📚 PHẦN I: LÝ THUYẾT VÀ CƠ SỞ KHOA HỌC

### 1. GIỚI THIỆU VỀ TẤN CÔNG DoS

**Tham khảo bài báo:**

- A1: Kaur et al. (2012) - Phát hiện dị thường dựa trên entropy
- B1-B3: Các khảo sát DDoS Layer 4/7 (2018-2020)
- C1: Cơ chế bảo vệ SDN chống DDoS

**Nội dung Thành viên 1 cần chuẩn bị:**

```
THEORY_BACKGROUND.md
├── 1. Phân loại tấn công DDoS
│   ├── Layer 4 (Transport): Flood SYN, UDP, ACK, FIN, RST
│   ├── Layer 7 (Application): Flood HTTP, DNS, SMTP
│   ├── Tấn công giả mạo: IP spoofing + phân tích entropy nguồn
│   └── Tấn công tầm thấp: Khó phát hiện (entropy + phân tích thời gian)
│
├── 2. Tại sao dùng Entropy?
│   ├── Entropy Shannon: H(X) = -Σ p(x) log₂(p(x))
│   ├── Lưu lượng bình thường: nguồn đa dạng → entropy ≈ 4-5 bits
│   ├── Tấn công flood: cùng nguồn → entropy ≈ 0-1 bits
│   ├── Tấn công giả mạo: nguồn ngẫu nhiên → entropy ≈ 6-8 bits
│   └── Paper: "Entropy-based Anomaly Detection" (A1)
│
├── 3. Phương pháp thống kê để phát hiện
│   ├── Dị thường tốc độ: (tốc độ_hiện_tại - tốc độ_baseline) / baseline_std > 3σ
│   ├── Tỉ lệ cờ: Lệch SYN%, RST%, ACK%
│   ├── Tăng đột ngột luồng: luồng_mới > baseline * 5
│   └── Paper: "Flow-based Botnet Detection" (A2)
│
└── 4. Mitigation dựa trên SDN
    ├── Bảo vệ phản ứng vs chủ động
    ├── OpenFlow FlowMod: cài đặt quy tắc giới hạn tốc độ
    ├── DQoS: hàng đợi ưu tiên
    ├── Traffic shaping: token bucket, leaky bucket
    └── Paper: "SDN DDoS Detection" (A3)
```

---

### 2. TỔNG QUAN KIẾN TRÚC (Kế thừa Code)

```
TRẠNG THÁI HIỆN TẠI (đã có):
  topology_nhom4.py → 5 switch, 8 host, 4 zone
  l3_router.py      → Ryu L3 router + flow stats + port stats
  l3_router_test.py → Demo với entropy cơ bản

CẦN PHÁT TRIỂN (mục tiêu V3):

  ┌─────────────────────────────────────────────────────────────┐
  │          THÀNH VIÊN 1: Trưởng nghiên cứu                   │
  │  • Xem xét 20-25 papers (IEEE/ACM)                         │
  │  • Viết THEORY_BACKGROUND.md (3000+ từ)                   │
  │  • Liên kết papers với phương pháp phát hiện/mitigation   │
  │  • Định nghĩa chữ ký tấn công từ tài liệu                │
  └─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
  ┌───────▼────────┐  ┌──────▼─────────┐  ┌─────▼───────────┐
  │  THÀNH VIÊN 2  │  │ THÀNH VIÊN 3   │  │ THÀNH VIÊN 4    │
  │   LỚPDATA      │  │ LỚPPHÁT HIỆN   │  │LỚPMITIGATION    │
  │                │  │                │  │                 │
  │ • Tạo 10 loại  │  │ • Trích xuất   │  │ • Ryu l3_router │
  │   DoS          │  │   15+ entropy  │  │   (phát triển)   │
  │ • Trích entropy│  │   stats        │  │ • Thêm DQoS     │
  │ • Capture      │  │ • Khớp chữ ký  │  │ • Traffic shape │
  │   real-time    │  │ • Hệ thống     │  │ • Priority flow │
  │ • Pcap files   │  │   cảnh báo     │  │                 │
  └────────────────┘  └────────────────┘  └─────────────────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
  ┌─────────────────────────────────────────────────────────────┐
  │  THÀNH VIÊN 5: Testing & Integration                        │
  │  • Kết hợp 2+3+4 lại                                        │
  │  • Test toàn bộ: attack → detect → mitigate → measure       │
  │  • Visualization: 8+ biểu đồ                                │
  │  • Live demo: 15-20 phút thuyết trình                       │
  └─────────────────────────────────────────────────────────────┘
```

---

## 📋 PHẦN II: CHI TIẾT PHÂN CÔNG

### 👤 THÀNH VIÊN 1: Ngô Thị Mai Anh (Trưởng nhóm Nghiên cứu)

| STT     | Công việc                          | Tuần | Chi tiết                                                                                                                                                                                                                                                                                      | Deadline   | Sản phẩm                                 | Papers                            |
| ------- | ---------------------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------- | --------------------------------- |
| **1.1** | **Survey Tài liệu (20-25 papers)** | 1    | • NHÓM A (4 papers): Phát hiện entropy<br>• NHÓM B (5 papers): Phương pháp flow + thống kê<br>• NHÓM C (5 papers): Kiến trúc SDN + OpenFlow<br>• NHÓM D (3 papers): Chiến lược mitigation DoS<br>• NHÓM E (4 papers): Hệ thống real-time<br>• Tổ chức: Title, Authors, Year, DOI, Insights    | Hết tuần 1 | `LITERATURE_SURVEY.md` (5000+ từ, IEEE)  | A1-A4, B1-B5, C1-C5, D1-D3, E1-E4 |
| **1.2** | **Khung lý thuyết**                | 1    | • Công thức entropy Shannon + giải thích<br>• Phát hiện dị thường thống kê:<br> - Z-score: (x - mean)/std<br> - Moving average baseline<br> - Ngưỡng độ lệch<br>• Phân loại tấn công DoS (L4/L7, giả mạo, tầm thấp)<br>• Tại sao mỗi phương pháp hoạt động<br>• Tạo cây quyết định            | Hết tuần 1 | `THEORY_BACKGROUND.md` (3000+ từ, sơ đồ) | A1-A3, B1-B3                      |
| **1.3** | **Chữ ký tấn công từ tài liệu**    | 1-2  | • Mapping: Tấn công → Paper → Rule → Thresholds<br> - SYN flood → SYN% > 60%, entropy < 2<br> - UDP flood → pps > 5x baseline<br> - DNS ampl → DNS_resp/DNS_req > 10x<br> - IP spoof → entropy > 6 bits<br> - Low-rate → timing + entropy<br>• Tạo bảng: Tấn công → Paper → Rule → Thresholds | Tuần 2     | `ATTACK_SIGNATURES.md` (1500+ từ, CSV)   | Tất cả nhóm                       |
| **1.4** | **Evaluation Protocol**            | 1-2  | • Định nghĩa metrics với cơ sở papers:<br> - TPR/FPR theo tấn công<br> - Thời gian detect < 3 sec<br> - Hiệu quả mitigation<br>• Dataset test: 70% train, 30% test<br>• Tiêu chí chấp nhận: TPR ≥90%, FPR ≤5%                                                                                 | Hết tuần 2 | `EVALUATION_PROTOCOL.md` (1000+ từ)      | B2, B3, E1                        |
| **1.5** | **Code Review & Giám sát**         | 2-4  | • Tuần 2: Xem xét features TV2, detection TV3, mitigation TV4<br>• Tuần 3: Kiểm chứng độ chính xác vs papers<br>• Tuần 4: Liên kết cuối cùng papers trong code<br>• Đảm bảo tất cả code có citations                                                                                          | Tuần 4     | Weekly logs, code có citations           |                                   |

---

### 👤 THÀNH VIÊN 2: Đỗ Hoàng Phúc (Kỹ sư Data + Lab)

**Tái sử dụng**: topology_nhom4.py (không thay đổi)

| STT     | Công việc                           | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Deadline   | Sản phẩm                                     | Cơ sở Lý thuyết         |
| ------- | ----------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- | -------------------------------------------- | ----------------------- |
| **2.1** | **Kiểm chứng Lab**                  | 1    | • Start topology_nhom4.py<br>• Kiểm chứng: 5 switch online, 8 host kết nối<br>• Test connectivity: mỗi host ping được nhau<br>• Setup monitoring: tcpdump trên s2                                                                                                                                                                                                                                                                                                                                                                                                                                | Hết tuần 1 | Lab chạy, tcpdump sẵn                        | -                       |
| **2.2** | **Thu thập Lưu lượng Baseline**     | 1-2  | • Lưu lượng bình thường: 5 phút<br> - h_pc1 → h_web1: HTTP (Apache Bench)<br> - h_pc1 → h_dns1: DNS queries (dig)<br> - h_pc1 → h_app1: Kết nối TCP<br>• Capture: flows.pcap<br>• Extract: baseline_stats.json                                                                                                                                                                                                                                                                                                                                                                                   | Hết tuần 2 | `flows_baseline.pcap`, `baseline_stats.json` | B1: Flow-based          |
| **2.3** | **Tạo 10 kịch bản DoS (KHÁC NHAU)** | 2    | **Layer 4 Floods (3):**<br>1. SYN Flood: hping3 -S --flood, entropy <1 bit<br>2. UDP Flood: 5k+ pps, entropy signature khác<br>3. ACK+RST Flood: >30% RST packets (vs <5%)<br><br>**Layer 7 Floods (3):**<br>4. HTTP GET: 500+ req/sec, kết nối established<br>5. HTTP POST: Thân lớn, test traffic shaping<br>6. DNS Amplification: DNS_resp >> DNS_req (10x)<br><br>**Giả mạo + Tầm thấp (4):**<br>7. IP Spoof: Random src IPs, entropy >6 bits<br>8. Low-Rate: 1 req/sec 10 phút (stealthy)<br>9. Distributed: Multi-source (h_att1+h_ext1)<br>10. Port Scan+Flood: Reconnaissance rồi attack | Hết tuần 2 | `dos_*.pcap` (10 file, gắn nhãn)             | A1, B2, C1, E1          |
| **2.4** | **Pipeline Trích xuất Features**    | 2-3  | • Parse mỗi pcap (baseline + 10 DoS)<br>• Trích xuất mỗi 1 giây:<br> - entropy src/dst IP (công thức A1)<br> - pps, bps, SYN%/RST%/ACK%<br> - unique src/dst IPs, new flows/sec<br> - std packet size<br>• Output CSV với tất cả metrics                                                                                                                                                                                                                                                                                                                                                         | Hết tuần 3 | `feature_extraction.py` (200 dòng), 11 CSV   | B1: Feature engineering |
| **2.5** | **Setup Capture Real-time**         | 3    | • Script capture live trên s2<br>• Rolling pcap files (1 per phút)<br>• Sẵn cho TV4 real-time demo                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Tuần 3     | `capture_live.sh`, demo_setup.sh             | -                       |

---

### 👤 THÀNH VIÊN 3: Bùi Lê Huy Phước (Kỹ sư Phát hiện)

**Phát triển**: l3_router.py (thêm module detection)

| STT | Công việc                   | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Deadline   | Sản phẩm                                | Cơ sở lý thuyết  |
| --- | --------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | --------------------------------------- | ---------------- |
| 3.1 | Module Phát hiện Entropy    | 2    | • Xây dựng trên l3_router.py stats <br> • Mỗi 1 giây tính: <br> - H_src = Shannon entropy src IPs <br> - H_dst = Shannon entropy dst ports <br> - H_ttl = TTL entropy <br> - H_pkt_size = packet size entropy <br><br> • So sánh ngưỡng baseline: <br> - SYN flood: H_src < 1 bit → cảnh báo <br> - IP spoof: H_src > 6 bits → cảnh báo <br><br> • Cảnh báo nếu bất thường 2+ giây liên tiếp                                                                                                                                                                      | Hết tuần 2 | detection_entropy.py (150 dòng)         | A1: Kaur entropy |
| 3.2 | Module Phát hiện Thống kê   | 2    | • Tính mỗi 1 giây: <br> - rate_current, rate_baseline, rate_std <br> - z_score = (rate_current - baseline) / std <br><br> • Quy tắc cảnh báo: <br> - Z > 3: Dị thường traffic cao <br> - Spike: rate > 5x baseline <br> - Tăng luồng: new_conns > 3x baseline <br> - Tỉ lệ cờ bất thường: \|SYN% - baseline\| > 20% <br> - RST% bất thường: \|RST% - baseline\| > 15% <br><br> • Cảnh báo nếu trigger 3+ giây                                                                                                                                                     | Hết tuần 2 | detection_stats.py (150 dòng)           | B2, B3           |
| 3.3 | Khớp Chữ ký Tấn công        | 2-3  | • Triển khai quy tắc: <br><br> SYN Flood: <br> IF (entropy_src < 1.5 AND syn_pct > 50%) → SYN_FLOOD <br><br> UDP Flood: <br> IF (pps > 5x AND pkt_size_std < 10) → UDP_FLOOD <br><br> HTTP Flood: <br> IF (http_req_rate > 100/s AND entropy normal) → HTTP_FLOOD <br><br> DNS Amplification: <br> IF (dns_resp >> dns_req AND entropy_dst high) → DNS_AMPL <br><br> IP Spoofing: <br> IF (entropy_src > 6.5 AND pps high) → IP_SPOOF <br><br> Low-rate DoS: <br> IF (pps normal BUT entropy_src < 2) → LOW_RATE <br><br> • Có confidence score (HIGH/MEDIUM/LOW) | Tuần 3     | attack_signature_matching.py (200 dòng) | Tất cả           |
| 3.4 | Hệ thống Cảnh báo Real-time | 3    | • Lắng nghe pcap/stats từ TV2 <br> • Tạo cảnh báo (JSON): <br> {timestamp, attack_type, confidence, src_ip, dst_ip, dst_port, metrics, mitigation_action} <br> • Log: alerts.json <br> • Gửi đến TV4                                                                                                                                                                                                                                                                                                                                                              | Tuần 3     | alert_system.py (100 dòng), alerts.json | -                |

---

### 👤 THÀNH VIÊN 4: Phạm Ngọc Trúc Quỳnh (Kỹ sư SDN Mitigation)

**Phát triển**: l3_router.py (thêm mitigation app)

| STT     | Công việc                             | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Deadline   | Sản phẩm                              | Cơ sở Lý thuyết  |
| ------- | ------------------------------------- | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------- | ---------------- |
| **4.1** | **Phát triển Ryu với Chặn Cơ bản**    | 1-2  | • Bắt đầu từ l3_router.py<br>• Thêm method: `block_source_ip(src_ip)`<br>• Cài đặt quy tắc DROP trên tất cả switches:<br> - match: ipv4_src=src_ip<br> - action: DROP<br> - priority: 100<br>• Test: SYN flood detect → rule → traffic drop<br>• Đo latency: cảnh báo đến drop (mục tiêu: <100ms)                                                                                                                                                                                | Hết tuần 2 | Mở rộng l3_router.py với blocking     | C1: OpenFlow     |
| **4.2** | **Giới hạn Tốc độ dùng Token Bucket** | 2    | • Triển khai giới hạn tốc độ per src IP<br>• Token bucket:<br> - Rate: R tokens/sec<br> - Bucket: B tokens<br> - Nếu tokens >= pkt_size → forward; else DROP<br>• OpenFlow METER tables (v1.3):<br> - Tạo meter: max_rate=1000pps per src<br> - Install rule: match src_ip, meter<br>• Cấu hình per tấn công:<br> - SYN flood: 100 pps<br> - UDP flood: 200 pps<br> - HTTP flood: 50 req/sec                                                                                     | Hết tuần 2 | `mitigation_rate_limit.py` (150 dòng) | D1: Token bucket |
| **4.3** | **DQoS + Traffic Shaping**            | 2-3  | • Triển khai Quality of Service<br>• Classes:<br> - Ưu tiên 1 (cao): DNS, Critical → không throttle<br> - Ưu tiên 2 (trung): Normal → throttle nhẹ<br> - Ưu tiên 3 (thấp): Attack → throttle mạnh<br>• OpenFlow DSCP tagging:<br> - Traffic ưu tiên 3: DSCP=8<br> - Queue rules: per DSCP value<br> - Bandwidth: P1=50%, P2=30%, P3=20%<br>• Multi-level filtering:<br> - L1: Gói đầu → Ưu tiên 3<br> - L2: Nếu whitelist → Ưu tiên 1<br> - L3: Nếu legit protocol → Ưu tiên 1-2 | Tuần 3     | `mitigation_dqos.py` (200 dòng)       | D2, D3           |
| **4.4** | **Quản lý Blacklist/Whitelist**       | 3    | • Blacklist động từ cảnh báo TV3<br>• Subscribe alert system:<br> `python<br>  def receive_alert(alert_msg):<br>      if alert_msg.confidence == "HIGH":<br>          add_to_blacklist(alert_msg.src_ip)<br>          install_drop_rule(alert_msg.src_ip)<br>  `<br>• Whitelist: IP tin cậy định sẵn<br>• Auto-recovery: xóa sau 5 phút<br>• Log: mitigation_actions.json                                                                                                        | Tuần 3     | `mitigation_blacklist.py` (100 dòng)  | C1               |
| **4.5** | **Benchmarking Hiệu suất**            | 3    | • Đo latency Ryu:<br> - Rule install: time(alert) → time(installed)<br> - Mục tiêu: <100ms<br> - Throughput: >1Gbps với rules<br>• Load test: 1000 rules, đo CPU/mem<br>• Plot: rules vs latency, rules vs CPU                                                                                                                                                                                                                                                                   | Tuần 3     | `benchmark_mitigation.py` (100 dòng)  | C3               |

---

### 👤 THÀNH VIÊN 5: Phạm Nguyễn Tấn Sang (Testing + Integration + Demo)

| STT     | Công việc                            | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Deadline   | Sản phẩm                                            | Cơ sở Lý thuyết |
| ------- | ------------------------------------ | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | --------------------------------------------------- | --------------- |
| **5.1** | **Testing Toàn bộ Hệ thống**         | 3    | Với mỗi 10 DoS + baseline:<br>1. Start topology<br>2. Chạy Ryu + detection (TV3) + mitigation (TV4)<br>3. Tạo traffic tấn công (TV2)<br>4. Đo: detection latency, mitigation latency, hiệu quả<br>5. Kiểm chứng: metrics match papers<br><br>**Test per tấn công:**<br>- Test_001: SYN flood latency ≤ 3s<br>- Test_002: UDP detection TPR ≥ 90%<br>- Test_003: HTTP FPR ≤ 5%<br>- Test_004-010: Loại DoS khác<br>- Test_011: Baseline FPR = 0<br><br>**Results JSON:** test_results.json<br>**Failures:** Root cause, bug report                                                                                                                                                                                         | Hết tuần 3 | `integration_test.py` (300 dòng), test_results.json | Tất cả          |
| **5.2** | **Visualization & Phân tích**        | 3    | **Biểu đồ 1: Timeline Phát hiện**<br> - X: Thời gian, Y: Metrics<br> - Show: baseline (xanh), attack (đỏ), alert (chấm)<br><br>**Biểu đồ 2: Chữ ký Entropy per Tấn công**<br> - 10 subplot, entropy theo thời gian<br><br>**Biểu đồ 3: Độ chính xác Phát hiện (Bar)**<br> - X: Loại tấn công, Y: TPR/FPR<br><br>**Biểu đồ 4: Latency Phát hiện (Box plot)**<br> - Phân bố qua loại tấn công<br><br>**Biểu đồ 5: Hiệu quả Mitigation**<br> - Before/after traffic volume<br><br>**Biểu đồ 6: Latency Ryu (Histogram)**<br> - Phân bố rule install latency<br><br>**Biểu đồ 7: Traffic Patterns (Stacked Area)**<br> - Normal vs SYN vs HTTP<br><br>**Biểu đồ 8: FPR vs Threshold Trade-off**<br> - Tìm điểm Youden optimal | Tuần 3     | `visualization.py` (300 dòng), 8 PNG plots          | E2              |
| **5.3** | **Live Demo (15-20 phút)**           | 3-4  | **Flow:**<br>[0-1p] Lab topology diagram<br>[1-2p] Start Mininet + Ryu<br>[2-3p] Show baseline traffic<br>[3-7p] SYN flood attack demo<br> - Show: attacker sends packets<br> - Show: Ryu detect entropy anomaly<br> - Show: Mitigation rule installed<br> - Show: Attack dropped<br>[7-12p] HTTP flood attack demo<br> - Detection khác (rate-based)<br> - Mitigation khác (rate limit)<br>[12-15p] Show plots + metrics<br>[15-20p] Q&A<br><br>**Fallback:** Video demo được quay sẵn                                                                                                                                                                                                                                   | Tuần 4     | `demo.sh`, live hoặc demo.mp4                       | -               |
| **5.4** | **Thuyết trình Cuối (12-15 slides)** | 4    | Slide 1: Title + Team<br>Slides 2-3: Problem + DDoS threat<br>Slides 4-5: Related work (5 papers chính)<br>Slides 6-7: Architecture (Mininet + Ryu + layers)<br>Slides 8-9: Theory (entropy, statistics)<br>Slides 10-12: Results (3 ví dụ tấn công)<br>Slide 13: Demo walkthrough<br>Slide 14: Conclusions & limitations<br>Slide 15: Future work<br><br>**Q&A Script:** 15+ câu hỏi + câu trả lời<br>- "Entropy threshold chọn như thế nào?" → từ A1 + baseline<br>- "Tại sao không dùng ML?" → đơn giản, paper-proven, real-time<br>- "FPR là bao nhiêu?" → <5% vs B3 benchmark                                                                                                                                        | Tuần 4     | `PRESENTATION.pptx` (15 slides), `QA_SCRIPT.md`     | -               |
| **5.5** | **Documentation & GitHub Cuối**      | 4    | • `README.md`: Quick start, cấu trúc<br>• `INSTALL.md`: Phụ thuộc, setup<br>• `QUICKSTART.md`: Chạy trong 5 phút<br>• `RESULTS.md`: Tóm tắt vs papers<br>• `TROUBLESHOOTING.md`: Issues + fixes<br><br>**GitHub cấu trúc:**<br>`<br>docs/  → markdown files + papers<br>code/  → Python scripts<br>data/  → pcap, CSV, stats<br>results/ → plots, benchmarks<br>`<br><br>• Code: docstrings với citations, type hints<br>• Tag: v1.0-final                                                                                                                                                                                                                                                                                | Tuần 4     | GitHub sạch, tất cả docs                            | -               |

---

## 📅 LỊCH TRÌNH CHI TIẾT: THỨ TỰ LÀM VIỆC & DEPENDENCIES

### TUẦN 1: Chuẩn bị & Đọc hiểu

| STT         | Công việc                   | Thành viên | Bắt đầu   | Kết thúc  | Ưu tiên      | Phụ thuộc vào | Ghi chú               |
| ----------- | --------------------------- | ---------- | --------- | --------- | ------------ | ------------- | --------------------- |
| 1.1         | Survey 20-25 papers         | TV1        | T1 Ngày 1 | T1 Ngày 5 | **CRITICAL** | Không         | Input cho tất cả      |
| 1.2         | Khung lý thuyết             | TV1        | T1 Ngày 2 | T1 Ngày 5 | **CRITICAL** | 1.1           | Định nghĩa quy tắc    |
| 2.1         | Kiểm chứng Lab              | TV2        | T1 Ngày 1 | T1 Ngày 3 | **CRITICAL** | Không         | Cơ sở cho tất cả data |
| 2.2 (start) | Thu thập Lưu lượng Baseline | TV2        | T1 Ngày 3 | T2 Ngày 2 | High         | 2.1           | Parallel với TV3, TV4 |
| 3.0         | Xem papers phát hiện        | TV3        | T1 Ngày 1 | T1 Ngày 3 | High         | 1.1           | Chuẩn bị ý tưởng      |
| 4.0         | Xem Ryu + OpenFlow          | TV4        | T1 Ngày 1 | T1 Ngày 3 | High         | Không         | Học tập tổng quát     |
| 5.0         | Setup test framework        | TV5        | T1 Ngày 1 | T1 Ngày 5 | Medium       | Không         | Sẵn cho integration   |

### TUẦN 2: Phát triển SONG SONG (3 dòng độc lập)

| STT                 | Công việc                | Thành viên | Bắt đầu   | Kết thúc  | Ưu tiên      | Phụ thuộc vào | Ghi chú                |
| ------------------- | ------------------------ | ---------- | --------- | --------- | ------------ | ------------- | ---------------------- |
| **DÒA: DATA**       |                          |            |           |           |              |               |                        |
| 2.2 (tiếp)          | Thu thập Baseline (tiếp) | TV2        | T2 Ngày 1 | T2 Ngày 2 | High         | 2.1           | Xong baseline          |
| 2.3                 | Tạo 10 DoS attack        | TV2        | T2 Ngày 2 | T2 Ngày 5 | **CRITICAL** | 1.2           | Input cho TV3, TV5     |
| 2.4 (start)         | Trích xuất Features      | TV2        | T2 Ngày 4 | T3 Ngày 3 | High         | 2.3           | Extract metrics        |
| **DÒB: DETECTION**  |                          |            |           |           |              |               |                        |
| 3.1                 | Module Entropy           | TV3        | T2 Ngày 1 | T2 Ngày 4 | **CRITICAL** | 1.2           | Song song với DÒA      |
| 3.2                 | Module Statistics        | TV3        | T2 Ngày 2 | T2 Ngày 4 | **CRITICAL** | 1.2           | Song song với DÒA      |
| **DÒC: MITIGATION** |                          |            |           |           |              |               |                        |
| 4.1                 | Ryu Blocking             | TV4        | T2 Ngày 1 | T2 Ngày 4 | **CRITICAL** | 1.2           | Song parallel TV2, TV3 |
| 4.2                 | Rate Limit Token Bucket  | TV4        | T2 Ngày 3 | T2 Ngày 5 | High         | 4.1           | Extend Ryu             |
| **DÒD: RESEARCH**   |                          |            |           |           |              |               |                        |
| 1.3                 | Chữ ký tấn công          | TV1        | T2 Ngày 1 | T2 Ngày 5 | High         | 1.2           | Cho TV3 matching       |
| 1.4                 | Evaluation Protocol      | TV1        | T2 Ngày 3 | T2 Ngày 5 | Medium       | 1.2           | Tiêu chí test          |
| **DÒE: SUPPORT**    |                          |            |           |           |              |               |                        |
| 5.0 (tiếp)          | Refine test framework    | TV5        | T2 Ngày 1 | T2 Ngày 5 | Medium       | 5.0           | Sẵn cho tuần 3         |

### TUẦN 3: Integration & Testing

| STT        | Công việc                  | Thành viên | Bắt đầu   | Kết thúc  | Ưu tiên      | Phụ thuộc vào    | Ghi chú                 |
| ---------- | -------------------------- | ---------- | --------- | --------- | ------------ | ---------------- | ----------------------- |
| 2.4 (tiếp) | Trích xuất Features (tiếp) | TV2        | T3 Ngày 1 | T3 Ngày 2 | High         | 2.3              | Xong 11 CSV             |
| 2.5        | Setup Real-time Capture    | TV2        | T3 Ngày 2 | T3 Ngày 3 | Medium       | 2.4              | Demo sẵn                |
| 3.3        | Signature Matching         | TV3        | T3 Ngày 1 | T3 Ngày 3 | **CRITICAL** | 1.3, 3.1, 3.2    | Kết hợp entropy + stats |
| 3.4        | Alert System               | TV3        | T3 Ngày 2 | T3 Ngày 4 | **CRITICAL** | 3.3              | Input cho TV4           |
| 4.3        | DQoS + Shaping             | TV4        | T3 Ngày 1 | T3 Ngày 4 | High         | 4.2, 1.3         | Extend mitigation       |
| 4.4        | Blacklist/Whitelist        | TV4        | T3 Ngày 3 | T3 Ngày 4 | High         | 3.4, 4.3         | Subscribe alerts        |
| 4.5        | Benchmarking               | TV4        | T3 Ngày 4 | T3 Ngày 5 | Medium       | 4.1-4.4          | Đo performance          |
| 5.1        | Integration Testing        | TV5        | T3 Ngày 2 | T3 Ngày 5 | **CRITICAL** | 2.4, 3.4, 4.4    | End-to-end test         |
| 5.2        | Visualization              | TV5        | T3 Ngày 3 | T3 Ngày 5 | High         | 5.1              | 8 biểu đồ               |
| 1.5        | Code Review                | TV1        | T3 Ngày 1 | T3 Ngày 5 | Medium       | 3.3-3.4, 4.1-4.4 | Kiểm citations          |

### TUẦN 4: Demo & Finalization

| STT        | Công việc            | Thành viên      | Bắt đầu   | Kết thúc  | Ưu tiên      | Phụ thuộc vào | Ghi chú         |
| ---------- | -------------------- | --------------- | --------- | --------- | ------------ | ------------- | --------------- |
| 5.3        | Live Demo (Rehearse) | TV2,TV3,TV4,TV5 | T4 Ngày 1 | T4 Ngày 3 | **CRITICAL** | 4.5, 5.2      | Demo chạy       |
| 5.4        | Thuyết trình + Q&A   | TV1,TV5         | T4 Ngày 1 | T4 Ngày 3 | **CRITICAL** | 5.2, 1.5      | Slides + script |
| 5.5        | Docs + GitHub Final  | TV5 + Tất cả    | T4 Ngày 2 | T4 Ngày 4 | High         | 5.1           | Push v1.0-final |
| 1.5 (tiếp) | Báo cáo cuối         | TV1             | T4 Ngày 1 | T4 Ngày 4 | Medium       | 1.3-1.4, 5.1  | Tổng kết        |

---

## 📊 MA TRẬN SONG SONG HÓA

| Tuần  | TV1 (Lý thuyết)     | TV2 (Data)                          | TV3 (Phát hiện)                     | TV4 (Mitigation)                      | TV5 (Testing)                      |
| ----- | ------------------- | ----------------------------------- | ----------------------------------- | ------------------------------------- | ---------------------------------- |
| **1** | Survey 20-25 papers | Lab setup                           | Xem papers phát hiện                | Xem Ryu + OpenFlow                    | Setup test framework               |
| **2** | Lý thuyết + chữ ký  | Tạo 10 DoS + features **SONG SONG** | Build entropy + stats **SONG SONG** | Build rate limit + DQoS **SONG SONG** | Sẵn integrate                      |
| **3** | Code review         | Fine-tune + live capture            | Signatures + alerts                 | Benchmarking + rules                  | Integration + visualization + demo |
| **4** | Báo cáo cuối        | Xong                                | Xong                                | Xong                                  | Live presentation + docs           |

**Cơ hội Song song:**

- **Tuần 2:** TV2, TV3, TV4 làm hoàn toàn độc lập (chỉ TV1 là input)
- **Tuần 3:** Integration (TV3→TV4 via alerts, TV2→TV5 via features)
- **Tuần 4:** Tất cả hội tụ cho demo + docs

---

## ✅ TIÊU CHÍ THÀNH CÔNG

| Tiêu chí                   | Mục tiêu                | Người phụ trách    | Paper Ref |
| -------------------------- | ----------------------- | ------------------ | --------- |
| **Độ chính xác Phát hiện** | TPR ≥90%, FPR ≤5%       | TV3, TV5           | B2, B3    |
| **Tốc độ Phát hiện**       | Cảnh báo ≤3 giây        | TV3, TV5           | E1        |
| **Tốc độ Mitigation**      | Rule install <100ms     | TV4, TV5           | C1        |
| **Bao phủ Tấn công**       | Tất cả 10 loại detect   | TV3, TV5           | TV1 sigs  |
| **Ổn định Baseline**       | FPR=0 trên normal       | TV3, TV5           | B1        |
| **Chất lượng Code**        | 100+ dòng/module, cited | Tất cả             | -         |
| **Live Demo**              | 15-20 phút chạy         | TV5, TV2, TV3, TV4 | -         |
| **Cơ sở Khoa học**         | Liên kết 20-25 papers   | TV1, Tất cả        | -         |

---

## 📁 CẤU TRÚC OUTPUT MONG ĐỢI

```
NT541.Q21-DDoS/
├── docs/
│   ├── LITERATURE_SURVEY.md
│   ├── THEORY_BACKGROUND.md
│   ├── ATTACK_SIGNATURES.md
│   ├── EVALUATION_PROTOCOL.md
│   ├── README.md
│   ├── INSTALL.md
│   ├── QUICKSTART.md
│   ├── RESULTS.md
│   └── TROUBLESHOOTING.md
├── code/
│   ├── topology_nhom4.py (có)
│   ├── l3_router.py (có)
│   ├── l3_router_extended.py (TV4)
│   ├── detection_entropy.py (TV3)
│   ├── detection_stats.py (TV3)
│   ├── attack_signature_matching.py (TV3)
│   ├── alert_system.py (TV3)
│   ├── mitigation_rate_limit.py (TV4)
│   ├── mitigation_dqos.py (TV4)
│   ├── mitigation_blacklist.py (TV4)
│   ├── benchmark_mitigation.py (TV4)
│   ├── feature_extraction.py (TV2)
│   ├── integration_test.py (TV5)
│   ├── visualization.py (TV5)
│   ├── demo.sh (TV5)
│   └── capture_live.sh (TV2)
├── data/
│   ├── flows_baseline.pcap (TV2)
│   ├── baseline_stats.json (TV2)
│   ├── dos_*.pcap (TV2, 10 file)
│   ├── features_*.csv (TV2, 11 file)
│   └── attacks_metadata.json
├── results/
│   ├── test_results.json
│   ├── alerts.json
│   ├── mitigation_actions.json
│   ├── benchmark_results.json
│   └── plots/ (8 PNG file)
├── PRESENTATION.pptx
├── QA_SCRIPT.md
├── .gitignore
└── requirements.txt
```

---

## 📝 CÁC CUỘC HỌP CHECKPOINT HÀNG TUẦN

### Tuần 1 - Khởi động

- [ ] TV1: Papers tổ chức, lý thuyết tài liệu
- [ ] TV2: Lab chạy, baseline captured
- [ ] TV3: Công thức entropy coded, test
- [ ] TV4: Ryu basic blocking chạy
- [ ] TV5: Test framework sẵn

### Tuần 2 - Sprint Triển khai

- [ ] TV2: Tất cả 10 DoS + features extracted
- [ ] TV3: Detect tất cả 10 loại trên data TV2
- [ ] TV4: Rate limit + DQoS triển khai
- [ ] TV1: Chữ ký tấn công + liên kết papers
- [ ] TV5: Sẵn để integration

### Tuần 3 - Integration & Prep Demo

- [ ] TV5: End-to-end tests passing
- [ ] TV5: Visualization complete, demo script chạy
- [ ] Tất cả: Code reviewed, citations added
- [ ] Tất cả: GitHub sạch sẽ

### Tuần 4 - Cuối cùng

- [ ] Live demo rehearsed
- [ ] Presentation sẵn
- [ ] Tất cả docs complete
- [ ] GitHub tagged v1.0-final

---

## 🎯 CÁC KHÁC BIỆT CHÍNH SO VỚI V2

| Khía cạnh         | V2             | V3                                        |
| ----------------- | -------------- | ----------------------------------------- |
| Cơ sở code        | Từ đầu         | **Kế thừa + phát triển**                  |
| Papers            | ~15 vague      | **20-25 cụ thể**, cited                   |
| Kịch bản tấn công | 10 chung chung | **10 duy nhất**, khác biệt                |
| Phát hiện         | Entropy        | **Entropy + Statistical**                 |
| Mitigation        | Drop đơn giản  | **DQoS + Shaping + Multi-level**          |
| Lý thuyết         | Yếu            | **THEORY_BACKGROUND + ATTACK_SIGNATURES** |
| Song song         | Lỏng lẻo       | **Ma trận chặt**: W2 fully parallel       |

---

## 📚 PAPERS TÂM CHIẾU THEO NHÓM

- **NHÓM A (4)**: Phát hiện entropy (A1-A4)
- **NHÓM B (5)**: Flow-based + statistical (B1-B5)
- **NHÓM C (5)**: Kiến trúc SDN + OpenFlow (C1-C5)
- **NHÓM D (3)**: Mitigation DoS (D1-D3)
- **NHÓM E (4)**: Hệ thống real-time (E1-E4)

_Chi tiết trong LITERATURE_SURVEY.md của TV1_
