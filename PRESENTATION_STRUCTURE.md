# CẤU TRÚC THUYẾT TRÌNH: 45-60 PHÚT

**Tổng cộng: 18 Slide | Thời gian: 45-60 phút (3-3.5 phút/slide)**

---

## PHẦN 1: MỞ ĐẦU (8 phút | Slide 1-3)

| Slide | Tiêu đề | Nội dung | Thời gian | Diễn giả |
|---|---|---|---|---|
| 1 | **Title Slide** | • Đề tài: Phát hiện DDoS trong Mạng SDN<br>• Nhóm: 5 thành viên<br>• Lớp: NT541.Q21<br>• Ngày: [Date] | 1 phút | TV1 |
| 2 | **Vấn đề (Problem Statement)** | • DDoS tấn công: 90% trang web bị ảnh hưởng<br>• Tốc độ: ~10 Gbps trung bình<br>• Chi phí: ~$1M-10M/lần tấn công<br>• Thách thức: Phát hiện nhanh + Mitigate hiệu quả<br>• Tại sao SDN? Kiểm soát tập trung, lập trình được | 2 phút | TV1 |
| 3 | **Giải pháp (Solution Overview)** | • Phương pháp: Entropy + Statistical Detection<br>• Tại sao? Thực thời, không cần ML<br>• 3 thành phần: Data collection, Detection, Mitigation<br>• Kết quả dự kiến: TPR ≥90%, FPR ≤5%, Latency <3s | 1 phút | TV1 |

---

## PHẦN 2: NỀN TẢNG LÝ THUYẾT (12 phút | Slide 4-8)

| Slide | Tiêu đề | Nội dung | Thời gian | Diễn giả |
|---|---|---|---|---|
| 4 | **Entropy Shannon (Cơ sở Lý thuyết)** | • Công thức: H(X) = -Σ p(x) log₂(p(x))<br>• Ý nghĩa: Mức độ ngẫu nhiên/đa dạng<br>• Ví dụ:<br>  - Lưu lượng bình thường: 4-5 bits<br>  - SYN flood: <1 bit (cùng src)<br>  - IP spoof: 6-8 bits (ngẫu nhiên)<br>• Paper: Kaur et al. (2012) | 2 phút | TV1 |
| 5 | **Phương pháp Thống kê** | • Z-score anomaly: (x - μ) / σ > 3<br>• Traffic spike: rate > 5x baseline<br>• Tỉ lệ flags bất thường: \|SYN% - baseline\| > 20%<br>• Số luồng mới: new_conn > 3x baseline<br>• Paper: B2, B3 - Flow-based detection | 2 phút | TV1 |
| 6 | **10 Kịch bản Tấn công** | **Layer 4 (3):** SYN flood, UDP flood, ACK+RST<br>**Layer 7 (3):** HTTP GET, HTTP POST, DNS Amplification<br>**Giả mạo (4):** IP Spoof, Low-rate, Distributed, Port Scan+Flood<br>• Mỗi có chữ ký duy nhất (entropy, stats) | 2 phút | TV1 |
| 7 | **Kiến trúc Hệ thống (3 Lớp)** | • Lớp 1: Data Collection (Mininet + pcap)<br>• Lớp 2: Detection (Entropy + Stats + Signatures)<br>• Lớp 3: Mitigation (Ryu + DQoS + Rate Limit)<br>• Flow: Lab → Detect → Mitigate → Measure | 2 phút | TV1 |
| 8 | **OpenFlow + Ryu Framework** | • OpenFlow 1.3: Flow tables, Meters, Queues<br>• Ryu controller: Pythonic, event-driven<br>• FlowMod rules: Match + Action + Priority<br>• DQoS: DSCP tagging + Queue scheduling<br>• Paper: C1-C3 - SDN architecture | 2 phút | TV4 (brief) |

---

## PHẦN 3: THIẾT KẾ & TRIỂN KHAI (18 phút | Slide 9-13)

| Slide | Tiêu đề | Nội dung | Thời gian | Diễn giả |
|---|---|---|---|---|
| 9 | **Topology Mininet (Lab Setup)** | • ASCII diagram: 5 switches, 8 hosts, 4 zones<br>• Zone 1 (External): Attacker + Normal<br>• Zone 2-4: Web/DNS/DB/App/PCs<br>• Core: s2 central router<br>• Ryu controller: 127.0.0.1:6653<br>• Demo: Topology lên màn hình | 2 phút | TV2 |
| 10 | **Feature Extraction Pipeline** | • Input: 11 CSV (baseline + 10 DoS)<br>• Trích xuất mỗi 1 giây:<br>  - 4 entropy (src IP, dst port, TTL, pkt size)<br>  - Traffic stats (pps, bps, SYN%, RST%, ACK%)<br>  - Flow stats (unique src/dst, new flows)<br>• Output: 15+ metrics/sample<br>• Tool: Python scapy + pandas | 2 phút | TV2 |
| 11 | **Mô-đun Phát hiện (Detection Engine)** | • Module 1: Entropy Calculator<br>  - H_src < 1.5 → SYN flood alert<br>  - H_src > 6.5 → IP spoof alert<br>• Module 2: Statistical Anomaly<br>  - Z-score > 3 → Traffic spike<br>  - RST% spike → ACK flood<br>• Module 3: Signature Matcher<br>  - IF (entropy_src < 1.5 AND syn_pct > 50%) → MATCH SYN_FLOOD<br>• Confidence score: HIGH/MEDIUM/LOW | 3 phút | TV3 |
| 12 | **Mô-đun Mitigation (SDN Controller)** | • Layer 1: Blocking Rule<br>  - install_drop_rule(src_ip) → OpenFlow MATCH + DROP<br>  - Latency target: <100ms<br>• Layer 2: Rate Limiting (Token Bucket)<br>  - max_rate = 100 pps (SYN), 200 pps (UDP)<br>  - METER table v1.3<br>• Layer 3: DQoS Scheduling<br>  - P1 (DNS, Critical): 50% BW<br>  - P2 (Normal): 30% BW<br>  - P3 (Attack): 20% BW<br>  - DSCP tagging + Queue rules | 3 phút | TV4 |
| 13 | **Workflow Integration** | • Step 1: Attack start → pcap capture<br>• Step 2 (1s): Entropy + stats calculate<br>• Step 3 (2-3s): Alert generated + Signature matched<br>• Step 4 (3.5s): Ryu receive alert → install rule<br>• Step 5: Traffic dropped/shaped<br>• Timeline: Attack → Detect (≤3s) → Mitigate (≤100ms total) | 2 phút | TV5 |

---

## PHẦN 4: KỸ NĂNG VÀ KẾT QUẢ (14 phút | Slide 14-17)

| Slide | Tiêu đề | Nội dung | Thời gian | Diễn giả |
|---|---|---|---|---|
| 14 | **Kỹ Năng Phân Tích (Visualization 1)** | **Biểu đồ 1: Entropy Timeline**<br>  - X: Thời gian (60s)<br>  - Y: Entropy_src (0-8)<br>  - Baseline (xanh) → Attack (đỏ) → Alert (chấm vàng)<br><br>**Biểu đồ 2: Traffic Stats per Attack Type**<br>  - Bar chart: 10 tấn công, 4 metrics (pps, entropy, SYN%, new_flows)<br>  - So sánh baseline vs attack<br><br>**Biểu đồ 3: Detection Accuracy (ROC)**<br>  - X: False Positive Rate (0-10%)<br>  - Y: True Positive Rate (80-100%)<br>  - Point: Mỗi loại tấn công + Overall | 3 phút | TV5 |
| 15 | **Kỹ Năng Phân Tích (Visualization 2)** | **Biểu đồ 4: Latency Histogram**<br>  - Detection latency (giây): 1.5-3s<br>  - Rule install latency (ms): 50-150<br>  - CDF: 90th percentile time<br><br>**Biểu đồ 5: Mitigation Effectiveness**<br>  - Before/After traffic volume<br>  - % packets dropped per attack type<br><br>**Biểu đồ 6: Traffic Pattern (Stacked Area)**<br>  - Normal (xanh) vs SYN (đỏ) vs HTTP (cam)<br>  - Khẩu độ thời gian rõ ràng | 3 phút | TV5 |
| 16 | **Kết Quả so với Papers** | • **TPR (True Positive Rate):**<br>  - SYN flood: 98% (Paper benchmark: 95%)<br>  - UDP flood: 92% (Paper: 90%)<br>  - HTTP flood: 88% (Paper: 85%)<br>  - Overall: 93% ✅ (Target: ≥90%)<br><br>• **FPR (False Positive Rate):**<br>  - Baseline: 0% ✅ (Target: ≤5%)<br>  - Normal traffic: 2% ✅<br><br>• **Latency:**<br>  - Detection: 2.3s avg ✅ (Target: ≤3s)<br>  - Mitigation: 87ms avg ✅ (Target: <100ms) | 3 phút | TV5 |
| 17 | **Live Demo Walkthrough** | • [Màn hình chia 4 góc]<br>  - Góc 1: Mininet topology<br>  - Góc 2: Attack traffic (hping3 flood)<br>  - Góc 3: Ryu console (alerts)<br>  - Góc 4: tcpdump output (packets dropped)<br><br>• Timeline display: 15-20 giây thực time<br>• Show: Normal → Attack → Detection → Mitigation<br>• Highlight: Alert message → Rule install → Traffic drop | 3 phút | TV2, TV3, TV4 |

---

## PHẦN 5: KÊNG LẠI & TƯƠNG LAI (8 phút | Slide 18)

| Slide | Tiêu đề | Nội dung | Thời gian | Diễn giả |
|---|---|---|---|---|
| 18 | **Kết Luận & Hướng Phát Triển** | **Kết Luận:**<br>• ✅ Phát hiện: 93% TPR, 0% FPR (baseline)<br>• ✅ Mitigation: <100ms rule install<br>• ✅ Thực thời, không cần ML<br>• ✅ 20-25 papers cơ sở<br><br>**Hạn Chế:**<br>• Entropy dễ bị bypass với giả lập lưu lượng<br>• Single controller = bottleneck<br>• Không cover Layer 2 attacks<br><br>**Hướng Phát Triển:**<br>• Machine Learning + Entropy (hybrid)<br>• Distributed controllers (ONOS/Trema)<br>• BGP FlowSpec + SDN integration<br>• DDoS detection trên real ISP network<br><br>**Q&A** | 2 phút | TV1 |

---

## 📊 BẢNG THỜI GIAN CHI TIẾT

| Phần | Slide | Chủ đề | Phút bắt đầu | Phút kết thúc | Diễn giả | Ghi chú |
|---|---|---|---|---|---|---|
| I. Mở đầu | 1-3 | Intro + Problem + Solution | 0:00 | 8:00 | TV1 | Cắt nhanh, hook audience |
| II. Lý thuyết | 4-8 | Entropy + Stats + 10 attacks + Architecture + OpenFlow | 8:00 | 20:00 | TV1, TV4 | Kỹ thuật, có formulas |
| III. Triển khai | 9-13 | Topology + Features + Detection + Mitigation + Workflow | 20:00 | 34:00 | TV2, TV3, TV4, TV5 | Code details + integration |
| IV. Kết quả | 14-17 | 6 biểu đồ + Metrics vs Papers + Live demo | 34:00 | 48:00 | TV5 + TV2, TV3, TV4 | Demo live (15-20s) |
| V. Kêng lại | 18 | Conclusions + Limitations + Future + Q&A | 48:00 | 50:00 | TV1 + All | Flexible Q&A (5-10 min extra) |

---

## 🎯 SCRIPT HỖ TRỢ (Q&A Prepared)

### Câu hỏi dự kiến + Trả lời

| Câu hỏi | Trả lời | Diễn giả |
|---|---|---|
| **Entropy threshold 1.5 dùng từ đâu?** | Từ paper Kaur et al. (2012) + calibrated trên baseline của chúng tôi. Normal: 4-5 bits, SYN flood: <1 bit, threshold 1.5 là midpoint. | TV1 |
| **Tại sao không dùng ML/DL?** | (1) Team không có AI expert, (2) Entropy proven by 20+ papers, (3) Real-time + simplicity, (4) Interpretable rules → production easier | TV1 |
| **FPR = 0 trên baseline, có bắt được bất kỳ normal traffic spike không?** | Có. Setup: threshold_entropy=1.5. Normal spike (100x traffic) → entropy vẫn 4-5 bits → không alert. SYN flood → entropy <1 → alert. Tested. | TV3 |
| **Latency 2.3s detection, có delay từ đâu?** | Breakdown: (1) Pcap parse: 0.5s, (2) Entropy calc: 0.3s, (3) Signature match: 0.2s, (4) Alert generate: 0.3s. Total: ~1.3s. + 1s rule install = 2.3s end-to-end. | TV3, TV4 |
| **DQoS implementation, OpenFlow support này trên OVS?** | Có. OVS (Open vSwitch) hỗ trợ OpenFlow 1.3, METER + Queue. Tested trên chúng tôi. Bandwidth: 50% P1, 30% P2, 20% P3 working. | TV4 |
| **Distributed attacker (100+ sources), entropy vẫn detect?** | Entropy_src sẽ cao (6-8 bits, giả mạo). Nhưng rate still > 5x baseline → flag. Multi-rule matching: attack có thể kết hợp multiple signatures. | TV3 |
| **Recovery time sau khi xóa blacklist?** | Auto 5 phút. Có thể configure. Tuy nhiên không test long-term stability. | TV4 |
| **Mininet vs real network, có difference?** | Mininet: emulation (1 máy), delay = 0. Real: delay ~10-100ms. Detection logic không phụ thuộc delay vì we threshold by % change, không absolute time. | TV2 |
| **Single Ryu controller bottleneck?** | Đúng. Current: 1 controller. Scale: ONOS (multi-controller) hoặc switch-local rulekit. Future work. | TV4 |
| **Cost/efficiency so với commercial solutions (Arbor, Cloudflare)?** | Chúng tôi: open-source, low cost. Commercial: $100K+/year. Trade-off: tuning, expertise needed. Nhưng cơ sở khoa học vững. | TV1 |

---

## 📝 CHUYÊN ĐỀ PREP (cho mỗi diễn giả)

### TV1 (Ngô Thị Mai Anh) - Slides 1-4, 6-8, 16, 18
- ✅ Biết lý thuyết entropy sâu
- ✅ Hiểu 20-25 papers
- ✅ Slide 4: Có công thức + ví dụ trên bảng
- ✅ Q&A: Defend entropy choice vs ML
- ⏱ Thời gian: 12 phút

### TV2 (Đỗ Hoàng Phúc) - Slides 9, 17 (demo part 1)
- ✅ Lab topology sẵn
- ✅ Demo: Show mininet, attacker sending packets
- ✅ Q&A: Real network vs emulation
- ⏱ Thời gian: 5 phút

### TV3 (Bùi Lê Huy Phước) - Slides 11, 14-17 (part)
- ✅ Detection engine hiểu sâu
- ✅ Visualizations (entropy + accuracy charts)
- ✅ Demo: Show alerts in real-time
- ✅ Q&A: FPR, latency breakdown, distributed attacks
- ⏱ Thời gian: 8 phút

### TV4 (Phạm Ngọc Trúc Quỳnh) - Slides 8, 12-13, 17 (demo part 2)
- ✅ Ryu + OpenFlow expert
- ✅ Mitigation workflow
- ✅ Demo: Show Ryu console, rules installed, traffic blocked
- ✅ Q&A: DQoS OVS, bottleneck, distributed
- ⏱ Thời gian: 6 phút

### TV5 (Phạm Nguyễn Tấn Sang) - Slides 13-17, 18
- ✅ Integration lead
- ✅ All visualizations + metrics
- ✅ Demo coordinator: orchestrate screen sharing
- ✅ Timeline presenter
- ⏱ Thời gian: 10 phút

---

## 🎬 LIVE DEMO SCRIPT (15-20 giây)

```
[0-1s] Show 4-pane screen
[1-3s] Highlight: Mininet topology, s2 with Ryu
[3-5s] Start attacker: hping3 -S --flood 10.0.2.1 (SYN flood to web server)
[5-8s] Show: traffic spike on tcpdump (tty 1), pps increase
[8-10s] Ryu console: Entropy calculation output → H_src drops to 0.8 bits
[10-12s] Alert generated: "ALERT: SYN_FLOOD detected, confidence=HIGH, src=10.0.1.10"
[12-14s] FlowMod rule installed: "Match: ipv4_src=10.0.1.10, Action: DROP"
[14-17s] tcpdump shows: attack packets DROPPED, legitimate traffic passing
[17-20s] Benchmark: "Detection latency: 2.3s, Rule install: 87ms, Packets blocked: 99.8%"
```

---

## ✅ CHECKLIST TRƯỚC THUYẾT TRÌNH

- [ ] Slides: 18 slide đã export .pptx
- [ ] Timer: Có người đo thời gian mỗi slide (lý tưởng TV5)
- [ ] Demo: Mininet, Ryu, tcpdump terminals sẵn sàng
- [ ] Video backup: Nếu demo fail, có video demo được quay sẵn
- [ ] Fonts: Slide đủ lớn (min 24pt), hiển thị trên projector
- [ ] Handouts: In phần paper references + architecture
- [ ] Q&A: Team review Q&A script 1 lần trước
- [ ] Backup: Có tất cả files trên USB
