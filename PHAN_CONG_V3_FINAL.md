# PHÂN CÔNG V3 FINAL - DoS Detection using SDN with Scientific Basis

**Đặc điểm V3:**

- ✅ **Kế thừa code**: topology_nhom4.py + l3_router.py (phát triển lên)
- ✅ **Cơ sở khoa học**: 20-25 papers khoa học (IEEE/ACM/Springer)
- ✅ **Phương pháp cụ thể**: Entropy + Statistical methods (không trùng lặp)
- ✅ **Mitigation nâng cao**: DQoS, traffic shaping, multi-level filtering
- ✅ **Song song hóa**: 3 core streams độc lập (Data, Detection, Mitigation)
- ✅ **Timeline**: 3-4 tuần, 5 người

---

## 📚 PHẦN I: LÝ THUYẾT VÀ CƠ SỞ KHOA HỌC

### 1. BACKGROUND ON DoS ATTACKS

**Paper References:**

- A1: Kaur et al. (2012) - Entropy-based anomaly detection
- B1-B3: Layer 4/7 DDoS surveys (2018-2020)
- C1: SDN DDoS defense mechanisms

**Nội dung T1 cần chuẩn bị:**

```
THEORY_BACKGROUND.md
├── 1. DDoS Classification
│   ├── Layer 4 (Transport): SYN, UDP, ACK, FIN, RST floods
│   ├── Layer 7 (Application): HTTP, DNS, SMTP floods
│   ├── Spoofing attacks: IP spoofing + source entropy analysis
│   └── Low-rate attacks: Hard to detect (need entropy + timing analysis)
│
├── 2. Why Entropy?
│   ├── Shannon entropy: H(X) = -Σ p(x) log₂(p(x))
│   ├── Normal traffic: diverse sources → entropy ≈ 4-5 bits
│   ├── Flood attack: same source → entropy ≈ 0-1 bits
│   ├── Spoofed attack: random sources → entropy ≈ 6-8 bits (too high!)
│   └── Paper: "Entropy-based Anomaly Detection" (A1)
│
├── 3. Statistical Methods for Detection
│   ├── Rate anomaly: (current_rate - baseline_rate) / baseline_std > 3σ
│   ├── Flag ratios: SYN%, RST%, ACK% deviations from baseline
│   ├── Flow count spike: new_flows > baseline * 5
│   └── Paper: "Flow-based Botnet Detection" (A2)
│
└── 4. SDN-based Mitigation
    ├── Reactive vs Proactive defense
    ├── OpenFlow FlowMod: install rate-limit rules
    ├── DQoS (Dynamic QoS): priority queues
    ├── Traffic shaping: token bucket, leaky bucket
    └── Paper: "SDN-based DDoS Detection using Dynamic Flow Rate" (A3)
```

---

### 2. ARCHITECTURE OVERVIEW (Code inheritance)

```
CURRENT STATE (đã có):
  topology_nhom4.py → 5 switches, 8 hosts, 4 zones
  l3_router.py      → Ryu L3 router + flow stats + port stats
  l3_router_test.py → Demo with basic entropy checking

TO DEVELOP (mục tiêu V3):

  ┌─────────────────────────────────────────────────────────────┐
  │              THÀNH VIÊN 1: Theory Lead                     │
  │  • Review 20-25 papers (IEEE/ACM)                          │
  │  • Write THEORY_BACKGROUND.md (3000+ từ)                  │
  │  • Link papers to each detection/mitigation method         │
  │  • Define attack signatures from literature                │
  └─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
  ┌───────▼────────┐  ┌──────▼─────────┐  ┌─────▼───────────┐
  │  THÀNH VIÊN 2  │  │ THÀNH VIÊN 3   │  │ THÀNH VIÊN 4    │
  │  DATA LAYER    │  │ DETECTION      │  │ MITIGATION      │
  │                │  │ LAYER          │  │ LAYER           │
  │ • Generate     │  │                │  │                 │
  │   10 DoS types │  │ • Extract 15+  │  │ • Ryu l3_router │
  │ • Feature xtor │  │   entropy stats│  │   (extend)      │
  │ • Real-time    │  │ • Signature    │  │ • Add DQoS      │
  │   capture      │  │   matching     │  │ • Traffic shape │
  │ • Pcap files   │  │ • Alert system │  │ • Priority flow │
  └────────────────┘  └────────────────┘  └─────────────────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
  ┌─────────────────────────────────────────────────────────────┐
  │ THÀNH VIÊN 5: Testing & Integration                         │
  │ • Combine 2+3+4 together                                    │
  │ • Test end-to-end: attack → detect → mitigate → measure    │
  │ • Visualization: 8+ plots (entropy, latency, effectiveness) │
  │ • Live demo: 15-20 min presentation                         │
  └─────────────────────────────────────────────────────────────┘
```

---

## 📋 PHẦN II: CHI TIẾT PHÂN CÔNG

### 👤 THÀNH VIÊN 1: Ngô Thị Mai Anh (Theory + Research Lead)

| STT     | Task                                    | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Deadline   | Sản phẩm                                          | Papers                            |
| ------- | --------------------------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------- | --------------------------------- |
| **1.1** | **Literature Survey (20-25 papers)**    | 1    | • GROUP A (4 papers): Entropy-based detection<br>• GROUP B (5 papers): Flow-based + statistical methods<br>• GROUP C (5 papers): SDN architecture + OpenFlow<br>• GROUP D (3 papers): DDoS mitigation strategies<br>• GROUP E (4 papers): Real-time detection systems<br>• Organize by: Title, Authors, Year, DOI, Key insights, Relevance                                                                                                                      | Hết tuần 1 | `LITERATURE_SURVEY.md` (5000+ từ, formatted IEEE) | A1-A4, B1-B5, C1-C5, D1-D3, E1-E4 |
| **1.2** | **Theoretical Framework**               | 1    | • Shannon entropy formula + explanation<br>• Statistical anomaly detection methods:<br> - Z-score: (x - mean)/std<br> - Moving average baseline<br> - Deviation thresholds<br>• DDoS attack taxonomy (layer 4/7, spoofing, low-rate)<br>• Why each method works for each attack type<br>• Create decision tree: "When to use entropy vs stats"                                                                                                                  | Hết tuần 1 | `THEORY_BACKGROUND.md` (3000+ từ, with diagrams)  | Reference A1-A3, B1-B3            |
| **1.3** | **Attack Signatures from Literature**   | 1-2  | • Map each paper's findings to attack detection rule:<br> - SYN flood → SYN% > 60%, entropy < 2 bits (A1 says)<br> - UDP flood → packet rate > 5x baseline, entropy medium (B2 says)<br> - DNS ampl → DNS_resp/DNS_req > 10x (E1 case study)<br> - IP spoof → entropy > 6 bits from literature thresholds<br> - Low-rate → needs timing analysis + entropy drop (E2 paper)<br>• Create table: Attack type → Paper reference → Detection rule → Threshold values | Tuần 2     | `ATTACK_SIGNATURES.md` (1500+ từ, CSV table)      | Cross-reference to all groups     |
| **1.4** | **Evaluation Protocol**                 | 1-2  | • Define metrics with paper backing:<br> - TPR (True Positive Rate) per attack type<br> - FPR (False Positive Rate) - cite "optimal false alarm" from B3<br> - Detection latency < 3 sec (from E1 real-time requirement)<br> - Mitigation effectiveness: % traffic drop without blocking legitimate<br>• Test dataset design: 70% training, 30% test (from papers)<br>• Acceptance criteria: TPR ≥90%, FPR ≤5% (based on B2)                                    | Hết tuần 2 | `EVALUATION_PROTOCOL.md` (1000+ từ)               | B2, B3, E1                        |
| **1.5** | **Code Review & Integration Oversight** | 2-4  | • Weekly checklist:<br> - Tuần 2: Review T2's feature extraction (match to paper specs), T3's Ryu rules, T4's detection algo<br> - Tuần 3: Verify detection accuracy vs paper claims<br> - Tuần 4: Final paper linking in code comments<br>• Ensure all code has paper citations in docstrings                                                                                                                                                                  | Tuần 4     | Weekly review logs, code with citations           |                                   |

---

### 👤 THÀNH VIÊN 2: Đỗ Hoàng Phúc (Data Generation + Feature Extraction)

**Outputs kế thừa từ code hiện tại:** topology_nhom4.py (sử dụng lại)

| STT     | Task                                                             | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Deadline   | Sản phẩm                                                                | Theory Basis                                                                |
| ------- | ---------------------------------------------------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| **2.1** | **Lab Verification**                                             | 1    | • Start topology_nhom4.py (không thay đổi)<br>• Verify: all 5 switches online, 8 hosts connected<br>• Test connectivity: each host can ping others<br>• Setup baseline monitoring: tcpdump on s2 (core switch)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Hết tuần 1 | Lab running, tcpdump ready                                              | -                                                                           |
| **2.2** | **Baseline Traffic Collection**                                  | 1-2  | • Normal traffic: 5 minutes<br> - h_pc1 → h_web1: HTTP requests (Apache Bench)<br> - h_pc1 → h_dns1: DNS queries (dig)<br> - h_pc1 → h_app1: TCP connections<br>• Capture: flows.pcap (input for T4 entropy calc)<br>• Extract baseline stats: flows/sec, bytes/sec, entropy per second<br>• Save as: `baseline_stats.json`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Hết tuần 2 | `flows_baseline.pcap`, `baseline_stats.json`                            | B1: "Flow-based detection"                                                  |
| **2.3** | **Generate 10 DoS Attack Scenarios (DIFFERENT from each other)** | 2    | **Layer 4 Floods (3):**<br>1. **SYN Flood** (Test entropy LOW):<br> - From h_att1: hping3 -S --flood 10.0.2.10:80<br> - Metric: 10k+ SYN/sec from single src IP<br> - Expected entropy: <1 bit (A1 paper) → Easy to detect<br> - Duration: 2 mins<br><br>2. **UDP Flood** (Test packet rate HIGH):<br> - From h_att1: UDP flood to 10.0.2.10:53<br> - Metric: 5k+ UDP pkt/sec<br> - Expected: Different entropy signature than SYN<br> - Duration: 2 mins<br><br>3. **ACK+RST Flood** (Test flag ratio ABNORMAL):<br> - From h_att1: hping3 -A/-R --flood 10.0.2.10<br> - Metric: >30% ACK/RST packets (vs <5% baseline)<br> - Duration: 2 mins<br><br>**Layer 7 Floods (3):**<br>4. **HTTP GET Flood** (High conn rate):<br> - From h_att1: ab -n 10000 -c 100 http://10.0.2.10/<br> - Metric: 500+ HTTP reqs/sec<br> - Different from SYN: established connections, not SYN flood<br> - Duration: 2 mins<br><br>5. **HTTP POST Flood** (Slow attack, high bandwidth):<br> - Large POST bodies vs GET<br> - Metric: Byte rate high but flow count moderate<br> - Tests traffic shaping vs flow-rate detection<br> - Duration: 2 mins<br><br>6. **DNS Amplification** (Query → Response spike):<br> - From h_att1: craft DNS queries with spoofed source<br> - Metric: DNS_resp >> DNS_req (10x ratio)<br> - Tests DNS-specific detection (E1 paper)<br> - Duration: 2 mins<br><br>**Spoofing + Low-Rate (3-4):**<br>7. **IP Spoofing Flood** (High entropy test):<br> - Random source IPs + same dst → high src entropy<br> - Metric: entropy > 6 bits (A1 says this is abnormal)<br> - Duration: 2 mins<br><br>8. **Low-Rate DoS** (Stealthy, hard to detect):<br> - 1 HTTP req/sec for 10 mins (slower than baseline)<br> - Tests timing analysis + entropy drop detection<br> - Metric: Average rate low but pattern suspicious<br> - Duration: 10 mins<br><br>9. **Distributed Flood** (Multi-source from h_att1+h_ext1):<br> - Both send attacks simultaneously<br> - Tests multi-source entropy behavior<br> - Duration: 2 mins<br><br>10. **Port Scan then Flood** (Reconnaissance + attack):<br> - First: h_att1 scans multiple ports (SYN scan)<br> - Then: Targets open ports with UDP flood<br> - Duration: 5 mins (2 min scan + 3 min flood) | Hết tuần 2 | `dos_*.pcap` (10 files, labeled with attack type)                       | A1 (entropy), B2 (flow stats), C1 (SDN visibility), E1 (real-time examples) |
| **2.4** | **Feature Extraction Pipeline**                                  | 2-3  | • Parse each pcap (baseline + 10 DoS):<br>• Extract per 1-second window:<br> - Src IP entropy (using A1 formula)<br> - Dst port entropy<br> - Total packets/sec, bytes/sec<br> - SYN%, RST%, ACK% flags<br> - Unique src IPs, unique dst IPs<br> - New flows/sec (connections per sec)<br> - Packet size std deviation<br>• Output CSV format:<br> `<br>  timestamp, src_entropy, dst_entropy, pps, bps, syn_pct, rst_pct, <br>  unique_src, new_flows, pkt_size_std, attack_type<br>  `<br>• Save for each attack: `features_dos_1.csv`, `features_dos_2.csv`, etc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Hết tuần 3 | `feature_extraction.py` (200 lines), 11 CSV files (1 baseline + 10 DoS) | B1: feature engineering from flow stats                                     |
| **2.5** | **Real-time Traffic Capture Setup**                              | 3    | • Create script to capture live traffic on s2<br>• Setup for demo: Run attack → capture → send to T4 in real-time<br>• Format: rolling pcap files (1 file per minute)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Tuần 3     | `capture_live.sh`, demo_traffic_setup.sh                                | -                                                                           |

---

### 👤 THÀNH VIÊN 3: Bùi Lê Huy Phước (Detection Engine)

**Extends:** l3_router.py (thêm detection module)

| STT     | Task                             | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Deadline             | Sản phẩm                                                          | Theory Basis                                      |
| ------- | -------------------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- | ----------------------------------------------------------------- | ------------------------------------------------- | --------------------------------------------------------------------------------- | ---------- | -------------------------------- | --------------------------------------------------------- |
| **3.1** | **Entropy Detection Module**     | 2    | • Build on l3_router.py stats collection<br>• For each 1-sec window, compute:<br> - H_src = Shannon entropy of src IPs (A1 formula)<br> - H_dst = Shannon entropy of dst ports<br> - H_ttl = Shannon entropy of TTL values<br> - H_pkt_size = entropy of packet sizes<br>• Compare to baseline thresholds (from T1):<br> - Normal: H_src ≈ 4 bits<br> - SYN flood: H_src < 1 bit (alert!)<br> - IP spoof: H_src > 6 bits (alert!)<br>• Alert if entropy abnormal for 2+ consecutive seconds (reduce FP)<br>• Code: `detection_entropy.py`                                                                                                                                                                                                                                                                                                                                   | Hết tuần 2           | `detection_entropy.py` (150 lines)                                | A1: Kaur et al. entropy-based anomaly detection   |
| **3.2** | **Statistical Detection Module** | 2    | • Compute per 1-sec window:<br> - rate_current = (packets_now - packets_1sec_ago) / 1<br> - rate_baseline = mean of last 60 sec<br> - rate_std = std of last 60 sec<br> - z_score = (rate_current - baseline) / std<br>• Alert rules (from B2, B3 papers):<br> - Z > 3: High traffic (3σ anomaly)<br> - Packet rate spike: rate_current > 5x baseline<br> - New flows spike: new_conns_now > baseline \* 3<br> - SYN% abnormality:                                                                                                                                                                                                                                                                                                                                                                                                                                          | SYN% - baseline_SYN% | > 20%<br> - RST% abnormality:                                     | RST% - baseline_RST%                              | > 15%<br>• Alert if any rule triggers for 3+ secs<br>• Code: `detection_stats.py` | Hết tuần 2 | `detection_stats.py` (150 lines) | B2: Flow-based botnet detection, B3: Statistical measures |
| **3.3** | **Attack Signature Matching**    | 2-3  | • Implement decision rules from T1's ATTACK_SIGNATURES.md:<br><br>**SYN Flood:**<br> - IF (entropy_src < 1.5 AND syn_pct > 50%) → SYN_FLOOD<br> - Confidence: HIGH<br><br>**UDP Flood:**<br> - IF (pps > 5x_baseline AND packet_size_std < 10 AND entropy_src medium) → UDP_FLOOD<br> - Confidence: MEDIUM<br><br>**HTTP Flood:**<br> - IF (http_req_rate > 100/sec AND syn_pct normal AND entropy_src normal) → HTTP_FLOOD<br> - Confidence: HIGH<br><br>**DNS Amplification:**<br> - IF (dns_resp_count >> dns_req_count AND entropy_dst_port high) → DNS_AMPL<br> - Confidence: MEDIUM<br><br>**IP Spoofing:**<br> - IF (entropy_src > 6.5 AND pps high) → IP_SPOOF<br> - Confidence: MEDIUM<br><br>**Low-rate DoS:**<br> - IF (pps normal BUT entropy_src < 2 bits) → LOW_RATE<br> - Confidence: LOW (need manual review)<br><br>• Code: `attack_signature_matching.py` | Tuần 3               | `attack_signature_matching.py` (200 lines), signature rules table | All papers: each attack signature from literature |
| **3.4** | **Real-time Alert System**       | 3    | • Listen to T2's live pcap (or T4's processed stats)<br>• Generate alerts in JSON format:<br> `json<br>  {<br>    "timestamp": "2024-04-21T10:30:15Z",<br>    "attack_type": "SYN_FLOOD",<br>    "confidence": "HIGH",<br>    "src_ip": "10.0.1.10",<br>    "dst_ip": "10.0.2.10",<br>    "dst_port": 80,<br>    "metrics": {<br>      "entropy_src": 0.8,<br>      "syn_pct": 78,<br>      "pps": 15000<br>    },<br>    "mitigation_action": "rate_limit_src_10.0.1.10"<br>  }<br>  `<br>• Log all alerts: `alerts.json`<br>• Integrate with T4 (mitigation): send alert → trigger blocking rule                                                                                                                                                                                                                                                                          | Tuần 3               | `alert_system.py` (100 lines), alerts.json (runtime)              | -                                                 |

---

### 👤 THÀNH VIÊN 4: Phạm Ngọc Trúc Quỳnh (SDN Mitigation Layer)

**Extends:** l3_router.py (thêm mitigation app)

| STT     | Task                                            | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Deadline   | Sản phẩm                                                                          | Theory Basis                                   |
| ------- | ----------------------------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | --------------------------------------------------------------------------------- | ---------------------------------------------- |
| **4.1** | **Extend Ryu l3_router.py with Basic Blocking** | 1-2  | • Start from existing l3_router.py<br>• Add method: `block_source_ip(src_ip)`<br> - Install DROP rule on all switches:<br> `<br>    match: ipv4_src=src_ip<br>    action: DROP<br>    priority: 100 (higher than normal traffic)<br>    `<br> - Verify in Ryu logs: "Flow installed"<br>• Test: SYN flood detected → rule installed → attack traffic dropped<br>• Measure latency: time from alert to traffic drop (target: <100ms)                                                                                                                                                                                                                                                                                                                                                                         | Hết tuần 2 | Extend l3_router.py with `block_source_ip()` method                               | C1: OpenFlow reactive defense                  |
| **4.2** | **Rate Limiting using Token Bucket**            | 2    | • Implement per-source-IP rate limiting (not just drop)<br>• Token bucket algorithm:<br> - Rate: R tokens/sec<br> - Bucket size: B tokens<br> - For each packet: if tokens >= pkt_size → forward + remove tokens; else DROP<br>• OpenFlow representation:<br> - Use METER tables (OpenFlow 1.3 feature)<br> - Create meter: `max_rate=1000pps` per src IP<br> - Install rule: `match: ipv4_src=src_ip, meter=meter_id`<br>• Configuration: Different rate limits per attack type:<br> - SYN flood: 100 pps<br> - UDP flood: 200 pps<br> - HTTP flood: 50 req/sec (harder to meter)<br>• Code: `mitigation_rate_limit.py`                                                                                                                                                                                    | Hết tuần 2 | `mitigation_rate_limit.py` (150 lines), meter configs                             | D1: Traffic policing using token bucket        |
| **4.3** | **DQoS + Traffic Shaping**                      | 2-3  | • Implement Quality of Service prioritization:<br>• Classes:<br> - Priority 1 (highest): DNS, Critical apps → no throttle<br> - Priority 2: Normal traffic → light throttle if congestion<br> - Priority 3 (lowest): Attack traffic → aggressive throttle<br>• OpenFlow implementation:<br> - Use DSCP (Differentiated Services Code Point) tagging<br> - Tag priority 3 traffic with DSCP=8 (CS1 class)<br> - Queue rules on switch: priority queues per DSCP value<br> - Bandwidth allocation: Priority 1=50%, Priority 2=30%, Priority 3=20%<br>• Multi-level filtering:<br> - Level 1: First packet → default priority 3 (attack?) <br> - Level 2: If whitelisted IP → move to priority 1<br> - Level 3: If legitimate protocol (DNS, HTTP from trusted) → priority 1-2<br>• Code: `mitigation_dqos.py` | Tuần 3     | `mitigation_dqos.py` (200 lines), priority rules                                  | D2: DQoS mechanisms, D3: Multi-level filtering |
| **4.4** | **Blacklist/Whitelist Management**              | 3    | • Maintain dynamic blacklist (from T3's alerts)<br>• Subscribe to T3's alert system:<br> `python<br>  def receive_alert(alert_msg):<br>      if alert_msg.confidence == "HIGH":<br>          self.add_to_blacklist(alert_msg.src_ip)<br>          self.install_drop_rule(alert_msg.src_ip)<br>  `<br>• Whitelist: Pre-defined trusted IPs (e.g., admin, legit partner)<br>• Auto-recovery: Remove from blacklist after 5 minutes (configurable)<br>• Logging: `mitigation_actions.json` (when rules added/removed)                                                                                                                                                                                                                                                                                          | Tuần 3     | `mitigation_blacklist.py` (100 lines), dynamic list                               | C1: Reactive defense strategies                |
| **4.5** | **Performance Benchmarking**                    | 3    | • Measure Ryu controller bottlenecks:<br> - Rule installation latency: time(alert received) → time(OpenFlow sent) → time(switch confirms)<br> - Expected: <100ms (from C1, C3 papers)<br> - Throughput with rules: Switch can still process >1Gbps traffic<br>• Load test: Install 1000 rate-limit rules, measure CPU/memory<br>• Create plot: rule_count vs latency, rule_count vs CPU%<br>• Code: `benchmark_mitigation.py`                                                                                                                                                                                                                                                                                                                                                                               | Tuần 3     | `benchmark_mitigation.py` (100 lines), benchmark_results.json, benchmark_plot.png | C3: SDN scalability analysis                   |

---

### 👤 THÀNH VIÊN 5: Phạm Nguyễn Tấn Sang (Testing + Integration + Demo)

| STT     | Task                                        | Tuần | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Deadline   | Sản phẩm                                             | Theory Basis                                   |
| ------- | ------------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------- | ---------------------------------------------- |
| **5.1** | **End-to-End Integration Testing**          | 3    | • For each of 10 DoS attacks + baseline:<br> 1. Start topology (from T2)<br> 2. Run Ryu l3_router + detection (from T3) + mitigation (from T4)<br> 3. Generate attack traffic (from T2's pcap replay or live)<br> 4. Measure: detection_latency, mitigation_latency, effectiveness<br> 5. Verify: metrics match paper baselines (from T1)<br><br>• **Test for each attack:**<br> - Test_001: SYN flood detection latency ≤ 3 sec (E1 requirement)<br> - Test_002: UDP flood detection accuracy ≥ 90% TPR (B2 benchmark)<br> - Test_003: HTTP flood detected vs false positive rate ≤ 5% (B3)<br> - ... (10 tests total)<br> - Test_011: Baseline (normal traffic): FPR = 0 (no false alarms)<br><br>• Results: `test_results.json`<br> `json<br>  {<br>    "test_001_syn_flood": {<br>      "status": "PASS",<br>      "detection_time_sec": 2.1,<br>      "paper_requirement": "≤ 3 sec",<br>      "tpr": 0.98,<br>      "fpr": 0.02<br>    }<br>  }<br>  `<br>• Failures: Root cause analysis, bug report to T3/T4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Hết tuần 3 | `integration_test.py` (300 lines), test_results.json | All papers: compare results to literature      |
| **5.2** | **Visualization & Analysis**                | 3    | • **Plot 1: Detection Timeline per Attack**<br> - X: Time (sec), Y: Metrics (entropy, pps, etc.)<br> - Show: baseline (green), attack starts (red line), detection alert (black dot)<br> - Example: SYN flood @ t=60s, detected @ t=62s<br><br>• **Plot 2: Entropy Signature per Attack Type**<br> - 10 subplots (1 per attack)<br> - Each: entropy_src over time, threshold line, alert markers<br> - Shows why each attack has different entropy signature<br><br>• **Plot 3: Detection Accuracy per Attack (Bar chart)**<br> - X: Attack types, Y: TPR (blue bar) + FPR (red bar)<br> - Compare vs paper baselines (add reference line)<br><br>• **Plot 4: Detection Latency Distribution (Box plot)**<br> - X: Attack types, Y: Latency in seconds<br> - Show: median, quartiles, outliers<br> - Reference: E1 paper recommends <3 sec<br><br>• **Plot 5: Mitigation Effectiveness**<br> - Before mitigation: attack traffic volume (Mbps)<br> - After mitigation: blocked % vs allowed legitimate % (stacked bar)<br> - Shows: successful attack suppression without collateral damage<br><br>• **Plot 6: Ryu Rule Installation Latency**<br> - Histogram: latency distribution for 1000 rules<br> - Target: <100ms (from C1)<br><br>• **Plot 7: Traffic Pattern Comparison (Stacked Area)**<br> - Normal vs SYN flood vs HTTP flood<br> - Show: packet count per port, protocol distribution<br><br>• **Plot 8: False Positive Rate vs Detection Threshold**<br> - Trade-off: as entropy threshold decreases, TPR↑ but FPR↑<br> - Find optimal point (Youden index)\br>• Code: `visualization.py` (300 lines) | Tuần 3     | `visualization.py`, 8 PNG plots                      | E2: Analysis & evaluation of detection systems |
| **5.3** | **Live Demo (15-20 min presentation)**      | 3-4  | • **Demo flow:**<br> 1. [0-1 min] Show lab topology (diagram on screen)<br> 2. [1-2 min] Start Mininet + Ryu (show controller logs)<br> 3. [2-3 min] Show baseline traffic (normal pcap + Ryu stats)<br> 4. [3-7 min] Launch attack #1 (SYN flood):<br> - Show: attacker sends traffic (terminal 1)<br> - Show: Ryu detects entropy anomaly (controller logs)<br> - Show: Mitigation rule installed (OpenFlow message)<br> - Show: Attack traffic blocked (tcpdump shows drop)<br> 5. [7-12 min] Launch attack #2 (HTTP flood):<br> - Different detection signature (rate-based, not entropy)<br> - Different mitigation (rate limit vs full drop)<br> 6. [12-15 min] Show results: plots, detection times, effectiveness metrics<br> 7. [15-20 min] Q&A<br><br>• **Fallback:** Pre-recorded demo video (if live demo fails)<br>• **Demo artifact:** `demo.sh` (automation script)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Tuần 4     | `demo.sh`, live demo or demo.mp4                     | -                                              |
| **5.4** | **Final Presentation (12-15 slides + Q&A)** | 4    | • **Slide 1:** Title + Team<br>• **Slide 2-3:** Problem statement + DDoS threat (from T1 literature)<br>• **Slide 4-5:** Related work: 5 key papers (summary)<br>• **Slide 6-7:** Architecture: Mininet topology + Ryu + detection + mitigation layers<br>• **Slide 8-9:** Theory: Entropy & statistical methods (formulas, intuition)<br>• **Slide 10-12:** Results: 3 attack examples (detection + mitigation effectiveness)<br>• **Slide 13:** Demo walkthrough + metrics<br>• **Slide 14:** Conclusions & limitations<br>• **Slide 15:** Future work<br><br>• **Q&A script:** 15+ typical questions + answers (1 page each)<br> - "How is your entropy threshold chosen?" (answer: from A1 paper + our baseline)<br> - "Why not use ML?" (answer: entropy + stats simpler, paper-proven, real-time)<br> - "What's the false positive rate?" (answer: <5% on test set vs B3 benchmark)<br> - ...                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Tuần 4     | `PRESENTATION.pptx` (15 slides), `QA_SCRIPT.md`      | -                                              |
| **5.5** | **Final Documentation & Clean GitHub**      | 4    | • `README.md`: Quick start, folder structure, how to run demo<br>• `INSTALL.md`: Dependencies, setup steps<br>• `QUICKSTART.md`: "Run in 5 minutes" guide<br>• `RESULTS.md`: Summary of findings + comparison to papers<br>• `TROUBLESHOOTING.md`: Common issues + fixes<br>• GitHub structure:<br> `<br>  docs/  → all markdown files + papers\br>  code/  → Python files (Ryu, detection, mitigation, scripts)\br>  data/  → pcap files, feature CSVs, baseline stats\br>  results/ → plots, test results, benchmark data\br>  `<br>• Code quality: docstrings with paper citations, type hints, clean syntax<br>• Tag: `v1.0-final`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Tuần 4     | Clean GitHub, all docs, code organized               | -                                              |

---

## 📊 PARALLELIZATION MATRIX

| Week  | T1 (Theory)                                          | T2 (Data)                                        | T3 (Detection)                                     | T4 (Mitigation)                                | T5 (Testing)                               |
| ----- | ---------------------------------------------------- | ------------------------------------------------ | -------------------------------------------------- | ---------------------------------------------- | ------------------------------------------ |
| **1** | Lit survey 20-25 papers                              | Lab setup (topology)                             | Study detection papers (from T1)                   | Study Ryu + OpenFlow                           | Setup test framework                       |
| **2** | Theory + attack sigs (done early, shares with T3-T4) | Generate 10 DoS + feature extraction (PARALLEL!) | Build entropy module + stats module (PARALLEL!)    | Build rate limit + DQoS (PARALLEL!)            | Ready to integrate                         |
| **3** | Code review                                          | Fine-tune features + live capture                | Signature matching + alerts (wait for T2 features) | Benchmark + dynamic rules (consumes T3 alerts) | Integration testing + visualization + demo |
| **4** | Final report linkage                                 | (done)                                           | (done)                                             | (done)                                         | Live presentation + final docs             |

**Key parallel opportunities:**

- **Tuần 2:** T2, T3, T4 work completely independently (only input is T1's theory)
- **Tuần 3:** Integration happens (T3→T4 via alerts, T2→T5 via features)
- **Tuần 4:** All output converges for demo + docs

---

## ✅ SUCCESS CRITERIA

| Criteria               | Target                                           | Owner          | Paper Reference |
| ---------------------- | ------------------------------------------------ | -------------- | --------------- |
| **Detection Accuracy** | TPR ≥90%, FPR ≤5%                                | T3, T5         | B2, B3          |
| **Detection Speed**    | Alert ≤3 sec after attack                        | T3, T5         | E1              |
| **Mitigation Speed**   | Rule install <100ms                              | T4, T5         | C1              |
| **Attack Coverage**    | All 10 types detected correctly                  | T3, T5         | T1 attack sigs  |
| **Baseline Stability** | FPR=0 on normal traffic                          | T3, T5         | B1              |
| **Code Quality**       | 100+ lines per module, documented with citations | All            | -               |
| **Live Demo**          | 15-20 min end-to-end, working                    | T5, T2, T3, T4 | -               |
| **Scientific Basis**   | All code/design linked to 20-25 papers           | T1, All        | -               |

---

## 📁 EXPECTED OUTPUT STRUCTURE

```
NT541.Q21-DDoS/
├── docs/
│   ├── LITERATURE_SURVEY.md           (T1, 5000+ words)
│   ├── THEORY_BACKGROUND.md           (T1, 3000+ words)
│   ├── ATTACK_SIGNATURES.md           (T1, 1500+ words)
│   ├── EVALUATION_PROTOCOL.md         (T1, 1000+ words)
│   ├── README.md                      (T5)
│   ├── INSTALL.md                     (T5)
│   ├── QUICKSTART.md                  (T5)
│   ├── RESULTS.md                     (T5)
│   └── TROUBLESHOOTING.md             (T5)
├── code/
│   ├── topology_nhom4.py              (T2, existing)
│   ├── l3_router.py                   (T4, extended)
│   ├── l3_router_extended.py          (T4 new version with mitigation)
│   ├── detection_entropy.py           (T3)
│   ├── detection_stats.py             (T3)
│   ├── attack_signature_matching.py   (T3)
│   ├── alert_system.py                (T3)
│   ├── mitigation_rate_limit.py       (T4)
│   ├── mitigation_dqos.py             (T4)
│   ├── mitigation_blacklist.py        (T4)
│   ├── benchmark_mitigation.py        (T4)
│   ├── feature_extraction.py          (T2)
│   ├── integration_test.py            (T5)
│   ├── visualization.py               (T5)
│   ├── demo.sh                        (T5)
│   └── capture_live.sh                (T2)
├── data/
│   ├── flows_baseline.pcap            (T2)
│   ├── baseline_stats.json            (T2)
│   ├── dos_*.pcap                     (T2, 10 files)
│   ├── features_*.csv                 (T2, 11 files)
│   └── attacks_metadata.json          (T2 info)
├── results/
│   ├── test_results.json              (T5)
│   ├── alerts.json                    (T3, runtime)
│   ├── mitigation_actions.json        (T4, runtime)
│   ├── benchmark_results.json         (T4)
│   └── plots/
│       ├── detection_timeline_*.png   (T5, 10 plots)
│       ├── entropy_signatures.png     (T5)
│       ├── detection_accuracy.png     (T5)
│       ├── mitigation_effectiveness.png (T5)
│       ├── ryu_latency.png            (T5)
│       └── ... (8 total)
├── PRESENTATION.pptx                  (T5, 15 slides)
├── QA_SCRIPT.md                       (T5)
└── .gitignore, requirements.txt

```

---

## 📝 WEEKLY CHECKPOINT MEETINGS

### Tuần 1 - Kickoff

- [ ] T1: Papers organized, theory documented
- [ ] T2: Lab running, baseline captured
- [ ] T3: Entropy formula coded, tested on baseline
- [ ] T4: Ryu basic blocking working
- [ ] T5: Test framework skeleton ready
      **Q:** Are all attack types well-defined and unique from each other?

### Tuần 2 - Implementation Sprint

- [ ] T2: All 10 DoS attacks generated + features extracted
- [ ] T3: Detection all 10 types, test on T2's data
- [ ] T4: Rate limiting + DQoS implemented
- [ ] T1: Attack signatures document complete + linked to papers
- [ ] T5: Ready for integration testing
      **Q:** Can each component detect/mitigate independently? Any missing logic?

### Tuần 3 - Integration & Demo Prep

- [ ] T5: End-to-end tests passing for all 10 attacks
- [ ] T5: Visualization complete, demo script working
- [ ] All: Code reviewed, paper citations added
- [ ] All: GitHub cleaned up
      **Q:** Are detection times <3 sec? Mitigation <100ms? Any failures?

### Tuần 4 - Final Submission

- [ ] Live demo rehearsed & working
- [ ] Presentation slides ready
- [ ] All documentation complete
- [ ] GitHub tagged v1.0-final, all tests passing
      **Q:** Ready for submission?

---

## 🎯 KEY DIFFERENCES FROM V2

| Aspect                | V2                    | V3                                                                   |
| --------------------- | --------------------- | -------------------------------------------------------------------- |
| **Code foundation**   | Designed from scratch | **Kế thừa + extend** topology + l3_router                            |
| **Papers**            | ~15 vague references  | **20-25 specific IEEE/ACM** papers, cited per method                 |
| **Attack scenarios**  | 10 generic            | **10 unique**, well-differentiated signatures                        |
| **Detection**         | Entropy only          | **Entropy + Statistical** (from literature)                          |
| **Mitigation**        | Basic drop            | **DQoS + Traffic shaping + Multi-level** (from papers D1-D3)         |
| **Theory foundation** | Weak                  | **THEORY_BACKGROUND.md** + **ATTACK_SIGNATURES.md** linked to papers |
| **Parallelization**   | Loose                 | **Tight matrix:** T2/T3/T4 work fully parallel in W2                 |

---

## 📚 REFERENCE PAPERS BY GROUP

**GROUP A (4):** Entropy-based detection (A1-A4)
**GROUP B (5):** Flow-based + statistical (B1-B5)
**GROUP C (5):** SDN architecture + OpenFlow (C1-C5)
**GROUP D (3):** DDoS mitigation (D1-D3)
**GROUP E (4):** Real-time systems (E1-E4)

_Details in T1's LITERATURE_SURVEY.md_
