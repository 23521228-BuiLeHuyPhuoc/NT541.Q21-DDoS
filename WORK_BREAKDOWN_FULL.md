# Work Breakdown Structure - DoS Detection Project

**Đề tài:** Denial-of-Service Attack Detection & Classification  
**Mục tiêu:** 10 điểm, thực hành 70%, cơ sở khoa học mạnh  
**Ngày cập nhật:** 2026-04-21

---

## 📋 TONG QUAN CAC PHAN VIEC

### **PHAN I: NGHIEN CUU & CHUAN BI KHOA HOC (20% tong effort)**

- [ ] Survey 15+ bài báo khoa học
- [ ] Tổng hợp related work (entropy, ML, DL methods)
- [ ] Chọn metrics & protocol đánh giá
- [ ] Phân loại attack types & scenarios

### **PHAN II: CO SO HAT TANG (15% tong effort)**

- [ ] Cấu hình Mininet topology (reuse `topology_nhom4.py`)
- [ ] Cài đặt Ryu controller (reuse `l3_router_test.py`)
- [ ] Cấu hình InfluxDB + Grafana monitoring
- [ ] Test connectivity & traffic capture

### **PHAN III: DU LIEU & FEATURE ENGINEERING (25% tong effort)**

- [ ] Thu thập pcap files (normal + DoS)
- [ ] Tích hợp feature extraction pipeline
- [ ] Xử lý imbalance, missing values, outliers
- [ ] Tạo train/val/test datasets

### **PHAN IV: PHUONG PHAP PHAT HIEN (35% tong effort)**

- [ ] Review & tối ưu Entropy detection (cơ sở sẵn)
- [ ] Xây dựng ML baseline (Random Forest, XGBoost)
- [ ] Implement Deep Learning (CNN/LSTM/Autoencoder)
- [ ] Integrate real-time inference module

### **PHAN V: DANH GIA & SO SANH (5% tong effort)**

- [ ] Benchmark (Precision, Recall, F1, ROC-AUC, Latency)
- [ ] Tạo visualization (curves, heatmaps, trends)
- [ ] Phân tích false positives/negatives

---

## 🔍 PHAN I - NGHIEN CUU & CHUAN BI KHOA HOC

### 1.1 Survey Bài Báo (15+ papers)

```
[ ] Group A - Entropy-based Detection (3 papers)
    [ ] Paper 1: "Entropy-based network intrusion detection"
    [ ] Paper 2: "Flow-based DDoS detection using statistics"
    [ ] Paper 3: "Shannon entropy for SDN security"

[ ] Group B - Machine Learning IDS (4 papers)
    [ ] Paper 4: "Random Forest for network intrusion"
    [ ] Paper 5: "XGBoost vs ensemble methods in IDS"
    [ ] Paper 6: "Feature selection for DoS detection"
    [ ] Paper 7: "Class imbalance in network anomaly detection"

[ ] Group C - Deep Learning IDS (4 papers)
    [ ] Paper 8: "CNN for traffic classification"
    [ ] Paper 9: "LSTM for temporal intrusion detection"
    [ ] Paper 10: "Autoencoder for unsupervised anomaly"
    [ ] Paper 11: "GRU vs LSTM for sequential attacks"

[ ] Group D - Datasets & Benchmarks (2 papers)
    [ ] Paper 12: "CICIDS2017: Evaluating IDS"
    [ ] Paper 13: "UNSW-NB15: comprehensive dataset"

[ ] Group E - Advanced Topics (2 papers)
    [ ] Paper 14: "Real-time inference optimization"
    [ ] Paper 15: "Adversarial robustness in DL-IDS"
```

**Deliverable 1.1:** `RESEARCH_SURVEY.md` (3000 words)

- Bảng: Title | Authors | Year | Venue | Key Method | Accuracy | Latency
- Tóm tắt methods từng paper (2-3 câu)
- Nhận xét: Pros/Cons, applicability cho project

### 1.2 Attack Taxonomy & Classification

```
[ ] Classify DoS attack types:
    [ ] Single-source IP flooding (SYN/UDP/ICMP)
    [ ] Distributed flooding (botnet, multi-IP)
    [ ] IP spoofing attacks
    [ ] Slow attacks (Slowloris)
    [ ] Reflection attacks (NTP, DNS)

[ ] Define scenarios:
    [ ] Scenario A: Sudden spike in packet rate (1 IP, 1000+ pps)
    [ ] Scenario B: Distributed sources (10+ IPs, 100+ pps each)
    [ ] Scenario C: Spoofed sources (high entropy, unpredictable IPs)
    [ ] Scenario D: Mixed (botnet + spoof)
    [ ] Scenario E: Stealthy (low rate, pattern-based)
```

**Deliverable 1.2:** `ATTACK_SCENARIOS.md`

- Diagram: attack types, characteristics, detection difficulty
- Mô tả từng scenario & kịch bản test

### 1.3 Evaluation Protocol

```
[ ] Define metrics:
    [ ] Accuracy = (TP + TN) / (TP + TN + FP + FN)
    [ ] Precision = TP / (TP + FP)
    [ ] Recall = TP / (TP + FN)
    [ ] F1 = 2 * (Precision * Recall) / (Precision + Recall)
    [ ] ROC-AUC = area under ROC curve
    [ ] Specificity = TN / (TN + FP)
    [ ] Latency = end-to-end detection time (ms)
    [ ] Throughput = flows/sec or packets/sec

[ ] Define dataset split:
    [ ] Train: 70%, Val: 20%, Test: 10% (time-ordered)
    [ ] Stratified sampling cho class balance
    [ ] Cross-validation: 5-fold

[ ] Define thresholds:
    [ ] Entropy > X → High suspicion
    [ ] ML confidence > 0.7 → Positive
    [ ] DL prediction > 0.8 → Positive
```

**Deliverable 1.3:** `EVALUATION_PROTOCOL.md` (500 words)

- Chính xác định nghĩa từng metric
- Cách tính, khi nào sử dụng
- Acceptance criteria (≥85% F1, ≤50ms latency)

---

## 🏗️ PHAN II - CO SO HAT TANG

### 2.1 Topology & Mininet Setup

```
[ ] Review `topology_nhom4.py`:
    [ ] Kiểm tra 5 switches (s1-s5), 8 hosts
    [ ] Verify IP ranges (10.0.x.0/24)
    [ ] Check link bandwidth & latency

[ ] Enhance topology (nếu cần):
    [ ] Add packet loss simulation (loss=1%)
    [ ] Add jitter (latency variance)
    [ ] Add physical link constraints

[ ] Create `setup_topology.sh`:
    [ ] Cài đặt dependencies (mininet, ryu, ovs)
    [ ] Tạo topology
    [ ] Verify connectivity (ping tests)
```

**Deliverable 2.1:** `setup_topology.sh`, verified topology.mn file

### 2.2 Ryu Controller & OpenFlow Rules

```
[ ] Review `l3_router_test.py`:
    [ ] Hiểu routing logic (ARP table, flow rules)
    [ ] Hiểu entropy calculation (window size=1000)
    [ ] Hiểu blocking mechanism (drop packets)

[ ] Enhance controller (optional):
    [ ] Add real-time flow stats export (InfluxDB)
    [ ] Add per-flow tracking (5-tuple)
    [ ] Add configurable thresholds

[ ] Create `enhanced_controller.py`:
    [ ] Export flow stats every 1s
    [ ] Include: src_ip, dst_ip, pkt_count, byte_count, duration
    [ ] Format: JSON or InfluxDB line protocol
```

**Deliverable 2.2:** Enhanced controller code, config file

### 2.3 Monitoring Infrastructure

```
[ ] InfluxDB Setup:
    [ ] Install InfluxDB (docker or native)
    [ ] Create database: sdn_monitor
    [ ] Measurements: flows, entropy, packet_stats

[ ] Grafana Dashboard (optional):
    [ ] Visualize packet rate over time
    [ ] Entropy trend
    [ ] Blocked IPs list

[ ] Traffic Capture Setup:
    [ ] tcpdump/tshark on router interface
    [ ] Rotate pcap files (1GB chunks)
    [ ] Store in `data/raw/`
```

**Deliverable 2.3:** InfluxDB schema, Grafana JSON, capture scripts

---

## 📊 PHAN III - DU LIEU & FEATURE ENGINEERING

### 3.1 Data Collection - Normal Traffic

```
[ ] Scenario A: Baseline normal traffic
    [ ] Run: h_web1 iperf -s; h_pc1 iperf -c 10.0.2.10
    [ ] Duration: 5 mins
    [ ] Expected: 1000-5000 pps
    [ ] Capture: data/raw/normal_baseline_5min.pcap

[ ] Scenario B: Mixed normal services
    [ ] DNS queries: h_pc1 dig @10.0.2.11
    [ ] Web browsing: h_pc1 curl http://10.0.2.10
    [ ] FTP: vsftpd on h_db1
    [ ] Duration: 10 mins
    [ ] Capture: data/raw/normal_mixed_10min.pcap

[ ] Scenario C: Background traffic (reference)
    [ ] Light traffic: h_pc2 ping 10.0.2.10 (1 pps)
    [ ] Duration: 5 mins
    [ ] Capture: data/raw/normal_light_5min.pcap
```

**Deliverable 3.1a:** `normal_*.pcap` files (≥500MB total)

### 3.2 Data Collection - DoS Attack Traffic

```
[ ] Attack Scenario A: Single-source SYN Flood
    [ ] Attacker: h_att1 hping3 -S -p 80 --flood 10.0.2.10
    [ ] Duration: 2 mins
    [ ] Expected attack: 10k-50k pps
    [ ] Capture before block: data/raw/dos_synflood_2min.pcap

[ ] Attack Scenario B: Single-source UDP Flood
    [ ] Attacker: h_att1 udp-flood (custom tool) 10.0.2.10
    [ ] Duration: 2 mins
    [ ] Expected: 20k-100k pps
    [ ] Capture: data/raw/dos_udpflood_2min.pcap

[ ] Attack Scenario C: IP Spoofing Attack
    [ ] Attacker: h_att1 custom spoof script
    [ ] Spoof random sources (varies every packet)
    [ ] High entropy IPs
    [ ] Duration: 2 mins
    [ ] Capture: data/raw/dos_spoof_2min.pcap

[ ] Attack Scenario D: Distributed (simulated)
    [ ] Multiple attackers: h_att1, h_ext1 + script
    [ ] Each sends 5k pps to h_web1
    [ ] Total: ~10k pps from different sources
    [ ] Duration: 2 mins
    [ ] Capture: data/raw/dos_distributed_2min.pcap

[ ] Attack Scenario E: Slow/Stealthy Attack
    [ ] Attacker: low rate (500 pps) but sustained
    [ ] Pattern: regular intervals, fixed size
    [ ] Expected: hard to detect, may be FP for alert
    [ ] Duration: 5 mins
    [ ] Capture: data/raw/dos_stealthy_5min.pcap
```

**Deliverable 3.2:** `dos_*.pcap` files (≥500MB total, labeled)

### 3.3 Feature Extraction Pipeline

```
[ ] Task: Parse pcap → extract flows → compute features

[ ] Create script `feature_extraction.py`:
    [ ] Input: pcap file
    [ ] Output: CSV with columns:
        - src_ip, dst_ip, src_port, dst_port, protocol
        - flow_duration (seconds)
        - total_fwd_packets, total_bwd_packets
        - total_fwd_bytes, total_bwd_bytes
        - fwd_pkt_rate (pkt/sec)
        - fwd_byte_rate (bytes/sec)
        - bwd_pkt_rate, bwd_byte_rate
        - min_fwd_pkt_size, max_fwd_pkt_size, mean_fwd_pkt_size
        - fwd_pkt_len_std, bwd_pkt_len_std
        - fwd_iat_mean, fwd_iat_std (inter-arrival time)
        - tcp_flags_diversity (unique flags in flow)
        - entropy_src_ip, entropy_dst_port
        - label: NORMAL / FLOOD / SPOOF

    [ ] Handle edge cases:
        - Empty pcap
        - Corrupted packets
        - Single-packet flows
        - IPv6 (skip or handle separately)

    [ ] Output format:
        - CSV: `data/features/flows_<label>_extracted.csv`
        - Stats: row count, null values, class distribution
```

**Deliverable 3.3a:** `feature_extraction.py` (500+ lines)

### 3.4 Data Labeling & Validation

```
[ ] Auto-label based on source:
    [ ] normal_*.pcap → NORMAL (0)
    [ ] dos_synflood_*.pcap → FLOOD (1)
    [ ] dos_udpflood_*.pcap → FLOOD (1)
    [ ] dos_spoof_*.pcap → SPOOF (1) or FLOOD (1)
    [ ] dos_distributed_*.pcap → FLOOD (1)
    [ ] dos_stealthy_*.pcap → FLOOD (1)

[ ] Manual verification:
    [ ] Check 100 random rows per pcap
    [ ] Verify expected features (rate, entropy, etc.)
    [ ] Flag suspicious/edge-case flows

[ ] Handle imbalance:
    [ ] Check class distribution
    [ ] If NORMAL >> FLOOD, downsample or weight
    [ ] Document sampling strategy
```

**Deliverable 3.4:** Labeled dataset CSV, validation report

### 3.5 Data Preprocessing & Normalization

```
[ ] Missing value handling:
    [ ] Identify columns with NaNs
    [ ] Drop rows with >30% missing
    [ ] Impute mean/median for <5% missing

[ ] Outlier detection:
    [ ] Use IQR or Z-score (Z > 3)
    [ ] Flag outliers but keep them
    [ ] Document distribution

[ ] Feature scaling:
    [ ] StandardScaler: (x - mean) / std
    [ ] Apply to training set, fit then transform test
    [ ] Keep scaling params for inference

[ ] Feature engineering (optional):
    [ ] Polynomial features (rate^2, duration^2)
    [ ] Interaction terms (rate * entropy)
    [ ] Log-transform for skewed features

[ ] Create train/val/test split:
    [ ] Time-ordered or stratified random
    [ ] Save to: `data/train.csv`, `data/val.csv`, `data/test.csv`
    [ ] Document split strategy
```

**Deliverable 3.5:** `preprocessing.py`, train/val/test CSVs, scaler file

### 3.6 Dataset Documentation

```
[ ] Create `DATASET_DESCRIPTION.md`:
    [ ] Schema: column names, types, ranges, meanings
    [ ] Size: total rows, per class, train/val/test split
    [ ] Features: 20+ features with descriptions
    [ ] Class distribution: histograms
    [ ] Missing values: %
    [ ] Data collection procedure
    [ ] Ground truth labeling method
    [ ] Known issues/limitations
```

**Deliverable 3.6:** `DATASET_DESCRIPTION.md` (1000+ words)

---

## 🤖 PHAN IV - PHUONG PHAP PHAT HIEN

### 4.1 Entropy-based Detection (Baseline từ codebase)

```
[ ] Task: Review & validate existing entropy method

[ ] Understand implementation:
    [ ] Window size = 1000 packets
    [ ] Shannon entropy = -Σ p_i * log2(p_i)
    [ ] ENTROPY_HIGH = 8.0 (spoof suspicion)
    [ ] ENTROPY_LOW = 1.5 (single IP suspicion)

[ ] Create validation script:
    [ ] Synthetic test cases:
        - Single IP → entropy ~0
        - 10 uniform IPs → entropy ~3.3
        - 1000 random IPs → entropy ~9.97
    [ ] Verify entropy calculation correctness

[ ] Test on real pcap:
    [ ] Run on normal_*.pcap
    [ ] Run on dos_flood_*.pcap
    [ ] Run on dos_spoof_*.pcap
    [ ] Plot entropy timeline

[ ] Measure performance:
    [ ] True Positive Rate (detect attack)
    [ ] False Positive Rate (false alarm on normal)
    [ ] Latency: time to compute entropy (should be <10ms)
```

**Deliverable 4.1:** `entropy_validator.py`, performance report

### 4.2 Machine Learning Baseline (3 models)

```
[ ] Task A: Random Forest
    [ ] Hyperparameters:
        - n_estimators = 50-100 (test multiple)
        - max_depth = 10-20
        - min_samples_split = 5-10
        - class_weight = 'balanced' (handle imbalance)

    [ ] Training:
        [ ] Load train.csv
        [ ] Fit on 70% data
        [ ] Validate on 20% data
        [ ] Save model to: `models/rf_model.pkl`

    [ ] Evaluation on test set:
        [ ] Compute: Precision, Recall, F1, ROC-AUC
        [ ] Generate confusion matrix
        [ ] Feature importance (top 10)
        [ ] Training time, inference time per batch

    [ ] Hyperparameter tuning:
        [ ] Grid search: test 5-10 configurations
        [ ] 5-fold cross-validation
        [ ] Select best based on F1-score

[ ] Task B: XGBoost
    [ ] Hyperparameters:
        - max_depth = 5-8
        - learning_rate = 0.01-0.1
        - n_estimators = 100-500
        - scale_pos_weight = NORMAL_COUNT / ATTACK_COUNT

    [ ] Similar training/eval as RF
    [ ] Save: `models/xgb_model.pkl`
    [ ] Feature importance comparison

[ ] Task C: LightGBM (optional, faster)
    [ ] Hyperparameters:
        - num_leaves = 31-64
        - learning_rate = 0.01-0.1
        - n_estimators = 100-500

    [ ] Training/eval same as RF/XGBoost
    [ ] Save: `models/lgb_model.pkl`
    [ ] Compare latency vs XGBoost

[ ] Comparison table:
    [ ] Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Train Time | Infer Time (ms)
```

**Deliverable 4.2:**

- `ml_train.py` (train all 3 models)
- 3 model files (pkl)
- `ML_RESULTS.md` (comparison, feature importance, analysis)

### 4.3 Deep Learning Models

```
[ ] Task A: 1D-CNN for DoS Detection
    [ ] Architecture:
        - Input: (batch_size, 20, feature_dim=23)
          - 20 consecutive flows
          - 23 features each
        - Conv1D: 32 filters, kernel=3, ReLU
        - MaxPool1D: pool=2
        - Conv1D: 64 filters, kernel=3, ReLU
        - MaxPool1D: pool=2
        - Flatten
        - Dense: 128 ReLU
        - Dropout: 0.3
        - Dense: 1 Sigmoid

    [ ] Training:
        [ ] Prepare sequences (sliding window)
        [ ] Split 70/20/10 (or time-series)
        [ ] Batch size = 32
        [ ] Epochs = 50-100 (with early stopping)
        [ ] Loss = binary_crossentropy
        [ ] Optimizer = Adam (lr=0.001)
        [ ] Validation split = 0.2

    [ ] Evaluation:
        [ ] Test loss & accuracy
        [ ] ROC-AUC, Precision, Recall, F1
        [ ] Confusion matrix

    [ ] Save: `models/cnn_model.h5`, `models/cnn_scaler.pkl`

[ ] Task B: LSTM (Temporal Modeling)
    [ ] Architecture:
        - Input: (batch_size, 20, 23)
        - LSTM: 64 units, return_sequences=True
        - LSTM: 32 units
        - Dense: 64 ReLU
        - Dropout: 0.3
        - Dense: 1 Sigmoid

    [ ] Training:
        [ ] Same as CNN
        [ ] Epochs = 50-100

    [ ] Evaluation:
        [ ] ROC-AUC, F1, latency
        [ ] Compare to CNN

    [ ] Save: `models/lstm_model.h5`

[ ] Task C: Autoencoder (Unsupervised/Semi-supervised)
    [ ] Architecture (Encoder-Decoder):
        - Encoder:
          - Dense(input_dim=23, 16, ReLU)
          - Dense(16, 8, ReLU)
          - Dense(8, 4, ReLU) ← bottleneck
        - Decoder:
          - Dense(4, 8, ReLU)
          - Dense(8, 16, ReLU)
          - Dense(16, 23, ReLU)
        - Output: reconstruction of input

    [ ] Training:
        [ ] Train on NORMAL data only (unsupervised)
        [ ] Loss = MSE (reconstruction error)
        [ ] Epochs = 100

    [ ] Inference:
        [ ] Compute reconstruction error on all data
        [ ] Threshold: normal ~low error, attack ~high error
        [ ] Tune threshold on val set

    [ ] Evaluation:
        [ ] ROC-AUC, F1 (compare to supervised baselines)
        [ ] Advantage: no labeled attack data needed

    [ ] Save: `models/autoencoder_model.h5`

[ ] Comparison:
    [ ] CNN vs LSTM vs Autoencoder vs RF vs XGBoost
    [ ] Metrics: F1, ROC-AUC, Latency, Throughput, Memory
```

**Deliverable 4.3:**

- `dl_train_cnn.py`, `dl_train_lstm.py`, `dl_train_autoencoder.py`
- 3 model files (h5)
- `DL_RESULTS.md` (comparison, convergence plots, analysis)

### 4.4 Real-time Inference Module

```
[ ] Task: Create live detection pipeline

[ ] Create `real_time_detector.py`:
    [ ] Listen to traffic source:
        - Option A: pcap live capture (tcpdump)
        - Option B: InfluxDB flow stats
        - Option C: Socket from router

    [ ] Batch flows every 1 second:
        [ ] Collect up to 50 flows
        [ ] Extract features
        [ ] Normalize using saved scaler
        [ ] Run inference (Entropy + ML + DL)

    [ ] Output predictions:
        [ ] Timestamp, flows, predictions, confidence
        [ ] Alert if consensus detect (e.g., 2/3 methods agree)
        [ ] Log to file + stdout

    [ ] Performance measurement:
        [ ] Latency: time from packet arrival → alert (should <100ms)
        [ ] Throughput: flows/sec (should >1000)
        [ ] CPU usage, memory footprint

    [ ] Load testing:
        [ ] Simulate 10k pps traffic
        [ ] Measure latency/throughput degradation
        [ ] Document bottlenecks
```

**Deliverable 4.4:**

- `real_time_detector.py`
- `REALTIME_BENCHMARK.md` (latency, throughput, resource usage)

---

## ✅ PHAN V - DANH GIA & SO SANH

### 5.1 Benchmark Experiments

```
[ ] Experiment A: Baseline accuracy comparison
    [ ] Run 5 methods on test set:
        1. Entropy
        2. Random Forest
        3. XGBoost
        4. CNN
        5. LSTM / Autoencoder

    [ ] For each method:
        [ ] Accuracy, Precision, Recall, F1
        [ ] ROC-AUC, specificity
        [ ] Confusion matrix

    [ ] Create comparison table (spreadsheet)
    [ ] Statistical test (e.g., McNemar's test for significance)

[ ] Experiment B: Real-time latency comparison
    [ ] Run each method on live pcap (10k pps)
    [ ] Measure: time from packet in → alert out
    [ ] Expected:
        - Entropy: <5ms (simplest)
        - RF/XGBoost: 10-50ms
        - CNN/LSTM: 50-200ms (GPU faster)
        - Autoencoder: 20-100ms

[ ] Experiment C: Robustness under attack variation
    [ ] Test on unseen attack types:
        - DNS amplification (not in training)
        - Slowloris (slow, sustained)
        - Mixture of attacks
    [ ] Measure: false negative rate (miss new attacks)

[ ] Experiment D: Class imbalance impact
    [ ] Downsample normal: 1:1, 1:5, 1:20 ratio
    [ ] Measure: F1, Precision-Recall curve
    [ ] Recommend best ratio
```

**Deliverable 5.1:** `BENCHMARK_RESULTS.md`, comparison tables, experiment logs

### 5.2 Visualization & Analysis

```
[ ] Plot 1: ROC Curves (overlay 5 methods)
    [ ] X-axis: FPR, Y-axis: TPR
    [ ] Add AUC values in legend

[ ] Plot 2: PR Curves (Precision vs Recall)
    [ ] Show trade-off between precision & recall

[ ] Plot 3: Confusion Matrices (heatmaps)
    [ ] One heatmap per method
    [ ] Normalize by true class

[ ] Plot 4: Feature Importance
    [ ] Top 10 features for RF/XGBoost
    [ ] Bar chart

[ ] Plot 5: Latency Distribution
    [ ] Histogram/box plot
    [ ] Methods vs latency (ms)
    [ ] Percentiles (p50, p95, p99)

[ ] Plot 6: Temporal Detection (timeline)
    [ ] X: time (sec), Y: detection method
    [ ] Show when each method detects attack

[ ] Plot 7: Throughput vs Accuracy
    [ ] Scatter: throughput (flows/sec) vs F1
    [ ] Show trade-off curve
```

**Deliverable 5.2:** `visualization.py`, output PDFs/PNGs

### 5.3 Error Analysis

```
[ ] Analyze false positives:
    [ ] Find flows misclassified as ATTACK (but NORMAL)
    [ ] Check characteristics (why confused?)
    [ ] Can threshold adjustment help?

[ ] Analyze false negatives:
    [ ] Find flows misclassified as NORMAL (but ATTACK)
    [ ] Identify attack types methods missed
    [ ] Need more data/features?

[ ] Create error analysis report:
    [ ] Top 20 FP examples with features
    [ ] Top 20 FN examples with features
    [ ] Recommendation for improvement
```

**Deliverable 5.3:** `ERROR_ANALYSIS.md` (500+ words)

---

## 🎬 KỊCH BẢN DEMO & TEST

### 6.1 Demo Scenario 1: SYN Flood Detection

```
Duration: 5 mins total

Timeline:
[ 0:00-1:00 ] Normal traffic (baseline)
              - Web server (h_web1) running
              - Normal client (h_pc1) making requests
              - Expected: Entropy ~2-3, all methods predict NORMAL
              - Monitor: real-time dashboard

[ 1:00-3:00 ] Start SYN flood attack
              - h_att1 runs: hping3 -S -p 80 --flood 10.0.2.10
              - Packet rate jumps to 10k pps
              - Expected:
                * Entropy drops <1.5 (many from same source)
                * RF/XGBoost: >90% confidence ATTACK
                * CNN/LSTM: >85% confidence ATTACK
              - Alert triggered
              - Router blocks h_att1

[ 3:00-4:00 ] Attack ongoing but blocked
              - Router drops SYN from h_att1
              - Packet rate on h_web1 returns to normal
              - Entropy returns to normal range

[ 4:00-5:00 ] Normal traffic resumes
              - h_att1 blocked (in MAC filter)
              - All methods predict NORMAL again
              - Whitelist restored
```

**Deliverable 6.1:** Demo script, expected output log

### 6.2 Demo Scenario 2: IP Spoofing Detection

```
Duration: 5 mins total

Timeline:
[ 0:00-1:00 ] Normal baseline

[ 1:00-3:00 ] Start IP spoofing attack
              - h_att1 sends packets with random src IPs
              - Packet rate: 5k pps (slower than flood)
              - Expected:
                * Entropy HIGH (~8-9, many different IPs)
                * Different pattern vs flood
                * RF: >85% confidence ATTACK (features distinguish)
                * CNN/LSTM: >80% confidence
                * Entropy alone might have high FP rate
              - Alert triggered

[ 3:00-5:00 ] Attack blocked & recovery
              - Whitelist updated
              - Normal traffic resumes
```

**Deliverable 6.2:** Demo script, expected output

### 6.3 Demo Scenario 3: Stealthy Attack

```
Duration: 10 mins total

Timeline:
[ 0:00-2:00 ] Normal traffic (higher rate, e.g., iperf -b 5M)

[ 2:00-10:00 ] Stealthy attack (slow, hard to detect)
              - h_att1 sends 500 pps (low rate)
              - Mixed src/dst (moderate entropy)
              - Pattern: similar to normal traffic
              - Expected:
                * Entropy: normal range
                * RF/XGBoost: might confuse (~70% confidence)
                * CNN/LSTM: may learn temporal pattern → >75%
                * Autoencoder: high reconstruction error
                * Challenge: can method distinguish from legitimacy?
```

**Deliverable 6.3:** Demo script, analysis of missed detection

### 6.4 Demo Scenario 4: Distributed Attack (Simulated)

```
Duration: 5 mins total

Timeline:
[ 0:00-1:00 ] Normal baseline

[ 1:00-3:00 ] Multiple sources attack
              - h_att1, h_ext1 simultaneously send traffic
              - Each: 5k pps to h_web1
              - Total: ~10k pps from 2 different sources
              - Expected:
                * Entropy: moderate (multiple IPs)
                * Entropy alone might have FP
                * ML methods: >85% confidence (high rate key feature)
                * Real-time module: aggregate stats across sources

[ 3:00-5:00 ] Attack blocked & recovery
```

**Deliverable 6.4:** Demo script

### 6.5 Demo Scenario 5: Model Comparison Under Load

```
Duration: 5 mins total, sustained attack

Measure:
[ ] Latency of each method (ms per batch)
[ ] Throughput (flows/sec sustained)
[ ] False alarm rate (FP on normal background traffic)
[ ] Detection rate on attack (TP rate)

Expected:
- Entropy: fastest (<1ms), but high FP
- RF: medium speed (~20ms), high accuracy
- XGBoost: medium speed (~25ms), similar/better than RF
- CNN: slower (~100ms), high accuracy
- LSTM: slower (~150ms), possible overfitting
- Autoencoder: medium (~50ms), good unsupervised
```

**Deliverable 6.5:** Load test script, comparison table

---

## 📚 THAM KHAO BAI BAO (Links & DOI)

### Group A: Entropy-based Detection

```
[ ] Paper A1:
    Title: "Entropy-Based Anomaly Detection System for TCP Connections"
    Authors: Kaur et al.
    Year: 2012
    Link: IEEE Xplore
    DOI: 10.1109/ICCCS.2012.
    Key: Use entropy on source IPs to detect DDoS

[ ] Paper A2:
    Title: "Flow-based DDoS Detection using Statistical Measures"
    Authors: [Research needed]
    Year: 2015
    Link: Springer
    DOI: [To be found]
    Key: Flow statistics (rate, entropy, duration) for detection

[ ] Paper A3:
    Title: "Real-time Detection of DDoS Attacks using Entropy in SDN"
    Authors: [Research needed]
    Year: 2018
    Link: ACM
    DOI: [To be found]
    Key: Apply entropy in OpenFlow switches
```

### Group B: Machine Learning IDS

```
[ ] Paper B1:
    Title: "Intrusion Detection System Using Machine Learning on Big Data"
    Authors: Sharafaldin et al.
    Year: 2017
    Link: https://www.mdpi.com/1999-5903/8/4/19
    DOI: 10.3390/fi8040019
    Dataset: CICIDS2017
    Key: Benchmark ML models on real attack dataset

[ ] Paper B2:
    Title: "Evaluation of Machine Learning Algorithms for Network-based IDS"
    Authors: [Research needed]
    Year: 2016
    Link: ACM
    DOI: [To be found]
    Key: Compare RF, SVM, Naive Bayes, Decision Tree

[ ] Paper B3:
    Title: "XGBoost for Network Intrusion Detection"
    Authors: [Research needed]
    Year: 2019
    Link: Springer
    DOI: [To be found]
    Key: XGBoost achieves >99% accuracy on UNSW-NB15

[ ] Paper B4:
    Title: "Handling Class Imbalance in Anomaly Detection"
    Authors: [Research needed]
    Year: 2018
    Link: IEEE
    DOI: [To be found]
    Key: SMOTE, weighted loss, cost-sensitive learning
```

### Group C: Deep Learning IDS

```
[ ] Paper C1:
    Title: "Convolutional Neural Networks for Network Traffic Classification"
    Authors: [Research needed]
    Year: 2016
    Link: ACM
    DOI: [To be found]
    Key: CNN for raw traffic or flow-based classification

[ ] Paper C2:
    Title: "Recurrent Neural Networks for Intrusion Detection"
    Authors: Kim et al.
    Year: 2016
    Link: IEEE/ACM
    DOI: [To be found]
    Key: LSTM for temporal patterns in traffic

[ ] Paper C3:
    Title: "Deep Autoencoders for Anomaly Detection"
    Authors: [Research needed]
    Year: 2018
    Link: Springer
    DOI: [To be found]
    Key: Unsupervised learning for anomaly

[ ] Paper C4:
    Title: "Comparison of Deep Learning Architectures for IDS"
    Authors: [Research needed]
    Year: 2020
    Link: IEEE Transactions on Network and Service Management
    DOI: [To be found]
    Key: CNN vs LSTM vs GRU vs Hybrid
```

### Group D: Datasets & Benchmarks

```
[ ] Paper D1:
    Title: "CICIDS2017: Toward Generating a Realistic Intrusion Detection Dataset"
    Authors: Sharafaldin et al.
    Year: 2017
    Link: https://www.mdpi.com/1999-5903/8/4/19
    DOI: 10.3390/fi8040019
    Dataset: Available at: https://www.unb.ca/cic/datasets/ids-2017.html
    Key: 80 features, modern attack types, highly realistic

[ ] Paper D2:
    Title: "UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems"
    Authors: Moustafa et al.
    Year: 2015
    Link: https://ieeexplore.ieee.org/document/7582378
    DOI: 10.1109/ACCESS.2015.2502207
    Dataset: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/UNSW-NB15-Datasets/
    Key: 49 features, 9 attack categories, 2.5GB data
```

### Group E: Advanced Topics

```
[ ] Paper E1:
    Title: "Real-time DDoS Detection using Machine Learning"
    Authors: [Research needed]
    Year: 2019
    Link: IEEE
    DOI: [To be found]
    Key: Optimize inference latency, on-device deployment

[ ] Paper E2:
    Title: "Adversarial Robustness of Deep Learning-based IDS"
    Authors: [Research needed]
    Year: 2020
    Link: CCS/IEEE
    DOI: [To be found]
    Key: Security evaluation, attack generation, defense
```

---

## 📊 SUMMARY: TOTAL WORK ITEMS

```
PHAN I (Nghien cuu):
  [ ] 1.1: Survey 15+ papers, RESEARCH_SURVEY.md
  [ ] 1.2: Attack taxonomy, ATTACK_SCENARIOS.md
  [ ] 1.3: Evaluation protocol, EVALUATION_PROTOCOL.md
  → 3 deliverables

PHAN II (Co so):
  [ ] 2.1: Topology setup (review + enhance)
  [ ] 2.2: Ryu controller (review + enhance)
  [ ] 2.3: Monitoring (InfluxDB, Grafana, capture)
  → 3 deliverables

PHAN III (Du lieu):
  [ ] 3.1: Collect normal traffic (3 scenarios)
  [ ] 3.2: Collect DoS traffic (5 attack scenarios)
  [ ] 3.3: Feature extraction script
  [ ] 3.4: Data labeling & validation
  [ ] 3.5: Preprocessing script + train/val/test split
  [ ] 3.6: Dataset documentation
  → 6 deliverables + 1GB+ data

PHAN IV (Phuong phap):
  [ ] 4.1: Entropy-based validation (review existing)
  [ ] 4.2: ML baseline (RF, XGBoost, LightGBM)
  [ ] 4.3: Deep Learning (CNN, LSTM, Autoencoder)
  [ ] 4.4: Real-time inference module
  → 8 deliverables + 3+ models

PHAN V (Danh gia):
  [ ] 5.1: Benchmark experiments
  [ ] 5.2: Visualization (7 plots)
  [ ] 5.3: Error analysis
  → 3 deliverables

DEMO & TEST:
  [ ] 6.1-6.5: 5 demo scenarios, test scripts
  → 5 demo scripts

TOTAL: 30+ technical deliverables + 1GB data + 5 demo scenarios
```

---

## 🎯 SUCCESS CRITERIA (Huong toi 10 diem)

```
✅ Code Quality (3 diem):
  [ ] ≥50 test cases (unittest/pytest)
  [ ] Code coverage ≥80%
  [ ] Reproducible (seed, requirements.txt, README)
  [ ] Clean code (PEP8, docstrings, comments)

✅ Technical Depth (3 diem):
  [ ] 3+ detection methods (entropy, ML, DL)
  [ ] 5+ attack scenarios tested
  [ ] Real-time inference (<100ms latency)
  [ ] Benchmark with comparison table

✅ Scientific Rigor (2 diem):
  [ ] 15+ papers cited
  [ ] Dataset description & splitting strategy
  [ ] Evaluation metrics properly defined
  [ ] Statistical analysis (p-values, confidence intervals)

✅ Presentation (2 diem):
  [ ] 20-min slide (clear structure)
  [ ] Demo video or live demo
  [ ] Q&A preparedness
  [ ] GitHub repo (clean, documented)
```

---

**Status:** WBS Complete  
**Next Step:** Assign to 5 members based on this breakdown
