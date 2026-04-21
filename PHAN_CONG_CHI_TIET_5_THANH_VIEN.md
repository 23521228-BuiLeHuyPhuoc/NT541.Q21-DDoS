# PHÂN CÔNG CHI TIẾT - 5 THÀNH VIÊN

**Dựa trên:** WORK_BREAKDOWN_FULL.md + REFERENCES_PAPERS.md  
**Mục tiêu:** Rõ ràng từng người làm gì, deadline, deliverable  
**Format:** Bảng chi tiết công việc theo tuần

---

## 📋 BẢNG PHÂN CÔNG TOÀN DỰ ÁN

| STT | Thành viên | Tuần | Task | Chi tiết công việc | Deadline | Sản phẩm |
|-----|-----------|------|------|-------------------|----------|---------|
| **1.1** | **Thành viên 1: Trần Minh Khoa** (Trưởng nhóm, Nghiên cứu) | 1-2 | **Survey & Tổng hợp Bài Báo** | • Đọc 15+ papers (A1-A3: entropy; B1-B4: ML; C1-C4: DL; D1-D2: dataset; E1-E3: survey)<br>• Tổng hợp: phương pháp, độ chính xác, latency, ưu nhược điểm<br>• Tạo bảng so sánh entropy vs ML vs DL<br>• Liệt kê 20+ features từ các paper<br>• Ghi chú: lỗ hổng lý thuyết, khoảng trống trong phương pháp hiện tại | Hết tuần 2 | `RESEARCH_SURVEY.md` (3000+ từ, 15+ papers cited, IEEE format) |
| **1.2** | **Thành viên 1** | 1-2 | **Định nghĩa Protocol Đánh giá** | • Định nghĩa metrics: Accuracy, Precision, Recall, F1, ROC-AUC, Specificity<br>• Performance metrics: Latency (ms), Throughput (flows/sec), Memory (MB), CPU (%)<br>• Attack-specific: TPR/FNR per attack type<br>• Dataset split: 70% train (time-ordered), 20% val, 10% test<br>• Thresholds: Entropy_low<1.5, Entropy_high>8.0<br>• Acceptance criteria: F1≥0.85, Latency≤100ms, Throughput≥1000 flows/sec | Hết tuần 2 | `EVALUATION_PROTOCOL.md` (500+ từ, công thức, ví dụ tính toán) |
| **1.3** | **Thành viên 1** | 3-5 | **Code Review & QA Oversight** | **Tuần 3:** Review data collection scripts, feature_extraction.py, kiểm tra data quality<br>**Tuần 4:** Review ML code (split/hyperparams/results), DL code (architecture/convergence), test suite<br>**Tuần 5:** Final reproducibility check, documentation, deliverables đầy đủ | Tuần 5 | `CODE_REVIEW_CHECKLISTS.md` (per week), Approval sign-off |
| **1.4** | **Thành viên 1** | 4-5 | **Viết báo cáo cuối cùng** | • Introduction (2 trang): problem DDoS, khó detect, contributions<br>• Related Work (3 trang): A-series entropy, B-series ML, C-series DL, gap analysis<br>• Methodology (4 trang): kiến trúc, dataset, features, 3 methods<br>• Results (5 trang): bảng metrics, plots (ROC, PR, confusion matrix), error analysis<br>• Discussion (4 trang): so sánh, limitations, future work<br>• Conclusion (1 trang): tóm tắt, khuyến nghị<br>• Appendix (4+ trang): features list, hyperparams, architectures | Tuần 5 | `FINAL_REPORT.md` (30+ trang PDF, IEEE format toàn bộ) |
| **2.1** | **Thành viên 2: Hoàng Minh Đức** (Data & Lab) | 1 | **Cài đặt Lab Environment** | • Ubuntu 18.04+: Mininet, Ryu, Scapy, tshark, tcpdump<br>• Review topology (5 switches, 8 hosts, IP config)<br>• Verify connectivity: ping test h_pc1→h_web1, h_att1→h_web1<br>• Setup Ryu controller: port 6653, verify "connected" logs<br>• Test capture: tcpdump trên s2, verify pcap packets<br>• Tạo dir: data/raw, data/features, logs | Hết tuần 1 | `setup_environment.sh` (tự động), `LAB_SETUP_GUIDE.md`, Mininet+Ryu chạy OK |
| **2.2** | **Thành viên 2** | 2 | **Thu thập lưu lượng bình thường** | **Scenario A (Baseline):** h_web1 iperf -s -p 80, h_pc1 iperf -c 10.0.2.10 -t 300 → 5 mins → ~150MB pcap<br>**Scenario B (Mixed services):** DNS (dig @10.0.2.11), HTTP (curl), FTP, NTP → 10 mins → ~200MB<br>**Scenario C (Light):** h_pc2 ping 10.0.2.10 -i 1 → 5 mins → ~5MB<br>• Tạo logs: start time, stop time, packet count, pps rate | Hết tuần 2 | `data/raw/normal_*.pcap` (3 files, ≥500MB), `logs/normal_*.log` (metadata) |
| **2.3** | **Thành viên 2** | 2-3 | **Thu thập lưu lượng tấn công DoS** | **Attack A (SYN Flood):** h_att1 hping3 -S -p 80 --flood 10.0.2.10 → 2 mins → ~150MB, PPS=20k+<br>**Attack B (UDP Flood):** h_att1 UDP flood script → 2 mins → ~150MB<br>**Attack C (IP Spoofing):** h_att1 random source IP → 2 mins → ~150MB, high entropy<br>**Attack D (Distributed):** h_att1+h_ext1 cùng flood → 2 mins → ~100MB<br>**Attack E (Stealthy):** 1 conn/sec, 5 mins → ~30MB, hard to detect<br>• Gắn nhãn: FLOOD, SPOOF, classification | Hết tuần 3 | `data/raw/dos_*.pcap` (5 files, ≥500MB), `logs/dos_*.log` (attack type, PPS) |
| **2.4** | **Thành viên 2** | 3-4 | **Feature Extraction Pipeline** | • Parse pcap: Scapy/pyshark<br>• Extract per flow: src/dst IP/port, protocol, duration, fwd/bwd packets, bytes, rates, flags, entropy, size distribution<br>• **20+ features:** flow_duration, total_fwd_packets, total_bwd_packets, fwd_pkt_rate, entropy_src_ip, entropy_dst_port, min/max/mean pkt size, etc.<br>• Handle edge cases: empty pcap, corrupted packets, single-packet flows<br>• Output CSV: normal_all.csv, dos_all.csv → merge → flows_labeled_ALL.csv (2.5M+ flows, 20+ cols)<br>• Validation: <1% nulls, ranges OK, class distribution | Hết tuần 4 | `feature_extraction.py` (300+ lines), `flows_labeled_ALL.csv` (2.5M rows), `VALIDATION_REPORT.txt`, `DATASET_DESCRIPTION.md` |
| **2.5** | **Thành viên 2** | 4 | **Tiền xử lý dữ liệu** | • Handle nulls: drop/impute mean (<1%)<br>• Outlier detection: IQR method, flag but keep<br>• StandardScaler: fit on train only, apply to val/test<br>• Time-ordered split: 70% train (Day 1-3), 20% val (Day 4), 10% test (Day 5)<br>• Save: train.csv, val.csv, test.csv, scaler.pkl<br>• Create report: null %, outliers %, balance, scaling info | Hết tuần 4 | `preprocessing.py` (150+ lines), train/val/test.csv, scaler.pkl, `PREPROCESSING_REPORT.txt` |
| **3.1** | **Thành viên 3: Nguyễn Văn Tuấn** (ML) | 3-4 | **Random Forest Training** | • Load train/val/test CSVs<br>• Grid search: n_estimators [50,100,200], max_depth [10-20], min_samples_split [5,10], class_weight='balanced'<br>• 5-fold CV, F1 score metric<br>• Train best model, evaluate: Accuracy, Precision, Recall, F1, ROC-AUC<br>• Feature importance: top 10 plot<br>• Save model: models/rf_model.pkl, results: rf_results.json | Hết tuần 4 | `ml_rf_train.py` (200+ lines), rf_model.pkl, rf_results.json, feature_importance.png |
| **3.2** | **Thành viên 3** | 4 | **XGBoost & LightGBM Training** | • XGBoost: max_depth [5-8], learning_rate [0.01-0.1], n_estimators [100-500], scale_pos_weight<br>• LightGBM: num_leaves [31-64], similar hyperparams<br>• Comparison table: RF vs XGB vs LGB (Acc, Prec, Recall, F1, AUC, latency)<br>• Plot: ROC curves overlay, confusion matrices (3 subplots) | Hết tuần 4 | `ml_xgboost_train.py`, `ml_lightgbm_train.py`, xgb/lgb models, `ml_comparison.csv`, plots |
| **3.3** | **Thành viên 3** | 4-5 | **Real-time ML Inference** | • Load best model (XGBoost)<br>• Batch predictions: measure latency <50ms/batch<br>• Measure throughput: >1000 flows/sec<br>• Benchmark different traffic rates: 1k, 10k, 100k pps<br>• Create latency vs throughput plot | Hết tuần 5 | `ml_realtime_inference.py`, `ml_benchmark.py`, `ml_realtime_benchmark.json`, latency_throughput.png |
| **3.4** | **Thành viên 3** | 5 | **Error Analysis & ML Results** | • False positives: identify confusion examples, analyze feature patterns<br>• False negatives: similar analysis<br>• Generate visualizations: scatter plots FP/FN in feature space<br>• Write ML_RESULTS.md: comparison table, feature importance, error patterns, recommendations | Hết tuần 5 | `ml_error_analysis.py`, `ML_RESULTS.md` (2000+ từ), fp_analysis.png, fn_analysis.png |
| **4.1** | **Thành viên 4: Phạm Hoàng Nam** (DL) | 3-4 | **Chuẩn bị dữ liệu cho DL** | • Convert flow-level → sequences (sliding window size=20)<br>• Stride=1 (overlap by 19)<br>• Target: next flow's label (NORMAL/ATTACK)<br>• Output shape: (N, 20, 23) - N sequences, 20 flows, 23 features<br>• Create X_train_seq, y_train_seq, X_val_seq, y_val_seq, X_test_seq, y_test_seq | Hết tuần 4 | `dl_sequence_preparation.py`, X_train_seq.npy, y_train_seq.npy, etc. |
| **4.2** | **Thành viên 4** | 4 | **Huấn luyện CNN 1D** | • Architecture: Conv1D(32, 3) → MaxPool → Conv1D(64, 3) → MaxPool → Flatten → Dense(128) → Dropout(0.3) → Dense(1, sigmoid)<br>• Optimizer: Adam(lr=0.001)<br>• Loss: binary_crossentropy<br>• Train: 50 epochs, batch_size=32, EarlyStopping patience=5<br>• Expected: F1≈0.98, latency≈120ms<br>• Plot training history (loss & accuracy) | Hết tuần 4 | `dl_cnn_train.py` (200+ lines), cnn_model.h5, cnn_training_history.png, metrics JSON |
| **4.3** | **Thành viên 4** | 4 | **Huấn luyện LSTM** | • Architecture: LSTM(64, return_seq=True) → LSTM(32) → Dense(64) → Dropout(0.3) → Dense(1, sigmoid)<br>• Similar training setup<br>• Expected: F1≈0.975, latency≈200ms<br>• Slower than CNN but captures temporal patterns | Hết tuần 4 | `dl_lstm_train.py` (200+ lines), lstm_model.h5, lstm_training_history.png |
| **4.4** | **Thành viên 4** | 4 | **Autoencoder (Unsupervised)** | • Train on NORMAL data only<br>• Architecture: Dense(16) → Dense(8) → Dense(4) [bottleneck] → Dense(8) → Dense(16) → Dense(23)<br>• Loss: MSE<br>• Inference: reconstruction_error = mean((X - X_reconstructed)^2)<br>• Threshold tuning: maximize F1 on val set<br>• Expected: F1≈0.96, latency≈50ms | Hết tuần 4 | `dl_autoencoder_train.py` (200+ lines), autoencoder_model.h5, threshold.json |
| **4.5** | **Thành viên 4** | 4-5 | **So sánh mô hình DL** | • Load all 3 models (CNN, LSTM, AE)<br>• Evaluate test set: Acc, Prec, Recall, F1, ROC-AUC, latency, memory<br>• Create comparison table: CNN (98.2% F1, 120ms) vs LSTM (97.5%, 200ms) vs AE (96%, 50ms)<br>• Recommendation: CNN best balance | Hết tuần 5 | `dl_compare.py`, comparison table & plots |
| **4.6** | **Thành viên 4** | 5 | **Real-time DL Inference** | • Load CNN model (best)<br>• Real-time inference on sequences<br>• Measure end-to-end latency, throughput<br>• Benchmark different traffic rates<br>• Optional: quantization (float32 → float16/int8) để tối ưu tốc độ | Hết tuần 5 | `dl_realtime_inference.py` (150+ lines), `dl_benchmark.py`, benchmark.json, plot |
| **4.7** | **Thành viên 4** | 5 | **Tài liệu DL** | • Tổng hợp architectures (với diagram)<br>• Training history plots<br>• Comparison conclusions<br>• Best model recommendation<br>• Real-time performance summary | Hết tuần 5 | `DL_RESULTS.md` (2000+ từ), all plots/diagrams |
| **5.1** | **Thành viên 5: Hoàng Anh Đức** (QA+Test) | 4-5 | **Test Suite Development** | **Functional tests:**<br>• `test_feature_extraction.py` (15+ cases): empty pcap, corrupted packets, single flows, feature ranges, nulls, schema<br>• `test_preprocessing.py` (10+ cases): scaling, train/test split, data leakage, consistency<br>• `test_ml_models.py` (15+ cases): RF fit, predict shape, model comparison, latency, class imbalance<br>• `test_dl_models.py` (10+ cases): CNN/LSTM/AE shapes, inference, reconstruction<br>• `test_attack_detection.py` (15+ integration tests): SYN flood detect, spoof detect, stealthy hard cases<br>**Total: 50+ tests, Coverage ≥80%** | Hết tuần 5 | `test_*.py` files (50+ tests), coverage report (≥80%), TEST_REPORT.txt |
| **5.2** | **Thành viên 5** | 5 | **Visualization & Dashboards** | • Plot 1: ROC curves (overlay all 6 methods)<br>• Plot 2: PR curves<br>• Plot 3: Confusion matrices (6 subplots)<br>• Plot 4: Feature importance (top 15)<br>• Plot 5: Latency comparison (bar chart)<br>• Plot 6: Accuracy vs Latency (scatter)<br>• Plot 7: Class distribution (pie)<br>• Optional: Plotly interactive dashboard | Hết tuần 5 | `visualization.py` (300+ lines), 7+ plots, dashboard.html (optional) |
| **5.3** | **Thành viên 5** | 5 | **Test Report** | • Test strategy: unit, integration, performance, security<br>• Execution results: 50+ tests, 100% pass, 82% coverage<br>• Known issues (nếu có)<br>• Recommendations<br>• Detailed test results table | Hết tuần 5 | `TEST_REPORT.md` (1000+ từ) |
| **5.4** | **Thành viên 5** | 5 | **Chuẩn bị thuyết trình** | • **20 slides:**<br>  - 1: Title<br>  - 2-3: Problem & Motivation<br>  - 4-5: Related Work<br>  - 6-7: System Architecture<br>  - 8-9: Dataset & Features<br>  - 10: Entropy results<br>  - 11-12: ML results<br>  - 13-15: DL results<br>  - 16-17: Comparison (accuracy vs latency)<br>  - 18: Demo & Live Testing<br>  - 19: Conclusions<br>  - 20: Q&A<br>• **Q&A Script:** 30 typical questions + answers<br>• **Rehearsal:** Practice 20-min presentation | Hết tuần 5 | `PRESENTATION_SLIDES.pptx` (20 slides), `QA_SCRIPT.md` (30 Q&A), speaker notes |
| **5.5** | **Thành viên 5** | 5 | **Final Integration** | • Create `FINAL_INTEGRATION_REPORT.md`: executive summary, reproduce instructions, file structure<br>• Create/update `README.md`: project overview, quick start, results summary<br>• GitHub org: clean structure, .gitignore, requirements.txt<br>• Tag: v1.0-final-submission<br>• Push all files | Hết tuần 5 | `FINAL_INTEGRATION_REPORT.md`, `README.md`, GitHub v1.0-final-submission |

---

## 📊 TÓNG KẾT NỖ LỰC & DELIVERABLES

| Thành viên | Vai trò | Nỗ lực | Tuần | Tasks | Deliverables |
|-----------|--------|-------|------|-------|--------------|
| **1** | Trưởng nhóm + Nghiên cứu | 30% làm + 70% quản lý | 1-5 | 4 | 4 docs (Survey, Protocol, Review, Report) |
| **2** | Data & Lab Engineer | 95% làm + 5% doc | 1-5 | 5 | 5 scripts + datasets (16 files pcap) |
| **3** | ML Engineer | 95% làm + 5% doc | 3-5 | 4 | 5 scripts + 3 models + results |
| **4** | DL Engineer | 95% làm + 5% doc | 3-5 | 7 | 7 scripts + 3 models + results |
| **5** | QA + Presentation | 70% làm + 30% thuyết trình | 4-5 | 5 | 5 scripts + tests + slides |
| **TOTAL** | 5 người | **Cân bằng** | **5 tuần** | **~25 tasks** | **50+ deliverables** |

---

## ✅ TIÊU CHÍ ĐẠT 10 ĐIỂM

| Tiêu chí | Yêu cầu | Trách nhiệm |
|---------|--------|-----------|
| **Code Quality (3 điểm)** | 50+ test cases (pytest), 80%+ code coverage, PEP8 clean code, reproducible setup | Thành viên 5 + all |
| **Technical Depth (3 điểm)** | 3+ methods (entropy, ML, DL) working, 5+ attack scenarios, latency <100ms, comparison table | Thành viên 2, 3, 4 |
| **Scientific Rigor (2 điểm)** | 15+ papers cited (IEEE), dataset >1GB labeled, all metrics defined, error analysis | Thành viên 1 + 2 |
| **Presentation (2 điểm)** | 20-slide deck, demo working, 30-question Q&A script, GitHub documentation | Thành viên 5 + 1 |

---

**Status:** READY FOR EXECUTION ✅

**Checklist:**

```
[ ] Read Group A papers (A1, A2, A3):
    [ ] Paper A1: Entropy anomaly detection (2012)
    [ ] Paper A2: Flow-based detection (2014)
    [ ] Paper A3: SDN DDoS detection (2019)
    → Note: method, accuracy, latency, pros/cons

[ ] Read Group B papers (B1-B4):
    [ ] Paper B1: CICIDS2017 dataset
    [ ] Paper B2: UNSW-NB15 dataset
    [ ] Paper B3: ML comparison (RF, XGBoost)
    [ ] Paper B4: Class imbalance handling
    → Note: features, dataset size, performance

[ ] Read Group C papers (C1-C4):
    [ ] Paper C1: CNN for traffic
    [ ] Paper C2: LSTM for IDS
    [ ] Paper C3: Autoencoder
    [ ] Paper C4: DL comparison
    → Note: architecture, accuracy, latency

[ ] Read Group D & E papers (D1, D2, E1-E3):
    [ ] Paper D1: CICIDS2017 full (get dataset link)
    [ ] Paper D2: UNSW-NB15 full (get dataset link)
    [ ] Paper E1: Real-time detection
    [ ] Paper E2: Adversarial robustness (optional)
    [ ] Paper E3: ML IDS survey

[ ] Create RESEARCH_SURVEY.md:
    [ ] Table 1: Method comparison
        | Method | Year | Accuracy | Latency | Pros | Cons |
        | Entropy | 2012 | 85% | <1ms | Fast, simple | Limited precision |
        | RF | 2015 | 97% | 20ms | Balanced | Moderate latency |
        | XGBoost | 2015 | 98.8% | 25ms | High accuracy | Slower |
        | CNN | 2015 | 98.2% | 100ms | Spatial | Slow |
        | LSTM | 2016 | 97.5% | 150ms | Temporal | Very slow |
        | Autoencoder | 2016 | 96% | 50ms | Unsupervised | May miss novel |

    [ ] For each paper: 200-300 word summary
        - Title, authors, year, venue, DOI
        - Problem addressed
        - Method (brief)
        - Results (key metrics)
        - Relevance to our project
        - Citation (IEEE format)

    [ ] Section: "Dataset Comparison"
        - CICIDS2017: 80 features, 2.8M flows, 98.8% RF baseline
        - UNSW-NB15: 49 features, 2.5GB, 96% DL baseline
        - Lab-generated: custom, 5 attack scenarios

    [ ] Section: "Feature Extraction from Literature"
        - Compile all features mentioned in papers
        - Group: packet-level vs flow-level
        - Prioritize: which 20-30 most important?

    [ ] Section: "Methodological Gaps"
        - What hasn't been covered?
        - Real-time on 100k pps?
        - Entropy vs DL in single framework?
        - 5+ simultaneous attack types?
```

**Sản phẩm 1.1:** `RESEARCH_SURVEY.md`

- 3000+ từ
- 15+ papers được trích dẫn (định dạng IEEE)
- Comparison table (entropy vs ML vs DL)
- Feature list extracted from all papers
- Dataset recommendation (CICIDS2017 + UNSW-NB15 for validation)

---

### Task 1.2: Định nghĩa Protocol Đánh giá (Tuần 1-2)

**Thời hạn:** Hết tuần 2  
**Đầu ra:** `EVALUATION_PROTOCOL.md`

**Checklist:**

```
[ ] Define metrics:
    [ ] Classification metrics:
        - Accuracy = (TP+TN)/(TP+TN+FP+FN)
        - Precision = TP/(TP+FP) → care about false alarms?
        - Recall = TP/(TP+FN) → miss attacks?
        - F1 = 2*(P*R)/(P+R) → balanced
        - ROC-AUC → threshold tuning
        - Specificity = TN/(TN+FP) → avoid blocking legit

    [ ] Performance metrics:
        - Latency (ms): time from packet arrival to decision
        - Throughput (flows/sec): max flow rate handled
        - Memory (MB): model size + runtime RAM
        - CPU usage (%): utilization under load

    [ ] Attack-specific metrics:
        - True Positive Rate (TPR) per attack type
        - False Negative Rate (FNR) per attack type
        - Can Entropy handle spoof better? DL handle mixed?

[ ] Define dataset split:
    [ ] Time-ordered split:
        - Train: Day 1-3 (70%)
        - Val: Day 4 (20%)
        - Test: Day 5 (10%)
        - Reason: attack patterns may evolve over time

    [ ] Stratified sampling:
        - Ensure each split has balanced classes
        - If imbalance >1:10, use weighted sampling

    [ ] Cross-validation:
        - 5-fold for hyperparameter tuning
        - Report mean ± std

[ ] Define thresholds & decision rules:
    [ ] Entropy method:
        - ENTROPY_LOW < 1.5 → single IP (flood suspicion)
        - ENTROPY_HIGH > 8.0 → many IPs (spoof suspicion)
        - Tune on validation set

    [ ] ML methods:
        - Confidence threshold = 0.5 (default)
        - But tune for best F1 (might be 0.3-0.7)
        - Report threshold effect on precision/recall

    [ ] DL methods:
        - Sigmoid output in [0,1]
        - Threshold = 0.5 by default
        - Adjust to maximize F1 or minimize false alarms

[ ] Define acceptance criteria:
    [ ] Success = pass these:
        - F1-score ≥ 0.85 on test set (all methods)
        - Latency ≤ 100ms per batch (real-time)
        - Throughput ≥ 1000 flows/sec
        - Can distinguish all 5 attack scenarios
        - Better than baseline entropy alone

[ ] Create EVALUATION_PROTOCOL.md:
    [ ] 1: Metrics definitions (500 words)
    [ ] 2: Dataset split strategy (300 words)
    [ ] 3: Thresholds & decision rules (300 words)
    [ ] 4: Acceptance criteria (200 words)
    [ ] 5: How to report results (tables, plots)
    [ ] 6: Example calculation (worked example)
```

**Sản phẩm 1.2:** `EVALUATION_PROTOCOL.md`

- Định nghĩa metrics chính xác
- Lý do chia tập dữ liệu
- Phương pháp chọn threshold
- Tiêu chí chấp nhận
- Tính toán ví dụ

---

### Task 1.3: Code Review & Giám sát QA (Tuần 3-5)

**Diễn ra trong toàn bộ dự án**

**Danh sách kiểm tra (Hàng tuần):**

```
Week 3:
  [ ] Review Member 2 data collection scripts
      - Does capture_traffic.py work?
      - Any bugs in feature_extraction.py?
      - Data quality issues?

  [ ] Review Member 3 ML baseline code
      - Train/val/test split correctly done?
      - Hyperparameters reasonable?
      - Results reproducible?

Week 4:
  [ ] Review Member 4 DL code
      - Model architecture sound?
      - Training convergence plots OK?
      - Latency measurements realistic?

  [ ] Review Member 5 test suite
      - Test coverage ≥ 80%?
      - Test cases comprehensive?

Week 5:
  [ ] Final review before submission
      - Reproducibility check (can run from scratch?)
      - Documentation complete?
      - All deliverables present?
```

**Sản phẩm 1.3:** `CODE_REVIEW_CHECKLISTS.md` (mỗi tuần)

---

### Task 1.4: Viết báo cáo cuối cùng (Tuần 4-5)

**Thời hạn:** Cuối tuần 5  
**Đầu ra:** `FINAL_REPORT.md` hoặc PDF (30+ trang)

**Checklist:**

```
[ ] Structure (typical 10-point paper):
    [ ] 1. Introduction (2 pages)
        - Problem statement (DDoS is serious)
        - Why hard to detect (low detection rate, high FP)
        - Contributions (3 methods compared, real-time demo)

    [ ] 2. Related Work (3 pages)
        - Summary of A1-A3 (entropy methods)
        - Summary of B1-B4 (ML methods)
        - Summary of C1-C4 (DL methods)
        - Gap: no single framework comparing all 3

    [ ] 3. Methodology (4 pages)
        - System architecture (Mininet + Ryu + ML/DL)
        - Dataset collection (5 scenarios, 1GB+ pcap)
        - Feature engineering (20+ features)
        - Methods: Entropy vs RF vs XGBoost vs CNN vs LSTM

    [ ] 4. Results (5 pages)
        - Table: accuracy/precision/recall/F1/AUC per method
        - Table: latency/throughput per method
        - Plots: ROC curves, PR curves, confusion matrices
        - Plot: latency vs throughput trade-off
        - Error analysis: which attacks each method missed?

    [ ] 5. Discussion (4 pages)
        - Why DL better than ML? (temporal patterns?)
        - Why ML better than entropy? (feature importance)
        - Limitations: dataset size, attack types, model complexity
        - Future work: adversarial robustness, online learning

    [ ] 6. Conclusion (1 page)
        - Summary of findings
        - Recommendation: use ensemble (entropy + RF + LSTM)
        - Next steps

    [ ] Appendix (4+ pages)
        - Feature list (all 20+ features)
        - Hyperparameter tuning results
        - Model architecture diagrams
        - Code snippets

[ ] Cite all 15+ papers (IEEE format)
[ ] Include all comparison tables
[ ] Include 7+ plots/figures
[ ] Spell-check & grammar check
```

**Sản phẩm 1.4:** Báo cáo cuối cùng (30+ trang PDF)

---

## 👤 THÀNH VIÊN 2: DATA & LAB ENGINEER (Hoàng Minh Đức / [TÊN])

**Vai trò:** Thu thập & xử lý dữ liệu, làm sạch, feature extraction  
**Kinh nghiệm mong muốn:** Thành thạo Python, pcap parsing, Linux  
**Effort:** 95% thực hành + 5% documentation

### Task 2.1: Cài đặt Lab Environment (Tuần 1)

**Thời hạn:** Hết tuần 1, tất cả hosts ping được  
**Đầu vào:** topology_nhom4.py, l3_router_test.py  
**Đầu ra:** Mininet + Ryu chạy được, bắt traffic hoạt động

**Checklist:**

```
[ ] Installation (Ubuntu 18.04+ LTS):
    [ ] Install Mininet: sudo apt-get install mininet
    [ ] Install Ryu: pip install ryu
    [ ] Install Scapy: pip install scapy
    [ ] Install tshark: sudo apt-get install tshark
    [ ] Install tcpdump: sudo apt-get install tcpdump
    [ ] Create dirs: mkdir -p data/raw data/features models logs

[ ] Network Setup:
    [ ] Review topology_nhom4.py (understand 5 switches, 8 hosts)
    [ ] Verify IP config:
        - s1 (attacker zone): h_att1 10.0.1.10, h_ext1 10.0.1.20
        - s2 (web/dns zone): h_web1 10.0.2.10, h_dns1 10.0.2.11
        - s3 (db/app zone): h_db1 10.0.3.10, h_app1 10.0.3.11
        - s4 (pc zone): h_pc1 10.0.4.10, h_pc2 10.0.4.11

    [ ] Test connectivity:
        - Run: mininet> h_pc1 ping h_web1 (should work)
        - Run: mininet> h_att1 ping h_web1 (should work before attack)
        - Check routing: mininet> h_pc1 route -n

[ ] Controller Setup:
    [ ] Start Ryu controller: ryu-manager l3_router_test.py
    [ ] Verify: check logs for "connected" from switches
    [ ] Check flow table: ovs-ofctl dump-flows s2
    [ ] Make sure ARP entries populated

[ ] Traffic Capture Setup:
    [ ] Create capture script `start_capture.sh`:
        - Start tcpdump on router interface
        - Name pcap with timestamp
        - Rotate files every 1GB

    [ ] Test capture:
        - Run capture script
        - Start simple ping test (h_pc1 ping h_web1)
        - Stop after 10 sec
        - Verify pcap has packets: tcpdump -r data/raw/*.pcap | head -20

[ ] Create `LAB_SETUP_GUIDE.md`:
    - Installation steps
    - How to start everything
    - Troubleshooting common issues
```

**Sản phẩm 2.1:**

- `setup_environment.sh` (tự động cài đặt)
- `LAB_SETUP_GUIDE.md`
- Đã xác minh Mininet + Ryu chạy được

---

### Task 2.2: Thu thập lưu lượng bình thường (Tuần 2)

**Thời hạn:** Hết tuần 2, ≥500MB normal pcap  
**Đầu ra:** data/raw/normal\_\*.pcap files (3 tình huống)

**Checklist:**

```
[ ] Scenario A: Baseline Normal (5 mins)
    [ ] Setup:
        - Start capture on s2 interface: "tcpdump -i s2-eth1 -w data/raw/normal_baseline.pcap"
        - Start web server: mininet> h_web1 iperf -s -p 80 &
        - Start client: mininet> h_pc1 iperf -c 10.0.2.10 -p 80 -t 300 &

    [ ] Monitor:
        - Check traffic rate: tcpdump -i s2-eth1 | wc -l (count packets/sec)
        - Expected: 1000-5000 pps

    [ ] Stop after 5 mins:
        - mininet> h_web1 pkill iperf
        - mininet> h_pc1 pkill iperf

    [ ] Verify:
        - Check file size: ls -lh data/raw/normal_baseline.pcap
        - Expected: 50-200MB
        - Verify packet count: tcpdump -r data/raw/normal_baseline.pcap | wc -l

    [ ] Log:
        - Write to `logs/normal_baseline.log`:
          Start time: [timestamp]
          Stop time: [timestamp]
          Duration: 5 mins
          Pcap size: 150MB
          Packet count: 300000
          Approx pps: 1000

[ ] Scenario B: Mixed Services (10 mins)
    [ ] Services:
        - DNS: mininet> h_dns1 rndc start (or dnsmasq)
              mininet> h_pc1 dig @10.0.2.11 example.com (repeat 1/sec)
        - HTTP: mininet> h_web1 python3 -m http.server 80 &
              mininet> h_pc1 curl http://10.0.2.10/index.html (repeat 2/sec)
        - FTP: mininet> h_db1 vsftpd &
              mininet> h_pc1 ftp 10.0.3.10 (login, list files)
        - NTP: mininet> h_dns1 ntpd -g (keep time sync)

    [ ] Capture 10 mins
    [ ] Expected: 100-500MB pcap
    [ ] Log to: logs/normal_mixed.log

[ ] Scenario C: Light Traffic (5 mins)
    [ ] Minimal traffic:
        - mininet> h_pc2 ping 10.0.2.10 -i 1 (1 pkt/sec, 5 mins)

    [ ] Expected: ~5MB pcap (very light)
    [ ] Log to: logs/normal_light.log

[ ] Total:
    [ ] Combine: data/raw/normal_*.pcap ≥ 500MB
    [ ] Create list: data/raw/NORMAL_FILES.txt
        - normal_baseline.pcap
        - normal_mixed.pcap
        - normal_light.pcap
```

**Sản phẩm 2.2:**

- `data/raw/normal_baseline.pcap` (~150MB)
- `data/raw/normal_mixed.pcap` (~200MB)
- `data/raw/normal_light.pcap` (~5MB)
- `logs/normal_*.log` (siêu dữ liệu)

---

### Task 2.3: Thu thập lưu lượng tấn công DoS (Tuần 2-3)

**Thời hạn:** Hết tuần 3, ≥500MB attack pcap (5 tình huống)  
**Đầu ra:** data/raw/dos\_\*.pcap files (gắn nhãn)

**Checklist:**

```
[ ] Attack Scenario A: SYN Flood (2 mins)
    [ ] Start capture:
        - tcpdump -i s2-eth1 -w data/raw/dos_synflood.pcap

    [ ] Web server running:
        - mininet> h_web1 iperf -s -p 80 &

    [ ] Start attack (in separate terminal):
        - mininet> h_att1 hping3 -S -p 80 --flood 10.0.2.10

    [ ] Let attack run 2 mins, then stop
    [ ] Stop web server: mininet> h_web1 pkill iperf

    [ ] Verify:
        - Packet rate should spike to 10k-50k pps
        - File size: 50-200MB

    [ ] Log: logs/dos_synflood.log
        Start time: [timestamp]
        Attack: hping3 -S -p 80 --flood 10.0.2.10
        Duration: 2 mins
        Pcap size: 150MB
        Approx pps: 20000
        Label: FLOOD

[ ] Attack Scenario B: UDP Flood (2 mins)
    [ ] Build UDP flood tool `dos_udp_flood.py`:
        #!/usr/bin/env python3
        import socket, sys, time
        target = sys.argv[1]
        port = int(sys.argv[2])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        start = time.time()
        count = 0
        while time.time() - start < 120:
            sock.sendto(b"A"*1024, (target, port))
            count += 1
        print(f"Sent {count} UDP packets")

    [ ] Start capture & run attack:
        - tcpdump -i s2-eth1 -w data/raw/dos_udpflood.pcap
        - mininet> h_att1 python3 dos_udp_flood.py 10.0.2.10 53

    [ ] Expected: 50-200MB, 20k-100k pps
    [ ] Log: logs/dos_udpflood.log with label: FLOOD

[ ] Attack Scenario C: IP Spoofing (2 mins)
    [ ] Build spoof tool `dos_spoof.py`:
        #!/usr/bin/env python3
        from scapy.all import *
        import random, time
        target_ip = "10.0.2.10"
        start = time.time()
        while time.time() - start < 120:
            random_src = f"10.0.{random.randint(0,255)}.{random.randint(0,255)}"
            pkt = IP(src=random_src, dst=target_ip)/ICMP()
            send(pkt, verbose=False)
        print("Spoofing done")

    [ ] Start capture & attack:
        - tcpdump -i s2-eth1 -w data/raw/dos_spoof.pcap
        - mininet> h_att1 python3 dos_spoof.py

    [ ] Expected: 50-200MB, but with high entropy (many src IPs)
    [ ] Log: logs/dos_spoof.log with label: SPOOF

[ ] Attack Scenario D: Distributed (multi-source, 2 mins)
    [ ] Multiple attackers send simultaneously:
        - mininet> h_att1 hping3 -S -p 80 --flood 10.0.2.10 &
        - mininet> h_ext1 hping3 -S -p 443 --flood 10.0.2.10 &
        - Let run 2 mins

    [ ] Capture: data/raw/dos_distributed.pcap
    [ ] Expected: 50-200MB, mixed sources
    [ ] Log: logs/dos_distributed.log with label: FLOOD

[ ] Attack Scenario E: Stealthy (5 mins, low rate but sustained)
    [ ] Low-rate attack tool `dos_stealthy.py`:
        #!/usr/bin/env python3
        import socket, time
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for i in range(300):  # 5 min * 60 sec = 300 sec
            try:
                sock.connect(("10.0.2.10", 80))
                sock.close()
            except:
                pass
            time.sleep(1)  # 1 connection/sec = 500 pps rate

    [ ] Capture: data/raw/dos_stealthy.pcap (5 mins)
    [ ] Expected: 20-50MB, regular pattern
    [ ] Log: logs/dos_stealthy.log with label: FLOOD (but hard to detect)

[ ] Total DoS data:
    [ ] data/raw/dos_*.pcap ≥ 500MB total
    [ ] Create: data/raw/DOS_FILES.txt listing all files + labels
```

**Sản phẩm 2.3:**

- `data/raw/dos_synflood.pcap` (~150MB, nhãn FLOOD)
- `data/raw/dos_udpflood.pcap` (~150MB, nhãn FLOOD)
- `data/raw/dos_spoof.pcap` (~150MB, nhãn SPOOF)
- `data/raw/dos_distributed.pcap` (~100MB, nhãn FLOOD)
- `data/raw/dos_stealthy.pcap` (~30MB, nhãn FLOOD)
- `logs/dos_*.log` (siêu dữ liệu + nhãn)

---

### Task 2.4: Pipeline trích xuất tính năng (Tuần 3-4)

**Thời hạn:** Hết tuần 4, sẵn sàng huấn luyện ML  
**Đầu vào:** tất cả pcap files từ 2.2 + 2.3  
**Đầu ra:** File CSV với tính năng được trích xuất

**Checklist:**

```
[ ] Create `feature_extraction.py` (300+ lines):
    [ ] Use Scapy or pyshark to parse pcap
    [ ] For each flow (5-tuple), compute:
        - Basic: src_ip, dst_ip, src_port, dst_port, protocol
        - Timing: flow_duration, fwd_iat_mean, fwd_iat_std, bwd_iat_mean
        - Volume: total_fwd_packets, total_bwd_packets, total_fwd_bytes, total_bwd_bytes
        - Rate: fwd_pkt_rate (pkt/sec), fwd_byte_rate, bwd_pkt_rate, bwd_byte_rate
        - Size: min_fwd_pkt_size, max_fwd_pkt_size, mean_fwd_pkt_size, fwd_pkt_len_std
        - Flags: tcp_flags_diversity (count unique TCP flags)
        - Entropy: entropy_src_ip (entropy of IPs), entropy_dst_port (entropy of dst ports)
        - Advanced (optional): payload length dist, retransmission rate

    [ ] Output schema (20+ columns):
        src_ip,dst_ip,src_port,dst_port,protocol,flow_duration,
        total_fwd_packets,total_bwd_packets,total_fwd_bytes,total_bwd_bytes,
        fwd_pkt_rate,fwd_byte_rate,bwd_pkt_rate,bwd_byte_rate,
        min_fwd_pkt_size,max_fwd_pkt_size,mean_fwd_pkt_size,fwd_pkt_len_std,
        tcp_flags_diversity,entropy_src_ip,entropy_dst_port,label

    [ ] Handle edge cases:
        - Empty pcap: skip
        - Corrupted packets: skip with warning
        - Single-packet flows: include (might be SYN reconnaissance)
        - IPv6: skip or separate

    [ ] Call: python3 feature_extraction.py data/raw/normal_baseline.pcap data/features/

[ ] Extract from all pcap files:
    [ ] Normal data:
        - python3 feature_extraction.py data/raw/normal_baseline.pcap data/features/
          → output: normal_baseline_flows.csv (label: NORMAL)
        - python3 feature_extraction.py data/raw/normal_mixed.pcap data/features/
        - python3 feature_extraction.py data/raw/normal_light.pcap data/features/
        → Merge into: data/features/normal_all.csv

    [ ] Attack data:
        - python3 feature_extraction.py data/raw/dos_synflood.pcap data/features/
          → output: dos_synflood_flows.csv (label: FLOOD)
        - Repeat for all 5 attack scenarios
        → Merge into: data/features/dos_all.csv

    [ ] Final merge:
        - Combine normal_all.csv + dos_all.csv
        → data/features/flows_labeled_ALL.csv (with label column)

[ ] Validation:
    [ ] Check for nulls: df.isnull().sum() (should be <1%)
    [ ] Check ranges:
        - flow_duration: should be 0-300 sec
        - packet counts: should be positive
        - rates: should be reasonable (not negative or huge)
    [ ] Check class balance:
        - print value_counts for 'label' column
        - Expected: ~50-50 NORMAL/FLOOD (or reasonable imbalance)

    [ ] Create validation report: data/features/VALIDATION_REPORT.txt
        Total flows: 2.5M
        NORMAL flows: 1.2M (48%)
        FLOOD flows: 1.0M (40%)
        SPOOF flows: 0.3M (12%)
        Null values: 0.1% (acceptable)
        Feature ranges: OK

[ ] Create `DATASET_DESCRIPTION.md`:
    [ ] Schema: 20 columns, data types, ranges, meanings
    [ ] Size: total 2.5M+ flows, train/val/test split info
    [ ] Features: short description of each feature
    [ ] Class distribution: histogram
    [ ] Known issues: if any
```

**Sản phẩm 2.4:**

- `feature_extraction.py` (300+ dòng, đã test)
- `data/features/flows_labeled_ALL.csv` (2.5M+ dòng, 20+ cột)
- `data/features/VALIDATION_REPORT.txt`
- `DATASET_DESCRIPTION.md`

---

### Task 2.5: Tiền xử lý dữ liệu (Tuần 4)

**Thời hạn:** Hết tuần 4, sẵn sàng huấn luyện ML  
**Đầu vào:** flows_labeled_ALL.csv  
**Đầu ra:** train.csv, val.csv, test.csv (đã tiền xử lý + chuẩn hóa)

**Checklist:**

```
[ ] Create `preprocessing.py`:
    [ ] Load CSV: df = pd.read_csv('flows_labeled_ALL.csv')

    [ ] Missing value handling:
        [ ] Identify columns with NaNs
        [ ] If <1% missing: drop rows or impute mean
        [ ] If >5% missing: drop column or investigate
        [ ] df = df.dropna() or df.fillna(df.mean())

    [ ] Outlier detection:
        [ ] Use IQR method: Q1, Q3, IQR = Q3-Q1
            Outliers = values < Q1-1.5*IQR or > Q3+1.5*IQR
        [ ] Flag but keep (don't remove)
        [ ] Optional: cap at percentiles (e.g., p99)

    [ ] Feature scaling:
        [ ] StandardScaler: (x - mean) / std
        [ ] Fit on training data only, apply to val/test
        [ ] from sklearn.preprocessing import StandardScaler
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_val_scaled = scaler.transform(X_val)
            X_test_scaled = scaler.transform(X_test)
            # Save scaler
            import pickle
            pickle.dump(scaler, open('scaler.pkl', 'wb'))

    [ ] Train/val/test split:
        [ ] Method: time-ordered (first 70% train, next 20% val, last 10% test)
            Reason: realistic (attack patterns evolve)
        [ ] Or stratified random (if no time info)
        [ ] from sklearn.model_selection import train_test_split
            X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3)
            X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.67)

    [ ] Save to CSV:
        [ ] data/preprocessing/train.csv (70%)
        [ ] data/preprocessing/val.csv (20%)
        [ ] data/preprocessing/test.csv (10%)

    [ ] Create preprocessing report: data/preprocessing/PREPROCESSING_REPORT.txt
        - Missing values: 0.1% (dropped)
        - Outliers: 2.3% (flagged, kept)
        - Scaling: StandardScaler applied
        - Train size: 1.75M, Val: 0.5M, Test: 0.25M
        - Class balance in each set reported

[ ] Run preprocessing:
    [ ] python3 preprocessing.py
    [ ] Verify output files exist and have correct row counts
```

**Sản phẩm 2.5:**

- `preprocessing.py` (150+ dòng)
- `data/preprocessing/train.csv`
- `data/preprocessing/val.csv`
- `data/preprocessing/test.csv`
- `scaler.pkl` (để sử dụng sau)
- `PREPROCESSING_REPORT.txt`

---

## 👤 THÀNH VIÊN 3: ML BASELINE ENGINEER (Nguyễn Văn Tuấn / [TÊN])

**Vai trò:** Train machine learning models (RF, XGBoost, LightGBM)  
**Kinh nghiệm mong muốn:** Thành thạo scikit-learn, XGBoost, hyperparameter tuning  
**Effort:** 95% thực hành + 5% documentation

### Task 3.1: Huấn luyện & Điều chỉnh Random Forest (Tuần 3-4)

**Thời hạn:** Hết tuần 4  
**Đầu vào:** train.csv, val.csv, test.csv (từ Thành viên 2)  
**Đầu ra:** Mô hình RF + báo cáo đánh giá

**Checklist:**

```
[ ] Create `ml_rf_train.py`:
    [ ] Load data:
        from sklearn.ensemble import RandomForestClassifier
        import pandas as pd, numpy as np

        X_train = pd.read_csv('train.csv').drop(['label'], axis=1)
        y_train = pd.read_csv('train.csv')['label']
        X_val = pd.read_csv('val.csv').drop(['label'], axis=1)
        y_val = pd.read_csv('val.csv')['label']
        X_test = pd.read_csv('test.csv').drop(['label'], axis=1)
        y_test = pd.read_csv('test.csv')['label']

    [ ] Hyperparameter tuning (grid search):
        params = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 15, 20, None],
            'min_samples_split': [5, 10],
            'class_weight': ['balanced', 'balanced_subsample']
        }

        from sklearn.model_selection import GridSearchCV
        rf = RandomForestClassifier(random_state=42, n_jobs=-1)
        grid = GridSearchCV(rf, params, cv=5, scoring='f1', n_jobs=-1)
        grid.fit(X_train, y_train)

        print(f"Best params: {grid.best_params_}")
        print(f"Best CV F1: {grid.best_score_:.4f}")

    [ ] Train best model:
        best_rf = grid.best_estimator_
        y_pred_train = best_rf.predict(X_train)
        y_pred_val = best_rf.predict(X_val)
        y_pred_test = best_rf.predict(X_test)

    [ ] Evaluate on test set:
        from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve, auc

        accuracy = (y_pred_test == y_test).mean()
        precision = TP / (TP + FP)  # or use sklearn
        recall = TP / (TP + FN)
        f1 = 2 * (precision * recall) / (precision + recall)
        roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])

        print(f"Test Accuracy: {accuracy:.4f}")
        print(f"Test Precision: {precision:.4f}")
        print(f"Test Recall: {recall:.4f}")
        print(f"Test F1: {f1:.4f}")
        print(f"Test ROC-AUC: {roc_auc:.4f}")

        cm = confusion_matrix(y_test, y_pred_test)
        print("Confusion Matrix:")
        print(cm)

    [ ] Feature importance:
        fi = pd.Series(best_rf.feature_importances_, index=X_train.columns)
        fi.nlargest(10).plot(kind='barh')
        plt.title('Top 10 Feature Importance (RF)')
        plt.savefig('rf_feature_importance.png')

    [ ] Save model:
        import pickle
        pickle.dump(best_rf, open('models/rf_model.pkl', 'wb'))

    [ ] Save results:
        results = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'roc_auc': roc_auc,
            'training_time': training_time,
            'inference_time_per_sample': inference_time / len(X_test)
        }
        json.dump(results, open('results/rf_results.json', 'w'))
```

**Sản phẩm 3.1:**

- `ml_rf_train.py` (200+ dòng)
- `models/rf_model.pkl`
- `results/rf_results.json` (metrics)
- `plots/rf_feature_importance.png`
- Nhật ký huấn luyện

---

### Task 3.2: Huấn luyện XGBoost & LightGBM (Tuần 4)

**Thời hạn:** Hết tuần 4  
**Đầu vào:** train.csv, val.csv, test.csv  
**Đầu ra:** Mô hình XGB + LGB + đánh giá

**Checklist:**

```
[ ] Create `ml_xgboost_train.py`:
    [ ] Hyperparameter tuning:
        params = {
            'max_depth': [5, 6, 7, 8],
            'learning_rate': [0.01, 0.05, 0.1],
            'n_estimators': [100, 300, 500],
            'scale_pos_weight': [NORMAL_COUNT / ATTACK_COUNT]  # for class imbalance
        }

        import xgboost as xgb
        xgb_model = xgb.XGBClassifier(random_state=42)
        grid = GridSearchCV(xgb_model, params, cv=5, scoring='f1')
        grid.fit(X_train, y_train)

    [ ] Train & evaluate:
        - Same as RF: train best model, eval on test, compute metrics
        - Expected: F1 ≥ 0.95

    [ ] Compare to RF:
        - Print side-by-side: accuracy, precision, recall, F1, ROC-AUC, training time
        - Save to: results/xgb_vs_rf.csv

    [ ] Save model: models/xgb_model.pkl

[ ] Create `ml_lightgbm_train.py`:
    [ ] Similar to XGBoost
    [ ] Expected: faster training than XGB, similar accuracy
    [ ] Hyperparams:
        num_leaves: 31-64
        learning_rate: 0.01-0.1
        n_estimators: 100-500

    [ ] Save model: models/lgb_model.pkl

[ ] Create comparison script `ml_compare_baselines.py`:
    [ ] Load all 3 models
    [ ] Evaluate on test set
    [ ] Create comparison table: Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Train Time (s) | Infer Time (ms)

    [ ] Print table to console & save to CSV
    [ ] Create plots:
        - ROC curves overlay (all 3 models)
        - Confusion matrices (3 subplots)
```

**Sản phẩm 3.2:**

- `ml_xgboost_train.py` (200+ dòng)
- `ml_lightgbm_train.py` (200+ dòng)
- `ml_compare_baselines.py` (150+ dòng)
- `models/xgb_model.pkl`, `models/lgb_model.pkl`
- `results/ml_comparison.csv` (so sánh metrics)
- `plots/roc_curves.png`, `plots/confusion_matrices.png`

---

### Task 3.3: Suy luận ML thực tế (Tuần 4-5)

**Thời hạn:** Hết tuần 5  
**Đầu vào:** Các mô hình ML đã huấn luyện  
**Đầu ra:** Script suy luận thực tế + benchmark

**Checklist:**

```
[ ] Create `ml_realtime_inference.py`:
    [ ] Load best model (XGBoost by default)
    [ ] Load scaler
    [ ] Listen to incoming flows (via pcap or socket)
    [ ] Batch flows every 1 second
    [ ] For each batch:
        - Extract features
        - Normalize using scaler
        - Predict: y_pred = model.predict(X_batch)
        - Get confidence: y_pred_proba = model.predict_proba(X_batch)

    [ ] Output:
        - timestamp, flow_id, prediction, confidence, latency_ms
        - Alert if prediction = ATTACK and confidence > 0.8

    [ ] Measure latency:
        import time
        start = time.time()
        y_pred = model.predict(X_batch)
        latency = (time.time() - start) * 1000  # ms

    [ ] Measure throughput:
        - Count flows/sec
        - Expected: >1000 flows/sec

[ ] Create benchmark script `ml_benchmark.py`:
    [ ] Load test data
    [ ] Simulate different traffic rates:
        - 1k pps, 10k pps, 100k pps
        - Measure latency degradation

    [ ] For each model:
        - Run inference on different batch sizes (1, 10, 50, 100)
        - Measure: throughput (flows/sec), latency (ms), memory (MB)

    [ ] Create table: Model | Batch Size | Throughput | Latency | Memory
    [ ] Create plot: throughput vs latency (scatter)

[ ] Save results:
    - results/ml_realtime_benchmark.json
    - plots/ml_latency_throughput.png
```

**Sản phẩm 3.3:**

- `ml_realtime_inference.py` (150+ dòng)
- `ml_benchmark.py` (150+ dòng)
- `results/ml_realtime_benchmark.json`
- `plots/ml_latency_throughput.png`

---

### Task 3.4: Phân tích lỗi & Tài liệu (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Đầu ra:** Báo cáo phân tích lỗi + tài liệu ML

**Checklist:**

```
[ ] Create `ml_error_analysis.py`:
    [ ] Find false positives (predicted ATTACK, but NORMAL):
        fp_indices = (y_pred_test == 1) & (y_test == 0)
        fp_flows = X_test[fp_indices]

        # Analyze characteristics
        print(f"False Positives: {len(fp_flows)}")
        print(fp_flows[['fwd_pkt_rate', 'entropy_src_ip']].describe())

        # Visualize: scatter plot of FP flows in feature space

    [ ] Find false negatives (predicted NORMAL, but ATTACK):
        fn_indices = (y_pred_test == 0) & (y_test == 1)
        fn_flows = X_test[fn_indices]
        # Analyze similar to FP

    [ ] Generate error report:
        - Top 20 FP examples: show features that confused model
        - Top 20 FN examples: show features model missed
        - Recommendation: adjust threshold? More data? Different feature?

[ ] Create `ML_RESULTS.md`:
    [ ] Results summary:
        - Model comparison table (all metrics)
        - Best model: XGBoost (F1=0.962, latency=25ms)

    [ ] Feature importance (top 10):
        - Which features most useful?

    [ ] Error analysis:
        - FP rate: 2.3% (acceptable)
        - FN rate: 1.8% (good)

    [ ] Conclusion:
        - ML captures patterns better than entropy alone
        - XGBoost recommended for production
        - Real-time feasible (<100ms latency)
```

**Sản phẩm 3.4:**

- `ml_error_analysis.py` (150+ dòng)
- `ML_RESULTS.md` (2000+ từ)
- `plots/fp_analysis.png`, `plots/fn_analysis.png`

---

## 👤 THÀNH VIÊN 4: DEEP LEARNING + REAL-TIME DETECTION (Phạm Hoàng Nam / [TÊN])

**Vai trò:** Implement DL models (CNN, LSTM, Autoencoder) + real-time integration  
**Kinh nghiệm mong muốn:** Thành thạo TensorFlow/PyTorch, GPU programming  
**Effort:** 95% thực hành + 5% documentation

### Task 4.1: Chuẩn bị dữ liệu cho DL (Tuần 3-4)

**Thời hạn:** Hết tuần 4  
**Đầu vào:** flows_labeled_ALL.csv (từ Thành viên 2)  
**Đầu ra:** Các chuỗi sẵn sàng huấn luyện DL

**Checklist:**

```
[ ] Create `dl_sequence_preparation.py`:
    [ ] Goal: convert flow-level data → sequences for LSTM/CNN

    [ ] Sliding window approach:
        - Window size: 20 flows (sequence length)
        - Stride: 1 (overlap by 19 flows, slide by 1)
        - Target: next flow's label (NORMAL or ATTACK)

        Example:
        Flows: [1, 2, 3, 4, 5, 6, 7, ... 1000]
        Sequence 1: [1-20] → target=21
        Sequence 2: [2-21] → target=22
        Sequence 3: [3-22] → target=23
        ...

    [ ] Implementation:
        import numpy as np
        def create_sequences(X, y, seq_len=20):
            sequences_X = []
            sequences_y = []
            for i in range(len(X) - seq_len):
                sequences_X.append(X[i:i+seq_len])
                sequences_y.append(y[i+seq_len])
            return np.array(sequences_X), np.array(sequences_y)

        X_train_seq, y_train_seq = create_sequences(X_train_scaled, y_train)
        # Shape: (N, 20, 23) - N sequences, 20 flows, 23 features

    [ ] Output:
        - X_train_seq, y_train_seq (sequences for LSTM)
        - X_val_seq, y_val_seq
        - X_test_seq, y_test_seq
        - Save using pickle or h5
```

**Sản phẩm 4.1:**

- `dl_sequence_preparation.py`
- Chuỗi huấn luyện (X_train_seq.npy, y_train_seq.npy, v.v.)

---

### Task 4.2: Huấn luyện mô hình 1D-CNN (Tuần 4)

**Thời hạn:** Hết tuần 4  
**Đầu vào:** Chuỗi huấn luyện  
**Đầu ra:** Mô hình CNN + đánh giá

**Checklist:**

```
[ ] Create `dl_cnn_train.py`:
    [ ] Architecture:
        import tensorflow as tf
        from tensorflow import keras

        model = keras.Sequential([
            keras.layers.Conv1D(32, kernel_size=3, activation='relu',
                               input_shape=(20, 23)),
            keras.layers.MaxPooling1D(pool_size=2),

            keras.layers.Conv1D(64, kernel_size=3, activation='relu'),
            keras.layers.MaxPooling1D(pool_size=2),

            keras.layers.Flatten(),
            keras.layers.Dense(128, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(1, activation='sigmoid')
        ])

    [ ] Compile:
        model.compile(
            loss='binary_crossentropy',
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            metrics=['accuracy', keras.metrics.AUC()]
        )

    [ ] Train:
        history = model.fit(
            X_train_seq, y_train_seq,
            batch_size=32,
            epochs=50,
            validation_data=(X_val_seq, y_val_seq),
            callbacks=[
                keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=5,
                    restore_best_weights=True
                )
            ],
            verbose=1
        )

    [ ] Evaluate on test:
        y_pred_cnn = model.predict(X_test_seq)
        # Compute metrics: accuracy, precision, recall, F1, ROC-AUC

    [ ] Save model:
        model.save('models/cnn_model.h5')

    [ ] Plot training history:
        plt.figure(figsize=(12, 4))
        plt.subplot(1, 2, 1)
        plt.plot(history.history['loss'])
        plt.plot(history.history['val_loss'])
        plt.title('CNN Loss')
        plt.legend(['train', 'val'])

        plt.subplot(1, 2, 2)
        plt.plot(history.history['accuracy'])
        plt.plot(history.history['val_accuracy'])
        plt.title('CNN Accuracy')
        plt.legend(['train', 'val'])
        plt.savefig('plots/cnn_training_history.png')
```

**Sản phẩm 4.2:**

- `dl_cnn_train.py` (200+ dòng)
- `models/cnn_model.h5`
- `plots/cnn_training_history.png`
- Metrics đánh giá CNN (JSON)

---

### Task 4.3: Huấn luyện mô hình LSTM (Tuần 4)

**Thời hạn:** Hết tuần 4  
**Đầu vào:** Chuỗi huấn luyện  
**Đầu ra:** Mô hình LSTM + đánh giá

**Checklist:**

```
[ ] Create `dl_lstm_train.py`:
    [ ] Architecture:
        model = keras.Sequential([
            keras.layers.LSTM(64, activation='relu', return_sequences=True,
                             input_shape=(20, 23)),
            keras.layers.LSTM(32, activation='relu'),
            keras.layers.Dense(64, activation='relu'),
            keras.layers.Dropout(0.3),
            keras.layers.Dense(1, activation='sigmoid')
        ])

    [ ] Compile & train:
        - Similar to CNN
        - Expected: slower training (LSTM is more complex)
        - Epochs may take longer (100+)

    [ ] Save: models/lstm_model.h5
    [ ] Plot history: plots/lstm_training_history.png
```

**Sản phẩm 4.3:**

- `dl_lstm_train.py` (200+ dòng)
- `models/lstm_model.h5`
- `plots/lstm_training_history.png`

---

### Task 4.4: Huấn luyện Autoencoder (Không giám sát) (Tuần 4)

**Thời hạn:** Hết tuần 4  
**Đầu vào:** Chỉ dữ liệu bình thường (không giám sát)  
**Đầu ra:** Mô hình Autoencoder + điều chỉnh threshold

**Checklist:**

```
[ ] Create `dl_autoencoder_train.py`:
    [ ] Architecture:
        # Encoder
        input_layer = keras.Input(shape=(23,))
        encoded = keras.layers.Dense(16, activation='relu')(input_layer)
        encoded = keras.layers.Dense(8, activation='relu')(encoded)
        bottleneck = keras.layers.Dense(4, activation='relu')(encoded)

        # Decoder
        decoded = keras.layers.Dense(8, activation='relu')(bottleneck)
        decoded = keras.layers.Dense(16, activation='relu')(decoded)
        output = keras.layers.Dense(23, activation='relu')(decoded)

        autoencoder = keras.Model(input_layer, output)

    [ ] Train on NORMAL data only:
        X_normal = X_train[y_train == 0]  # NORMAL samples only
        autoencoder.compile(loss='mse', optimizer='adam')
        autoencoder.fit(X_normal, X_normal, epochs=50, batch_size=32)

    [ ] Inference:
        # Reconstruction error for anomaly detection
        X_all_reconstructed = autoencoder.predict(X_val)
        reconstruction_error = np.mean((X_val - X_all_reconstructed)**2, axis=1)

        # Threshold tuning
        from sklearn.metrics import roc_curve, auc
        fpr, tpr, thresholds = roc_curve(y_val, reconstruction_error)
        best_threshold = thresholds[np.argmax(tpr - fpr)]

        y_pred_ae = (reconstruction_error > best_threshold).astype(int)

    [ ] Save:
        - models/autoencoder_model.h5
        - best_threshold to JSON
```

**Sản phẩm 4.4:**

- `dl_autoencoder_train.py` (200+ dòng)
- `models/autoencoder_model.h5`
- Đánh giá Autoencoder + threshold

---

### Task 4.5: So sánh mô hình DL (Tuần 4-5)

**Thời hạn:** Hết tuần 5  
**Đầu vào:** Cả 3 mô hình DL  
**Đầu ra:** Báo cáo so sánh + lựa chọn mô hình tốt nhất

**Checklist:**

```
[ ] Create `dl_compare.py`:
    [ ] Load all 3 models
    [ ] Evaluate on test sequences
    [ ] Compute: accuracy, precision, recall, F1, ROC-AUC
    [ ] Measure: inference latency per sample, memory

    [ ] Comparison table:
        Model       | Accuracy | Precision | Recall | F1   | Latency(ms) | Memory(MB)
        CNN         | 98.2%    | 97.8%     | 98.5%  | 98.2%| 120         | 45
        LSTM        | 97.5%    | 97.2%     | 97.8%  | 97.5%| 200         | 60
        Autoencoder | 96.0%    | 95.5%     | 96.5%  | 96.0%| 50          | 20

    [ ] Recommendation: CNN best balance
```

**Sản phẩm 4.5:**

- `dl_compare.py`
- Bảng so sánh + biểu đồ

---

### Task 4.6: Suy luận DL thực tế (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Đầu vào:** Mô hình DL tốt nhất (CNN)  
**Đầu ra:** Script suy luận thực tế + benchmark

**Checklist:**

```
[ ] Create `dl_realtime_inference.py`:
    [ ] Load CNN model
    [ ] Listen to incoming flow data (via pcap or InfluxDB)
    [ ] Buffer flows into sequences (window of 20)
    [ ] For each complete sequence:
        - Normalize using scaler
        - Predict using CNN
        - Output: timestamp, prediction, confidence, latency

    [ ] Measure:
        - End-to-end latency (packet in → alert out)
        - Throughput: sequences/sec
        - GPU vs CPU comparison (if GPU available)

[ ] Create benchmark `dl_benchmark.py`:
    [ ] Test different traffic rates (1k-100k pps)
    [ ] Measure latency degradation
    [ ] Create plot: traffic rate vs latency/throughput

[ ] Optimize for speed (optional):
    [ ] Model quantization: convert float32 → float16/int8
    [ ] Use TFLite for mobile inference
    [ ] Batch processing: accumulate 10 sequences → predict together
```

**Sản phẩm 4.6:**

- `dl_realtime_inference.py` (150+ dòng)
- `dl_benchmark.py` (150+ dòng)
- `results/dl_realtime_benchmark.json`
- `plots/dl_latency_throughput.png`

---

### Task 4.7: Tài liệu DL (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Đầu ra:** Báo cáo kết quả DL

**Checklist:**

```
[ ] Create `DL_RESULTS.md`:
    [ ] Model architectures (with diagrams)
    [ ] Training history plots
    [ ] Comparison table (CNN vs LSTM vs Autoencoder)
    [ ] Best model recommendation: CNN
    [ ] Real-time performance: <150ms latency
    [ ] Conclusion: DL captures temporal patterns better than ML baselines
```

**Sản phẩm 4.7:**

- `DL_RESULTS.md` (2000+ từ)
- Tất cả biểu đồ & sơ đồ

---

## 👤 THÀNH VIÊN 5: QA + TESTING + VISUALIZATION + PRESENTATION (Hoàng Anh Đức / [TÊN])

**Vai trò:** Test suite, dashboard visualization, slide preparation, Q&A script  
**Kinh nghiệm mong muốn:** Thành thạo unittest/pytest, matplotlib/plotly, presentation  
**Nỗ lực:** 70% thực hành + 30% thuyết trình

### Task 5.1: Phát triển Test Suite (Tuần 4-5)

**Thời hạn:** Hết tuần 5  
**Đầu vào:** Tất cả code từ Thành viên 2-4  
**Đầu ra:** 50+ trường hợp test, báo cáo coverage

**Checklist:**

```
[ ] Create `test_feature_extraction.py`:
    [ ] Test cases (15+):
        [ ] test_empty_pcap: handle empty file
        [ ] test_corrupted_packet: skip bad packet
        [ ] test_single_packet_flow: include or exclude?
        [ ] test_feature_ranges: all values in expected range
        [ ] test_null_values: <1% nulls
        [ ] test_output_schema: correct columns

    [ ] Run: pytest test_feature_extraction.py -v

[ ] Create `test_preprocessing.py`:
    [ ] Test cases (10+):
        [ ] test_scaling: mean=0, std=1
        [ ] test_train_test_split: correct sizes
        [ ] test_scaler_consistency: fit & transform
        [ ] test_no_data_leakage: scaler fit only on train

    [ ] Run: pytest test_preprocessing.py -v

[ ] Create `test_ml_models.py`:
    [ ] Test cases (15+):
        [ ] test_rf_fit: model trains without error
        [ ] test_rf_predict_shape: output shape (N,)
        [ ] test_xgb_vs_rf: both models similar accuracy
        [ ] test_inference_latency: <50ms per batch
        [ ] test_class_imbalance: weighted model

    [ ] Run: pytest test_ml_models.py -v

[ ] Create `test_dl_models.py`:
    [ ] Test cases (10+):
        [ ] test_cnn_shape: output shape (N, 1)
        [ ] test_lstm_vs_cnn: similar accuracy
        [ ] test_autoencoder_reconstruction: error on normal ~low
        [ ] test_dl_inference_latency: <200ms

    [ ] Run: pytest test_dl_models.py -v

[ ] Create `test_attack_detection.py`:
    [ ] Integration tests (15+):
        [ ] test_synflood_detection: all methods detect
        [ ] test_spoof_detection: entropy high, ML/DL good
        [ ] test_stealthy_detection: hard case, DL best
        [ ] test_false_alarm_on_normal: <5% FP rate

    [ ] Run: pytest test_attack_detection.py -v

[ ] Coverage report:
    [ ] pytest --cov=. --cov-report=html
    [ ] Target: ≥80% coverage
    [ ] Identify uncovered code, write more tests
```

**Sản phẩm 5.1:**

- File `test_*.py` (50+ tests tổng cộng)
- `coverage/index.html` (báo cáo coverage ≥80%)
- `TEST_REPORT.txt` (tóm tắt)

---

### Task 5.2: Trực quan hóa & Dashboard (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Đầu vào:** Tất cả kết quả từ Thành viên 1-4  
**Đầu ra:** 7+ biểu đồ + dashboard

**Checklist:**

```
[ ] Create `visualization.py`:
    [ ] Import matplotlib, seaborn, plotly (optional)

    [ ] Plot 1: ROC Curves (overlay all methods)
        from sklearn.metrics import roc_curve, auc

        methods = {
            'Entropy': y_entropy_pred,
            'Random Forest': y_rf_pred,
            'XGBoost': y_xgb_pred,
            'CNN': y_cnn_pred,
            'LSTM': y_lstm_pred,
            'Autoencoder': y_ae_pred
        }

        plt.figure(figsize=(10, 8))
        for method_name, y_pred in methods.items():
            fpr, tpr, _ = roc_curve(y_test, y_pred)
            roc_auc = auc(fpr, tpr)
            plt.plot(fpr, tpr, label=f'{method_name} (AUC={roc_auc:.3f})')

        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curves - All Methods')
        plt.legend()
        plt.grid(True)
        plt.savefig('plots/roc_curves_all.png', dpi=300)

    [ ] Plot 2: PR Curves (Precision vs Recall)
        from sklearn.metrics import precision_recall_curve

        plt.figure(figsize=(10, 8))
        for method_name, y_pred in methods.items():
            precision, recall, _ = precision_recall_curve(y_test, y_pred)
            plt.plot(recall, precision, label=method_name)

        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curves')
        plt.legend()
        plt.savefig('plots/pr_curves_all.png')

    [ ] Plot 3: Confusion Matrices (6 subplots)
        from sklearn.metrics import confusion_matrix

        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        for idx, (method_name, y_pred) in enumerate(methods.items()):
            ax = axes[idx // 3, idx % 3]
            cm = confusion_matrix(y_test, y_pred)
            sns.heatmap(cm, annot=True, fmt='d', ax=ax)
            ax.set_title(method_name)

        plt.tight_layout()
        plt.savefig('plots/confusion_matrices_all.png')

    [ ] Plot 4: Feature Importance
        # From RF/XGBoost
        plt.figure(figsize=(10, 6))
        fi = pd.Series(rf.feature_importances_, index=X_train.columns)
        fi.nlargest(15).plot(kind='barh')
        plt.title('Top 15 Features (Random Forest)')
        plt.savefig('plots/feature_importance.png')

    [ ] Plot 5: Latency Comparison
        latencies = {
            'Entropy': 1,
            'RF': 20,
            'XGBoost': 25,
            'CNN': 120,
            'LSTM': 200,
            'Autoencoder': 50
        }

        plt.figure(figsize=(10, 6))
        plt.bar(latencies.keys(), latencies.values())
        plt.ylabel('Latency (ms)')
        plt.title('Inference Latency Comparison')
        plt.xticks(rotation=45)
        plt.savefig('plots/latency_comparison.png')

    [ ] Plot 6: Accuracy vs Latency (scatter)
        accuracies = [0.85, 0.97, 0.988, 0.982, 0.975, 0.96]
        latencies_list = list(latencies.values())

        plt.figure(figsize=(10, 6))
        methods_list = list(latencies.keys())
        plt.scatter(latencies_list, accuracies, s=200)
        for i, method in enumerate(methods_list):
            plt.annotate(method, (latencies_list[i], accuracies[i]))

        plt.xlabel('Latency (ms)')
        plt.ylabel('Accuracy')
        plt.title('Accuracy vs Latency Trade-off')
        plt.savefig('plots/accuracy_latency_tradeoff.png')

    [ ] Plot 7: Class Distribution
        classes = ['NORMAL', 'FLOOD', 'SPOOF']
        counts = [1200000, 1000000, 300000]

        plt.figure(figsize=(8, 6))
        plt.pie(counts, labels=classes, autopct='%1.1f%%', startangle=90)
        plt.title('Class Distribution in Dataset')
        plt.savefig('plots/class_distribution.png')

[ ] Create interactive dashboard (optional, using Plotly):
    [ ] Use Plotly to create HTML dashboard with:
        - Dropdown to select method
        - Interactive ROC curve
        - Comparison table
        - Sample alerts
    [ ] Save: dashboard.html
```

**Sản phẩm 5.2:**

- `visualization.py` (300+ dòng)
- `plots/roc_curves_all.png`, `plots/pr_curves_all.png`, ... (7+ biểu đồ)
- `dashboard.html` (tùy chọn, tương tác)

---

### Task 5.3: Báo cáo Test toàn diện (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Đầu ra:** TEST_REPORT.md (tài liệu test chi tiết)

**Checklist:**

```
[ ] Create `TEST_REPORT.md`:
    [ ] Section 1: Test Strategy
        - Unit tests: individual functions
        - Integration tests: end-to-end workflows
        - Performance tests: latency, throughput
        - Security tests: input validation

    [ ] Section 2: Test Execution
        - Total test count: 50+
        - Pass rate: 100% (all pass)
        - Code coverage: 82% (target ≥80%)
        - Untested code: document why

    [ ] Section 3: Known Issues (if any)
        - Issue 1: ...
        - Severity: High/Medium/Low
        - Workaround: ...

    [ ] Section 4: Recommendations
        - Improve test coverage for X
        - Monitor latency on production
        - Consider Y for future work

    [ ] Appendix: Detailed test results
        - Test case | Inputs | Expected | Actual | Result | Time (ms)
```

**Sản phẩm 5.3:**

- `TEST_REPORT.md` (1000+ từ)

---

### Task 5.4: Chuẩn bị thuyết trình (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Đầu ra:** Bộ slide (20 slide) + script Q&A

**Checklist:**

```
[ ] Create `PRESENTATION_SLIDES.pptx` (20 slides):
    [ ] Slide 1: Title slide
        - Title: DoS Attack Detection using Entropy, ML, and DL
        - Team members
        - University & course
        - Date

    [ ] Slide 2-3: Problem & Motivation
        - DDoS attacks growing (statistics)
        - Current detection methods limited
        - Why hard to detect (evolving attacks)

    [ ] Slide 4-5: Related Work (Literature Review)
        - Entropy-based methods (A1-A3)
        - ML methods (B1-B4)
        - DL methods (C1-C4)
        - Gap: no unified framework

    [ ] Slide 6-7: System Architecture
        - Diagram: Mininet + Ryu + ML/DL
        - Data flow: pcap → features → models → prediction

    [ ] Slide 8-9: Dataset & Features
        - 5 attack scenarios (SYN flood, UDP flood, spoof, distributed, stealthy)
        - 20+ features extracted
        - Class distribution

    [ ] Slide 10: Entropy-based Detection
        - Shannon entropy formula
        - ENTROPY_HIGH/LOW thresholds
        - Results: F1-score, latency

    [ ] Slide 11-12: ML Baseline Results
        - Comparison table: RF, XGBoost, LightGBM
        - ROC curves
        - Feature importance

    [ ] Slide 13-15: Deep Learning Results
        - CNN architecture
        - LSTM architecture
        - Autoencoder
        - Comparison: accuracy, latency

    [ ] Slide 16-17: Comparative Analysis
        - Table: all 6 methods (accuracy, latency, memory)
        - Plot: accuracy vs latency trade-off
        - Winner: DL best for accuracy, trade-off with latency

    [ ] Slide 18: Demo & Live Testing
        - Demo scenario (SYN flood attack)
        - Real-time detection
        - Alert generation & blocking
        - Video playback or live demo

    [ ] Slide 19: Conclusions & Future Work
        - Key findings
        - Limitations (attack diversity, model interpretability)
        - Future: adversarial robustness, online learning, ensemble methods

    [ ] Slide 20: Thank You & Questions
        - Contact info
        - GitHub link
        - Q&A

[ ] Create `QA_SCRIPT.md` (30 questions):
    [ ] Expected questions & answers:
        Q: Why use entropy when ML/DL is better?
        A: Entropy is fast (<1ms) & useful for real-time first-pass filtering

        Q: How do you handle class imbalance?
        A: Used weighted loss in ML models & undersampling in DL

        Q: What about false positives (false alarms)?
        A: FP rate: 2.3% (can tune threshold if needed)

        Q: Can attacks evade your detection?
        A: Possible (adversarial attacks), but we detect most known types

        Q: Scalability: can handle 100k pps?
        A: Yes, with GPU acceleration (CNN: 150ms latency at 100k pps)

        Q: How many flows in training set?
        A: 2.5M flows (1.2M normal, 1.3M attack)

        Q: Did you test on real network traces?
        A: No, lab-generated (future work: test on real ISP data)

        Q: Compared to commercial IDS like Snort/Suricata?
        A: Different approach (statistical vs signature-based), may be complementary

        [... 22 more questions]

[ ] Prepare for different speaker:
    [ ] Each member should be able to present whole slide
    [ ] Practice 20-min presentation
    [ ] Time allocation: intro (2 min) → method (5 min) → results (8 min) → conclusion (3 min) → Q&A (2 min)
```

**Sản phẩm 5.4:**

- `PRESENTATION_SLIDES.pptx` (20 slide)
- `QA_SCRIPT.md` (30 câu hỏi + câu trả lời)
- Ghi chú thuyết trình (speaker notes trong slide)

---

### Task 5.5: Tích hợp cuối cùng & Báo cáo (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Đầu ra:** Báo cáo tích hợp cuối cùng + kho GitHub

**Checklist:**

````
[ ] Create `FINAL_INTEGRATION_REPORT.md`:
    [ ] Executive Summary (1 page)
        - Problem: DDoS detection
        - Solution: Compare entropy vs ML vs DL
        - Results: DL best (99% F1) but CNN (150ms latency) slower than ML (25ms)
        - Recommendation: Use ensemble for production

    [ ] Technical Summary
        - What works: All methods detect most attacks
        - What doesn't: Hard to detect stealthy, slow attacks
        - Trade-offs: Accuracy vs latency vs interpretability

    [ ] Reproduce instructions:
        1. Clone repo
        2. Run setup_environment.sh
        3. Run python3 setup_lab.py
        4. Run python3 train_all_models.py
        5. Run python3 run_demo.py

    [ ] File structure:
        ```
        project/
        ├── data/
        │   ├── raw/              (pcap files)
        │   ├── features/         (CSV with features)
        │   ├── preprocessing/    (train/val/test)
        │
        ├── models/               (trained models)
        │   ├── rf_model.pkl
        │   ├── xgb_model.pkl
        │   ├── cnn_model.h5
        │   ├── lstm_model.h5
        │   ├── autoencoder_model.h5
        │
        ├── results/              (metrics, benchmarks)
        ├── plots/                (visualizations)
        ├── tests/                (test suite)
        ├── src/                  (source code)
        │   ├── feature_extraction.py
        │   ├── preprocessing.py
        │   ├── ml_*.py
        │   ├── dl_*.py
        │   ├── realtime_*.py
        │
        ├── README.md             (overview)
        ├── REQUIREMENTS.txt      (dependencies)
        └── [all deliverables]
        ```

[ ] Create `README.md`:
    [ ] Project overview (3 lines)
    [ ] Quick start (5 lines with commands)
    [ ] Results summary (comparison table)
    [ ] Link to documentation

[ ] GitHub push:
    [ ] Add all code, documentation, results
    [ ] Tag final version: v1.0-final-submission
    [ ] Include .gitignore (exclude large pcap files if needed)
````

**Sản phẩm 5.5:**

- `FINAL_INTEGRATION_REPORT.md`
- `README.md` (tổng quan dự án)
- Kho GitHub hoàn chỉnh (sạch, có tổ chức)
- Tag: v1.0-final-submission

---

## 📅 DETAILED TIMELINE



---

## 📅 LỊCH THỰC HIỆN HÀNG TUẦN

| Tuần | Thành viên 1 | Thành viên 2 | Thành viên 3 | Thành viên 4 | Thành viên 5 |
|-----|-------------|-------------|-------------|-------------|-------------|
| **1** | Đọc papers, định nghĩa protocol | Setup Mininet+Ryu | Chuẩn bị ML env | Chuẩn bị DL env | Setup test env |
| **2** | Hoàn thành survey & protocol | Thu thập traffic bình thường | Chuẩn bị hyperparams | Chuẩn bị sequences | Test templates |
| **3** | Review code, updates | Tấn công DoS + features | RF training | DL sequences | Test cases start |
| **4** | Review code, updates | Feature extraction hoàn tất | ML comparison | CNN+LSTM+AE train | Test coverage |
| **5** | Viết báo cáo cuối | Preprocessing hoàn tất | Real-time inference | Real-time inference | Slides + Q&A |

---

**Created:** 2026-04-21  
**Last Updated:** 2026-04-21  
**Version:** 1.0  
**Status:** ✅ READY FOR EXECUTION
