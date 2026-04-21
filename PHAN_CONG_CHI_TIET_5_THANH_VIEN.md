# PHÂN CÔNG CHI TIẾT - 5 THÀNH VIÊN

**Dựa trên:** WORK_BREAKDOWN_FULL.md + REFERENCES_PAPERS.md  
**Mục tiêu:** Rõ ràng từng người làm gì, deadline, deliverable  
**Format:** Bảng chi tiết công việc theo tuần

---

## 📋 BẢNG PHÂN CÔNG TOÀN DỰ ÁN

| STT     | Thành viên                                                 | Tuần | Task                                | Chi tiết công việc                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Deadline   | Sản phẩm                                                                                                                     |
| ------- | ---------------------------------------------------------- | ---- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **1.1** | **Thành viên 1: Trần Minh Khoa** (Trưởng nhóm, Nghiên cứu) | 1-2  | **Survey & Tổng hợp Bài Báo**       | • Đọc 15+ papers (A1-A3: entropy; B1-B4: ML; C1-C4: DL; D1-D2: dataset; E1-E3: survey)<br>• Tổng hợp: phương pháp, độ chính xác, latency, ưu nhược điểm<br>• Tạo bảng so sánh entropy vs ML vs DL<br>• Liệt kê 20+ features từ các paper<br>• Ghi chú: lỗ hổng lý thuyết, khoảng trống trong phương pháp hiện tại                                                                                                                                                                                                                                                                              | Hết tuần 2 | `RESEARCH_SURVEY.md` (3000+ từ, 15+ papers cited, IEEE format)                                                               |
| **1.2** | **Thành viên 1**                                           | 1-2  | **Định nghĩa Protocol Đánh giá**    | • Định nghĩa metrics: Accuracy, Precision, Recall, F1, ROC-AUC, Specificity<br>• Performance metrics: Latency (ms), Throughput (flows/sec), Memory (MB), CPU (%)<br>• Attack-specific: TPR/FNR per attack type<br>• Dataset split: 70% train (time-ordered), 20% val, 10% test<br>• Thresholds: Entropy_low<1.5, Entropy_high>8.0<br>• Acceptance criteria: F1≥0.85, Latency≤100ms, Throughput≥1000 flows/sec                                                                                                                                                                                  | Hết tuần 2 | `EVALUATION_PROTOCOL.md` (500+ từ, công thức, ví dụ tính toán)                                                               |
| **1.3** | **Thành viên 1**                                           | 3-5  | **Code Review & QA Oversight**      | **Tuần 3:** Review data collection scripts, feature_extraction.py, kiểm tra data quality<br>**Tuần 4:** Review ML code (split/hyperparams/results), DL code (architecture/convergence), test suite<br>**Tuần 5:** Final reproducibility check, documentation, deliverables đầy đủ                                                                                                                                                                                                                                                                                                              | Tuần 5     | `CODE_REVIEW_CHECKLISTS.md` (per week), Approval sign-off                                                                    |
| **1.4** | **Thành viên 1**                                           | 4-5  | **Viết báo cáo cuối cùng**          | • Introduction (2 trang): problem DDoS, khó detect, contributions<br>• Related Work (3 trang): A-series entropy, B-series ML, C-series DL, gap analysis<br>• Methodology (4 trang): kiến trúc, dataset, features, 3 methods<br>• Results (5 trang): bảng metrics, plots (ROC, PR, confusion matrix), error analysis<br>• Discussion (4 trang): so sánh, limitations, future work<br>• Conclusion (1 trang): tóm tắt, khuyến nghị<br>• Appendix (4+ trang): features list, hyperparams, architectures                                                                                           | Tuần 5     | `FINAL_REPORT.md` (30+ trang PDF, IEEE format toàn bộ)                                                                       |
| **2.1** | **Thành viên 2: Hoàng Minh Đức** (Data & Lab)              | 1    | **Cài đặt Lab Environment**         | • Ubuntu 18.04+: Mininet, Ryu, Scapy, tshark, tcpdump<br>• Review topology (5 switches, 8 hosts, IP config)<br>• Verify connectivity: ping test h_pc1→h_web1, h_att1→h_web1<br>• Setup Ryu controller: port 6653, verify "connected" logs<br>• Test capture: tcpdump trên s2, verify pcap packets<br>• Tạo dir: data/raw, data/features, logs                                                                                                                                                                                                                                                  | Hết tuần 1 | `setup_environment.sh` (tự động), `LAB_SETUP_GUIDE.md`, Mininet+Ryu chạy OK                                                  |
| **2.2** | **Thành viên 2**                                           | 2    | **Thu thập lưu lượng bình thường**  | **Scenario A (Baseline):** h_web1 iperf -s -p 80, h_pc1 iperf -c 10.0.2.10 -t 300 → 5 mins → ~150MB pcap<br>**Scenario B (Mixed services):** DNS (dig @10.0.2.11), HTTP (curl), FTP, NTP → 10 mins → ~200MB<br>**Scenario C (Light):** h_pc2 ping 10.0.2.10 -i 1 → 5 mins → ~5MB<br>• Tạo logs: start time, stop time, packet count, pps rate                                                                                                                                                                                                                                                  | Hết tuần 2 | `data/raw/normal_*.pcap` (3 files, ≥500MB), `logs/normal_*.log` (metadata)                                                   |
| **2.3** | **Thành viên 2**                                           | 2-3  | **Thu thập lưu lượng tấn công DoS** | **Attack A (SYN Flood):** h_att1 hping3 -S -p 80 --flood 10.0.2.10 → 2 mins → ~150MB, PPS=20k+<br>**Attack B (UDP Flood):** h_att1 UDP flood script → 2 mins → ~150MB<br>**Attack C (IP Spoofing):** h_att1 random source IP → 2 mins → ~150MB, high entropy<br>**Attack D (Distributed):** h_att1+h_ext1 cùng flood → 2 mins → ~100MB<br>**Attack E (Stealthy):** 1 conn/sec, 5 mins → ~30MB, hard to detect<br>• Gắn nhãn: FLOOD, SPOOF, classification                                                                                                                                      | Hết tuần 3 | `data/raw/dos_*.pcap` (5 files, ≥500MB), `logs/dos_*.log` (attack type, PPS)                                                 |
| **2.4** | **Thành viên 2**                                           | 3-4  | **Feature Extraction Pipeline**     | • Parse pcap: Scapy/pyshark<br>• Extract per flow: src/dst IP/port, protocol, duration, fwd/bwd packets, bytes, rates, flags, entropy, size distribution<br>• **20+ features:** flow_duration, total_fwd_packets, total_bwd_packets, fwd_pkt_rate, entropy_src_ip, entropy_dst_port, min/max/mean pkt size, etc.<br>• Handle edge cases: empty pcap, corrupted packets, single-packet flows<br>• Output CSV: normal_all.csv, dos_all.csv → merge → flows_labeled_ALL.csv (2.5M+ flows, 20+ cols)<br>• Validation: <1% nulls, ranges OK, class distribution                                     | Hết tuần 4 | `feature_extraction.py` (300+ lines), `flows_labeled_ALL.csv` (2.5M rows), `VALIDATION_REPORT.txt`, `DATASET_DESCRIPTION.md` |
| **2.5** | **Thành viên 2**                                           | 4    | **Tiền xử lý dữ liệu**              | • Handle nulls: drop/impute mean (<1%)<br>• Outlier detection: IQR method, flag but keep<br>• StandardScaler: fit on train only, apply to val/test<br>• Time-ordered split: 70% train (Day 1-3), 20% val (Day 4), 10% test (Day 5)<br>• Save: train.csv, val.csv, test.csv, scaler.pkl<br>• Create report: null %, outliers %, balance, scaling info                                                                                                                                                                                                                                           | Hết tuần 4 | `preprocessing.py` (150+ lines), train/val/test.csv, scaler.pkl, `PREPROCESSING_REPORT.txt`                                  |
| **3.1** | **Thành viên 3: Nguyễn Văn Tuấn** (ML)                     | 3-4  | **Random Forest Training**          | • Load train/val/test CSVs<br>• Grid search: n_estimators [50,100,200], max_depth [10-20], min_samples_split [5,10], class_weight='balanced'<br>• 5-fold CV, F1 score metric<br>• Train best model, evaluate: Accuracy, Precision, Recall, F1, ROC-AUC<br>• Feature importance: top 10 plot<br>• Save model: models/rf_model.pkl, results: rf_results.json                                                                                                                                                                                                                                     | Hết tuần 4 | `ml_rf_train.py` (200+ lines), rf_model.pkl, rf_results.json, feature_importance.png                                         |
| **3.2** | **Thành viên 3**                                           | 4    | **XGBoost & LightGBM Training**     | • XGBoost: max_depth [5-8], learning_rate [0.01-0.1], n_estimators [100-500], scale_pos_weight<br>• LightGBM: num_leaves [31-64], similar hyperparams<br>• Comparison table: RF vs XGB vs LGB (Acc, Prec, Recall, F1, AUC, latency)<br>• Plot: ROC curves overlay, confusion matrices (3 subplots)                                                                                                                                                                                                                                                                                             | Hết tuần 4 | `ml_xgboost_train.py`, `ml_lightgbm_train.py`, xgb/lgb models, `ml_comparison.csv`, plots                                    |
| **3.3** | **Thành viên 3**                                           | 4-5  | **Real-time ML Inference**          | • Load best model (XGBoost)<br>• Batch predictions: measure latency <50ms/batch<br>• Measure throughput: >1000 flows/sec<br>• Benchmark different traffic rates: 1k, 10k, 100k pps<br>• Create latency vs throughput plot                                                                                                                                                                                                                                                                                                                                                                      | Hết tuần 5 | `ml_realtime_inference.py`, `ml_benchmark.py`, `ml_realtime_benchmark.json`, latency_throughput.png                          |
| **3.4** | **Thành viên 3**                                           | 5    | **Error Analysis & ML Results**     | • False positives: identify confusion examples, analyze feature patterns<br>• False negatives: similar analysis<br>• Generate visualizations: scatter plots FP/FN in feature space<br>• Write ML_RESULTS.md: comparison table, feature importance, error patterns, recommendations                                                                                                                                                                                                                                                                                                             | Hết tuần 5 | `ml_error_analysis.py`, `ML_RESULTS.md` (2000+ từ), fp_analysis.png, fn_analysis.png                                         |
| **4.1** | **Thành viên 4: Phạm Hoàng Nam** (DL)                      | 3-4  | **Chuẩn bị dữ liệu cho DL**         | • Convert flow-level → sequences (sliding window size=20)<br>• Stride=1 (overlap by 19)<br>• Target: next flow's label (NORMAL/ATTACK)<br>• Output shape: (N, 20, 23) - N sequences, 20 flows, 23 features<br>• Create X_train_seq, y_train_seq, X_val_seq, y_val_seq, X_test_seq, y_test_seq                                                                                                                                                                                                                                                                                                  | Hết tuần 4 | `dl_sequence_preparation.py`, X_train_seq.npy, y_train_seq.npy, etc.                                                         |
| **4.2** | **Thành viên 4**                                           | 4    | **Huấn luyện CNN 1D**               | • Architecture: Conv1D(32, 3) → MaxPool → Conv1D(64, 3) → MaxPool → Flatten → Dense(128) → Dropout(0.3) → Dense(1, sigmoid)<br>• Optimizer: Adam(lr=0.001)<br>• Loss: binary_crossentropy<br>• Train: 50 epochs, batch_size=32, EarlyStopping patience=5<br>• Expected: F1≈0.98, latency≈120ms<br>• Plot training history (loss & accuracy)                                                                                                                                                                                                                                                    | Hết tuần 4 | `dl_cnn_train.py` (200+ lines), cnn_model.h5, cnn_training_history.png, metrics JSON                                         |
| **4.3** | **Thành viên 4**                                           | 4    | **Huấn luyện LSTM**                 | • Architecture: LSTM(64, return_seq=True) → LSTM(32) → Dense(64) → Dropout(0.3) → Dense(1, sigmoid)<br>• Similar training setup<br>• Expected: F1≈0.975, latency≈200ms<br>• Slower than CNN but captures temporal patterns                                                                                                                                                                                                                                                                                                                                                                     | Hết tuần 4 | `dl_lstm_train.py` (200+ lines), lstm_model.h5, lstm_training_history.png                                                    |
| **4.4** | **Thành viên 4**                                           | 4    | **Autoencoder (Unsupervised)**      | • Train on NORMAL data only<br>• Architecture: Dense(16) → Dense(8) → Dense(4) [bottleneck] → Dense(8) → Dense(16) → Dense(23)<br>• Loss: MSE<br>• Inference: reconstruction_error = mean((X - X_reconstructed)^2)<br>• Threshold tuning: maximize F1 on val set<br>• Expected: F1≈0.96, latency≈50ms                                                                                                                                                                                                                                                                                          | Hết tuần 4 | `dl_autoencoder_train.py` (200+ lines), autoencoder_model.h5, threshold.json                                                 |
| **4.5** | **Thành viên 4**                                           | 4-5  | **So sánh mô hình DL**              | • Load all 3 models (CNN, LSTM, AE)<br>• Evaluate test set: Acc, Prec, Recall, F1, ROC-AUC, latency, memory<br>• Create comparison table: CNN (98.2% F1, 120ms) vs LSTM (97.5%, 200ms) vs AE (96%, 50ms)<br>• Recommendation: CNN best balance                                                                                                                                                                                                                                                                                                                                                 | Hết tuần 5 | `dl_compare.py`, comparison table & plots                                                                                    |
| **4.6** | **Thành viên 4**                                           | 5    | **Real-time DL Inference**          | • Load CNN model (best)<br>• Real-time inference on sequences<br>• Measure end-to-end latency, throughput<br>• Benchmark different traffic rates<br>• Optional: quantization (float32 → float16/int8) để tối ưu tốc độ                                                                                                                                                                                                                                                                                                                                                                         | Hết tuần 5 | `dl_realtime_inference.py` (150+ lines), `dl_benchmark.py`, benchmark.json, plot                                             |
| **4.7** | **Thành viên 4**                                           | 5    | **Tài liệu DL**                     | • Tổng hợp architectures (với diagram)<br>• Training history plots<br>• Comparison conclusions<br>• Best model recommendation<br>• Real-time performance summary                                                                                                                                                                                                                                                                                                                                                                                                                               | Hết tuần 5 | `DL_RESULTS.md` (2000+ từ), all plots/diagrams                                                                               |
| **5.1** | **Thành viên 5: Hoàng Anh Đức** (QA+Test)                  | 4-5  | **Test Suite Development**          | **Functional tests:**<br>• `test_feature_extraction.py` (15+ cases): empty pcap, corrupted packets, single flows, feature ranges, nulls, schema<br>• `test_preprocessing.py` (10+ cases): scaling, train/test split, data leakage, consistency<br>• `test_ml_models.py` (15+ cases): RF fit, predict shape, model comparison, latency, class imbalance<br>• `test_dl_models.py` (10+ cases): CNN/LSTM/AE shapes, inference, reconstruction<br>• `test_attack_detection.py` (15+ integration tests): SYN flood detect, spoof detect, stealthy hard cases<br>**Total: 50+ tests, Coverage ≥80%** | Hết tuần 5 | `test_*.py` files (50+ tests), coverage report (≥80%), TEST_REPORT.txt                                                       |
| **5.2** | **Thành viên 5**                                           | 5    | **Visualization & Dashboards**      | • Plot 1: ROC curves (overlay all 6 methods)<br>• Plot 2: PR curves<br>• Plot 3: Confusion matrices (6 subplots)<br>• Plot 4: Feature importance (top 15)<br>• Plot 5: Latency comparison (bar chart)<br>• Plot 6: Accuracy vs Latency (scatter)<br>• Plot 7: Class distribution (pie)<br>• Optional: Plotly interactive dashboard                                                                                                                                                                                                                                                             | Hết tuần 5 | `visualization.py` (300+ lines), 7+ plots, dashboard.html (optional)                                                         |
| **5.3** | **Thành viên 5**                                           | 5    | **Test Report**                     | • Test strategy: unit, integration, performance, security<br>• Execution results: 50+ tests, 100% pass, 82% coverage<br>• Known issues (nếu có)<br>• Recommendations<br>• Detailed test results table                                                                                                                                                                                                                                                                                                                                                                                          | Hết tuần 5 | `TEST_REPORT.md` (1000+ từ)                                                                                                  |
| **5.4** | **Thành viên 5**                                           | 5    | **Chuẩn bị thuyết trình**           | • **20 slides:**<br> - 1: Title<br> - 2-3: Problem & Motivation<br> - 4-5: Related Work<br> - 6-7: System Architecture<br> - 8-9: Dataset & Features<br> - 10: Entropy results<br> - 11-12: ML results<br> - 13-15: DL results<br> - 16-17: Comparison (accuracy vs latency)<br> - 18: Demo & Live Testing<br> - 19: Conclusions<br> - 20: Q&A<br>• **Q&A Script:** 30 typical questions + answers<br>• **Rehearsal:** Practice 20-min presentation                                                                                                                                            | Hết tuần 5 | `PRESENTATION_SLIDES.pptx` (20 slides), `QA_SCRIPT.md` (30 Q&A), speaker notes                                               |
| **5.5** | **Thành viên 5**                                           | 5    | **Final Integration**               | • Create `FINAL_INTEGRATION_REPORT.md`: executive summary, reproduce instructions, file structure<br>• Create/update `README.md`: project overview, quick start, results summary<br>• GitHub org: clean structure, .gitignore, requirements.txt<br>• Tag: v1.0-final-submission<br>• Push all files                                                                                                                                                                                                                                                                                            | Hết tuần 5 | `FINAL_INTEGRATION_REPORT.md`, `README.md`, GitHub v1.0-final-submission                                                     |

---

## 📊 TÓNG KẾT NỖ LỰC & DELIVERABLES

| Thành viên | Vai trò                  | Nỗ lực                     | Tuần       | Tasks         | Deliverables                              |
| ---------- | ------------------------ | -------------------------- | ---------- | ------------- | ----------------------------------------- |
| **1**      | Trưởng nhóm + Nghiên cứu | 30% làm + 70% quản lý      | 1-5        | 4             | 4 docs (Survey, Protocol, Review, Report) |
| **2**      | Data & Lab Engineer      | 95% làm + 5% doc           | 1-5        | 5             | 5 scripts + datasets (16 files pcap)      |
| **3**      | ML Engineer              | 95% làm + 5% doc           | 3-5        | 4             | 5 scripts + 3 models + results            |
| **4**      | DL Engineer              | 95% làm + 5% doc           | 3-5        | 7             | 7 scripts + 3 models + results            |
| **5**      | QA + Presentation        | 70% làm + 30% thuyết trình | 4-5        | 5             | 5 scripts + tests + slides                |
| **TOTAL**  | 5 người                  | **Cân bằng**               | **5 tuần** | **~25 tasks** | **50+ deliverables**                      |

---

## ✅ TIÊU CHÍ ĐẠT 10 ĐIỂM

| Tiêu chí                      | Yêu cầu                                                                                     | Trách nhiệm        |
| ----------------------------- | ------------------------------------------------------------------------------------------- | ------------------ |
| **Code Quality (3 điểm)**     | 50+ test cases (pytest), 80%+ code coverage, PEP8 clean code, reproducible setup            | Thành viên 5 + all |
| **Technical Depth (3 điểm)**  | 3+ methods (entropy, ML, DL) working, 5+ attack scenarios, latency <100ms, comparison table | Thành viên 2, 3, 4 |
| **Scientific Rigor (2 điểm)** | 15+ papers cited (IEEE), dataset >1GB labeled, all metrics defined, error analysis          | Thành viên 1 + 2   |
| **Presentation (2 điểm)**     | 20-slide deck, demo working, 30-question Q&A script, GitHub documentation                   | Thành viên 5 + 1   |

---

## 👤 THÀNH VIÊN 1: TRƯỞNG NHÓM & NGHIÊN CỨU (Trần Minh Khoa / [TÊN])

**Vai trò:** Quản lý dự án, Survey literature, thiết kế Protocol, giám sát Code Review và viết Báo cáo.  
**Kinh nghiệm mong muốn:** Khả năng đọc hiểu bài báo khoa học, tổng hợp kiến thức, kỹ năng leadership.  
**Effort:** 30% thực hành (docs) + 70% quản lý điều phối

### Task 1.1: Survey & Tổng hợp Bài Báo (Tuần 1-2)

**Thời hạn:** Hết tuần 2  
**Nỗ lực:** 25 giờ (đọc papers + viết tóm tắt + tạo bảng so sánh)

**Công việc cụ thể:**

```
[ ] Đọc 15+ bài báo được phân nhóm:
    [ ] Nhóm A (Entropy): 3 papers về phát hiện dị thường bằng entropy
    [ ] Nhóm B (ML): 4 papers về ML models (RF, XGBoost, LightGBM, imbalance handling)
    [ ] Nhóm C (DL): 4 papers về DL architectures (CNN, LSTM, Autoencoder, comparisons)
    [ ] Nhóm D (Dataset): 2 papers về public datasets (CICIDS2017, UNSW-NB15)
    [ ] Nhóm E (Survey): 2 papers về IDS survey + real-time detection

[ ] Ghi chép từ mỗi paper:
    ✓ Phương pháp chính + công thức chính (nếu có)
    ✓ Độ chính xác (%), Latency (ms), các metrics khác
    ✓ 3-5 ưu điểm & 3-5 nhược điểm
    ✓ Dữ liệu dùng để test + số lượng samples
    ✓ Citation đầy đủ (authors, title, year, venue)

[ ] Tổng hợp features:
    ✓ Lấy tất cả features được đề cập trong papers
    ✓ Phân loại: packet-level vs flow-level
    ✓ Chọn 20-25 features quan trọng nhất
```

**Sản phẩm 1.1: RESEARCH_SURVEY.md**

**Định dạng:** File Markdown (có thể in ra PDF)  
**Kích thước:** 3500-4000 từ, ~10-12 trang PDF

**Nội dung cụ thể:**

| Phần                               | Mô tả                            | Chi tiết                                                                                                                                                                                                                                                                                                                          |
| ---------------------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Phần 1: Bảng so sánh Methods**   | Bảng tóm tắt 3 phương pháp chính | Cột: Phương pháp \| Năm \| Accuracy (%) \| Latency (ms) \| Ưu điểm \| Nhược điểm <br> Dòng 1: Entropy \| 2012 \| 85 \| <1 \| Nhanh, đơn giản \| Độ chính xác thấp <br> Dòng 2: ML (RF) \| 2015 \| 97 \| 20 \| Cân bằng \| Cần tuning <br> Dòng 3: DL (CNN) \| 2017 \| 98 \| 120 \| Chính xác cao \| Chậm, phức tạp                |
| **Phần 2: Tóm tắt 15+ papers**     | Mỗi paper: 250-350 từ            | **Format mỗi paper:** <br> **[Paper ID]** (Tác giả, Năm) <br> - Tiêu đề <br> - Vấn đề: [1 câu] <br> - Phương pháp: [2-3 câu] <br> - Kết quả chính: Accuracy=X%, Latency=Y ms <br> - 3 ưu điểm <br> - 3 nhược điểm <br> - Liên quan đến project: [1 câu] <br> - Citation IEEE: [Chi tiết đầy đủ]                                   |
| **Phần 3: Features từ literature** | Danh sách 20-25 features         | Bảng: Tên Feature \| Loại (Packet/Flow-level) \| Định nghĩa \| Ý nghĩa <br> Ví dụ: <br> - flow_duration \| Flow \| Tổng thời gian flow (ms) \| Phát hiện flood <br> - entropy_src_ip \| Flow \| Shannon entropy của src IPs \| Phát hiện spoofing <br> - fwd_pkt_rate \| Flow \| Packet/sec theo chiều forward \| Phát hiện flood |
| **Phần 4: Khoảng trống & Gaps**    | Điểm yếu của state-of-the-art    | - Nhiều papers test riêng lẻ (không framework unified) <br> - Ít papers test trên tấn công kết hợp 5+ kiểu <br> - Real-time trên 100k pps chưa kiểm chứng <br> - Chưa so sánh Entropy + ML + DL trong cùng dataset                                                                                                                |
| **Phần 5: Dataset summary**        | So sánh 2 public datasets        | CICIDS2017: 80 features, 2.8M flows, RF baseline 98.8% <br> UNSW-NB15: 49 features, 2.5GB, DL baseline 96% <br> Khuyến nghị: Lab-generated + 5 attack types                                                                                                                                                                       |

**Yêu cầu chất lượng:**

- ✅ Tất cả 15+ papers có mục "Tóm tắt" (250-350 từ mỗi)
- ✅ Bảng so sánh 3 phương pháp rõ ràng, số liệu cụ thể
- ✅ Danh sách 20-25 features đầy đủ với định nghĩa
- ✅ Tất cả citations IEEE format (Author, "Title," Journal, Year)
- ✅ Không có typo, font/format nhất quán

**Kiểm tra hoàn thành:**

```
[ ] Đã đọc xong 15 papers ✓
[ ] Có bảng so sánh 3 methods (Entropy/ML/DL) ✓
[ ] Có tóm tắt mỗi paper (250-350 từ) ✓
[ ] Có danh sách 20+ features từ papers ✓
[ ] Có phần "Gaps & Opportunities" ✓
[ ] Format IEEE citations ✓
[ ] Spelling & grammar check ✓
```

---

### Task 1.2: Định nghĩa Protocol Đánh giá (Tuần 1-2)

**Thời hạn:** Hết tuần 2  
**Nỗ lực:** 15 giờ (định nghĩa metrics, metrics calculation, ví dụ)

**Công việc cụ thể:**

```
[ ] Định nghĩa 6 metrics chính để đánh giá:
    ✓ Accuracy (Độ chính xác tổng thể)
    ✓ Precision (Trong số dự đoán là ATTACK, bao nhiêu % đúng)
    ✓ Recall (Trong số ATTACK thật sự, bao nhiêu % bị phát hiện)
    ✓ F1-score (Cân bằng giữa Precision & Recall)
    ✓ ROC-AUC (Đoạn cong độ nhạy vs độ đặc)
    ✓ Specificity (Tỷ lệ phát hiện đúng NORMAL)

[ ] Định nghĩa 3 metrics hiệu năng hệ thống:
    ✓ Latency (ms): Thời gian từ khi nhận packet đến quyết định (< 100ms là OK)
    ✓ Throughput (flows/sec): Số flows xử lý/giây (>1000 là OK)
    ✓ Memory (MB): Kích thước model + RAM sử dụng khi chạy

[ ] Chia train/val/test dataset:
    ✓ 70% Training data (dùng để huấn luyện model)
    ✓ 20% Validation data (dùng để tune hyperparams & select model)
    ✓ 10% Test data (final test - không dùng trong quá trình training)
    ✓ Nguyên tắc: Time-ordered (ngày 1-3 train, ngày 4 val, ngày 5 test)

[ ] Định threshold & decision rules cho từng method:
    ✓ Entropy: Nếu entropy_src_ip < 1.5 → ATTACK (flood),
                 Nếu entropy_src_ip > 8.0 → ATTACK (spoof)
    ✓ ML models: Nếu predict_proba > 0.5 → ATTACK
    ✓ DL models: Nếu sigmoid_output > 0.5 → ATTACK

[ ] Tiêu chí "PASS" dự án (để được điểm cao):
    ✓ F1-score ≥ 0.85 trên test set (tất cả methods)
    ✓ Latency ≤ 100ms per batch
    ✓ Throughput ≥ 1000 flows/sec
    ✓ Phát hiện được tất cả 5 loại attack
    ✓ Tốt hơn entropy đơn độc
```

**Sản phẩm 1.2: EVALUATION_PROTOCOL.md**

**Định dạng:** File Markdown  
**Kích thước:** 1500-2000 từ, ~5-6 trang PDF

**Nội dung cụ thể:**

| Phần                            | Nội dung                      | Chi tiết                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Phần 1: Metrics Định nghĩa**  | Công thức & ý nghĩa           | **Accuracy** = (TP+TN)/(TP+TN+FP+FN) <br> Ý nghĩa: Bao nhiêu % quyết định đúng <br> <br> **Precision** = TP/(TP+FP) <br> Ý nghĩa: Trong số dự đoán là ATTACK, bao nhiêu % thực sự là ATTACK <br> Mục tiêu: Giảm false alarm <br> <br> **Recall** = TP/(TP+FN) <br> Ý nghĩa: Trong số ATTACK thật, bao nhiêu % bị phát hiện <br> Mục tiêu: Không bỏ sót tấn công <br> <br> **F1-score** = 2×(Precision×Recall)/(Precision+Recall) <br> Ý nghĩa: Cân bằng precision & recall (0-1, càng cao càng tốt) <br> <br> **ROC-AUC** = Diện tích dưới đoạn cong ROC (0-1, >0.9 tốt) <br> <br> **Specificity** = TN/(TN+FP) <br> Ý nghĩa: Tỷ lệ phát hiện đúng normal traffic |
| **Phần 2: Performance Metrics** | Tiêu chí hiệu năng            | **Latency** (Độ trễ): <br> - Đo: Thời gian từ packet vào → quyết định xong (ms) <br> - Mục tiêu: < 100ms <br> - Ví dụ: CNN=120ms (OK nhưng cận), LSTM=200ms (quá) <br> <br> **Throughput** (Thông lượng): <br> - Đo: Số network flows xử lý/giây <br> - Mục tiêu: ≥ 1000 flows/sec <br> - Ví dụ: Nếu xử lý 2500 flows/sec → OK <br> <br> **Memory** (Bộ nhớ): <br> - Kích thước model .pkl/.h5 file + RAM sử dụng khi chạy <br> - Ví dụ: RF model = 45MB, CNN model = 120MB                                                                                                                                                                                       |
| **Phần 3: Dataset Split**       | Cách chia train/val/test      | **Nguyên tắc time-ordered:** <br> - Tuần 1-3: Training (2M flows) <br> - Tuần 4: Validation (0.5M flows) <br> - Tuần 5: Test (0.25M flows) <br> <br> **Lý do:** Mô phỏng thực tế - attack pattern có thể thay đổi theo thời gian <br> <br> **Class balance:** <br> - Train: 50% NORMAL, 50% ATTACK <br> - Val: 50% NORMAL, 50% ATTACK <br> - Test: 50% NORMAL, 50% ATTACK                                                                                                                                                                                                                                                                                         |
| **Phần 4: Thresholds**          | Cách set threshold quyết định | **Entropy method:** <br> - IF entropy_src_ip < 1.5 THEN "FLOOD" (nhiều packet từ 1 IP) <br> - IF entropy_src_ip > 8.0 THEN "SPOOF" (packet từ nhiều IP) <br> <br> **ML/DL methods:** <br> - Model output: xác suất ATTACK (0-1) <br> - Mặc định: IF probability > 0.5 THEN "ATTACK" <br> - Có thể tune: IF probability > 0.6 THEN "ATTACK" (ít false alarm) <br> - Hoặc: IF probability > 0.3 THEN "ATTACK" (bắt hết)                                                                                                                                                                                                                                             |
| **Phần 5: Acceptance Criteria** | Tiêu chí "PASS"               | Để được điểm cao, dự án phải: <br> - ✅ **F1-score ≥ 0.85** (cân bằng precision & recall) <br> - ✅ **Latency ≤ 100ms** (real-time acceptable) <br> - ✅ **Throughput ≥ 1000 flows/sec** (handle nhiều traffic) <br> - ✅ **Phát hiện tất cả 5 attack types** (SYN, UDP, Spoof, Distributed, Stealthy) <br> - ✅ **F1-score > entropy đơn độc** (show ML/DL better)                                                                                                                                                                                                                                                                                               |
| **Phần 6: Ví dụ tính toán**     | Worked example                | Giả sử test set có 1000 flows: <br> - 600 NORMAL (thật), 400 ATTACK (thật) <br> <br> Model dự đoán: <br> - 550 NORMAL đúng (TN), 50 NORMAL sai (FP) <br> - 350 ATTACK đúng (TP), 50 ATTACK sai (FN) <br> <br> Tính toán: <br> - Accuracy = (550+350)/(1000) = 90% <br> - Precision = 350/(350+50) = 87.5% <br> - Recall = 350/(350+50) = 87.5% <br> - F1 = 2×(87.5×87.5)/(87.5+87.5) = 87.5% ✅ (pass)                                                                                                                                                                                                                                                            |

**Yêu cầu chất lượng:**

- ✅ Tất cả 6 metrics có công thức & ý nghĩa rõ ràng
- ✅ 3 performance metrics có mục tiêu cụ thể
- ✅ Chia train/val/test rõ ràng (70/20/10)
- ✅ Threshold rules rõ ràng cho từng method
- ✅ Có ví dụ tính toán (worked example)
- ✅ Acceptance criteria cụ thể, có số (F1≥0.85, v.v.)

**Kiểm tra hoàn thành:**

```
[ ] Có công thức 6 metrics ✓
[ ] Có 3 performance metrics (Latency, Throughput, Memory) ✓
[ ] Có cách chia train/val/test (70/20/10) ✓
[ ] Có threshold rules cho 3 methods ✓
[ ] Có acceptance criteria cụ thể ✓
[ ] Có ví dụ tính toán (worked example) ✓
```

---

### Task 1.3: Code Review & Giám sát QA (Tuần 3-5)

**Thời hạn:** Hàng tuần (tuần 3-5 là lúc có code để review)  
**Nỗ lực:** 20 giờ (5-7 giờ/tuần, review code + tạo checklist)

**Công việc cụ thể:**

```
Tuần 3 - Review dữ liệu & Feature Extraction:
  [ ] Check script capture traffic của Thành viên 2:
      ✓ Có ghi log được start/stop time không?
      ✓ Pcap files có tên & metadata rõ ràng không?
      ✓ Tất cả 3 loại normal traffic + 5 loại attack traffic đã có không?

  [ ] Check script feature extraction:
      ✓ Output CSV có 20+ features không?
      ✓ Null values < 1% không?
      ✓ Feature ranges có hợp lý không? (flow_duration 0-300s, rates > 0, etc)

  [ ] Checklist: WEEK3_REVIEW.md

Tuần 4 - Review ML & DL models:
  [ ] Check ML model training (Thành viên 3):
      ✓ Train/val/test split 70/20/10 không?
      ✓ Grid search / hyperparameter tuning có kết quả không?
      ✓ Metrics (Accuracy, Precision, Recall, F1, AUC) có cả không?

  [ ] Check DL model training (Thành viên 4):
      ✓ Model architecture có rõ ràng không? (số layer, kích thước)
      ✓ Training history plot có không? (loss & accuracy curves)
      ✓ Model convergence bình thường không? (loss giảm, không spike)

  [ ] Check test suite (Thành viên 5):
      ✓ Có unit tests cho từng function chính không?
      ✓ Test coverage ≥ 80% không?
      ✓ Tất cả tests PASS không?

  [ ] Checklist: WEEK4_REVIEW.md

Tuần 5 - Final review:
  [ ] Reproducibility check:
      ✓ Từ raw data, có chạy lại được tất cả scripts không?
      ✓ Kết quả (metrics) có giống không?

  [ ] Documentation:
      ✓ Tất cả scripts có comment rõ ràng không?
      ✓ README.md có instructions cụ thể không?
      ✓ Tất cả deliverables có tên & nằm đúng folder không?

  [ ] Checklist: WEEK5_FINAL_REVIEW.md
```

**Sản phẩm 1.3: CODE_REVIEW_CHECKLISTS (3 files)**

**Định dạng:** 3 file Markdown (một file/tuần)  
**Nội dung:**

| File                      | Tuần | Nội dung                                                                                                          |
| ------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------- |
| **WEEK3_REVIEW.md**       | 3    | ✓ Data collection review <br> ✓ Feature extraction check <br> ✓ ~2-3 trang                                        |
| **WEEK4_REVIEW.md**       | 4    | ✓ ML model training review <br> ✓ DL model training review <br> ✓ Test suite review <br> ✓ ~3-4 trang             |
| **WEEK5_FINAL_REVIEW.md** | 5    | ✓ Reproducibility verification <br> ✓ Documentation completeness <br> ✓ Final approval sign-off <br> ✓ ~2-3 trang |

**Yêu cầu chất lượng:**

- ✅ Mỗi review file có checklist rõ ràng (✓/✗)
- ✅ Ghi chú issues tìm thấy + cách fix
- ✅ Approval từ leader khi tất cả OK

---

### Task 1.4: Viết Báo cáo Cuối Cùng (Tuần 4-5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 30 giờ (viết + edit + format)

**Công việc cụ thể:**

```
[ ] Phần Introduction (1-2 trang):
    ✓ Vấn đề: DDoS attacks nguy hiểm, detection khó
    ✓ Tại sao khó: Attack patterns thay đổi, false alarm cao
    ✓ Contribution của dự án: So sánh 3 methods (Entropy/ML/DL)

[ ] Phần Related Work (2-3 trang):
    ✓ Tóm tắt 15+ papers từ task 1.1
    ✓ Phân loại: Entropy methods → ML methods → DL methods
    ✓ Gap analysis: Chưa có framework compare all 3

[ ] Phần Methodology (3-4 trang):
    ✓ System architecture: Mininet + Ryu + models
    ✓ Dataset: Nơi, kích thước, 5 attack types
    ✓ Features: 20+ features, định nghĩa mỗi cái
    ✓ 3 methods: Entropy + ML (RF/XGB) + DL (CNN/LSTM/AE)

[ ] Phần Results (4-5 trang):
    ✓ Bảng 1: Metrics (Accuracy, Precision, Recall, F1, AUC) cho 6 methods
    ✓ Bảng 2: Performance (Latency, Throughput, Memory)
    ✓ Plot 1: ROC curves overlay (6 methods)
    ✓ Plot 2: PR curves overlay
    ✓ Plot 3: Confusion matrices (6 subplots)
    ✓ Plot 4: Feature importance (top 10)
    ✓ Plot 5: Latency comparison (bar chart)
    ✓ Plot 6: Accuracy vs Latency (scatter)
    ✓ Error analysis: FP/FN patterns

[ ] Phần Discussion (3-4 trang):
    ✓ Tại sao DL tốt hơn ML? (capture temporal patterns)
    ✓ Tại sao ML tốt hơn entropy? (more features)
    ✓ Limitations: dataset size, attack types, model complexity
    ✓ Real-time feasibility: Yes, with GPU
    ✓ False alarm rate: Acceptable (<5%)?

[ ] Phần Conclusion (1 trang):
    ✓ Summary: DL best (99% F1) but slow (120ms latency)
    ✓ Recommendation: Ensemble Entropy+ML for real-time
    ✓ Future work: Adversarial robustness, online learning

[ ] Appendix (3-4 trang):
    ✓ Feature list (20+ features + definitions)
    ✓ Hyperparameter tuning results
    ✓ Model architecture diagrams
```

**Sản phẩm 1.4: FINAL_REPORT.md (hoặc PDF)**

**Định dạng:** Markdown file (có thể convert sang PDF)  
**Kích thước:** 25-30 trang nếu in PDF

**Cấu trúc chi tiết:**

| Phần                | Số trang | Nội dung                               |
| ------------------- | -------- | -------------------------------------- |
| Cover               | 1        | Tiêu đề, tác giả, date, university     |
| Table of Contents   | 1        | Mục lục                                |
| **1. Introduction** | 2        | Problem, motivation, contributions     |
| **2. Related Work** | 3        | Survey 15+ papers, gaps                |
| **3. Methodology**  | 4        | Architecture, dataset, methods         |
| **4. Results**      | 5        | Tables, plots, metrics, error analysis |
| **5. Discussion**   | 4        | Why works, limitations, real-time      |
| **6. Conclusion**   | 1        | Summary, recommendation, future work   |
| **Appendix**        | 4        | Features, hyperparams, architectures   |
| **References**      | 2        | 15+ papers (IEEE format)               |

**Yêu cầu chất lượng:**

- ✅ Tất cả 15+ papers được cite (IEEE format)
- ✅ Ít nhất 6 bảng so sánh metrics
- ✅ Ít nhất 6 plots/figures
- ✅ Logic flow rõ ràng (Problem → Method → Results → Conclusion)
- ✅ Không có typo, grammar check
- ✅ Tất cả claims có evidence (từ results/experiments)
- ✅ Discussion section rõ ràng ưu nhược điểm

**Kiểm tra hoàn thành:**

```
[ ] Introduction rõ ràng vấn đề ✓
[ ] Related work cover 15+ papers ✓
[ ] Methodology chi tiết 3 methods ✓
[ ] Results có bảng + plot ✓
[ ] Discussion phân tích tại sao ✓
[ ] Conclusion có recommendation ✓
[ ] Tất cả citations IEEE format ✓
[ ] Spelling & grammar check ✓
```

---

## 👤 THÀNH VIÊN 2: DATA & LAB ENGINEER (Hoàng Minh Đức / [TÊN])

**Vai trò:** Thu thập & xử lý dữ liệu, feature extraction, tiền xử lý  
**Kinh nghiệm:** Thành thạo Linux, Python, pcap parsing (Scapy), network commands  
**Nỗ lực:** 95% lập trình + 5% documentation

### Task 2.1: Cài đặt Lab Environment (Tuần 1)

**Thời hạn:** Hết tuần 1  
**Nỗ lực:** 8 giờ (setup + test + verify)

**Công việc cụ thể:**

```
[ ] Cài đặt phần mềm cần thiết trên Ubuntu:
    ✓ Mininet (network simulator)
    ✓ Ryu (SDN controller)
    ✓ Scapy (packet manipulation)
    ✓ tcpdump (traffic capture)
    ✓ Python 3 + pip

[ ] Kiểm tra topology_nhom4.py:
    ✓ 5 switches (s1-s5) chạy được
    ✓ 8 hosts (h_att1, h_web1, h_dns1, ...) có IP đúng
    ✓ Ping từ h_pc1 → h_web1 OK
    ✓ Ping từ h_att1 → h_web1 OK

[ ] Test traffic capture:
    ✓ Chạy tcpdump trên interface -> lưu pcap file
    ✓ Verify pcap file có data (không empty)
    ✓ Tạo folders: data/raw, data/features, logs
```

**Sản phẩm 2.1:**

| File/Artifact                 | Mô tả                        | Chi tiết                                                                                                                                      |
| ----------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **setup_environment.sh**      | Shell script cài đặt tự động | Bash script gồm: <br> - apt-get install mininet, ryu, scapy, tcpdump <br> - pip install requirements <br> - mkdir folders                     |
| **LAB_SETUP_GUIDE.md**        | Hướng dẫn setup chi tiết     | Bao gồm: <br> - Câu lệnh cài đặt từng component <br> - Troubleshooting nếu lỗi <br> - Test ping connectivity <br> - Cách start Ryu controller |
| **Lab Environment hoạt động** | Mininet + Ryu chạy được      | ✓ Mininet có 5 switches + 8 hosts <br> ✓ Ryu controller connected (log "connected") <br> ✓ Ping test OK <br> ✓ tcpdump chạy được              |

---

### Task 2.2: Thu thập Traffic Bình thường (Tuần 2)

**Thời hạn:** Hết tuần 2  
**Nỗ lực:** 12 giờ (setup + run + verify)

**Công việc cụ thể:**

```
[ ] Scenario A - Baseline Normal Traffic (5 phút):
    ✓ Start web server: h_web1 iperf -s -p 80
    ✓ Start client: h_pc1 iperf -c 10.0.2.10 -t 300 (5 phút)
    ✓ Capture tcpdump
    ✓ Expected: 1000-5000 packets/sec, ~150MB pcap

[ ] Scenario B - Mixed Services (10 phút):
    ✓ DNS: h_dns1 chạy DNS service, h_pc1 dig queries
    ✓ HTTP: h_web1 chạy web, h_pc1 curl requests
    ✓ Ping từ host khác
    ✓ Expected: ~200MB pcap

[ ] Scenario C - Light Traffic (5 phút):
    ✓ Ping từ h_pc2 → h_web1 (1 packet/sec)
    ✓ Expected: ~5MB pcap (very light)

[ ] Ghi log metadata:
    ✓ File logs/normal_baseline.log: start time, stop time, file size, pps
```

**Sản phẩm 2.2:**

| File                              | Mô tả                                  | Định dạng   | Nội dung                                                                             |
| --------------------------------- | -------------------------------------- | ----------- | ------------------------------------------------------------------------------------ |
| **data/raw/normal_baseline.pcap** | Pcap file bình thường - baseline       | Binary pcap | 150MB, 1000-5000 pps                                                                 |
| **data/raw/normal_mixed.pcap**    | Pcap file bình thường - mixed services | Binary pcap | 200MB, DNS+HTTP+ping                                                                 |
| **data/raw/normal_light.pcap**    | Pcap file bình thường - light traffic  | Binary pcap | 5MB, ping only                                                                       |
| **logs/normal_baseline.log**      | Metadata: start/stop time, size        | Text        | Start: 2026-04-21 10:00:00 <br> Stop: 10:05:00 <br> Size: 150MB <br> Packets: 300000 |
| **logs/normal_mixed.log**         | Metadata file                          | Text        | Tương tự                                                                             |
| **logs/normal_light.log**         | Metadata file                          | Text        | Tương tự                                                                             |
| **Total**                         | Tất cả normal traffic                  | ~360MB      | data/raw/ chứa ≥ 350MB pcap                                                          |

---

### Task 2.3: Thu thập Traffic Tấn công DoS (Tuần 2-3)

**Thời hạn:** Hết tuần 3  
**Nỗ lực:** 16 giờ (setup + run 5 loại attack)

**Công việc cụ thể:**

```
[ ] Attack A - SYN Flood (2 phút):
    ✓ h_att1 chạy: hping3 -S -p 80 --flood 10.0.2.10
    ✓ Expected: 20k-50k pps, ~150MB

[ ] Attack B - UDP Flood (2 phút):
    ✓ h_att1 chạy UDP flood script
    ✓ Expected: Similar to SYN flood

[ ] Attack C - IP Spoofing (2 phút):
    ✓ h_att1 send packets từ random source IPs
    ✓ Expected: High entropy, ~150MB

[ ] Attack D - Distributed Flood (2 phút):
    ✓ h_att1 + h_ext1 cùng send flood packets
    ✓ Expected: 2 sources, ~100MB

[ ] Attack E - Stealthy Attack (5 phút):
    ✓ Slow flood: 1 connection/second, sustained
    ✓ Expected: Low rate nhưng sustained, ~30MB, khó phát hiện

[ ] Ghi label cho mỗi attack:
    ✓ logs/dos_*.log: attack type, start/stop time, pps
```

**Sản phẩm 2.3:**

| File                              | Attack Type        | Kích thước | Metadata                     |
| --------------------------------- | ------------------ | ---------- | ---------------------------- |
| **data/raw/dos_synflood.pcap**    | SYN Flood          | 150MB      | Label: FLOOD, PPS: 20k+      |
| **data/raw/dos_udpflood.pcap**    | UDP Flood          | 150MB      | Label: FLOOD                 |
| **data/raw/dos_spoof.pcap**       | IP Spoofing        | 150MB      | Label: SPOOF, High entropy   |
| **data/raw/dos_distributed.pcap** | Distributed        | 100MB      | Label: FLOOD, 2 sources      |
| **data/raw/dos_stealthy.pcap**    | Stealthy           | 30MB       | Label: FLOOD, hard to detect |
| **logs/dos\_\*.log**              | Metadata files     | Text       | Attack type + time + pps     |
| **Total**                         | 5 attack scenarios | ≥500MB     | Label mỗi file               |

---

### Task 2.4: Feature Extraction (Tuần 3-4)

**Thời hạn:** Hết tuần 4  
**Nỗ lực:** 20 giờ (code + run + validate)

**Công việc cụ thể:**

```
[ ] Viết feature_extraction.py:
    ✓ Input: pcap file
    ✓ Process: Parse từng packet → group thành flows (5-tuple)
    ✓ Trích 20+ features từ mỗi flow:
      - Basic: src_ip, dst_ip, src_port, dst_port, protocol
      - Duration: flow_duration (ms)
      - Volume: total_fwd_packets, total_bwd_packets, fwd_bytes, bwd_bytes
      - Rate: fwd_pkt_rate (pkt/sec), bwd_pkt_rate
      - Size: min/max/mean packet size
      - Entropy: entropy_src_ip, entropy_dst_port
    ✓ Output: CSV file với 20+ cột

[ ] Validate dữ liệu:
    ✓ Null values < 1%
    ✓ Feature ranges hợp lý (không negative, không NaN)
    ✓ Class distribution OK (normal vs attack)

[ ] Run extraction on all pcap files:
    ✓ normal_*.pcap → normal_all.csv
    ✓ dos_*.pcap → dos_all.csv
    ✓ Merge → flows_labeled_ALL.csv
```

**Sản phẩm 2.4:**

| File                                    | Mô tả               | Format                 | Nội dung                                                                                                                                            |
| --------------------------------------- | ------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **feature_extraction.py**               | Python script       | Python code, ~300 dòng | Hàm parse pcap + extract features <br> Input: pcap file <br> Output: CSV with features <br> Có error handling (corrupted packets)                   |
| **data/features/flows_labeled_ALL.csv** | Dataset chính       | CSV                    | ~2.5M dòng (flows) <br> Header: src_ip, dst_ip, ..., label (NORMAL/FLOOD/SPOOF) <br> Kích thước: ~500MB <br> Class balance: ~50% NORMAL, 50% ATTACK |
| **VALIDATION_REPORT.txt**               | Báo cáo kiểm tra QA | Text                   | Total flows: 2,500,000 <br> NORMAL: 1,200,000 (48%) <br> FLOOD: 1,300,000 (52%) <br> Null values: 0.1% ✓ <br> Feature ranges: OK ✓                  |
| **DATASET_DESCRIPTION.md**              | Tài liệu dataset    | Markdown               | Schema (20+ columns, data types) <br> Size: 2.5M flows <br> Features: định nghĩa mỗi feature <br> Class distribution                                |

---

### Task 2.5: Tiền xử lý Dữ liệu (Tuần 4)

**Thời hạn:** Hết tuần 4  
**Nỗ lực:** 12 giờ (clean + scale + split)

**Công việc cụ thể:**

```
[ ] Xử lý missing values:
    ✓ Nếu < 1% null: drop rows hoặc impute mean
    ✓ Report: bao nhiêu % được xóa/fill

[ ] Detect outliers (IQR method):
    ✓ Tính Q1, Q3, IQR
    ✓ Outliers = values < Q1-1.5*IQR or > Q3+1.5*IQR
    ✓ Flag nhưng keep (không xóa)

[ ] Feature scaling:
    ✓ StandardScaler: (x - mean) / std
    ✓ Fit ONLY trên train set
    ✓ Apply trên val + test set
    ✓ Save scaler.pkl để dùng sau

[ ] Train/Val/Test split:
    ✓ 70% train, 20% val, 10% test
    ✓ Time-ordered (ngày 1-3 train, ngày 4 val, ngày 5 test)
    ✓ Save: train.csv, val.csv, test.csv

[ ] Create report:
    ✓ Số rows của mỗi file
    ✓ Null % trước/sau
    ✓ Outliers %
    ✓ Scaling parameters (mean/std)
```

**Sản phẩm 2.5:**

| File                             | Mô tả                 | Format            | Nội dung                                                                                                                                              |
| -------------------------------- | --------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **preprocessing.py**             | Script tiền xử lý     | Python, ~150 dòng | Load flows_labeled_ALL.csv <br> Handle nulls, outliers <br> StandardScaler fit+transform <br> Train/val/test split <br> Save 3 CSV files + scaler.pkl |
| **data/preprocessing/train.csv** | Training data (70%)   | CSV               | 1,750,000 dòng <br> 20+ features + label <br> Ready cho ML/DL training                                                                                |
| **data/preprocessing/val.csv**   | Validation data (20%) | CSV               | 500,000 dòng <br> Để tune hyperparams                                                                                                                 |
| **data/preprocessing/test.csv**  | Test data (10%)       | CSV               | 250,000 dòng <br> Để final evaluation                                                                                                                 |
| **scaler.pkl**                   | Scaler object         | Pickle binary     | StandardScaler fitted trên train <br> Dùng để normalize val/test <br> Kích thước: ~1-2KB                                                              |
| **PREPROCESSING_REPORT.txt**     | QA report             | Text              | Null values: 0.1% (dropped) <br> Outliers: 2.3% (flagged) <br> Train: 1.75M, Val: 0.5M, Test: 0.25M <br> Scaler params: mean/std saved                |

---

## 👤 THÀNH VIÊN 3: ML ENGINEER (Nguyễn Văn Tuấn / [TÊN])

**Vai trò:** Huấn luyện 3 ML models (RF, XGBoost, LightGBM), so sánh & đánh giá  
**Kinh nghiệm:** Thành thạo scikit-learn, XGBoost, LightGBM  
**Nỗ lực:** 90% lập trình + 10% documentation

### Task 3.1: Huấn luyện Random Forest (Tuần 3-4)

**Thời hạn:** Hết tuần 4  
**Nỗ lực:** 16 giờ (code + train + evaluate + save)

**Công việc cụ thể:**

```
[ ] Viết ml_rf_train.py (~150 dòng):
    ✓ Load train/val/test CSVs từ preprocessing
    ✓ Tách features (X) và labels (y)
    ✓ Train Random Forest với hyperparams đơn giản:
      - n_estimators = 100 (số trees)
      - max_depth = 15 (độ sâu max)
      - class_weight = 'balanced' (xử lý imbalance)
    ✓ Predict trên test set
    ✓ Compute metrics: Accuracy, Precision, Recall, F1, ROC-AUC

[ ] Save outputs:
    ✓ Model: models/rf_model.pkl
    ✓ Metrics: results/rf_results.json (dict với các metrics)
    ✓ Plot: plots/rf_feature_importance.png (top 10 features)

[ ] Test & verify:
    ✓ Model training thành công (không crash)
    ✓ F1-score trên test set ≥ 0.80 (basic acceptable)
    ✓ Feature importance list có 10+ features
```

**Sản phẩm 3.1:**

| File                                | Mô tả                    | Format            | Nội dung                                                                                                                                                            |
| ----------------------------------- | ------------------------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ml_rf_train.py**                  | Training script cho RF   | Python, ~150 dòng | Load train.csv <br> Build RandomForestClassifier <br> Fit on training data <br> Predict on test data <br> Save model.pkl + results.json                             |
| **models/rf_model.pkl**             | Trained RF model         | Pickle binary     | scikit-learn RandomForest object <br> Kích thước: ~50-100MB                                                                                                         |
| **results/rf_results.json**         | Metrics kết quả          | JSON dict         | {<br> "accuracy": 0.97,<br> "precision": 0.965,<br> "recall": 0.975,<br> "f1": 0.970,<br> "roc_auc": 0.985,<br> "train_time": 120,<br> "inference_time_ms": 15<br>} |
| **plots/rf_feature_importance.png** | Feature importance chart | PNG image         | Bar chart, top 10 features <br> X-axis: feature names <br> Y-axis: importance score                                                                                 |

**Tiêu chí chấp nhận:**

- ✅ F1-score trên test set ≥ 0.80
- ✅ Model file lưu được & có thể load lại
- ✅ Feature importance plot rõ ràng

---

### Task 3.2: Huấn luyện XGBoost & LightGBM (Tuần 4)

**Thời hạn:** Hết tuần 4  
**Nỗ lực:** 16 giờ (2 models + so sánh)

**Công việc cụ thể:**

```
[ ] Viết ml_xgboost_train.py (~150 dòng):
    ✓ Load dữ liệu
    ✓ Train XGBoost với hyperparams đơn giản:
      - n_estimators = 200
      - max_depth = 6
      - learning_rate = 0.1
      - scale_pos_weight = (NORMAL_count / ATTACK_count) để xử lý imbalance
    ✓ Evaluate & save model, results, plot
    ✓ Expected F1 > RF (typically 0.975+)

[ ] Viết ml_lightgbm_train.py (~150 dòng):
    ✓ Tương tự XGBoost nhưng với LightGBM
    ✓ Hyperparams: num_leaves=31, learning_rate=0.1, n_estimators=200
    ✓ Expected: tương tự XGBoost nhưng nhanh hơn

[ ] Viết ml_compare_all_models.py (~100 dòng):
    ✓ Load 3 models (RF, XGB, LGB) từ pickle files
    ✓ Evaluate tất cả trên test set
    ✓ Create comparison table:
      Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Train Time | Infer Time
      RF    | 0.970    | 0.965     | 0.975  | 0.970 | 0.985  | 120s | 15ms
      XGB   | 0.975    | 0.972     | 0.978  | 0.975 | 0.990  | 180s | 20ms
      LGB   | 0.973    | 0.970     | 0.976  | 0.973 | 0.988  | 90s  | 18ms
    ✓ Create ROC curve overlay plot (3 lines)
    ✓ Create confusion matrices subplot (3x1)

[ ] Save outputs
```

**Sản phẩm 3.2:**

| File                                | Mô tả                    | Format            | Nội dung                                                              |
| ----------------------------------- | ------------------------ | ----------------- | --------------------------------------------------------------------- |
| **ml_xgboost_train.py**             | XGBoost training script  | Python            | ~150 dòng                                                             |
| **ml_lightgbm_train.py**            | LightGBM training script | Python            | ~150 dòng                                                             |
| **ml_compare_all_models.py**        | Comparison script        | Python, ~100 dòng | Load 3 models <br> Evaluate all <br> Create comparison table          |
| **models/xgb_model.pkl**            | Trained XGBoost          | Pickle            | ~50MB                                                                 |
| **models/lgb_model.pkl**            | Trained LightGBM         | Pickle            | ~30MB                                                                 |
| **results/ml_comparison.csv**       | Comparison table         | CSV               | Model,Accuracy,Precision,Recall,F1,ROC-AUC,Train_Time_s,Infer_Time_ms |
| **plots/ml_roc_curves.png**         | ROC curves overlay       | PNG               | 3 lines (RF, XGB, LGB) <br> Legend + AUC scores                       |
| **plots/ml_confusion_matrices.png** | 3 confusion matrices     | PNG               | 3 subplots, side by side                                              |

---

### Task 3.3: Real-time Inference Benchmark (Tuần 4-5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 12 giờ (benchmark + measure)

**Công việc cụ thể:**

```
[ ] Viết ml_realtime_inference.py (~120 dòng):
    ✓ Load best model (XGBoost)
    ✓ Load scaler.pkl
    ✓ Read test data in batches
    ✓ For each batch:
      - Normalize using scaler
      - Predict
      - Measure latency (ms)
    ✓ Output: timestamp, prediction, confidence, latency

[ ] Viết ml_benchmark.py (~150 dòng):
    ✓ Test different batch sizes: 1, 10, 50, 100
    ✓ Measure: latency per batch (ms), throughput (flows/sec)
    ✓ Create table: Batch Size | Latency (ms) | Throughput (flows/sec)
    ✓ Create plot: scatter (batch size vs latency)
    ✓ Expected: latency < 50ms for batch_size=50

[ ] Test & verify:
    ✓ Latency ≤ 100ms acceptable
    ✓ Throughput ≥ 1000 flows/sec
```

**Sản phẩm 3.3:**

| File                              | Mô tả                      | Format | Nội dung                                                                                                                                                                                                                               |
| --------------------------------- | -------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ml_realtime_inference.py**      | Real-time inference script | Python | ~120 dòng                                                                                                                                                                                                                              |
| **ml_benchmark.py**               | Benchmark script           | Python | ~150 dòng                                                                                                                                                                                                                              |
| **results/ml_benchmark.json**     | Benchmark results          | JSON   | {<br> "batch_1": {"latency_ms": 15, "throughput": 500},<br> "batch_10": {"latency_ms": 20, "throughput": 5000},<br> "batch_50": {"latency_ms": 35, "throughput": 15000},<br> "batch_100": {"latency_ms": 60, "throughput": 25000}<br>} |
| **plots/ml_batch_vs_latency.png** | Latency vs batch size      | PNG    | Scatter plot + trend line                                                                                                                                                                                                              |

---

### Task 3.4: Error Analysis & Results Summary (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 10 giờ

**Công việc cụ thể:**

```
[ ] Viết ml_error_analysis.py (~120 dòng):
    ✓ Load predictions vs actual labels
    ✓ Find false positives (predicted ATTACK, but NORMAL)
    ✓ Find false negatives (predicted NORMAL, but ATTACK)
    ✓ Analyze characteristics:
      - FP features: thường có pattern gì?
      - FN features: thường có pattern gì?
    ✓ Create scatter plots: FP và FN trong feature space

[ ] Viết ML_RESULTS.md (~1500 từ):
    ✓ Results summary table
    ✓ Recommendation: best model
    ✓ Feature importance analysis
    ✓ Error patterns
    ✓ Conclusion
```

**Sản phẩm 3.4:**

| File                         | Mô tả                   | Format   | Nội dung                                                                                                                                                            |
| ---------------------------- | ----------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ml_error_analysis.py**     | Error analysis script   | Python   | ~120 dòng                                                                                                                                                           |
| **ML_RESULTS.md**            | Results document        | Markdown | 1500+ từ <br> - Model comparison table <br> - Feature importance (top 10) <br> - Error analysis (FP/FN patterns) <br> - Best model recommendation <br> - Conclusion |
| **plots/ml_fp_analysis.png** | False positive analysis | PNG      | Scatter plot FP flows                                                                                                                                               |
| **plots/ml_fn_analysis.png** | False negative analysis | PNG      | Scatter plot FN flows                                                                                                                                               |

---

## 👤 THÀNH VIÊN 4: DEEP LEARNING ENGINEER (Phạm Hoàng Nam / [TÊN])

**Vai trò:** Huấn luyện 3 DL models (CNN, LSTM, Autoencoder) + real-time inference  
**Kinh nghiệm:** Thành thạo TensorFlow/Keras, GPU optional  
**Nỗ lực:** 85% lập trình + 15% documentation

### Task 4.1: Chuẩn bị Sequence Data cho DL (Tuần 3-4)

**Thời hạn:** Hết tuần 4  
**Nỗ lực:** 8 giờ

**Công việc cụ thể:**

```
[ ] Viết dl_sequence_preparation.py (~80 dòng):
    ✓ Load train/val/test CSV files
    ✓ Convert flow-level data → sequences:
      - Window size = 20 flows (20 consecutive flows)
      - Stride = 1 (slide by 1, overlap by 19)
      - Target label = label của flow thứ 21
    ✓ Output shape: (N, 20, 23) - N sequences, 20 flows, 23 features
    ✓ Save as .npy files (numpy binary format)

[ ] Example:
    Flow sequence 1: flows[0:20] → target = flows[20].label
    Flow sequence 2: flows[1:21] → target = flows[21].label
    ...etc
```

**Sản phẩm 4.1:**

| File                                  | Mô tả                       | Format           | Nội dung                                                                   |
| ------------------------------------- | --------------------------- | ---------------- | -------------------------------------------------------------------------- |
| **dl_sequence_preparation.py**        | Sequence preparation script | Python, ~80 dòng | Load train.csv <br> Create sliding windows <br> Save .npy files            |
| **data/dl_sequences/X_train_seq.npy** | Training sequences          | Numpy binary     | Shape: (1.73M, 20, 23) <br> 1.73M sequences, mỗi cái 20 flows, 23 features |
| **data/dl_sequences/y_train_seq.npy** | Training labels             | Numpy binary     | Shape: (1.73M,) - labels 0/1                                               |
| **data/dl_sequences/X_val_seq.npy**   | Validation sequences        | Numpy binary     | Shape: (0.49M, 20, 23)                                                     |
| **data/dl_sequences/y_val_seq.npy**   | Validation labels           | Numpy binary     | Shape: (0.49M,)                                                            |
| **data/dl_sequences/X_test_seq.npy**  | Test sequences              | Numpy binary     | Shape: (0.24M, 20, 23)                                                     |
| **data/dl_sequences/y_test_seq.npy**  | Test labels                 | Numpy binary     | Shape: (0.24M,)                                                            |

---

### Task 4.2: Huấn luyện CNN 1D (Tuần 4)

**Thời hạn:** Hết tuần 4  
**Nỗ lực:** 12 giờ

**Công việc cụ thể:**

```
[ ] Viết dl_cnn_train.py (~120 dòng):
    ✓ Build model:
      - Input layer: (20, 23)
      - Conv1D(32 filters, kernel=3) + ReLU + MaxPool
      - Conv1D(64 filters, kernel=3) + ReLU + MaxPool
      - Flatten
      - Dense(128) + ReLU + Dropout(0.3)
      - Dense(1) + Sigmoid (binary output)

    ✓ Compile: loss=binary_crossentropy, optimizer=Adam(lr=0.001)

    ✓ Train:
      - epochs = 30 (đủ cho convergence)
      - batch_size = 32
      - Early stopping: nếu val_loss không giảm 3 epochs → stop

    ✓ Evaluate trên test set
    ✓ Save model, training history plot

    ✓ Expected: F1 ≈ 0.97-0.98, latency ≈ 50-100ms

[ ] Test & verify:
    ✓ Model training successful
    ✓ F1-score ≥ 0.90
    ✓ Training history plot rõ ràng (loss curve xuống)
```

**Sản phẩm 4.2:**

| File                               | Mô tả               | Format            | Nội dung                                                                                                                                                                  |
| ---------------------------------- | ------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **dl_cnn_train.py**                | CNN training script | Python, ~120 dòng | Build CNN model <br> Train with early stopping <br> Evaluate & save                                                                                                       |
| **models/cnn_model.h5**            | Trained CNN model   | HDF5 binary       | Keras model file <br> Kích thước: ~50-80MB                                                                                                                                |
| **results/cnn_results.json**       | CNN metrics         | JSON              | {<br> "accuracy": 0.975,<br> "precision": 0.972,<br> "recall": 0.978,<br> "f1": 0.975,<br> "roc_auc": 0.990,<br> "training_time_s": 300,<br> "inference_time_ms": 75<br>} |
| **plots/cnn_training_history.png** | Training curves     | PNG               | 2 subplots: <br> - Loss curve (train + val) <br> - Accuracy curve (train + val)                                                                                           |

---

### Task 4.3: Huấn luyện LSTM (Tuần 4)

**Thời hạn:** Hết tuần 4  
**Nỗ lực:** 12 giờ

**Công việc cụ thể:**

```
[ ] Viết dl_lstm_train.py (~120 dòng):
    ✓ Build model:
      - LSTM(64, return_sequences=True) + ReLU
      - LSTM(32) + ReLU
      - Dense(64) + ReLU + Dropout(0.3)
      - Dense(1) + Sigmoid

    ✓ Compile & train (similar to CNN)
    ✓ Expected: F1 ≈ 0.96-0.97, latency ≈ 100-150ms
      (Slower than CNN nhưng capture temporal patterns tốt hơn)

[ ] Save model & results
```

**Sản phẩm 4.3:**

| File                                | Mô tả                | Format            | Nội dung                                        |
| ----------------------------------- | -------------------- | ----------------- | ----------------------------------------------- |
| **dl_lstm_train.py**                | LSTM training script | Python, ~120 dòng | Build LSTM model <br> Train with early stopping |
| **models/lstm_model.h5**            | Trained LSTM model   | HDF5 binary       | ~50-80MB                                        |
| **results/lstm_results.json**       | LSTM metrics         | JSON              | Similar structure to CNN                        |
| **plots/lstm_training_history.png** | LSTM training curves | PNG               | Loss & accuracy plots                           |

---

### Task 4.4: Huấn luyện Autoencoder (Unsupervised) (Tuần 4)

**Thời hạn:** Hết tuần 4  
**Nỗ lực:** 10 giờ

**Công việc cụ thể:**

```
[ ] Viết dl_autoencoder_train.py (~120 dòng):
    ✓ Build model:
      - Encoder: Dense(16) → Dense(8) → Dense(4) [bottleneck]
      - Decoder: Dense(8) → Dense(16) → Dense(23) [output]
      - Input shape: (23,) - flat features, không sequences
      - Loss: MSE (reconstruction error)

    ✓ Train on NORMAL data only:
      - X_train_normal = X_train[y_train == 0]
      - Learn to reconstruct normal flows
      - ATTACK flows sẽ có reconstruction error cao

    ✓ Inference:
      - reconstruction_error = mean((X - X_reconstructed)^2)
      - IF reconstruction_error > threshold THEN ATTACK
      - Tune threshold trên validation set để maximize F1

    ✓ Expected: F1 ≈ 0.93-0.96, latency ≈ 20-50ms (rất nhanh)

[ ] Save model & threshold
```

**Sản phẩm 4.4:**

| File                            | Mô tả                       | Format            | Nội dung                                                            |
| ------------------------------- | --------------------------- | ----------------- | ------------------------------------------------------------------- |
| **dl_autoencoder_train.py**     | Autoencoder training script | Python, ~120 dòng | Train on NORMAL only <br> Tune threshold <br> Evaluate on full test |
| **models/autoencoder_model.h5** | Trained Autoencoder         | HDF5 binary       | ~30-50MB (smaller)                                                  |
| **results/ae_threshold.json**   | Best threshold              | JSON              | {"optimal_threshold": 0.045, "f1_at_threshold": 0.943}              |
| **results/ae_results.json**     | Autoencoder metrics         | JSON              | Accuracy, Precision, Recall, F1, ROC-AUC                            |

---

### Task 4.5: So sánh 3 DL Models (Tuần 4-5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 8 giờ

**Công việc cụ thể:**

```
[ ] Viết dl_compare_all_models.py (~100 dòng):
    ✓ Load all 3 models (CNN, LSTM, AE)
    ✓ Evaluate trên test set
    ✓ Create comparison table:
      Model  | Accuracy | Precision | Recall | F1   | ROC-AUC | Latency(ms) | Memory(MB)
      CNN    | 0.975    | 0.972     | 0.978  | 0.975| 0.990   | 75          | 60
      LSTM   | 0.965    | 0.962     | 0.968  | 0.965| 0.985   | 120         | 65
      AE     | 0.943    | 0.940     | 0.946  | 0.943| 0.975   | 40          | 35

    ✓ Create ROC curve overlay plot (3 lines)
    ✓ Recommendation: CNN best balance
```

**Sản phẩm 4.5:**

| File                          | Mô tả              | Format            | Nội dung                                                        |
| ----------------------------- | ------------------ | ----------------- | --------------------------------------------------------------- |
| **dl_compare_all_models.py**  | Comparison script  | Python, ~100 dòng | Load 3 models <br> Evaluate all                                 |
| **results/dl_comparison.csv** | Comparison table   | CSV               | Model,Accuracy,Precision,Recall,F1,ROC-AUC,Latency_ms,Memory_MB |
| **plots/dl_roc_curves.png**   | ROC curves overlay | PNG               | 3 lines (CNN, LSTM, AE) + AUC scores                            |
| **plots/dl_comparison.png**   | Metrics comparison | PNG               | Bar chart so sánh                                               |

---

### Task 4.6: Real-time DL Inference (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 8 giờ

**Công việc cụ thể:**

```
[ ] Viết dl_realtime_inference.py (~100 dòng):
    ✓ Load best CNN model
    ✓ Load scaler
    ✓ Read flow sequences (or create from incoming flows)
    ✓ For each sequence:
      - Normalize
      - Predict
      - Output: timestamp, prediction, confidence, latency

[ ] Viết dl_benchmark.py (~120 dòng):
    ✓ Test different batch sizes
    ✓ Measure latency & throughput
    ✓ Test on CPU vs GPU (if available)
    ✓ Create table & plot
```

**Sản phẩm 4.6:**

| File                              | Mô tả                 | Format | Nội dung                                       |
| --------------------------------- | --------------------- | ------ | ---------------------------------------------- |
| **dl_realtime_inference.py**      | Real-time inference   | Python | ~100 dòng                                      |
| **dl_benchmark.py**               | Benchmark script      | Python | ~120 dòng                                      |
| **results/dl_benchmark.json**     | Benchmark results     | JSON   | Latency & throughput for different batch sizes |
| **plots/dl_batch_vs_latency.png** | Latency vs batch size | PNG    | Scatter + trend line                           |

---

### Task 4.7: Tài liệu DL (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 6 giờ

**Sản phẩm 4.7:**

| File              | Mô tả               | Format                 | Nội dung                                                                                                                                    |
| ----------------- | ------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **DL_RESULTS.md** | DL results document | Markdown, 1200-1500 từ | - Model architectures <br> - Training history plots <br> - Comparison table (CNN/LSTM/AE) <br> - Recommendation: CNN best <br> - Conclusion |

---

## 👤 THÀNH VIÊN 5: QA + TESTING + VISUALIZATION (Hoàng Anh Đức / [TÊN])

**Vai trò:** Viết test suite, tạo visualizations, prepare presentation  
**Kinh nghiệm:** Thành thạo pytest, matplotlib, PowerPoint  
**Nỗ lực:** 60% testing + 30% visualization + 10% presentation prep

### Task 5.1: Viết Test Suite (Tuần 4-5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 16 giờ

**Công việc cụ thể:**

```
[ ] Viết test_feature_extraction.py (~80 dòng):
    ✓ Test cases (ít nhất 8):
      - test_empty_pcap: handle file rỗng
      - test_invalid_pcap: handle corrupt file
      - test_feature_count: đầu ra có 20+ features
      - test_null_values: < 1% null
      - test_feature_ranges: all values reasonable
      - test_class_labels: chỉ có NORMAL/ATTACK

    ✓ Run: pytest test_feature_extraction.py -v

[ ] Viết test_preprocessing.py (~60 dòng):
    ✓ Test cases (ít nhất 6):
      - test_scaling: mean=0, std=1
      - test_split_sizes: train 70%, val 20%, test 10%
      - test_scaler_save: scaler.pkl exist
      - test_no_data_leakage: scaler fit only on train

    ✓ Run: pytest test_preprocessing.py -v

[ ] Viết test_ml_models.py (~80 dòng):
    ✓ Test cases (ít nhất 8):
      - test_rf_train: model trains without error
      - test_rf_predict_shape: output shape (N,)
      - test_xgb_train: XGBoost train OK
      - test_model_save_load: pickle save/load
      - test_inference_latency: < 100ms

    ✓ Run: pytest test_ml_models.py -v

[ ] Viết test_dl_models.py (~60 dòng):
    ✓ Test cases (ít nhất 6):
      - test_cnn_shape: output (N, 1)
      - test_lstm_shape: output (N, 1)
      - test_ae_reconstruction: lower error on NORMAL
      - test_model_save: h5 file saved

    ✓ Run: pytest test_dl_models.py -v

[ ] Viết test_integration.py (~80 dòng):
    ✓ Integration tests (ít nhất 6):
      - test_full_pipeline: feature_extract → preprocess → train → evaluate
      - test_ml_detect_flood: phát hiện SYN flood
      - test_ml_detect_spoof: phát hiện IP spoof
      - test_dl_detect_stealthy: phát hiện stealthy attack
      - test_false_alarm: FP rate < 5%

    ✓ Run: pytest test_integration.py -v

[ ] Tính coverage:
    ✓ pytest --cov=. --cov-report=html
    ✓ Target: ≥ 80% coverage
```

**Sản phẩm 5.1:**

| File                           | Mô tả                    | Format                  | Nội dung                                                                    |
| ------------------------------ | ------------------------ | ----------------------- | --------------------------------------------------------------------------- |
| **test_feature_extraction.py** | Feature extraction tests | Python/pytest, ~80 dòng | 8+ test cases                                                               |
| **test_preprocessing.py**      | Preprocessing tests      | Python/pytest, ~60 dòng | 6+ test cases                                                               |
| **test_ml_models.py**          | ML model tests           | Python/pytest, ~80 dòng | 8+ test cases                                                               |
| **test_dl_models.py**          | DL model tests           | Python/pytest, ~60 dòng | 6+ test cases                                                               |
| **test_integration.py**        | Integration tests        | Python/pytest, ~80 dòng | 6+ test cases                                                               |
| **coverage/ (folder)**         | Coverage report          | HTML                    | Folder với index.html - show coverage %                                     |
| **TEST_SUMMARY.txt**           | Test execution report    | Text                    | Total tests: 34+ <br> Passed: 34 (100%) <br> Failed: 0 <br> Coverage: 82% ✓ |

---

### Task 5.2: Tạo Visualizations (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 12 giờ

**Công việc cụ thể:**

```
[ ] Viết visualization.py (~150 dòng):
    ✓ Plot 1: ROC Curves overlay (6 methods):
      - Load predictions từ tất cả models
      - Draw ROC curve cho mỗi method
      - Legend với AUC scores
      - Save: plots/01_roc_curves.png

    ✓ Plot 2: PR Curves (Precision-Recall):
      - Tương tự ROC
      - Save: plots/02_pr_curves.png

    ✓ Plot 3: Confusion Matrices (6 subplots):
      - 2x3 grid, mỗi cái 1 confusion matrix
      - Heatmap format
      - Save: plots/03_confusion_matrices.png

    ✓ Plot 4: Feature Importance (top 10):
      - Bar chart từ RF model
      - Save: plots/04_feature_importance.png

    ✓ Plot 5: Latency Comparison:
      - Bar chart so sánh 6 methods
      - X-axis: method name
      - Y-axis: latency (ms)
      - Save: plots/05_latency_bar.png

    ✓ Plot 6: Accuracy vs Latency (scatter):
      - X: latency, Y: accuracy
      - Mỗi method = 1 point + label
      - Save: plots/06_accuracy_vs_latency.png

    ✓ Plot 7: Class Distribution (pie chart):
      - % NORMAL vs ATTACK
      - Save: plots/07_class_distribution.png

[ ] Create visualization summary:
    ✓ Save: plots/PLOTS_DESCRIPTION.txt
```

**Sản phẩm 5.2:**

| File                                 | Mô tả                | Format            | Nội dung                     |
| ------------------------------------ | -------------------- | ----------------- | ---------------------------- |
| **visualization.py**                 | Visualization script | Python, ~150 dòng | Generate 7+ plots            |
| **plots/01_roc_curves.png**          | ROC curves           | PNG               | 6 lines overlay + AUC scores |
| **plots/02_pr_curves.png**           | PR curves            | PNG               | Precision vs Recall          |
| **plots/03_confusion_matrices.png**  | Confusion matrices   | PNG               | 2x3 subplots, 6 heatmaps     |
| **plots/04_feature_importance.png**  | Feature importance   | PNG               | Bar chart, top 10 features   |
| **plots/05_latency_bar.png**         | Latency comparison   | PNG               | Bar chart, 6 methods         |
| **plots/06_accuracy_vs_latency.png** | Tradeoff scatter     | PNG               | X: latency, Y: accuracy      |
| **plots/07_class_distribution.png**  | Class pie            | PNG               | % NORMAL vs ATTACK           |
| **plots/PLOTS_DESCRIPTION.txt**      | Plot descriptions    | Text              | Mô tả từng plot              |

---

### Task 5.3: Viết Test Report (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 6 giờ

**Sản phẩm 5.3:**

| File               | Mô tả                     | Format                 | Nội dung                                                                                                                                                                                                                                                                                                                                            |
| ------------------ | ------------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **TEST_REPORT.md** | Comprehensive test report | Markdown, 1000-1200 từ | **Phần 1: Test Strategy** <br> - Unit, integration, performance tests <br> - Coverage target: ≥80% <br> <br> **Phần 2: Test Results** <br> - Total: 34+ tests <br> - Passed: 34 (100%) ✓ <br> - Coverage: 82% ✓ <br> <br> **Phần 3: Known Issues** <br> - Nếu có, ghi down <br> <br> **Phần 4: Recommendations** <br> - Suggestions for improvement |

---

### Task 5.4: Chuẩn bị Presentation (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 12 giờ (slides + Q&A script + rehearse)

**Sản phẩm 5.4:**

| File                         | Mô tả         | Format                | Nội dung                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------- | ------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **PRESENTATION_SLIDES.pptx** | Slide deck    | PowerPoint, 20 slides | **Slide 1-2:** Title + Problem <br> **Slide 3-4:** Related Work (literature) <br> **Slide 5-6:** System Architecture <br> **Slide 7-8:** Dataset & Features <br> **Slide 9:** Entropy Results <br> **Slide 10-11:** ML Results <br> **Slide 12-14:** DL Results (CNN/LSTM/AE) <br> **Slide 15:** Comparison Table <br> **Slide 16:** Accuracy vs Latency Tradeoff <br> **Slide 17:** Demo & Live Testing <br> **Slide 18:** Conclusions <br> **Slide 19:** Future Work <br> **Slide 20:** Q&A |
| **QA_SCRIPT.md**             | Q&A script    | Markdown, 800+ từ     | **15 common questions + answers:** <br> - Why compare 3 methods? <br> - How handle class imbalance? <br> - False alarm rate acceptable? <br> - Real-time feasibility? <br> - Scalability to 100k pps? <br> - Test on real network? <br> - vs Snort/Suricata? <br> - Adversarial robustness? <br> - Future improvements? <br> ... etc                                                                                                                                                          |
| **SPEAKER_NOTES.txt**        | Speaker notes | Text                  | - Timing: 20 mins total <br> - Key talking points per slide <br> - Transition phrases <br> - Demo walkthrough steps                                                                                                                                                                                                                                                                                                                                                                           |

---

### Task 5.5: Final Integration & Cleanup (Tuần 5)

**Thời hạn:** Hết tuần 5  
**Nỗ lực:** 8 giờ

**Sản phẩm 5.5:**

| File                            | Mô tả               | Format             | Nội dung                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------- | ------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **FINAL_INTEGRATION_REPORT.md** | Integration report  | Markdown, 1000+ từ | **Executive Summary:** <br> - Problem: DDoS detection <br> - Solution: Compare 3 methods <br> - Result: DL best (98.2% F1) but slower latency <br> <br> **How to Reproduce:** <br> 1. git clone repo <br> 2. bash setup_environment.sh <br> 3. python3 run_all_steps.py <br> 4. Check results/ folder <br> <br> **Folder Structure:** <br> - data/: raw pcap + features + train/val/test <br> - models/: trained .pkl + .h5 files <br> - results/: metrics + benchmarks <br> - plots/: all visualizations <br> - tests/: test suite <br> <br> **Files Checklist:** <br> - ✓ Feature extraction <br> - ✓ ML models (RF, XGB, LGB) <br> - ✓ DL models (CNN, LSTM, AE) <br> - ✓ Comparison & analysis <br> - ✓ Documentation |
| **README.md**                   | Project overview    | Markdown           | **Project Title:** <br> DoS Attack Detection using Entropy, ML, and DL <br> <br> **Quick Start:** <br> `bash <br> bash setup.sh <br> python3 train_all.py <br> python3 evaluate.py <br> ` <br> <br> **Results Summary:** <br> - Best model: CNN (F1=98.2%, latency=75ms) <br> - Datasets: 2.5M flows, 5 attack types <br> - Throughput: ≥1000 flows/sec <br> <br> **Documentation:** <br> - See docs/ folder for detailed guides                                                                                                                                                                                                                                                                                          |
| **GitHub .gitignore**           | Git ignore file     | Text               | Exclude: <br> - _.pcap (large files) <br> - _.pkl (binary models) <br> - \*.h5 (keras models) <br> - **pycache**/ <br> - .venv/                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **requirements.txt**            | Python dependencies | Text               | pandas==1.3.0 <br> scikit-learn==1.0.0 <br> xgboost==1.5.0 <br> lightgbm==3.3.0 <br> tensorflow==2.8.0 <br> scapy==2.4.5 <br> pytest==6.2.5 <br> matplotlib==3.5.0 <br> ...                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| **GitHub tag**                  | Version tag         | Git tag            | v1.0-final-submission <br> (Mark final version)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

---

## 📅 DETAILED TIMELINE

---

## 📅 LỊCH THỰC HIỆN HÀNG TUẦN

| Tuần  | Thành viên 1                    | Thành viên 2                 | Thành viên 3         | Thành viên 4        | Thành viên 5     |
| ----- | ------------------------------- | ---------------------------- | -------------------- | ------------------- | ---------------- |
| **1** | Đọc papers, định nghĩa protocol | Setup Mininet+Ryu            | Chuẩn bị ML env      | Chuẩn bị DL env     | Setup test env   |
| **2** | Hoàn thành survey & protocol    | Thu thập traffic bình thường | Chuẩn bị hyperparams | Chuẩn bị sequences  | Test templates   |
| **3** | Review code, updates            | Tấn công DoS + features      | RF training          | DL sequences        | Test cases start |
| **4** | Review code, updates            | Feature extraction hoàn tất  | ML comparison        | CNN+LSTM+AE train   | Test coverage    |
| **5** | Viết báo cáo cuối               | Preprocessing hoàn tất       | Real-time inference  | Real-time inference | Slides + Q&A     |

---

**Created:** 2026-04-21  
**Last Updated:** 2026-04-21  
**Version:** 1.0  
**Status:** ✅ READY FOR EXECUTION
