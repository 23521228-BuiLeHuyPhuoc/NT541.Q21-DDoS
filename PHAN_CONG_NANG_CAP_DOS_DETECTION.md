# Phan Cong Phat Trien DoS Detection - 5 Thanh Vien

**Đề tài:** Denial-of-Service Attack Detection - So sánh Entropy vs Machine Learning vs Deep Learning  
**Mục tiêu:** 10 điểm, hướng thực hành 70%, có cơ sở khoa học

---

## 📊 TRANG THAI PROJECT HIEN TAI

### ✅ Code đã có (reuse & phát triển):

- `topology_nhom4.py`: Mô phỏng mạng 5 switch, 8 hosts (attacker, web, db, pc zones)
- `l3_router_test.py`: Router L3 dùng OpenFlow 1.3 + **Entropy detection** (Shannon entropy)
- Cơ chế block IP/MAC + whitelist cho phép
- InfluxDB integration để lưu metrics
- Demo scripts: `dos_botnet.txt`, `dos_spoof.txt` (hping3, iperf)
- Docs: `HOW_TO_USE.md`, `demo_guide.md`, `ANSWER_SCRIPT.md`

### ⚠️ Cần xây dựng (70% thực hành):

- **Feature extraction**: Tách flow records từ pcap, tính packet rate, byte rate, entropy, flow duration...
- **Baseline ML**: Random Forest, XGBoost, LightGBM trên features
- **Deep Learning**: CNN/LSTM/Autoencoder cho detection
- **Real-time module**: Inference lặp tức khi traffic đi qua router
- **Dataset**: Thu thập, gán nhãn, train/val/test split (ít nhất 70/20/10)
- **Benchmark**: So sánh accuracy, F1, ROC-AUC, latency, throughput
- **Test scenarios**: Imbalance, noisy, time-dependent attacks
- **Visualization + Report**: Dashboard, PR/ROC curve, bảng so sánh

---

## 👥 PHAN CONG 5 THANH VIEN

### **Thành viên 1 - TRƯỞNG NHÓM + HAY RESEARCH (30% tổ hợp, 70% quản lý)**

**Vị trí**: Leader phối hợp + survey tài liệu khoa học

**Nhiệm vụ chính**:

- Định hình khuôn khổ nghiên cứu, chọn metrics, protocol test
- Thu thập & phân loại báo khoa học (CICIDS2017, UNSW-NB15, DL-IDS, entropy-based methods)
- Kiểm soát chất lượng (reproducibility checklist, code review)

**Đầu ra cụ thể**:

1. **File `RESEARCH_SURVEY.md`** (2000+ words):
   - Tóm tắt 15 bài báo (title, year, venue, key findings, methods)
   - So sánh entropy vs ML vs DL theo feature, tốc độ, độ chính xác
   - Bảng: Dataset | Features | Model | Accuracy | Latency

2. **File `EVALUATION_PROTOCOL.md`**:
   - Định nghĩa chính xác: Precision, Recall, F1, ROC-AUC, Latency (ms), Throughput (pps)
   - Train/val/test split strategy (70/20/10 hoặc time-series)
   - Cách đánh giá trên 3 loại attack: single IP flood, IP spoof, mixed

3. **Code review checklist** (tuần 1-5):
   - Kiểm tra reproducibility (seed, hardware spec)
   - Commit message quality
   - Documentation trong code

---

### **Thành viên 2 - DATA & LAB ENGINEER (100% thực hành)**

**Vị trí**: Xây dựng pipeline Thu/Xử lý dữ liệu

**Nhiệm vụ chính**:

- Cấu hình topology test & đảm bảo traffic capture ổn định
- Thu thập pcap files từ normal + DoS scenarios
- Tích hợp feature extraction pipeline

**Đầu ra cụ thể**:

1. **Script `setup_lab_environment.sh`**:
   - Cài Mininet, Ryu, InfluxDB, scapy, tshark trên Ubuntu
   - Kiểm tra kết nối controller <-> switch
   - Tạo test topology & verify routing

2. **Script `capture_traffic.py`** (sử dụng scapy hoặc tcpdump):
   - Thu pcap từ port của router
   - Gán nhãn tự động: "NORMAL" / "FLOOD_ATTACK" / "SPOOF_ATTACK"
   - Output: `data/raw/normal_traffic.pcap`, `data/raw/dos_flood.pcap`, `data/raw/dos_spoof.pcap`
   - Ít nhất 1GB dữ liệu mỗi loại

3. **Script `feature_extraction.py`**:
   - Đọc pcap → tách flow records (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
   - Tính features mỗi flow (duration, pkt_count, byte_count, pkt_rate, byte_rate, entropy_src)
   - Output CSV: `data/features/flows_labeled.csv` (20+ features)
   - Có test cases: corrupted pcap, imbalanced class, missing values

4. **Documentation `DATA_COLLECTION_GUIDE.md`**:
   - Cách chạy attack scenarios từ `dos_botnet.txt` / `dos_spoof.txt`
   - Bảng check: timestamp, packet count, traffic profile cho mỗi lần thu

---

### **Thành viên 3 - ML BASELINE ENGINEER (100% thực hành)**

**Vị trí**: Xây dựng baseline machine learning

**Nhiệm vụ chính**:

- Train 3+ model ML trên flow features
- So sánh kết quả & phân tích feature importance
- Optimize hyperparameter & inference latency

**Đầu ra cụ thể**:

1. **Notebook/Script `ml_baseline_train.py`**:
   - Load `flows_labeled.csv` từ Thành viên 2
   - Preprocessing: scaling, normalization, handling missing
   - 3 models: **Logistic Regression**, **Random Forest** (50 trees), **XGBoost** (depth=6)
   - Cross-validation (5-fold), grid search cho hyperparameters
   - Output: confusion matrix, classification report mỗi model

2. **Evaluation report `ML_BASELINE_RESULTS.md`**:
   - Bảng: Model | Precision | Recall | F1 | ROC-AUC | Training Time | Inference Time
   - Analyze false positives/negatives: histograms, SHAP values (feature importance)
   - Kết luận model tốt nhất để integrate với DL
   - Câu hỏi: Tại sao Random Forest lại tốt hơn Logistic? → trả lời trong report

3. **Script `ml_inference_live.py`**:
   - Load trained model (pickle)
   - Real-time inference từ flow stats router
   - Output: prediction + confidence + latency per packet batch
   - Benchmark: throughput, latency ở tốc độ 10k pps, 100k pps

---

### **Thành viên 4 - DEEP LEARNING + REAL-TIME DETECTION (100% thực hành)**

**Vị trí**: Xây dựng model DL & pipeline real-time

**Nhiệm vụ chính**:

- Implement 1-2 DL model (CNN/LSTM/Autoencoder)
- Integrate với router để inference real-time
- Đo latency & throughput dưới tải cao

**Đầu ra cụ thể**:

1. **DL Model Implementation**:
   - **Option A: 1D-CNN**
     - Input: time-series flow features (sequence 10-20 flows)
     - Architecture: 2-3 Conv1D layers + MaxPool + Flatten + Dense 2-layer
     - Output: binary classification (Normal/DoS)
   - **Option B: LSTM**
     - Input: sequence flows (LSTM 64/128 units, 2 layers)
     - Capture temporal patterns
   - **Option C: Autoencoder (Unsupervised)**
     - Normal traffic = low reconstruction error
     - Attack = high reconstruction error → flag anomaly

2. **Script `dl_model_train.py`**:
   - Prepare sequences từ features
   - Data augmentation nếu class imbalance
   - Train with validation split 80/20 hoặc time-based
   - Early stopping, checkpoint best model
   - Evaluation: ROC-AUC, F1, confusion matrix

3. **Real-time Integration `rt_detection_module.py`**:
   - Hook vào router (listen InfluxDB hoặc socket)
   - Batch inference (10-50 flows/batch)
   - Trigger alert nếu detection score > threshold
   - Measure: latency per batch, throughput (flows/sec)
   - Hỗ trợ model switching (entropy → ML → DL)

4. **Benchmark Report `DL_REALTIME_BENCHMARK.md`**:
   - Bảng: Model | F1 | Latency(ms) | Throughput(flows/s) | Memory(MB)
   - So sánh với Entropy + ML baseline
   - Kết luận: Trade-off giữa accuracy vs latency

---

### **Thành viên 5 - TESTING, VISUALIZATION, REPORT & THUYẾT TRÌNH (90% thực hành, 10% tổng hợp)**

**Vị trí**: QA, Dashboard, Thuyết trình

**Nhiệm vụ chính**:

- Viết test cases cho tất cả module
- Tạo dashboard visualization kết quả
- Chuẩn bị slide & Q&A script

**Đầu ra cụ thể**:

1. **Test Suite `test_dos_detection.py`** (100+ test cases):
   - Test unit: feature extraction (null values, overflow, type check)
   - Test integration: Entropy detection + ML inference + DL inference
   - Stress test: 10k pps, 100k pps sustained traffic
   - Edge case: sudden traffic spikes, traffic with noise, imbalanced classes
   - Output: test report với coverage ≥ 80%

2. **Visualization Script `visualization_dashboard.py`** (dùng matplotlib/plotly):
   - **Graph 1**: ROC curves overlay (Entropy vs ML vs DL)
   - **Graph 2**: PR curves (Precision-Recall trade-off)
   - **Graph 3**: Latency vs Throughput scatter
   - **Graph 4**: Feature importance (SHAP/Permutation)
   - **Graph 5**: Temporal: Detection accuracy over time (dòng thời gian)
   - **Graph 6**: Confusion matrix heatmap cho mỗi model
   - → Xuất PDF report có all graphs

3. **Slide Thuyết Trình (20 phút)**:
   - Slide 1-2: Problem + Background (DoS types, why hard to detect)
   - Slide 3-4: Architecture & Data Collection
   - Slide 5-7: Entropy-based Detection (cơ chế, kết quả)
   - Slide 8-10: ML Baseline (features, models, results)
   - Slide 11-13: Deep Learning (model design, real-time integration)
   - Slide 14-16: So sánh 3 phương pháp (table + graphs)
   - Slide 17-18: Demo video
   - Slide 19-20: Kết luận, hạn chế, future work

4. **Q&A Script `QA_SCRIPT.md`** (30 câu hỏi dự kiến):
   - "Entropy có cách nào bị vượt qua?" → Trả lời cơ chế adaptive attack
   - "Tại sao chọn Random Forest thay vì SVM?" → So sánh training time, scalability
   - "Model DL training mất bao lâu?" → Trả lời hardware, dataset size, time
   - "False positive rate là bao nhiêu?" → Trả lời với threshold khác nhau
   - "Có thể scale to production?" → Trả lời bottleneck, optimization

---

## 📅 LICH TRINH 5 TUAN

| Tuần  | Mục tiêu           | Sprint                                                               | Deliver                                                     |
| ----- | ------------------ | -------------------------------------------------------------------- | ----------------------------------------------------------- |
| **1** | Setup + khuôn khổ  | Thành viên 1: chọn dataset, metric. Thành viên 2: setup lab          | `EVALUATION_PROTOCOL.md`, cấu hình topology ✅              |
| **2** | Thu thập & feature | Thành viên 2: pcap + feature extraction. Thành viên 1: survey        | `flows_labeled.csv` (20+ features), `RESEARCH_SURVEY.md` ✅ |
| **3** | ML baseline        | Thành viên 3: train 3 models. Thành viên 4: bắt đầu DL               | `ML_BASELINE_RESULTS.md`, best model (pkl) ✅               |
| **4** | DL + real-time     | Thành viên 4: train DL, integrate real-time. Thành viên 5: viết test | `DL_REALTIME_BENCHMARK.md`, test report ✅                  |
| **5** | Tích hợp + demo    | Tất cả: tính chạy demo live. Thành viên 5: slide + video             | Report tổng hợp, slide, video demo ✅                       |

**Tuần demo:**

- 5 phút: Entropy detection (kế thừa cũ)
- 5 phút: ML baseline trên feature
- 5 phút: DL real-time inference
- 5 phút: So sánh 3 phương pháp (bảng + biểu đồ)

---

## 📚 THAM KHAO BAO KHOA HOC (Tu khoa goi y)

**Bắt buộc đọc tối thiểu 15 bài (phân bố cho 5 người):**

### Entropy-based / Flow-based Detection

1. _"Entropy-based network anomaly detection"_ - IEEE/ACM
2. _"Real-time detection of DDoS attacks using entropy"_ - Springer
3. _"SDN-based DDoS detection using flow statistics"_ - MDPI

### Machine Learning for IDS

4. _"Random Forest for network intrusion detection"_ - CICIDS2017 paper
5. _"XGBoost for DDoS detection"_ - IEEE IoT
6. _"Feature importance analysis in ML-based IDS"_ - Elsevier

### Deep Learning for IDS

7. _"CNN for network traffic classification"_ - IEEE
8. _"LSTM for temporal intrusion detection"_ - Springer
9. _"Autoencoder for anomaly detection"_ - ACM

### Dataset & Benchmark

10. _"CICIDS2017: Evaluating Intrusion Detection Systems"_ - original paper
11. _"UNSW-NB15: A comprehensive network attack dataset"_ - original paper
12. _"KDD Cup 99 vs modern datasets"_ - comparison study

### Advanced Topics

13. _"Adversarial attacks on DL-based IDS"_ - arXiv
14. _"Real-time inference optimization for IDS"_ - IEEE IoT
15. _"DDoS in SDN: challenges and solutions"_ - Springer

**Các database tìm kiếm:**

- IEEE Xplore, ACM Digital Library, Springer, Elsevier, arXiv
- Google Scholar (scholar.google.com)
- ResearchGate, Academia.edu (tìm authors)

---

## ✅ CHECKLIST HUONG TOI 10 DIEM

- [x] **Demo live ≥ 2 lần thành công** trên topology Mininet, entropy + ML + DL
- [x] **So sánh 3 phương pháp**: Precision/Recall/F1/ROC-AUC/Latency cho Entropy vs ML vs DL
- [x] **Dataset ≥ 1GB**: gán nhãn, train/val/test split rõ ràng
- [x] **15+ bài báo**: tóm tắt trong `RESEARCH_SURVEY.md` có trích dẫn đúng chuẩn
- [x] **Code & Test**: ≥ 50 test cases, coverage ≥ 80%, có pytest/unittest
- [x] **Real-time module**: latency ≤ 100ms per batch, throughput ≥ 1k flows/s
- [x] **Visualization**: ROC/PR curves, confusion matrices, latency trends
- [x] **Mỗi thành viên có commit + demo**: GitHub history, 1 thanh viên = 1+ deliverable kỹ thuật
- [x] **Thuyết trình 20 phút**: rõ ràng, có Q&A script, nhóm trả lời được câu hỏi deep
- [x] **Bảng so sánh cuối**: Entropy (speed, accuracy, limited) vs ML (balanced) vs DL (best accuracy, slow)

---

## 🛠️ TOOLS & ENV REQS

**Mandatory:**

- Ubuntu 18.04+ LTS
- Python 3.7+
- Mininet (mạng ảo)
- Ryu controller (SDN)
- scikit-learn, XGBoost, LightGBM (ML)
- TensorFlow/PyTorch (DL)
- InfluxDB (optional, logging metrics)
- Scapy, tshark (packet capture)
- Jupyter Notebook (experiment)
- Git + GitHub (collaboration)

**Optional nhưng khuyến khích:**

- SHAP (feature explanation)
- Plotly (interactive visualization)
- Sphinx (code documentation)

---

## 📌 CO CHE KIEM SOAT CHAT LUONG

1. **Hop ky thuat 2x/tuan** (30 phút, online + offline):
   - Cập nhật tình hình, blocker
   - Phân chia lại công việc nếu cần

2. **PR review cheo**: ≥ 1 reviewer bên ngoài team trước merge main

3. **Weekly demo 5 phút/người** (cuối tuần):
   - Thanh viên 1: survey + khuôn khổ
   - Thanh viên 2: dataset status
   - Thanh viên 3: ML results
   - Thanh viên 4: DL + real-time
   - Thanh viên 5: test + slide

4. **Reproducibility check** (tuần 5):
   - Run từ git repo, không có manual setup
   - Tất cả script có README rõ ràng
   - Kết quả ≥ 95% so với report

---

## 📝 DELIVERABLES TONG HOP

**By end of week 5:**

1. ✅ GitHub repo: code + docs (tag: final-submission)
2. ✅ PDF Report (30+ pages):
   - Survey + Related work (10p)
   - Methodology & Dataset (8p)
   - Entropy detection review (3p)
   - ML baseline results (5p)
   - DL + real-time results (5p)
   - Comparison table + graphs (4p)
   - Conclusion (1p)
3. ✅ Slide (20 pages) + Q&A script
4. ✅ Demo video (5-7 min), hoặc live demo tại thuyết trình
5. ✅ Test report (coverage, results, test cases)
6. ✅ Jupyter notebooks (experiment tracking)

---

**Prepared by: Thành viên 1 (Leader)**  
**Last updated: 2026-04-21**  
**Status: ACTIVE - Tuần 1**
