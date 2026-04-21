# MASTER TO-DO LIST - DoS Detection Project

**Status:** Week 1 / Week 5  
**Last updated:** 2026-04-21  
**Cách sử dụng:** Tích [x] khi hoàn thành, cập nhật weekly

---

## 📅 WEEK 1: SETUP + RESEARCH + PLANNING

### Thành viên 1 - Research Lead

- [ ] Read all 15+ papers from REFERENCES_PAPERS.md (prioritize A1, A2, B1, B2, C1, C2)
- [ ] Create RESEARCH_SURVEY.md (3000+ words, all 15 papers cited)
- [ ] Create EVALUATION_PROTOCOL.md (500+ words, define metrics & thresholds)
- [ ] Create ATTACK_SCENARIOS.md (describe 5 scenarios: SYN, UDP, spoof, distributed, stealthy)
- [ ] Team kickoff meeting (all 5 members, 30 mins)
- [ ] Share research findings with team

**Deadline:** End of Week 1  
**Status:** ☐ NOT STARTED

---

### Thành viên 2 - Data & Lab Engineer

- [ ] Install Mininet, Ryu, Scapy, tshark on Ubuntu 18.04+
- [ ] Review `topology_nhom4.py` (understand 5 switches, 8 hosts)
- [ ] Review `l3_router_test.py` (understand entropy algorithm)
- [ ] Create `setup_environment.sh` (automated installation)
- [ ] Test topology: mininet > h_pc1 ping h_web1 ✓
- [ ] Test Ryu controller connection ✓
- [ ] Create data directories: data/raw, data/features, logs
- [ ] Create `LAB_SETUP_GUIDE.md` (installation + troubleshooting)
- [ ] **Deliverable:** Setup script + verified running Mininet topology

**Deadline:** End of Week 1  
**Status:** ☐ NOT STARTED

---

### Thành viên 3 - ML Engineer (prepare)

- [ ] Read ML papers (B3, B4 from REFERENCES_PAPERS.md)
- [ ] Understand: Random Forest, XGBoost, class imbalance handling
- [ ] Install sklearn, xgboost, lightgbm
- [ ] Study hyperparameter tuning techniques
- [ ] Prepare environment: Jupyter notebook or Python IDE
- [ ] **Deliverable:** Environment ready, no ML work yet (wait for data from Member 2)

**Deadline:** End of Week 1  
**Status:** ☐ NOT STARTED

---

### Thành viên 4 - DL Engineer (prepare)

- [ ] Read DL papers (C1, C2, C3, C4 from REFERENCES_PAPERS.md)
- [ ] Understand: CNN, LSTM, Autoencoder architectures
- [ ] Install TensorFlow/PyTorch + Keras
- [ ] Study sequence generation (sliding window approach)
- [ ] Prepare GPU environment (if available)
- [ ] **Deliverable:** DL environment ready, understand flow sequences

**Deadline:** End of Week 1  
**Status:** ☐ NOT STARTED

---

### Thành viên 5 - QA + Presentation (prepare)

- [ ] Read dataset papers (D1, D2 from REFERENCES_PAPERS.md)
- [ ] Understand: test strategy, pytest, matplotlib basics
- [ ] Create folder structure: tests/, plots/, results/
- [ ] Plan presentation: 20 slides structure
- [ ] **Deliverable:** Testing environment ready, slide template prepared

**Deadline:** End of Week 1  
**Status:** ☐ NOT STARTED

---

## 📅 WEEK 2: DATA COLLECTION + FEATURE RESEARCH

### Thành viên 1 - Research Lead

- [ ] Continue reading remaining papers (finish all 15)
- [ ] Create extended comparison table (method, accuracy, latency, pros/cons)
- [ ] Write "Related Work" section for final report
- [ ] Meet with Member 2 to review dataset design
- [ ] **Deliverable:** RESEARCH_SURVEY.md v1.0 completed

**Deadline:** End of Week 2  
**Status:** ☐ NOT STARTED

---

### Thành viên 2 - Data & Lab Engineer

- [ ] Collect **Normal Traffic** (3 scenarios):
  - [ ] Scenario A: Baseline (5 mins, iperf) → data/raw/normal_baseline.pcap (~150MB)
  - [ ] Scenario B: Mixed services (10 mins, DNS + HTTP + FTP) → data/raw/normal_mixed.pcap (~200MB)
  - [ ] Scenario C: Light traffic (5 mins, ping) → data/raw/normal_light.pcap (~5MB)
- [ ] Log all traffic collection metadata
- [ ] Verify pcap file sizes (expect ≥500MB total)
- [ ] **Deliverable:** data/raw/normal*\*.pcap files + logs/normal*\*.log

**Deadline:** End of Week 2  
**Status:** ☐ NOT STARTED

---

### Thành viên 3 - ML Engineer (prepare)

- [ ] Study feature selection techniques
- [ ] Plan hyperparameter tuning strategy for RF/XGBoost
- [ ] Create template: `ml_baseline_template.py`
- [ ] **Deliverable:** Ready to train models (wait for features)

**Deadline:** End of Week 2  
**Status:** ☐ NOT STARTED

---

### Thành viên 4 - DL Engineer (prepare)

- [ ] Study sequence generation from flows
- [ ] Create template: `dl_sequence_prep_template.py`
- [ ] Plan CNN/LSTM/AE architectures
- [ ] **Deliverable:** Ready for sequence preparation

**Deadline:** End of Week 2  
**Status:** ☐ NOT STARTED

---

### Thành viên 5 - QA + Presentation

- [ ] Create initial test templates
- [ ] Start outline for presentation slides
- [ ] **Deliverable:** Slide template + test structure

**Deadline:** End of Week 2  
**Status:** ☐ NOT STARTED

---

## 📅 WEEK 3: ATTACK TRAFFIC + FEATURE EXTRACTION + ML START

### Thành viên 1 - Research Lead

- [ ] Review Member 2 dataset collection process
- [ ] Finalize evaluation protocol & thresholds
- [ ] Plan error analysis approach
- [ ] **Deliverable:** EVALUATION_PROTOCOL.md finalized

**Deadline:** Tuần 3 mid  
**Status:** ☐ NOT STARTED

---

### Thành viên 2 - Data & Lab Engineer

- [ ] Collect **DoS Attack Traffic** (5 scenarios):
  - [ ] Scenario A: SYN Flood (2 mins, hping3 -S --flood) → data/raw/dos_synflood.pcap (~150MB)
  - [ ] Scenario B: UDP Flood (2 mins, custom tool) → data/raw/dos_udpflood.pcap (~150MB)
  - [ ] Scenario C: IP Spoofing (2 mins, random src IPs) → data/raw/dos_spoof.pcap (~150MB)
  - [ ] Scenario D: Distributed (2 mins, 2+ attackers) → data/raw/dos_distributed.pcap (~100MB)
  - [ ] Scenario E: Stealthy (5 mins, low rate) → data/raw/dos_stealthy.pcap (~30MB)
- [ ] Verify total DoS data ≥500MB
- [ ] Label all pcap files (NORMAL vs FLOOD vs SPOOF)
- [ ] **Deliverable:** data/raw/dos*\*.pcap files + logs/dos*\*.log

**Deadline:** Tuần 3 end  
**Status:** ☐ NOT STARTED

---

### Thành viên 2 (continued) - Feature Extraction

- [ ] Create `feature_extraction.py` (300+ lines)
  - [ ] Parse pcap using Scapy/pyshark
  - [ ] Extract 20+ features per flow (duration, rate, entropy, flags, etc.)
  - [ ] Handle edge cases (empty pcap, corrupted packets)
- [ ] Extract features from all normal pcap files → data/features/normal_all.csv
- [ ] Extract features from all attack pcap files → data/features/dos_all.csv
- [ ] Merge into: data/features/flows_labeled_ALL.csv
- [ ] Validate: check nulls, ranges, class distribution
- [ ] Create DATASET_DESCRIPTION.md (schema + statistics)
- [ ] **Deliverable:** flows_labeled_ALL.csv (2.5M+ rows, 20+ features)

**Deadline:** Tuần 3 end  
**Status:** ☐ NOT STARTED

---

### Thành viên 3 - ML Baseline Engineer

- [ ] Create `ml_rf_train.py`:
  - [ ] Load train/val/test from Member 2 (wait for split data)
  - [ ] Hyperparameter grid search (5-fold CV)
  - [ ] Train best RandomForest model
  - [ ] Evaluate: Accuracy, Precision, Recall, F1, ROC-AUC
  - [ ] Save model → models/rf_model.pkl
- [ ] Create evaluation report with metrics
- [ ] Create feature importance plot
- [ ] **Deliverable:** RF model + results (F1 ≥0.90 expected)

**Deadline:** Tuần 3 end  
**Status:** ☐ NOT STARTED

---

### Thành viên 4 - DL Engineer

- [ ] Create `dl_sequence_preparation.py`:
  - [ ] Load flows_labeled_ALL.csv (from Member 2)
  - [ ] Create sequences (window=20 flows per sequence)
  - [ ] Train/val/test split
  - [ ] Save sequences for DL training
- [ ] **Deliverable:** Training sequences ready (X_train_seq, y_train_seq, etc.)

**Deadline:** Tuần 3 end  
**Status:** ☐ NOT STARTED

---

### Thành viên 5 - QA + Presentation

- [ ] Start writing test suite: `test_feature_extraction.py`
- [ ] Create 15+ test cases for feature extraction validation
- [ ] Start designing presentation slides (intro, related work)
- [ ] **Deliverable:** Initial test suite started

**Deadline:** Tuần 3 end  
**Status:** ☐ NOT STARTED

---

## 📅 WEEK 4: ML TRAINING + DL TRAINING + TESTING

### Thành viên 1 - Research Lead

- [ ] Code review: check Member 2 feature extraction, Member 3 ML code
- [ ] Update research summary with early results
- [ ] **Deliverable:** Code review checklist completed

**Deadline:** Tuần 4  
**Status:** ☐ NOT STARTED

---

### Thành viên 2 - Data & Lab Engineer

- [ ] Create `preprocessing.py`:
  - [ ] Handle missing values (drop/impute)
  - [ ] Detect & flag outliers
  - [ ] StandardScaler normalization
  - [ ] Train/val/test split (70/20/10)
  - [ ] Save scaler → scaler.pkl
- [ ] Save processed data: train.csv, val.csv, test.csv
- [ ] Create PREPROCESSING_REPORT.txt (null %, outliers %, class balance)
- [ ] **Deliverable:** Preprocessed train/val/test CSVs ready for ML

**Deadline:** Tuần 4 mid  
**Status:** ☐ NOT STARTED

---

### Thành viên 3 - ML Baseline Engineer

- [ ] Create `ml_xgboost_train.py`:
  - [ ] Hyperparameter tuning
  - [ ] Train XGBoost model
  - [ ] Evaluate: F1 ≥0.95 expected
  - [ ] Save → models/xgb_model.pkl
- [ ] Create `ml_lightgbm_train.py`:
  - [ ] Similar to XGBoost
  - [ ] Save → models/lgb_model.pkl
- [ ] Create `ml_compare_baselines.py`:
  - [ ] Compare RF vs XGBoost vs LightGBM
  - [ ] Create comparison table & plots (ROC, confusion matrix)
  - [ ] Save → results/ml_comparison.csv
- [ ] Create `ml_realtime_inference.py`:
  - [ ] Load best model
  - [ ] Implement inference on batches
  - [ ] Measure latency & throughput
- [ ] Create `ml_benchmark.py`:
  - [ ] Test different traffic rates (1k-100k pps)
  - [ ] Measure latency/throughput degradation
  - [ ] Save → results/ml_realtime_benchmark.json
- [ ] **Deliverable:** All 3 ML models trained + comparison done

**Deadline:** Tuần 4 end  
**Status:** ☐ NOT STARTED

---

### Thành viên 4 - DL Engineer

- [ ] Create `dl_cnn_train.py`:
  - [ ] Define CNN architecture (Conv1D + Flatten + Dense)
  - [ ] Train on sequences
  - [ ] Evaluate: F1 expected ~0.98
  - [ ] Save model → models/cnn_model.h5
  - [ ] Plot training history
- [ ] Create `dl_lstm_train.py`:
  - [ ] Define LSTM architecture (2-layer LSTM)
  - [ ] Train on sequences
  - [ ] Save → models/lstm_model.h5
- [ ] Create `dl_autoencoder_train.py`:
  - [ ] Train on NORMAL data only
  - [ ] Threshold tuning on validation set
  - [ ] Save → models/autoencoder_model.h5
- [ ] Create `dl_compare.py`:
  - [ ] Compare CNN vs LSTM vs Autoencoder
  - [ ] Create comparison table & plots
  - [ ] Save → results/dl_comparison.csv
- [ ] **Deliverable:** All 3 DL models trained + comparison done

**Deadline:** Tuần 4 end  
**Status:** ☐ NOT STARTED

---

### Thành viên 5 - QA + Presentation

- [ ] Continue test suite:
  - [ ] test_preprocessing.py (10+ cases)
  - [ ] test_ml_models.py (15+ cases)
  - [ ] test_dl_models.py (10+ cases)
- [ ] Create test report: TEST_REPORT.md
- [ ] Create presentation slides: problem statement, related work, methodology (50% done)
- [ ] **Deliverable:** 40+ test cases written, 50% of slides done

**Deadline:** Tuần 4 end  
**Status:** ☐ NOT STARTED

---

## 📅 WEEK 5: INTEGRATION + DEMO + FINAL REPORT

### Thành viên 1 - Research Lead

- [ ] Write Final Report (30+ pages):
  - [ ] Introduction (2 pages)
  - [ ] Related Work (3 pages)
  - [ ] Methodology (4 pages)
  - [ ] Results (5 pages with tables & plots)
  - [ ] Discussion (4 pages)
  - [ ] Conclusion (1 page)
  - [ ] Appendix (8+ pages: features, hyperparams, architectures)
- [ ] Ensure all 15+ papers cited (IEEE format)
- [ ] Final code review before submission
- [ ] **Deliverable:** FINAL_REPORT.md (30+ pages PDF)

**Deadline:** Tuần 5 end  
**Status:** ☐ NOT STARTED

---

### Thành viên 2 - Data & Lab Engineer

- [ ] Finalize data documentation
- [ ] Create DATASET_DESCRIPTION.md final version
- [ ] Verify all data files exist & are accessible
- [ ] Clean up raw pcap files (optional: compress or document storage)
- [ ] **Deliverable:** Final dataset documentation + cleanup

**Deadline:** Tuần 5 mid  
**Status:** ☐ NOT STARTED

---

### Thành viên 3 - ML Baseline Engineer

- [ ] Create `ml_error_analysis.py`:
  - [ ] Analyze false positives & false negatives
  - [ ] Create visualizations (scatter plots of FP/FN in feature space)
- [ ] Create `ML_RESULTS.md` (2000+ words):
  - [ ] Model comparison table
  - [ ] Feature importance analysis
  - [ ] Error analysis
  - [ ] Recommendations
- [ ] **Deliverable:** ML_RESULTS.md + error analysis plots

**Deadline:** Tuần 5 mid  
**Status:** ☐ NOT STARTED

---

### Thành viên 4 - DL Engineer

- [ ] Create `dl_realtime_inference.py`:
  - [ ] Load best DL model (CNN)
  - [ ] Implement real-time inference on sequences
  - [ ] Measure latency & throughput
- [ ] Create `dl_benchmark.py`:
  - [ ] Test different traffic rates
  - [ ] Create plots: latency/throughput vs traffic rate
  - [ ] Save results → results/dl_realtime_benchmark.json
- [ ] Create `DL_RESULTS.md` (2000+ words):
  - [ ] Model architectures (with diagrams)
  - [ ] Training history analysis
  - [ ] Comparison: CNN vs LSTM vs Autoencoder
  - [ ] Best model recommendation
  - [ ] Real-time performance metrics
- [ ] **Deliverable:** DL_RESULTS.md + benchmark results

**Deadline:** Tuần 5 mid  
**Status:** ☐ NOT STARTED

---

### Thành viên 5 - QA + Presentation

- [ ] Complete test suite:
  - [ ] test_attack_detection.py (15+ integration tests)
  - [ ] Reach 50+ total test cases
  - [ ] Achieve ≥80% code coverage
- [ ] Create `visualization.py`:
  - [ ] Plot 1: ROC curves (all methods overlay)
  - [ ] Plot 2: PR curves
  - [ ] Plot 3: Confusion matrices (6 subplots)
  - [ ] Plot 4: Feature importance
  - [ ] Plot 5: Latency comparison
  - [ ] Plot 6: Accuracy vs latency scatter
  - [ ] Plot 7: Class distribution
- [ ] Create dashboard.html (optional, interactive visualization)
- [ ] Create TEST_REPORT.md (500+ words, test strategy + results)
- [ ] Complete presentation slides (20 slides total):
  - [ ] Include all plots & results
  - [ ] Demo scenario description (SYN flood detection)
  - [ ] Conclusions & future work
- [ ] Create `QA_SCRIPT.md` (30 common questions + answers):
  - [ ] Technical depth questions
  - [ ] Defense questions (why this approach?)
  - [ ] Limitations & future work
- [ ] Rehearse presentation (20 mins, time it)
- [ ] **Deliverable:** PRESENTATION_SLIDES.pptx + QA_SCRIPT.md + TEST_REPORT.md

**Deadline:** Tuần 5 end  
**Status:** ☐ NOT STARTED

---

## 🎯 FINAL INTEGRATION (Tuần 5 cuối)

### All Team Members

- [ ] Create README.md (project overview + quick start)
- [ ] Create REQUIREMENTS.txt (all dependencies)
- [ ] Organize GitHub repo (clean structure, .gitignore)
- [ ] Test reproducibility: clone fresh, run setup, train models ✓
- [ ] Create run scripts:
  - [ ] `setup_environment.sh` (install all)
  - [ ] `collect_data.sh` (run all traffic collection)
  - [ ] `train_all_models.py` (train all 6 methods)
  - [ ] `run_demo.py` (demo attack detection)
  - [ ] `visualize_results.py` (generate all plots)
- [ ] Verify all deliverables exist:
  - [ ] Research documents ✓
  - [ ] Code (feature extraction, preprocessing, ML, DL) ✓
  - [ ] Models (rf, xgb, lgb, cnn, lstm, ae) ✓
  - [ ] Results (metrics, benchmarks, plots) ✓
  - [ ] Tests (50+ cases, 80%+ coverage) ✓
  - [ ] Final report (30+ pages) ✓
  - [ ] Slides (20 pages) ✓
  - [ ] Documentation ✓
- [ ] Final GitHub commit: tag v1.0-final-submission
- [ ] **Deliverable:** Complete project ready for submission

**Deadline:** Tuần 5 end (before presentation date)  
**Status:** ☐ NOT STARTED

---

## 📊 SUCCESS METRICS

### By End of Week 5

```
Đạt 10 điểm = Thỏa mãn:
☐ Code Quality (3 điểm)
  - 50+ test cases
  - 80%+ code coverage
  - Clean code (PEP8, docstrings)
  - Reproducible setup

☐ Technical Depth (3 điểm)
  - 3+ methods (entropy, ML, DL) working
  - 5+ attack scenarios tested
  - Real-time latency <100ms
  - Comprehensive comparison table

☐ Scientific Rigor (2 điểm)
  - 15+ papers cited (IEEE format)
  - Dataset >1GB labeled
  - All evaluation metrics defined
  - Error analysis provided

☐ Presentation (2 điểm)
  - 20-slide deck
  - Demo runs successfully
  - Q&A script (30 questions)
  - GitHub documentation
```

---

## 📝 WEEKLY TEAM SYNC

```
Lịch họp:
- Thứ 2 hàng tuần, 10:00-10:30
- Mục đích: update progress, discuss blockers, adjust plans
- Format: 5 mins per member + 5 mins discussion

Week 1 sync: 2026-04-21 (today - kickoff)
Week 2 sync: 2026-04-28
Week 3 sync: 2026-05-05
Week 4 sync: 2026-05-12
Week 5 sync: 2026-05-19
```

---

**Document status:** ACTIVE - Week 1  
**Last updated by:** Thành viên 1 (Leader)  
**Next update:** Weekly on Mondays
