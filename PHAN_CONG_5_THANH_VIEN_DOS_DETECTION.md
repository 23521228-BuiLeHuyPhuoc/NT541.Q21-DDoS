# Phan Cong De Tai: Denial-of-Service Attack Detection (5 Thanh Vien)

## 1) Muc tieu de tai (huong toi 10 diem)

- Xay dung duoc he thong phat hien DoS co the chay demo thuc te trong moi truong lab.
- So sanh it nhat 3 huong phuong phap: rule-based, machine learning truyen thong, deep learning.
- Bao cao co co so khoa hoc: trich dan bao nghien cuu, dataset, phuong phap danh gia ro rang.
- Moi thanh vien deu co dong gop thuc hanh, co bang chung qua commit, script, log, video demo.

## 2) Nguyen tac chia viec

- Ty le dong gop de xuat: 70% thuc hanh, 30% tong hop ly thuyet va viet bao cao.
- Moi thanh vien phai co deliverable ky thuat hang tuan.
- Lam viec theo sprint 1 tuan, cuoi tuan demo va review cheo.
- Toan bo thi nghiem chi chay trong moi truong lab/noi bo, khong tac dong he thong that.

## 3) Phan cong chi tiet cho 5 thanh vien

### Thanh vien 1 - Truong nhom + Huong nghien cuu

**Nhiem vu chinh**

- Dieu phoi tien do, quan ly pham vi, chot tieu chi danh gia de tai.
- Tong hop tai lieu khoa hoc, tao khung phuong phap nghien cuu.

**Viec thuc hanh bat buoc**

- Tao bang review toi thieu 12 bai bao (dataset, feature engineering, model, metric).
- Chuan hoa protocol test (train/val/test split, metric: Precision, Recall, F1, ROC-AUC).
- Kiem tra tinh lap lai ket qua (reproducibility checklist).

**Dau ra**

- 1 file survey markdown + 1 bang so sanh paper.
- 1 tai lieu protocol danh gia de ca nhom ap dung.

### Thanh vien 2 - Data/Lab Engineer

**Nhiem vu chinh**

- Dung moi truong tao luong traffic va thu thap du lieu.
- Chiu trach nhiem pipeline raw traffic -> data da gan nhan.

**Viec thuc hanh bat buoc**

- Cau hinh topology test va thu traffic binh thuong + traffic DoS trong lab.
- Thu pcap, trich xuat flow, lam sach du lieu, gan nhan va tao bo train/val/test.
- Viet script tu dong hoa preprocess.

**Dau ra**

- Thu muc du lieu v1 (co mo ta schema ro rang).
- Script preprocess + huong dan tai tao bo du lieu.

### Thanh vien 3 - ML Baseline Engineer

**Nhiem vu chinh**

- Xay dung baseline machine learning truyen thong.
- Tim feature quan trong va toi uu baseline.

**Viec thuc hanh bat buoc**

- Trich xuat feature thong ke theo flow (duration, packet rate, byte rate, tcp flags,...).
- Train it nhat 3 model: Logistic Regression, Random Forest, XGBoost/LightGBM.
- Chay cross-validation, ve confusion matrix, phan tich false positive/false negative.

**Dau ra**

- Notebook/script train baseline + file metric tong hop.
- Bang so sanh baseline theo tung metric.

### Thanh vien 4 - Deep Learning + Real-time Detection

**Nhiem vu chinh**

- Xay dung model nang cao va module phat hien gan thoi gian thuc.
- Toi uu toc do suy luan de demo on dinh.

**Viec thuc hanh bat buoc**

- Thu nghiem it nhat 1 huong DL (1D-CNN/LSTM/Autoencoder).
- Tich hop model vao pipeline nhan input tu luong packet/flow (pcap hoac stream noi bo).
- Do latency, throughput, do on dinh khi traffic tang.

**Dau ra**

- Script inference thoi gian thuc + model weights.
- Bao cao benchmark latency/throughput.

### Thanh vien 5 - Testing, Visualization, Bao cao/Thuyet trinh

**Nhiem vu chinh**

- Tao kich ban test he thong, xay dashboard ket qua, dong goi san pham cuoi.
- Chiu trach nhiem chat luong tai lieu va slide.

**Viec thuc hanh bat buoc**

- Tao test cases kho (class imbalance, traffic noisy, bien dong theo thoi gian).
- Ve bieu do ket qua (PR curve, ROC curve, trend latency).
- Chuan bi demo 5-7 phut va Q&A checklist.

**Dau ra**

- Test report tong hop + dashboard/bieu do.
- Bo slide final + script thuyet trinh.

## 4) Ke hoach 5 tuan (thuc hanh trong tam)

- Tuan 1: Setup moi truong, chot scope, chia paper, chot metric.
- Tuan 2: Thu thap va tien xu ly du lieu, ra dataset v1.
- Tuan 3: Hoan thanh baseline ML + bao cao ket qua ban dau.
- Tuan 4: Hoan thanh DL/real-time module + benchmark.
- Tuan 5: Tich hop tong, test tong the, chot bao cao va tong duyet thuyet trinh.

## 5) Yeu cau tham khao bao khoa hoc

- Moi thanh vien doc va tom tat toi thieu 3 bai bao lien quan truc tiep phan viec cua minh.
- Uu tien nguon: IEEE Xplore, ACM Digital Library, Springer, Elsevier, arXiv (doi chieu chat luong).
- Tu khoa goi y tim kiem:
  - "DoS detection using machine learning"
  - "DDoS detection deep learning"
  - "network intrusion detection dataset CICIDS2017"
  - "UNSW-NB15 intrusion detection"
  - "real-time DDoS detection SDN"

## 6) Checklist de huong toi 10 diem

- Co demo live chay on dinh, tai tao duoc trong 1 lan setup.
- Co so sanh baseline vs model nang cao va giai thich duoc vi sao hon/kem.
- Co phan tich loi (false alarms, bo sot) va huong cai thien.
- Bao cao co trich dan khoa hoc dung chuan, co bang tong hop related work.
- Moi thanh vien thuyet trinh duoc phan minh da lam va tra loi duoc cau hoi ky thuat.

## 7) Co che kiem soat chat luong nhom

- Hop ky thuat 2 buoi/tuan (30-45 phut), cap nhat blocker va huong xu ly.
- PR review cheo toi thieu 1 thanh vien khac truoc khi merge.
- Cuoi moi tuan: demo ngan 5 phut/nguoi + cap nhat tien do theo deliverable.
