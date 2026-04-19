# 🗺️  Đây là những file mình chỉnh sửa:

- `topology_nhom4.py`
- `topology_nhom4_giaodien.mn`

Hai file này phục vụ cho việc chạy và chỉnh sửa sơ đồ mạng của hệ thống. Dưới đây là hướng dẫn chi tiết cách sử dụng.

---

## 1. Phân biệt chức năng 2 file

### **File `topology_nhom4_giaodien.mn` (Bản vẽ giao diện)**

Đây là file save của công cụ **MiniEdit**.  
Dùng khi bạn muốn:

- Xem sơ đồ mạng trực quan  
- Kéo thả thêm/bớt thiết bị  
- Chỉnh sửa IP / Link / Switch / Host  

---

### **File `topology_nhom4.py` (File thực thi code)**

Đây là file Python được export từ MiniEdit.  
Mininet sẽ đọc file này để:

- Khởi tạo topology mạng ảo  
- Tạo switch / host / link tương ứng  
- Kết nối với controller Ryu  

> **Lưu ý:** Khi chạy test Firewall/Routing/DDoS Detection thì luôn dùng file `.py`.

---

## 2. Cách mở file `.mn` để chỉnh sửa topology

> ⚠️ **LƯU Ý QUAN TRỌNG:**  
> MiniEdit bị lỗi nếu mở bằng Python 3.  
> Nếu dùng `python3`, file save có thể bị trắng (**0 byte**).  
> **Bắt buộc dùng `python2`.**

### Bước 1: Mở MiniEdit

```bash
sudo python2 ~/mininet/examples/miniedit.py
```

---

### Bước 2: Open file topology giao diện

Trên menu chọn:

```text
File → Open
```

Sau đó chọn file:

```text
topology_nhom4_giaodien.mn
```

---

### Bước 3: Chỉnh sửa topology

Bạn có thể:

- Thêm switch / host  
- Xóa node  
- Chỉnh IP  
- Chỉnh băng thông link  

---

### Bước 4: Save lại

```text
File → Save
```

---

### Bước 5: Export file Python mới

```text
File → Export Level 2 Script
```

Thao tác này sẽ sinh lại file `.py` mới tương ứng.

---

## 3. Cách chạy topology mạng

Nếu chỉ cần chạy mạng để test hệ thống thì **không cần mở file `.mn`**.

### Bước 1: Xóa toàn bộ network cũ

```bash
sudo mn -c
```

---

### Bước 2: Chạy topology

```bash
sudo python topology_nhom4.py
```

---

### Bước 3: Kiểm tra kết nối

Khi terminal hiện:

```bash
mininet>
```

thì topology đã chạy thành công.

Test ping toàn mạng:

```bash
pingall
```

---

## 4. Thông tin commit hiện tại

Hai file topology được thêm bởi commit:

```text
Them file giao dien va file python topology
```

Thời gian:

```text
2 hours ago
```

---

## 🎯 Tóm tắt nhanh

| File | Vai trò |
|------|--------|
| `topology_nhom4_giaodien.mn` | File chỉnh sửa giao diện topology |
| `topology_nhom4.py` | File chạy topology bằng Mininet |
| `python2` | Dùng để mở MiniEdit |
| `python` | Dùng để chạy topology |

---

## 🛡️ Kịch bản tấn công DoS

> **Lưu ý:** Đồ án này demo **DoS** (1 nguồn tấn công duy nhất), không phải DDoS (nhiều nguồn).

| File | Loại tấn công | Lệnh tấn công |
|------|--------------|---------------|
| `botnet.txt` | DoS - Fixed Source IP | `hping3 -S -p 80 --flood 10.0.2.10` |
| `spoof.txt` | DoS - Spoofed (Random) Source IP | `hping3 -S -p 80 --flood --rand-source 10.0.2.10` |

**Cách chạy kịch bản DoS trong Mininet CLI:**
```bash
source botnet.txt   # Kịch bản 1: Low Entropy (IP cố định)
source spoof.txt    # Kịch bản 2: High Entropy (IP ngẫu nhiên)
```

---

**Chúc Nhóm 4 làm việc hiệu quả với topology! 🚀**
