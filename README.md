# 📚 Hướng dẫn quy trình đẩy code lên github
# Chú ý: Không đẩy lên branch main, chỉ được đẩy lên branch tên của các bạn. Bạn người làm sau phải bao gồm code của người làm trước !

---

## 🚀 Bước 1: Tải kho lưu trữ về máy (Clone)

Nếu bạn chưa có mã nguồn trên máy ảo Mininet, hãy thực hiện lệnh sau:

```bash
git clone https://github.com/23521228-BuiLeHuyPhuoc/NT541.Q21-DDoS.git
cd NT541.Q21-DDoS
```

---

## 🔄 Bước 2: Kế thừa code từ thành viên trước

Câu lệnh sau sẽ chuyển branch sang branch của người làm trước đó( ai làm trước bạn thì đổi thành branch đó)

```bash
git checkout <tên_branch_người_làm_trước_bạn>
```

**Ví dụ:** Nếu bạn làm sau Phước, hãy gõ:

```bash
git checkout Phuoc
```

---

## 🌿 Bước 3: Tạo nhánh làm việc cá nhân

> **Quan trọng:** Bạn không được code trực tiếp trên nhánh của người khác.  
> Hãy tạo một nhánh mang tên mình:

```bash
git checkout -b <tên_của_bạn>
```

**Ví dụ:**

```bash
git checkout -b Phuc
```

---

## 🛠️ Bước 4: Thực hiện công việc và lưu thay đổi

Các bạn phải đảm bảo sau khi các bạn làm, sửa xong thì folder sau bắt buộc phải chứa thứ bạn mới sửa nhé ! nếu chưa có thì phải copy paste vô !
<img width="851" height="636" alt="image" src="https://github.com/user-attachments/assets/9a4ceffe-3a49-49c9-9dba-27581860cf6c" />
ví dụ như đây là 3 file mình đã làm:
<img width="734" height="579" alt="image" src="https://github.com/user-attachments/assets/b51c195c-ecc9-4280-93e0-35f6ba9cb929" />
sau khi đảm bảo xong thì các bạn mới chạy lệnh sau:

```bash
# Xem các file đã thay đổi
git status

# Đưa tất cả thay đổi vào hàng chờ
git add .

# Ghi chú nội dung đã làm (viết ngắn gọn, không dấu hoặc tiếng Anh)
git commit -m "Mo ta ngan gon cong viec da lam"
```
## Ví dụ:
## git add .
## git commit -m "Phước mới làm xong tính năng tạo topology"

---

## 📤 Bước 5: Đẩy code lên GitHub (Push)

Đẩy nhánh cá nhân của bạn lên GitHub để người tiếp theo có thể lấy về:

```bash
git push -u origin <tên_của_bạn>
```
ví dụ: git push -u origin Phuoc
---

## 🔑 Lưu ý về Xác thực (GitHub Token)

Khi thực hiện lệnh `push`, GitHub sẽ yêu cầu:

1. **Username:** Tên đăng nhập GitHub của bạn.  Ví dụ : 23521228-BuiLeHuyPhuoc
2. **Password:** **KHÔNG** dùng mật khẩu thông thường. Bạn phải dùng **Personal Access Token (PAT)**. (password này khi nhập sẽ không hiện nên các bạn phải tắt unikey rồi gõ cho chính xác nhé !!)

### Cách lấy Token(password) 

1. Vào GitHub → **Settings**  <img width="388" height="813" alt="image" src="https://github.com/user-attachments/assets/66416a73-622d-4836-b968-38dd1d4bfa8b" />

2. Chọn **Developer settings**  <img width="380" height="832" alt="image" src="https://github.com/user-attachments/assets/80cad738-a420-46dc-855e-d381bb1ddddd" />

3. Chọn **Tokens (classic)**  <img width="648" height="325" alt="image" src="https://github.com/user-attachments/assets/0f025c49-4209-4471-bfc1-f404bfc9d868" />

4. Chọn **Generate new token (classic)**  <img width="1442" height="698" alt="image" src="https://github.com/user-attachments/assets/3bd6f60f-970c-4651-bf6d-3e728d5d57d4" />

5. Đặt tên và tick chọn quyền **`repo`**  <img width="1462" height="728" alt="image" src="https://github.com/user-attachments/assets/308eeba6-5540-4a18-8a72-4d4126d44714" />

6. Copy mã token hiện ra và dán vào Terminal khi được hỏi Password
  Mã này chính là password của các bạn !!!
    <img width="1034" height="323" alt="image" src="https://github.com/user-attachments/assets/73c4cf8a-997d-4533-8989-6608be700548" />


---

## 🎯 Lưu ý quan trọng cho Nhóm 4

- Luôn lấy code mới nhất từ branch người trước trước khi bắt đầu.
- Không sửa trực tiếp branch của người khác.
- Commit rõ ràng để mọi người dễ theo dõi.
- Push ngay sau khi hoàn thành để tránh mất code.

---

**Chúc Nhóm 5 hoàn thành tốt đồ án! 🚀**
