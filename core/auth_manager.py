import streamlit as st
import json
import os
import re
import random
import time
import hashlib
import socket
import ssl
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone

AUTH_DB_FILE = "user_accounts_db.json"
DEFAULT_ADMIN_PIN_HASH = hashlib.sha256(b"HCMUS3001").hexdigest()

BANNED_FAKE_PREFIXES = {
    "123456", "1234567", "12345678", "123456789", "abcdef", "abcdefg",
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "test123",
    "testing", "admin123", "user123", "noname", "fakemail", "example"
}


def load_auth_db() -> dict:
    if not os.path.exists(AUTH_DB_FILE):
        default_salt = "usm_hcmus_2026_salt"
        default_pass_hash = hashlib.pbkdf2_hmac(
            "sha256", b"123456", default_salt.encode("utf-8"), 100000
        ).hex()
        seed_db = {
            "admin_pin_hash": DEFAULT_ADMIN_PIN_HASH,
            "smtp_config": {
                "sender_email": "phuhieu3001@gmail.com",
                "app_password": "",
                "require_login_gate": True
            },
            "accounts": {
                "phuhieu3001@gmail.com": {
                    "email": "phuhieu3001@gmail.com",
                    "callsign": "taolagautruc",
                    "salt": default_salt,
                    "password_hash": default_pass_hash,
                    "verified": True,
                    "created_at": "2026-10-25 UTC",
                    "last_login": "2026-10-25 UTC"
                }
            }
        }
        with open(AUTH_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(seed_db, f, ensure_ascii=False, indent=4)
        return seed_db
    try:
        with open(AUTH_DB_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "admin_pin_hash" not in data:
                data["admin_pin_hash"] = DEFAULT_ADMIN_PIN_HASH
            if "accounts" not in data:
                data["accounts"] = {}
            if "smtp_config" not in data:
                data["smtp_config"] = {
                    "sender_email": "phuhieu3001@gmail.com",
                    "app_password": "",
                    "require_login_gate": True
                }
            return data
    except Exception:
        return {
            "admin_pin_hash": DEFAULT_ADMIN_PIN_HASH,
            "smtp_config": {"sender_email": "phuhieu3001@gmail.com", "app_password": "", "require_login_gate": True},
            "accounts": {}
        }


def save_auth_db(data: dict):
    with open(AUTH_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
    ).hex()


def validate_strict_google_gmail(email: str) -> tuple[bool, str]:
    clean = email.strip().lower()
    if "@" not in clean:
        return False, "❌ Sai định dạng: Thiếu ký tự '@'."

    username, domain = clean.split("@", 1)

    if domain != "gmail.com" and not domain.endswith(".edu.vn"):
        return False, "❌ Hệ thống chỉ chấp nhận địa chỉ `@gmail.com` hoặc `@*.edu.vn`!"

    if len(username) < 6 or len(username) > 30:
        return False, "❌ Tên tài khoản Gmail phải có độ dài từ 6 đến 30 ký tự!"

    if username.startswith(".") or username.endswith(".") or ".." in username:
        return False, "❌ Tên Gmail không hợp lệ (chứa dấu chấm ở đầu/cuối hoặc '..')."

    if not re.match(r"^[a-z0-9.]+$", username):
        return False, "❌ Tên Gmail chỉ được chứa chữ cái (a-z), số (0-9) và dấu chấm (.)."

    clean_no_dots = username.replace(".", "")
    if clean_no_dots in BANNED_FAKE_PREFIXES or len(set(clean_no_dots)) <= 2:
        return False, "❌ Phát hiện địa chỉ Gmail mẫu/nhập bừa! Vui lòng nhập Gmail thật."

    return True, "✅ Định dạng Gmail hợp lệ."


def get_smtp_credentials(db: dict) -> tuple[str, str]:
    sender = ""
    app_pw = ""
    try:
        if "GMAIL_SENDER" in st.secrets:
            sender = str(st.secrets["GMAIL_SENDER"]).strip()
        if "GMAIL_APP_PASSWORD" in st.secrets:
            app_pw = str(st.secrets["GMAIL_APP_PASSWORD"]).strip()
    except Exception:
        pass

    if not sender or not app_pw:
        cfg = db.get("smtp_config", {})
        sender = cfg.get("sender_email", "").strip()
        app_pw = cfg.get("app_password", "").strip()

    # Nếu Admin chỉ gõ 'phuhieu3001' mà quên '@gmail.com', tự động nối thêm '@gmail.com'
    if sender and "@" not in sender:
        sender = f"{sender}@gmail.com"

    clean_pw = "".join(ch for ch in app_pw if ch.isalnum())
    return sender.lower(), clean_pw


def send_real_otp_email_strict(target_email: str, otp_code: str, purpose: str, db: dict) -> tuple[bool, str]:
    """
    Gửi mã OTP 6 số qua Cổng 587 (STARTTLS IPv4) để không bao giờ bị lỗi
    'Connection unexpectedly closed' trên Streamlit Cloud.
    """
    sender, app_pw = get_smtp_credentials(db)

    if not sender or not app_pw:
        return (
            False,
            "⚠️ **Chưa kết nối App Password của Gmail Admin!**\n\n"
            "Chủ web vui lòng mở mục **'⚙️ Web Owner Settings (Admin Only)'** ở dưới cùng cột trái, nhập PIN `HCMUS3001`, "
            "điền `phuhieu3001@gmail.com` kèm 16 chữ cái App Password rồi bấm Lưu."
        )

    if len(app_pw) != 16:
        return (
            False,
            f"⚠️ **Mã App Password trong phần Admin đang có {len(app_pw)} ký tự (Chuẩn Google phải là 16 chữ cái)!**"
        )

    msg = EmailMessage()
    msg["Subject"] = f"[Ultimate Secret Messenger] OTP Verification Code: {otp_code}"
    msg["From"] = sender
    msg["To"] = target_email

    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; background: #0f172a; color: #f8fafc; padding: 24px; border-radius: 12px; border: 2px solid #3b82f6;">
        <h2 style="color: #60a5fa; margin-top: 0;">🛡️ Ultimate Secret Messenger</h2>
        <p style="color: #cbd5e1; font-size: 15px;">Xin chào <b>{target_email}</b>,</p>
        <p style="color: #cbd5e1; font-size: 15px;">Mã xác thực OTP 6 số để xác minh tài khoản Gmail của bạn ({purpose}) là:</p>
        <div style="background: #1e293b; border: 1.5px dashed #38bdf8; padding: 16px; text-align: center; border-radius: 10px; margin: 20px 0;">
            <span style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #fde047;">{otp_code}</span>
        </div>
        <p style="color: #94a3b8; font-size: 13px;">⏳ Sau khi nhập mã này lên web, bạn sẽ được thiết lập Tên người dùng (Username) và Mật khẩu cá nhân.</p>
    </div>
    """
    msg.set_content(f"Your Ultimate Secret Messenger 6-digit OTP Code is: {otp_code}")
    msg.add_alternative(html_body, subtype="html")

    # Phân giải IPv4 của smtp.gmail.com để tránh lỗi ngắt kết nối IPv6 trên Streamlit Cloud
    try:
        smtp_ipv4 = socket.gethostbyname("smtp.gmail.com")
    except Exception:
        smtp_ipv4 = "smtp.gmail.com"

    ssl_ctx = ssl.create_default_context()

    # Ưu tiên số 1: Gửi qua Cổng 587 (STARTTLS) — Hoạt động xuyên suốt trên Streamlit Cloud
    try:
        with smtplib.SMTP(smtp_ipv4, 587, local_hostname="localhost", timeout=15) as server:
            server.ehlo("localhost")
            server.starttls(context=ssl_ctx)
            server.ehlo("localhost")
            server.login(sender, app_pw)
            server.send_message(msg)
        return (
            True,
            f"📧 **Đã gửi mã OTP 6 số vào hộp thư `{target_email}`!**\n\n"
            f"👉 Hãy mở Gmail `{target_email}` của bạn (kiểm tra cả Hộp thư đến và Thư rác/Spam) để lấy mã 6 số nhập vào Bước 2 bên dưới!"
        )
    except smtplib.SMTPAuthenticationError:
        return (
            False,
            f"❌ **Lỗi xác thực tại Gmail Tổng đài (`{sender}`):**\n\n"
            f"16 chữ cái App Password không khớp với địa chỉ `{sender}`. Hãy kiểm tra lại trong mục **Web Owner Settings** bên dưới!"
        )
    except Exception as err_587:
        # Dự phòng số 2: Cổng 465
        try:
            with smtplib.SMTP_SSL(smtp_ipv4, 465, local_hostname="localhost", context=ssl_ctx, timeout=15) as server:
                server.ehlo("localhost")
                server.login(sender, app_pw)
                server.send_message(msg)
            return (
                True,
                f"📧 **Đã gửi mã OTP 6 số vào hộp thư `{target_email}`!**\n\n"
                f"👉 Hãy mở Gmail `{target_email}` để lấy mã 6 số nhập vào Bước 2 bên dưới!"
            )
        except Exception as err_465:
            return False, f"❌ Không thể gửi thư tới `{target_email}` ({err_587} / {err_465})."


def sync_authenticated_identity(callsign: str, email: str):
    """Đồng bộ Tên tài khoản (Username) đã gắn với Gmail vào toàn bộ các tính năng trên Web."""
    st.session_state["auth_logged_in"] = True
    st.session_state["auth_email"] = email
    st.session_state["auth_callsign"] = callsign
    st.session_state["ctf_user"] = callsign
    st.session_state["acad_user"] = callsign
    st.session_state["chat_agent_name"] = callsign
    st.session_state["sdk_player_in"] = callsign
    st.session_state["comm_user_in"] = callsign


def render_sidebar_gmail_auth() -> tuple[bool, str, str]:
    db = load_auth_db()
    accounts = db.get("accounts", {})
    sender_cfg, app_pw_cfg = get_smtp_credentials(db)
    smtp_ready = bool(sender_cfg and len(app_pw_cfg) == 16)

    if "auth_logged_in" not in st.session_state:
        st.session_state["auth_logged_in"] = False
        st.session_state["auth_email"] = ""
        st.session_state["auth_callsign"] = "Guest_Agent"

    st.markdown("""
    <style>
        .gmail-profile-card {
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
            border: 1.5px solid #38bdf8;
            border-radius: 12px;
            padding: 12px 14px;
            margin-bottom: 10px;
            box-shadow: 0 4px 15px rgba(56, 189, 248, 0.2);
        }
        .step-box {
            background: rgba(30, 41, 59, 0.75);
            border: 1px solid #475569;
            border-radius: 10px;
            padding: 10px 12px;
            margin-bottom: 8px;
        }
    </style>
    """, unsafe_allow_html=True)

    # ==========================================================================
    # TRẠNG THÁI 1: ĐÃ ĐĂNG NHẬP (HIỂN THỊ TÀI KHOẢN GMAIL & TÊN NGƯỜI DÙNG NHƯ FACEBOOK)
    # ==========================================================================
    if st.session_state["auth_logged_in"]:
        email_now = st.session_state["auth_email"]
        callsign_now = st.session_state["auth_callsign"]
        st.session_state["ctf_user"] = callsign_now
        st.session_state["acad_user"] = callsign_now
        st.session_state["chat_agent_name"] = callsign_now

        st.markdown(f"""
        <div class="gmail-profile-card">
            <div style="font-size:0.7rem; color:#34d399; font-weight:800; letter-spacing:0.8px;">🟢 TÀI KHOẢN ĐÃ XÁC THỰC</div>
            <div style="font-size:1.05rem; font-weight:800; color:#fde047; margin-top:4px;">🕵️ {callsign_now}</div>
            <div style="font-size:0.8rem; color:#cbd5e1; margin-top:2px; word-break:break-all;">📧 {email_now}</div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🚪 Đăng xuất (Đổi tài khoản)", use_container_width=True, key="btn_gmail_logout"):
            st.session_state["auth_logged_in"] = False
            st.session_state["auth_email"] = ""
            st.session_state["auth_callsign"] = "Guest_Agent"
            st.rerun()

        return True, callsign_now, email_now

    # ==========================================================================
    # TRẠNG THÁI 2: CHƯA ĐĂNG NHẬP (QUY TRÌNH 3 BƯỚC KIỂU FACEBOOK)
    # ==========================================================================
    st.markdown("### 🛡️ Đăng Nhập / Tạo Tài Khoản")
    if smtp_ready:
        st.caption("🟢 Hệ thống xác thực OTP qua Gmail đang hoạt động.")
    else:
        st.caption("🟠 Chờ Chủ Web dán 16 chữ cái App Password ở mục Admin dưới cùng.")

    tab_login, tab_reg, tab_forgot = st.tabs([
        "🔑 Đăng nhập",
        "➕ Đăng ký",
        "🔄 Quên MK"
    ])

    # --- TAB 1: ĐĂNG NHẬP (BẰNG GMAIL HOẶC TÊN NGƯỜI DÙNG + MẬT KHẨU) ---
    with tab_login:
        login_id = st.text_input("📧 Nhập Gmail (hoặc Tên người dùng):", placeholder="phuhieu301207@gmail.com", key="in_login_gmail").strip()
        login_pass = st.text_input("🔒 Mật khẩu:", type="password", placeholder="Nhập mật khẩu...", key="in_login_pass")

        if st.button("🚀 Đăng Nhập Vào Web", type="primary", use_container_width=True, key="btn_gmail_signin"):
            if not login_id or not login_pass:
                st.error("❌ Vui lòng nhập đầy đủ tài khoản và mật khẩu!")
            else:
                # Cho phép người dùng đăng nhập bằng Gmail HOẶC bằng Tên hiển thị (Username)
                matched_email = None
                if login_id.lower() in accounts:
                    matched_email = login_id.lower()
                else:
                    for em_k, acc_v in accounts.items():
                        if acc_v.get("callsign", "").lower() == login_id.lower():
                            matched_email = em_k
                            break

                if not matched_email:
                    st.warning("⚠️ Tài khoản này chưa được đăng ký! Hãy bấm sang tab **'➕ Đăng ký'** bên cạnh để xác thực Gmail trước nhé.")
                else:
                    acc = accounts[matched_email]
                    calc_hash = hash_password(login_pass, acc["salt"])
                    if calc_hash == acc["password_hash"]:
                        acc["last_login"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                        save_auth_db(db)
                        sync_authenticated_identity(acc["callsign"], matched_email)
                        st.toast(f"✅ Xin chào {acc['callsign']}!", icon="🎉")
                        st.rerun()
                    else:
                        st.error("❌ Sai mật khẩu! Hãy bấm sang tab '🔄 Quên MK' để lấy lại mật khẩu qua Gmail.")

    # --- TAB 2: ĐĂNG KÝ 3 BƯỚC TUẦN TỰ NHƯ FACEBOOK ---
    with tab_reg:
        st.caption("📋 **Quy trình 3 bước:** Xác nhận Gmail thật bằng OTP trước $\\rightarrow$ Sau đó mới đặt Tên tài khoản & Mật khẩu!")

        # BƯỚC 1: CHỈ NHẬP GMAIL VÀ BẤM NHẬN MÃ OTP
        st.markdown("**Bước 1: Nhập Gmail thật của bạn**")
        reg_email = st.text_input(
            "📧 Địa chỉ Gmail (`@gmail.com`):",
            placeholder="phuhieu301207@gmail.com",
            key="in_reg_gmail"
        ).strip().lower()

        if st.button("📨 Gửi Mã OTP 6 Số Tới Gmail Này", use_container_width=True, key="btn_send_reg_otp"):
            ok_mail, mail_msg = validate_strict_google_gmail(reg_email)
            if not ok_mail:
                st.error(mail_msg)
            elif reg_email in accounts:
                st.info("✅ Gmail này đã có tài khoản rồi! Bạn hãy chuyển sang tab **'🔑 Đăng nhập'** nhé.")
            else:
                otp_code = f"{random.randint(100000, 999999)}"
                sent_ok, smtp_msg = send_real_otp_email_strict(reg_email, otp_code, "Xác minh đăng ký tài khoản", db)
                if sent_ok:
                    st.session_state["reg_step1_otp"] = {
                        "email": reg_email,
                        "otp_hash": hashlib.sha256(otp_code.encode("utf-8")).hexdigest(),
                        "exp": time.time() + 300,
                        "otp_verified": False
                    }
                    st.success(smtp_msg)
                else:
                    st.error(smtp_msg)

        # BƯỚC 2: NHẬP MÃ OTP 6 SỐ LẤY TỪ GMAIL ĐỂ CHỨNG MINH GMAIL TỒN TẠI THẬT
        pend_reg = st.session_state.get("reg_step1_otp")
        if pend_reg and pend_reg.get("email") == reg_email:
            st.divider()
            if not pend_reg.get("otp_verified", False):
                st.markdown("**Bước 2: Nhập mã OTP từ hộp thư Gmail**")
                otp_in = st.text_input("🔢 Mã OTP 6 số:", max_chars=6, placeholder="Nhập 6 số trong Gmail...", key="in_reg_otp_code").strip()
                if st.button("✅ Xác Nhận Mã OTP", type="primary", use_container_width=True, key="btn_verify_otp_step2"):
                    if time.time() > pend_reg["exp"]:
                        st.error("⏰ Mã OTP đã hết hạn (5 phút)! Vui lòng bấm gửi lại ở Bước 1.")
                    elif hashlib.sha256(otp_in.encode("utf-8")).hexdigest() != pend_reg["otp_hash"]:
                        st.error("❌ Mã OTP không chính xác! Vui lòng mở hộp thư Gmail kiểm tra lại.")
                    else:
                        st.session_state["reg_step1_otp"]["otp_verified"] = True
                        st.rerun()

            # BƯỚC 3: CHỈ KHI ĐÃ XÁC MINH OTP THÀNH CÔNG -> MỚI MỞ KHUNG ĐẶT TÊN NGƯỜI DÙNG & MẬT KHẨU!
            else:
                st.success(f"🎉 Đã xác minh Gmail **`{reg_email}`** là thật! Bây giờ hãy tạo hồ sơ của bạn:")
                st.markdown("**Bước 3: Tạo Tên Người Dùng & Mật Khẩu**")
                reg_callsign = st.text_input("🕵️ Tên hiển thị (Username như tên FB):", placeholder="VD: hieu3001", key="in_reg_callsign").strip()
                reg_pass = st.text_input("🔒 Đặt mật khẩu (Tối thiểu 6 ký tự):", type="password", key="in_reg_pass")
                reg_pass2 = st.text_input("🔒 Nhập lại mật khẩu:", type="password", key="in_reg_pass2")

                if st.button("🚀 Hoàn Tất Tạo Tài Khoản & Vào Web", type="primary", use_container_width=True, key="btn_finish_step3"):
                    if len(reg_callsign) < 2:
                        st.error("❌ Vui lòng đặt Tên hiển thị (tối thiểu 2 ký tự)!")
                    elif any(acc_v.get("callsign", "").lower() == reg_callsign.lower() for acc_v in accounts.values()):
                        st.error("❌ Tên hiển thị này đã có người dùng! Vui lòng chọn tên khác.")
                    elif len(reg_pass) < 6:
                        st.error("❌ Mật khẩu phải có ít nhất 6 ký tự!")
                    elif reg_pass != reg_pass2:
                        st.error("❌ Hai mật khẩu nhập vào không khớp nhau!")
                    else:
                        salt = hashlib.sha256(f"{reg_email}_{time.time()}".encode("utf-8")).hexdigest()[:16]
                        p_hash = hash_password(reg_pass, salt)
                        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                        accounts[reg_email] = {
                            "email": reg_email,
                            "callsign": reg_callsign,
                            "salt": salt,
                            "password_hash": p_hash,
                            "verified": True,
                            "created_at": now_str,
                            "last_login": now_str
                        }
                        db["accounts"] = accounts
                        save_auth_db(db)
                        del st.session_state["reg_step1_otp"]
                        sync_authenticated_identity(reg_callsign, reg_email)
                        st.balloons()
                        st.rerun()

    # --- TAB 3: QUÊN MẬT KHẨU (NHẬN OTP QUA GMAIL) ---
    with tab_forgot:
        st.caption("🔄 Nhập Gmail bạn đã đăng ký để nhận mã OTP 6 số khôi phục mật khẩu:")
        fg_email = st.text_input("📧 Gmail đã đăng ký:", placeholder="phuhieu301207@gmail.com", key="in_fg_email").strip().lower()

        if st.button("📨 Gửi Mã OTP Khôi Phục", use_container_width=True, key="btn_fg_send_otp"):
            if fg_email not in accounts:
                st.error("❌ Gmail này chưa được đăng ký trên hệ thống!")
            else:
                rst_otp = f"{random.randint(100000, 999999)}"
                sent_ok, smtp_msg = send_real_otp_email_strict(fg_email, rst_otp, "Khôi phục mật khẩu", db)
                if sent_ok:
                    st.session_state["pending_reset_otp"] = {
                        "email": fg_email,
                        "otp_hash": hashlib.sha256(rst_otp.encode("utf-8")).hexdigest(),
                        "exp": time.time() + 300
                    }
                    st.success(smtp_msg)
                else:
                    st.error(smtp_msg)

        if "pending_reset_otp" in st.session_state and st.session_state["pending_reset_otp"].get("email") == fg_email:
            rst_code_in = st.text_input("🔢 Nhập mã OTP 6 số trong Gmail:", max_chars=6, key="in_fg_otp").strip()
            fg_new_pass = st.text_input("🔑 Nhập mật khẩu mới (Tối thiểu 6 ký tự):", type="password", key="in_fg_newpass2")
            if st.button("✅ Lưu Mật Khẩu Mới", type="primary", use_container_width=True, key="btn_fg_otp_save"):
                r_pend = st.session_state["pending_reset_otp"]
                if time.time() > r_pend["exp"]:
                    st.error("⏰ Mã OTP đã hết hạn!")
                elif hashlib.sha256(rst_code_in.encode("utf-8")).hexdigest() != r_pend["otp_hash"]:
                    st.error("❌ Mã OTP không đúng!")
                elif len(fg_new_pass) < 6:
                    st.error("❌ Mật khẩu mới phải từ 6 ký tự trở lên!")
                else:
                    acc = accounts[fg_email]
                    new_salt = hashlib.sha256(f"{fg_email}_{time.time()}".encode("utf-8")).hexdigest()[:16]
                    acc["salt"] = new_salt
                    acc["password_hash"] = hash_password(fg_new_pass, new_salt)
                    save_auth_db(db)
                    del st.session_state["pending_reset_otp"]
                    st.success("✅ Đổi mật khẩu thành công! Hãy quay lại tab '🔑 Đăng nhập'.")

    # ==========================================================================
    # GÓC CÀI ĐẶT DÀNH RIÊNG CHO CHỦ WEB (PHÚ HIẾU)
    # ==========================================================================
    with st.expander("⚙️ Web Owner Settings (Admin Only)", expanded=False):
        st.caption("🔒 Chỉ dành cho Chủ Web (Phú Hiếu) để cài đặt Gmail Tổng đài (`phuhieu3001@gmail.com`).")
        adm_pin_in = st.text_input("🔑 Nhập Mã PIN Chủ Web:", type="password", key="smtp_adm_pin")

        saved_admin_hash = db.get("admin_pin_hash", DEFAULT_ADMIN_PIN_HASH)
        is_owner = (hashlib.sha256(adm_pin_in.strip().encode("utf-8")).hexdigest() == saved_admin_hash) if adm_pin_in else False

        if is_owner:
            st.success("🔓 Đã mở khóa bảng Chủ Web!")
            cfg = db.get("smtp_config", {})

            s_mail = st.text_input("Gmail Tổng đài (Dùng để gửi OTP đi):", value=cfg.get("sender_email", "phuhieu3001@gmail.com"))
            s_apw = st.text_input("16 chữ cái App Password của Gmail Tổng đài:", value=cfg.get("app_password", ""), type="password")
            req_gate = st.checkbox("🔒 Bắt buộc người dùng phải Đăng nhập / Đăng ký mới được vào dùng Web", value=cfg.get("require_login_gate", True))

            if st.button("💾 Lưu Cấu Hình Tổng Đài", type="primary", use_container_width=True):
                clean_sender = s_mail.strip().lower()
                if clean_sender and "@" not in clean_sender:
                    clean_sender += "@gmail.com"
                db["smtp_config"] = {
                    "sender_email": clean_sender,
                    "app_password": "".join(ch for ch in s_apw if ch.isalnum()),
                    "require_login_gate": req_gate
                }
                save_auth_db(db)
                st.success(f"✅ Đã lưu Tổng đài `{clean_sender}` qua Cổng 587!")
                st.rerun()

    return False, "Guest_Agent", ""
