#!/usr/bin/env python3
"""
IMA 下载助手 Pro - 服务端 (密码登录版)
功能：邮箱+密码登录、配额管理、订阅等级（日/月/年卡）、管理后台
关闭公开注册 - 仅管理员可创建用户
"""

import os
import re
import smtplib
import secrets
import hashlib
import time
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, verify_jwt_in_request
)
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
# 优先使用 PostgreSQL（LeapCell/Render 等云平台提供 DATABASE_URL）
_db_url = os.environ.get('DATABASE_URL', '')
if _db_url:
    if _db_url.startswith('postgres://'):
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ima_pro.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)  # 缩短token有效期 30天→7天

CORS(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ============================================================
# 安全：请求频率限制（内存版，轻量无依赖）
# ============================================================

class RateLimiter:
    """简单的内存频率限制器"""
    def __init__(self):
        self._requests = {}  # key -> [(timestamp, ...)]

    def is_limited(self, key, max_requests, window_seconds):
        """检查是否超频，返回 (is_limited, remaining_seconds)"""
        now = time.time()
        if key not in self._requests:
            self._requests[key] = []

        # 清理过期记录
        self._requests[key] = [t for t in self._requests[key] if now - t < window_seconds]

        if len(self._requests[key]) >= max_requests:
            oldest = self._requests[key][0]
            return True, int(window_seconds - (now - oldest))

        self._requests[key].append(now)
        return False, 0

rate_limiter = RateLimiter()

# ============================================================
# 安全：验证码尝试次数限制
# ============================================================

class LoginAttemptTracker:
    """登录尝试追踪，防暴力破解"""
    def __init__(self):
        self._attempts = {}  # email -> [timestamp, ...]

    def record_attempt(self, email, success):
        now = time.time()
        if email not in self._attempts:
            self._attempts[email] = []
        self._attempts[email].append((now, success))
        # 只保留最近1小时的记录
        self._attempts[email] = [(t, s) for t, s in self._attempts[email] if now - t < 3600]

    def is_locked(self, email):
        """连续失败5次后锁定15分钟"""
        now = time.time()
        attempts = self._attempts.get(email, [])
        recent = [(t, s) for t, s in attempts if now - t < 900]  # 最近15分钟
        failures = [t for t, s in recent if not s]
        if len(failures) >= 5:
            return True, int(900 - (now - failures[-5]))
        return False, 0

login_tracker = LoginAttemptTracker()

# ============================================================
# 数据模型
# ============================================================

class User(db.Model):
    """用户表"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    name = db.Column(db.String(100), default='')
    quota_total = db.Column(db.Integer, default=0)
    quota_used = db.Column(db.Integer, default=0)
    role = db.Column(db.String(20), default='user')
    password_hash = db.Column(db.String(256), nullable=True)  # pbkdf2_hmac 密码哈希
    subscription_type = db.Column(db.String(10), nullable=True)  # 'day' | 'month' | 'year' | None
    subscription_expires_at = db.Column(db.DateTime, nullable=True)  # 订阅到期时间
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    @property
    def quota_remaining(self):
        return max(0, self.quota_total - self.quota_used)

    @property
    def is_subscription_expired(self):
        """检查订阅是否已到期（无订阅类型返回 False）"""
        if not self.subscription_type or not self.subscription_expires_at:
            return False
        return datetime.utcnow() > self.subscription_expires_at

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'phone': self.phone,
            'name': self.name,
            'quota_total': self.quota_total,
            'quota_used': self.quota_used,
            'quota_remaining': self.quota_remaining,
            'role': self.role,
            'is_active': self.is_active,
            'subscription_type': self.subscription_type,
            'subscription_expires_at': self.subscription_expires_at.isoformat() if self.subscription_expires_at else None,
            'is_subscription_expired': self.is_subscription_expired,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class VerifyCode(db.Model):
    """验证码表"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=True)  # 邮箱验证码（可空，与phone二选一）
    phone = db.Column(db.String(20), nullable=True)   # 手机验证码（可空，与email二选一）
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)  # 安全：验证尝试次数


class Order(db.Model):
    """订单表（付费充值）"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, default=0)
    price = db.Column(db.Float, default=0)
    status = db.Column(db.String(20), default='pending')
    trade_no = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)

    user = db.relationship('User', backref='orders')


class DownloadLog(db.Model):
    """下载日志"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    share_id = db.Column(db.String(200))
    doc_title = db.Column(db.String(500))
    doc_type = db.Column(db.Integer)
    download_method = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='download_logs')


# ============================================================
# 辅助函数
# ============================================================

def admin_required(f):
    """管理员权限装饰器"""
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': '需要管理员权限'}), 403
        return f(*args, **kwargs)
    return decorated


def hash_password(password):
    """使用 pbkdf2_hmac 哈希密码，返回格式: $pbkdf2-sha256$iterations$salt_hex$hash_hex"""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f'$pbkdf2-sha256$100000${salt.hex()}${dk.hex()}'


def verify_password(password, password_hash):
    """验证密码是否正确"""
    if not password_hash or not password_hash.startswith('$pbkdf2-sha256$'):
        return False
    try:
        _, algo, iterations, salt_hex, hash_hex = password_hash.split('$')
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(iterations))
        return secrets.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def is_smtp_configured():
    """检查 SMTP 是否已配置"""
    return all([
        os.environ.get('SMTP_HOST', '').strip(),
        os.environ.get('SMTP_PORT', '').strip(),
        os.environ.get('SMTP_USER', '').strip(),
        os.environ.get('SMTP_PASSWORD', '').strip(),
    ])


def send_email_code(to_email, code):
    """发送验证码邮件"""
    if not is_smtp_configured():
        print(f"[EMAIL-DEV] 验证码 -> {to_email}: {code}")
        return True

    smtp_host = os.environ.get('SMTP_HOST', '').strip()
    smtp_port = int(os.environ.get('SMTP_PORT', '465').strip())
    smtp_user = os.environ.get('SMTP_USER', '').strip()
    smtp_password = os.environ.get('SMTP_PASSWORD', '').strip()
    from_name = os.environ.get('SMTP_FROM_NAME', 'IMA下载助手').strip()
    # SendGrid 等第三方 SMTP 的认证用户名（如 "apikey"）≠ 发件人邮箱
    from_email = os.environ.get('SMTP_FROM_EMAIL', smtp_user).strip()

    print(f"[EMAIL] 尝试发送: host={smtp_host}, port={smtp_port}, user={smtp_user}, from={from_email}, to={to_email}")

    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            server.starttls()

        server.login(smtp_user, smtp_password)
        print(f"[EMAIL] SMTP登录成功")

        subject = f'{from_name} - 登录验证码'
        body = f"""
您好！

您的登录验证码是：{code}

验证码5分钟内有效，请勿泄露给他人。

如非本人操作，请忽略此邮件。

—— {from_name}
"""
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = f'{from_name} <{from_email}>'
        msg['To'] = to_email

        server.sendmail(from_email, [to_email], msg.as_string())
        print(f"[EMAIL] 邮件已投递 -> {to_email}")
        server.quit()

        return True

    except Exception as e:
        print(f"[EMAIL] 发送失败 -> {to_email}: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================
# 腾讯云短信
# ============================================================

def is_sms_configured():
    """检查腾讯云短信是否已配置"""
    return all([
        os.environ.get('TENCENT_SMS_SECRET_ID', '').strip(),
        os.environ.get('TENCENT_SMS_SECRET_KEY', '').strip(),
        os.environ.get('TENCENT_SMS_SDK_APP_ID', '').strip(),
        os.environ.get('TENCENT_SMS_SIGN_NAME', '').strip(),
        os.environ.get('TENCENT_SMS_TEMPLATE_ID', '').strip(),
    ])


def send_phone_sms(phone, code):
    """
    发送短信验证码
    返回: True 发送成功 / None 开发模式(未配置SMS, 888888通用码) / False 发送失败
    """
    if not is_sms_configured():
        print(f"[SMS-DEV] 短信验证码 -> {phone}: {code}")
        return None  # 开发模式

    try:
        from tencentcloud.common import credential
        from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
        from tencentcloud.sms.v20210111 import sms_client, models

        secret_id = os.environ.get('TENCENT_SMS_SECRET_ID', '').strip()
        secret_key = os.environ.get('TENCENT_SMS_SECRET_KEY', '').strip()
        sdk_app_id = os.environ.get('TENCENT_SMS_SDK_APP_ID', '').strip()
        sign_name = os.environ.get('TENCENT_SMS_SIGN_NAME', '').strip()
        template_id = os.environ.get('TENCENT_SMS_TEMPLATE_ID', '').strip()

        cred = credential.Credential(secret_id, secret_key)
        client = sms_client.SmsClient(cred, "ap-guangzhou")

        req = models.SendSmsRequest()
        req.SmsSdkAppId = sdk_app_id
        req.SignName = sign_name
        req.TemplateId = template_id
        req.TemplateParamSet = [code, "5"]  # 验证码, 有效期(分钟)
        req.PhoneNumberSet = ["+86" + phone]

        resp = client.SendSms(req)
        print(f"[SMS] 发送成功 -> {phone}, 请求ID: {resp.RequestId}")

        # 检查发送结果
        for status in resp.SendStatusSet:
            if status.Code != "Ok":
                print(f"[SMS] 发送失败 -> {phone}: {status.Code} - {status.Message}")
                return False

        return True

    except TencentCloudSDKException as e:
        print(f"[SMS] SDK异常 -> {phone}: {e}")
        return False
    except Exception as e:
        print(f"[SMS] 发送失败 -> {phone}: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================
# API 路由
# ============================================================

@app.route('/api/v1/auth/session-key', methods=['POST'])
def get_session_key():
    """返回客户端加密用的会话密钥"""
    import base64
    key = secrets.token_bytes(32)
    return jsonify({'key': base64.b64encode(key).decode()})


@app.route('/api/v1/auth/send-code', methods=['POST'])
def send_code():
    """发送验证码到邮箱"""
    email = request.json.get('email', '').strip().lower()
    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({'error': '请输入正确的邮箱地址'}), 400

    # 安全：IP频率限制（同一IP每分钟最多5次）
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    limited, wait = rate_limiter.is_limited(f'send:{client_ip}', 5, 60)
    if limited:
        return jsonify({'error': f'请求太频繁，请{wait}秒后再试'}), 429

    # 安全：邮箱频率限制（同一邮箱60秒内只能发一次）
    limited2, wait2 = rate_limiter.is_limited(f'send:{email}', 1, 60)
    if limited2:
        return jsonify({'error': f'发送太频繁，请{wait2}秒后再试'}), 429

    # 安全：检查该邮箱是否有过多未使用验证码（防刷）
    unused_count = VerifyCode.query.filter(
        VerifyCode.email == email,
        VerifyCode.used == False,
        VerifyCode.expires_at > datetime.utcnow()
    ).count()
    if unused_count >= 3:
        return jsonify({'error': '验证码发送过多，请使用已收到的验证码'}), 429

    # 安全：使用 secrets 生成验证码（比 random.randint 更安全）
    code = str(secrets.randbelow(900000) + 100000)  # 6位数字 100000-999999

    verify = VerifyCode(
        email=email,
        code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.session.add(verify)
    db.session.commit()

    email_sent = send_email_code(email, code)

    if not email_sent:
        return jsonify({'error': '验证码发送失败，请稍后再试或联系管理员'}), 500

    return jsonify({'message': '验证码已发送'})


@app.route('/api/v1/auth/send-sms', methods=['POST'])
def send_sms_code():
    """发送短信验证码到手机"""
    phone = request.json.get('phone', '').strip()
    if not phone or not re.match(r'^1[3-9]\d{9}$', phone):
        return jsonify({'error': '请输入正确的手机号'}), 400

    # 安全：IP频率限制
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    limited, wait = rate_limiter.is_limited(f'sms:{client_ip}', 3, 60)
    if limited:
        return jsonify({'error': f'请求太频繁，请{wait}秒后再试'}), 429

    # 安全：手机号频率限制（同一手机号60秒内只能发一次）
    limited2, wait2 = rate_limiter.is_limited(f'sms:{phone}', 1, 60)
    if limited2:
        return jsonify({'error': f'发送太频繁，请{wait2}秒后再试'}), 429

    # 安全：检查该手机号未使用验证码数量
    unused_count = VerifyCode.query.filter(
        VerifyCode.phone == phone,
        VerifyCode.used == False,
        VerifyCode.expires_at > datetime.utcnow()
    ).count()
    if unused_count >= 3:
        return jsonify({'error': '验证码发送过多，请使用已收到的验证码'}), 429

    code = str(secrets.randbelow(900000) + 100000)

    verify = VerifyCode(
        phone=phone,
        code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.session.add(verify)
    db.session.commit()

    sms_result = send_phone_sms(phone, code)

    if sms_result is False:
        return jsonify({'error': '短信发送失败，请稍后再试或联系管理员'}), 500

    # dev_mode (sms_result is None) 或成功 (sms_result is True) 都返回成功
    return jsonify({'message': '验证码已发送'})


@app.route('/api/v1/auth/dev-status', methods=['GET'])
def dev_status():
    """调试端点：返回配置状态（安全：不暴露敏感信息）"""
    smtp_ok = is_smtp_configured()
    sms_ok = is_sms_configured()
    return jsonify({
        'dev_mode': not smtp_ok and not sms_ok,
        'smtp_configured': smtp_ok,
        'sms_configured': sms_ok,
    })


@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """邮箱+密码登录（关闭公开注册，仅管理员创建的用户可登录）"""
    email = request.json.get('email', '').strip().lower()
    password = request.json.get('password', '').strip()

    if not email or not password:
        return jsonify({'error': '请输入邮箱和密码'}), 400

    # 安全：检查登录锁定
    locked, lock_wait = login_tracker.is_locked(email)
    if locked:
        return jsonify({'error': f'登录尝试过多，请{lock_wait}秒后再试'}), 429

    # 安全：IP频率限制（同一IP每分钟最多10次登录）
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    limited, wait = rate_limiter.is_limited(f'login:{client_ip}', 10, 60)
    if limited:
        return jsonify({'error': f'请求太频繁，请{wait}秒后再试'}), 429

    # 查找用户（不自动创建，仅管理员创建的用户可登录）
    user = User.query.filter_by(email=email).first()
    if not user:
        login_tracker.record_attempt(email, False)
        return jsonify({'error': '账号不存在，请联系管理员开通'}), 401

    if not user.is_active:
        return jsonify({'error': '账号已被禁用，请联系管理员'}), 403

    # 验证密码
    if not verify_password(password, user.password_hash):
        login_tracker.record_attempt(email, False)
        return jsonify({'error': '密码错误'}), 401

    user.last_login = datetime.utcnow()
    db.session.commit()

    login_tracker.record_attempt(email, True)

    token = create_access_token(identity=str(user.id))
    return jsonify({
        'token': token,
        'user': user.to_dict()
    })


@app.route('/api/v1/auth/phone-login', methods=['POST'])
def phone_login():
    """手机号+验证码登录"""
    phone = request.json.get('phone', '').strip()
    code = request.json.get('code', '').strip()

    if not phone or not code:
        return jsonify({'error': '请输入手机号和验证码'}), 400
    if not re.match(r'^1[3-9]\d{9}$', phone):
        return jsonify({'error': '请输入正确的手机号'}), 400

    # 安全：检查登录锁定
    locked, lock_wait = login_tracker.is_locked(f'phone:{phone}')
    if locked:
        return jsonify({'error': f'登录尝试过多，请{lock_wait}秒后再试'}), 429

    # 安全：IP频率限制
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    limited, wait = rate_limiter.is_limited(f'login:{client_ip}', 10, 60)
    if limited:
        return jsonify({'error': f'请求太频繁，请{wait}秒后再试'}), 429

    # 验证码校验
    verify = VerifyCode.query.filter(
        VerifyCode.phone == phone,
        VerifyCode.code == code,
        VerifyCode.used == False,
        VerifyCode.expires_at > datetime.utcnow()
    ).order_by(VerifyCode.id.desc()).first()

    # 开发模式：通用验证码 888888（SMS 未配置时生效）
    dev_mode = not is_sms_configured()
    if not verify and dev_mode and code == '888888':
        pass
    elif not verify:
        login_tracker.record_attempt(f'phone:{phone}', False)
        return jsonify({'error': '验证码错误或已过期'}), 401

    # 安全：验证码最多尝试3次
    if verify and verify.attempts >= 3:
        verify.used = True
        db.session.commit()
        return jsonify({'error': '验证码已失效，请重新获取'}), 401

    if verify:
        verify.used = True

    # 查找或创建用户（按手机号）
    user = User.query.filter_by(phone=phone).first()
    if not user:
        user = User(phone=phone, name=f'用户{phone[-4:]}', quota_total=0)
        db.session.add(user)
    elif not user.is_active:
        return jsonify({'error': '账号已被禁用，请联系管理员'}), 403

    user.last_login = datetime.utcnow()
    db.session.commit()

    login_tracker.record_attempt(f'phone:{phone}', True)

    token = create_access_token(identity=str(user.id))
    return jsonify({
        'token': token,
        'user': user.to_dict()
    })


@app.route('/api/v1/auth/admin-login', methods=['POST'])
def admin_login():
    """管理员固定密码登录（安全：独立频率限制+锁定）"""
    email = request.json.get('email', '').strip().lower()
    password = request.json.get('password', '').strip()

    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '000000')

    if not email or not password:
        return jsonify({'error': '请输入邮箱和密码'}), 400

    # 安全：管理员登录频率限制（每分钟最多5次）
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    limited, wait = rate_limiter.is_limited(f'admin:{client_ip}', 5, 60)
    if limited:
        return jsonify({'error': f'请求太频繁，请{wait}秒后再试'}), 429

    # 安全：管理员登录锁定（连续3次失败锁15分钟）
    locked, lock_wait = login_tracker.is_locked(f'admin:{email}')
    if locked:
        return jsonify({'error': f'登录尝试过多，请{lock_wait}秒后再试'}), 429

    # 安全：使用 hmac 常量时间比较（防时序攻击）
    import hmac
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        login_tracker.record_attempt(f'admin:{email}', False)
        return jsonify({'error': '密码错误'}), 401

    user = User.query.filter_by(email=email).first()
    if not user or user.role != 'admin':
        login_tracker.record_attempt(f'admin:{email}', False)
        return jsonify({'error': '非管理员账号'}), 403

    user.last_login = datetime.utcnow()
    db.session.commit()

    login_tracker.record_attempt(f'admin:{email}', True)

    token = create_access_token(identity=str(user.id))
    return jsonify({
        'token': token,
        'user': user.to_dict()
    })


@app.route('/api/v1/quotas', methods=['GET'])
@jwt_required()
def get_quotas():
    """获取配额"""
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    return jsonify({
        'total': user.quota_total,
        'used': user.quota_used,
        'remaining': user.quota_remaining
    })


@app.route('/api/v1/quotas/consume', methods=['POST'])
@jwt_required()
def consume_quota():
    """消耗配额（下载时调用）"""
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': '用户不存在'}), 404

    if user.quota_remaining <= 0:
        return jsonify({'error': '配额不足，请联系管理员充值', 'message': '配额不足'}), 403

    # 检查订阅是否到期
    if user.is_subscription_expired:
        sub_type_names = {'day': '日卡', 'month': '月卡', 'year': '年卡'}
        sub_name = sub_type_names.get(user.subscription_type, user.subscription_type)
        return jsonify({'error': f'您的{sub_name}已到期，请联系管理员续费', 'message': '订阅已到期'}), 403

    # 安全：限制单次消耗数量
    count = request.json.get('count', 1)
    count = max(1, min(count, 100))  # 单次最多消耗100

    user.quota_used += count
    db.session.commit()

    # 安全：记录下载日志
    doc_title = request.json.get('doc_title', '')[:500]
    doc_type = request.json.get('doc_type')
    share_id = request.json.get('share_id', '')[:200]
    download_method = request.json.get('download_method', '')[:20]

    log = DownloadLog(
        user_id=user_id,
        share_id=share_id,
        doc_title=doc_title,
        doc_type=doc_type,
        download_method=download_method
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({
        'total': user.quota_total,
        'used': user.quota_used,
        'remaining': user.quota_remaining
    })


@app.route('/api/v1/user', methods=['GET'])
@jwt_required()
def get_user():
    """获取用户信息"""
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    return jsonify(user.to_dict())


# ============================================================
# 管理后台 API
# ============================================================

@app.route('/api/v1/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    """列出所有用户"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = min(per_page, 100)  # 安全：限制每页最多100条

    pagination = User.query.order_by(User.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'users': [u.to_dict() for u in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })


@app.route('/api/v1/admin/users/<int:user_id>/quota', methods=['PUT'])
@admin_required
def admin_update_quota(user_id):
    """修改用户配额"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    quota_total = request.json.get('quota_total')
    if quota_total is not None:
        # 安全：配额不能为负数
        user.quota_total = max(0, int(quota_total))

    quota_used = request.json.get('quota_used')
    if quota_used is not None:
        user.quota_used = max(0, int(quota_used))

    db.session.commit()
    return jsonify(user.to_dict())


@app.route('/api/v1/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    """启用/禁用用户"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    # 安全：不能禁用自己
    current_user_id = int(get_jwt_identity())
    if user.id == current_user_id:
        return jsonify({'error': '不能禁用自己的账号'}), 400

    user.is_active = not user.is_active
    db.session.commit()
    return jsonify(user.to_dict())


@app.route('/api/v1/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    """删除用户"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    current_user_id = int(get_jwt_identity())
    if user.id == current_user_id:
        return jsonify({'error': '不能删除自己的账号'}), 400

    if user.role == 'admin':
        return jsonify({'error': '不能删除管理员账号'}), 400

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': '用户已删除'})


@app.route('/api/v1/admin/users', methods=['POST'])
@admin_required
def admin_create_user():
    """管理员创建用户（关闭公开注册后唯一创建途径）"""
    email = request.json.get('email', '').strip().lower()
    password = request.json.get('password', '').strip()
    quota_total = request.json.get('quota_total', 100)
    subscription_type = request.json.get('subscription_type', '').strip()  # 'day' | 'month' | 'year' | ''
    name = request.json.get('name', '').strip()

    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({'error': '请输入正确的邮箱地址'}), 400
    if not password or len(password) < 6:
        return jsonify({'error': '密码至少6位'}), 400

    # 检查邮箱是否已存在
    if User.query.filter_by(email=email).first():
        return jsonify({'error': '该邮箱已注册'}), 409

    # 计算订阅到期时间
    expires_at = None
    if subscription_type in ('day', 'month', 'year'):
        delta_map = {'day': timedelta(days=1), 'month': timedelta(days=30), 'year': timedelta(days=365)}
        expires_at = datetime.utcnow() + delta_map[subscription_type]
    elif subscription_type:
        return jsonify({'error': '订阅类型无效，可选: day(日卡) / month(月卡) / year(年卡)'}), 400

    user = User(
        email=email,
        name=name or email.split('@')[0][:8],
        password_hash=hash_password(password),
        quota_total=max(1, int(quota_total)),
        subscription_type=subscription_type or None,
        subscription_expires_at=expires_at
    )
    db.session.add(user)
    db.session.commit()

    return jsonify(user.to_dict()), 201


@app.route('/api/v1/admin/users/<int:user_id>/subscription', methods=['PUT'])
@admin_required
def admin_update_subscription(user_id):
    """修改用户订阅类型和到期时间"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    subscription_type = request.json.get('subscription_type', '').strip()
    custom_expires_at = request.json.get('subscription_expires_at')  # ISO 格式，可选

    if subscription_type in ('day', 'month', 'year'):
        delta_map = {'day': timedelta(days=1), 'month': timedelta(days=30), 'year': timedelta(days=365)}
        user.subscription_type = subscription_type
        user.subscription_expires_at = datetime.utcnow() + delta_map[subscription_type]
    elif subscription_type == '' or subscription_type is None:
        user.subscription_type = None
        user.subscription_expires_at = None
    elif subscription_type:
        return jsonify({'error': '订阅类型无效，可选: day(日卡) / month(月卡) / year(年卡)'}), 400

    # 允许自定义到期时间（覆盖自动计算）
    if custom_expires_at:
        try:
            from datetime import datetime as dt
            user.subscription_expires_at = dt.fromisoformat(custom_expires_at)
        except ValueError:
            return jsonify({'error': '日期格式无效，请使用 ISO 格式如 2026-06-15T00:00:00'}), 400

    db.session.commit()
    return jsonify(user.to_dict())


@app.route('/api/v1/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    """管理后台统计"""
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_downloads = DownloadLog.query.count()
    total_quota_used = db.session.query(db.func.sum(User.quota_used)).scalar() or 0

    return jsonify({
        'total_users': total_users,
        'active_users': active_users,
        'total_downloads': total_downloads,
        'total_quota_used': total_quota_used
    })


# ============================================================
# 管理后台页面（内联，避免缓存问题）
# ============================================================

@app.route('/admin')
def admin_page():
    """管理后台 HTML 页面"""
    from flask import make_response
    resp = make_response("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IMA 下载助手 Pro - 管理后台 v4</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#0f0f1a;color:#e0e0e0;min-height:100vh}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:220px;background:#1a1a2e;padding:20px 0;border-right:1px solid #2d2d44}
.sidebar h2{font-size:16px;color:#7c3aed;padding:0 20px;margin-bottom:24px}
.sidebar a{display:block;padding:12px 20px;color:#999;text-decoration:none;font-size:14px;transition:all 0.2s}
.sidebar a:hover,.sidebar a.active{color:white;background:#2d2d44;border-left:3px solid #7c3aed}
.main{margin-left:220px;padding:24px}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:#1a1a2e;border-radius:12px;padding:20px;text-align:center}
.stat-card .num{font-size:32px;font-weight:700;color:#7c3aed}
.stat-card .label{font-size:12px;color:#888;margin-top:4px}
.card{background:#1a1a2e;border-radius:12px;padding:20px;margin-bottom:20px}
.card h3{font-size:16px;color:#7c3aed;margin-bottom:16px}
table{width:100%;border-collapse:collapse}
th,td{padding:6px 8px;text-align:left;font-size:11px;border-bottom:1px solid #2d2d44;white-space:nowrap}
th{color:#888;font-weight:600}
tr:hover td{background:#1e1e32}
.btn{padding:5px 10px;border-radius:6px;border:none;cursor:pointer;font-size:11px;transition:all 0.2s}
.btn-primary{background:#7c3aed;color:white}
.btn-primary:hover{background:#6d28d9}
.btn-danger{background:#dc3545;color:white}
.btn-danger:hover{background:#bb2d3b}
.btn-success{background:#16a34a;color:white}
.btn-success:hover{background:#15803d}
.btn-warning{background:#f59e0b;color:#1a1008}
.btn-warning:hover{background:#d97706}
.btn-sm{padding:3px 8px;font-size:10px}
.badge{display:inline-block;padding:1px 6px;border-radius:10px;font-size:10px;font-weight:500}
.badge-active{background:rgba(22,163,74,0.2);color:#16a34a}
.badge-disabled{background:rgba(220,53,69,0.2);color:#dc3545}
.badge-admin{background:rgba(124,58,237,0.2);color:#7c3aed}
.badge-day{background:rgba(59,130,246,0.2);color:#3b82f6}
.badge-month{background:rgba(245,158,11,0.2);color:#f59e0b}
.badge-year{background:rgba(22,163,74,0.2);color:#16a34a}
.badge-expired{background:rgba(220,53,69,0.2);color:#dc3545}
.expired-text{color:#dc3545;font-weight:600}
input,select{background:#2d2d44;border:1px solid #3d3d5c;border-radius:6px;padding:6px 8px;color:#e0e0e0;font-size:12px;outline:none}
input:focus,select:focus{border-color:#7c3aed}
input[type="number"]{width:55px}
.login-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(15,15,26,0.95);z-index:9999;display:flex;align-items:center;justify-content:center}
.login-box{background:#1a1a2e;border-radius:16px;padding:32px;width:360px}
.login-box h2{color:#7c3aed;margin-bottom:20px;text-align:center}
.login-box input{width:100%;background:#2d2d44;border:1px solid #3d3d5c;border-radius:8px;padding:12px;color:#e0e0e0;font-size:14px;margin-bottom:12px;outline:none}
.login-box input:focus{border-color:#7c3aed}
.login-box .btn{width:100%;padding:12px;font-size:14px}
.login-box .hint{font-size:11px;color:#888;text-align:center;margin-top:8px}
.hidden{display:none!important}
.msg{font-size:12px;margin-top:4px}
.msg-success{color:#16a34a}
.msg-error{color:#dc3545}
.form-row{display:flex;gap:8px;margin-bottom:8px;align-items:center;flex-wrap:wrap}
.form-row label{font-size:12px;color:#999;min-width:36px}
.form-row input[type="email"],.form-row input[type="password"],.form-row input[type="text"]{flex:1;min-width:120px}
</style>
</head>
<body>
<div class="login-overlay" id="loginOverlay">
  <div class="login-box">
    <h2>&#128272; 管理员登录</h2>
    <form onsubmit="return handleLogin(event)" style="margin:0">
    <input type="email" id="adminEmail" placeholder="管理员邮箱" value="2051645018@qq.com" />
    <input type="password" id="adminPassword" placeholder="管理员密码" />
    <button type="submit" class="btn btn-primary" id="adminLoginBtn" onclick="if(window.handleLogin){return handleLogin(event)}else{var ls=document.getElementById('loginStatus');if(ls){ls.textContent='❌ JS未加载，请刷新页面';ls.style.color='#dc3545'};return false}">登录</button>
    </form>
    <p id="loginStatus" style="margin-top:10px;font-size:12px;text-align:center;min-height:18px;"></p>
    <p class="hint">管理员使用固定密码登录 | v4 (外部JS)</p>
  </div>
</div>
<div class="sidebar hidden" id="sidebar">
  <h2>&#9889; 管理后台</h2>
  <a href="#" class="active" onclick="showPage('dashboard')">&#128202; 仪表盘</a>
  <a href="#" onclick="showPage('users')">&#128101; 用户管理</a>
</div>
<div class="main hidden" id="mainContent">
  <div id="page-dashboard">
    <h2 style="margin-bottom:20px;">&#128202; 仪表盘</h2>
    <div class="stats-grid">
      <div class="stat-card"><div class="num" id="s-totalUsers">-</div><div class="label">总用户数</div></div>
      <div class="stat-card"><div class="num" id="s-activeUsers">-</div><div class="label">活跃用户</div></div>
      <div class="stat-card"><div class="num" id="s-totalDownloads">-</div><div class="label">总下载次数</div></div>
      <div class="stat-card"><div class="num" id="s-quotaUsed">-</div><div class="label">配额已用</div></div>
    </div>
  </div>
  <div id="page-users" class="hidden">
    <h2 style="margin-bottom:20px;">&#128101; 用户管理</h2>
    <div class="card">
      <h3>➕ 创建用户</h3>
      <p style="font-size:11px;color:#888;margin-bottom:10px;">&#128161; 关闭公开注册，仅管理员可创建用户。设置邮箱、密码、配额和订阅等级。</p>
      <div class="form-row">
        <label>邮箱</label>
        <input type="email" id="newEmail" placeholder="user@example.com" />
      </div>
      <div class="form-row">
        <label>密码</label>
        <input type="password" id="newPassword" placeholder="至少6位" />
        <label>昵称</label>
        <input type="text" id="newName" placeholder="可选" style="flex:0.5;min-width:80px" />
      </div>
      <div class="form-row">
        <label>配额</label>
        <input type="number" id="newQuota" value="100" min="1" />
        <label>订阅</label>
        <select id="newSubType">
          <option value="">无限期</option>
          <option value="day">日卡 (1天)</option>
          <option value="month">月卡 (30天)</option>
          <option value="year">年卡 (365天)</option>
        </select>
        <button class="btn btn-success" id="createUserBtn">创建用户</button>
      </div>
      <p id="createMsg" class="msg hidden"></p>
    </div>
    <div class="card">
      <h3>用户列表</h3>
      <table><thead><tr><th>ID</th><th>邮箱</th><th>配额</th><th>已用</th><th>剩余</th><th>订阅</th><th>到期时间</th><th>状态</th><th>注册时间</th><th>操作</th></tr></thead><tbody id="userTableBody"></tbody></table>
    </div>
  </div>
</div>
<script type="text/javascript">
// 启动诊断：在外部JS加载前先显示状态
(function(){
  var ls=document.getElementById("loginStatus");
  if(ls){ls.textContent="⏳ 页面已加载，等待 /admin.js ...";ls.style.color="#f59e0b"}
  console.log("[Admin] HTML loaded v4, waiting for external JS...");
})();
</script>
<script type="text/javascript" src="/admin.js"></script>
</body>
</html>""")
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@app.route('/admin-test')
def admin_test_page():
    """最小诊断页面：验证 JS 是否能执行"""
    from flask import make_response
    resp = make_response("""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin JS Test</title>
<style>
body{font-family:monospace;background:#0f0f1a;color:#e0e0e0;padding:40px;text-align:center}
h1{color:#7c3aed}
#status{font-size:20px;margin-top:20px;padding:20px;border-radius:8px}
.ok{color:#16a34a;background:rgba(22,163,74,0.1)}
.fail{color:#dc3545;background:rgba(220,53,69,0.1)}
</style>
</head>
<body>
<h1>🧪 JS 执行诊断</h1>
<p id="status">⏳ 等待 JS 执行...</p>
<script>
(function(){
  var s=document.getElementById("status");
  s.textContent="✅ JS 执行成功! "+new Date().toISOString();
  s.className="ok";
  console.log("JS executed successfully at "+new Date().toISOString());
})();
</script>
</body>
</html>""")
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@app.route('/admin.js')
def admin_js():
    """管理员后台 JavaScript（外部文件，避免内联脚本问题）"""
    from flask import make_response
    js_code = """// IMA 下载助手 Pro - 管理后台 JS v4
(function(){
  'use strict';
  var API = window.location.origin + '/api/v1';
  var authToken = '';

  // 显示登录状态
  function logStatus(msg, color) {
    var ls = document.getElementById('loginStatus');
    if (ls) {
      ls.textContent = msg;
      ls.style.color = color || '#888';
    }
    console.log('[Admin]', msg);
  }

  logStatus('✅ 页面已加载 v4, API=' + API, '#16a34a');

  // 登录函数
  window.handleLogin = function(e) {
    if (e) e.preventDefault();
    var email = document.getElementById('adminEmail').value.trim();
    var password = document.getElementById('adminPassword').value.trim();
    logStatus('⏳ 验证输入...', '#f59e0b');
    if (!email || !password) {
      logStatus('❌ 请输入邮箱和密码', '#dc3545');
      return false;
    }
    logStatus('⏳ 发送登录请求到: ' + API + '/auth/admin-login', '#3b82f6');
    fetch(API + '/auth/admin-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: password })
    })
    .then(function(resp) {
      logStatus('⏳ 收到响应 HTTP ' + resp.status, '#3b82f6');
      return resp.json();
    })
    .then(function(data) {
      if (data.token && data.user && data.user.role === 'admin') {
        authToken = data.token;
        logStatus('✅ 登录成功！正在加载面板...', '#16a34a');
        document.getElementById('loginOverlay').classList.add('hidden');
        document.getElementById('sidebar').classList.remove('hidden');
        document.getElementById('mainContent').classList.remove('hidden');
        loadDashboard();
        loadUsers();
      } else {
        logStatus('❌ ' + (data.error || '登录失败或非管理员账号'), '#dc3545');
      }
    })
    .catch(function(e) {
      logStatus('❌ 网络错误: ' + e.message, '#dc3545');
    });
    return false;
  };

  // API 请求封装
  function apiFetch(path, options) {
    if (!options) options = {};
    options.headers = Object.assign({
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + authToken
    }, options.headers || {});
    return fetch(API + path, options).then(function(r) { return r.json(); });
  }

  // 加载仪表盘
  window.loadDashboard = function() {
    apiFetch('/admin/stats').then(function(data) {
      if (data.total_users !== undefined) {
        document.getElementById('s-totalUsers').textContent = data.total_users;
        document.getElementById('s-activeUsers').textContent = data.active_users;
        document.getElementById('s-totalDownloads').textContent = data.total_downloads;
        document.getElementById('s-quotaUsed').textContent = data.total_quota_used;
      }
    });
  };

  // 订阅标签
  function subTypeBadge(ut, exp) {
    if (!ut) return '<span style="color:#666">-</span>';
    var n = { day: '日卡', month: '月卡', year: '年卡' };
    var cls = exp ? 'badge-expired' : 'badge-' + ut;
    var lb = exp ? (n[ut] || ut) + ' ⚠' : (n[ut] || ut);
    return '<span class="badge ' + cls + '">' + lb + '</span>';
  }

  // 到期时间格式化
  function fmtExpiry(ea, exp) {
    if (!ea) return '<span style="color:#666">-</span>';
    var d = ea.split('T')[0];
    return exp ? '<span class="expired-text">' + d + ' (已到期)</span>' : d;
  }

  // 加载用户列表
  window.loadUsers = function() {
    apiFetch('/admin/users?per_page=100').then(function(data) {
      var tbody = document.getElementById('userTableBody');
      tbody.innerHTML = '';
      (data.users || []).forEach(function(u) {
        var subHtml = subTypeBadge(u.subscription_type, u.is_subscription_expired);
        var expHtml = fmtExpiry(u.subscription_expires_at, u.is_subscription_expired);
        var activeBadge = '<span class="badge ' + (u.is_active ? 'badge-active' : 'badge-disabled') + '">' + (u.is_active ? '活跃' : '禁用') + '</span>';
        var adminBadge = u.role === 'admin' ? '<span class="badge badge-admin">管理员</span>' : '';
        var createdDate = (u.created_at || '').split('T')[0] || '-';
        var tr = document.createElement('tr');
        tr.innerHTML = '<td style="color:#666;font-size:10px">' + u.id + '</td><td>' + u.email + '</td><td><input type="number" value="' + u.quota_total + '" id="qt-' + u.id + '" /></td><td>' + u.quota_used + '</td><td style="color:#7c3aed;font-weight:600">' + u.quota_remaining + '</td><td>' + subHtml + '</td><td style="font-size:10px">' + expHtml + '</td><td>' + activeBadge + adminBadge + '</td><td style="font-size:10px;color:#666">' + createdDate + '</td><td style="white-space:nowrap"><button class="btn btn-primary btn-sm" onclick="updateQuota(' + u.id + ')">💾</button> <button class="btn btn-warning btn-sm" onclick="showSubModal(' + u.id + ')">📅</button> <button class="btn ' + (u.is_active ? 'btn-danger' : 'btn-success') + ' btn-sm" onclick="toggleUser(' + u.id + ')">' + (u.is_active ? '禁用' : '启用') + '</button></td>';
        tbody.appendChild(tr);
      });
    });
  };

  // 更新配额
  window.updateQuota = function(userId) {
    var qt = document.getElementById('qt-' + userId).value;
    apiFetch('/admin/users/' + userId + '/quota', { method: 'PUT', body: JSON.stringify({ quota_total: parseInt(qt) }) }).then(function() { loadUsers(); });
  };

  // 修改订阅
  window.showSubModal = function(userId) {
    var st = prompt('输入订阅类型:\\n- day (日卡/1天)\\n- month (月卡/30天)\\n- year (年卡/365天)\\n- 留空 = 取消订阅', '');
    if (st === null) return;
    apiFetch('/admin/users/' + userId + '/subscription', { method: 'PUT', body: JSON.stringify({ subscription_type: st.trim() }) }).then(function() { loadUsers(); });
  };

  // 启用/禁用用户
  window.toggleUser = function(userId) {
    apiFetch('/admin/users/' + userId + '/toggle', { method: 'POST' }).then(function() { loadUsers(); });
  };

  // 创建用户按钮
  var createBtn = document.getElementById('createUserBtn');
  if (createBtn) {
    createBtn.addEventListener('click', function() {
      var email = document.getElementById('newEmail').value.trim();
      var pass = document.getElementById('newPassword').value.trim();
      var name = document.getElementById('newName').value.trim();
      var quota = parseInt(document.getElementById('newQuota').value) || 100;
      var sub = document.getElementById('newSubType').value;
      var m = document.getElementById('createMsg');
      if (!email || email.indexOf('@') < 0) {
        m.textContent = '请输入正确的邮箱';
        m.className = 'msg msg-error';
        m.classList.remove('hidden');
        return;
      }
      if (!pass || pass.length < 6) {
        m.textContent = '密码至少6位';
        m.className = 'msg msg-error';
        m.classList.remove('hidden');
        return;
      }
      var body = { email: email, password: pass, quota_total: quota, name: name };
      if (sub) body.subscription_type = sub;
      apiFetch('/admin/users', { method: 'POST', body: JSON.stringify(body) }).then(function(data) {
        if (data.id) {
          m.textContent = '✅ 用户创建成功！邮箱: ' + data.email;
          m.className = 'msg msg-success';
          m.classList.remove('hidden');
          document.getElementById('newEmail').value = '';
          document.getElementById('newPassword').value = '';
          document.getElementById('newName').value = '';
          loadUsers();
          setTimeout(function() { m.classList.add('hidden'); }, 5000);
        } else {
          m.textContent = data.error || '创建失败';
          m.className = 'msg msg-error';
          m.classList.remove('hidden');
        }
      }).catch(function(e) {
        m.textContent = '创建失败: ' + e.message;
        m.className = 'msg msg-error';
        m.classList.remove('hidden');
      });
    });
  }

  // 页面切换
  window.showPage = function(page) {
    document.querySelectorAll("[id^='page-']").forEach(function(el) { el.classList.add('hidden'); });
    document.getElementById('page-' + page).classList.remove('hidden');
    document.querySelectorAll('.sidebar a').forEach(function(a) { a.classList.remove('active'); });
    if (event && event.target) event.target.classList.add('active');
  };

  console.log('[Admin] v4 JS loaded successfully');
})();
"""
    resp = make_response(js_code)
    resp.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


# ============================================================
# 初始化
# ============================================================

def init_admin():
    """创建默认管理员（仅在无管理员时）"""
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        print('[INIT] No admin found, creating default admin...')
        ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', '2051645018@qq.com')
        ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '000000')
        admin_user = User(
            email=ADMIN_EMAIL,
            name='管理员',
            password_hash=hash_password(ADMIN_PASSWORD),
            role='admin',
            is_active=True,
            quota_total=999999,
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f'[INIT] Default admin created: {ADMIN_EMAIL}')

with app.app_context():
    # 安全迁移：使用 db.create_all() 创建表（仅在不存在时），不进行破坏性删除
    try:
        db.create_all()
        print('[INIT] 数据库表创建/验证完成')
        init_admin()
    except Exception as e:
        print('[INIT] db.create_all() failed: ' + str(e))
        raise

    # 安全添加 phone 列到 user 表（如果不存在）
    try:
        _db_url = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if 'postgresql' in _db_url:
            db.session.execute(db.text(
                'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS phone VARCHAR(20)'
            ))
            db.session.execute(db.text(
                'ALTER TABLE verify_code ADD COLUMN IF NOT EXISTS phone VARCHAR(20)'
            ))
            db.session.execute(db.text(
                'ALTER TABLE verify_code ALTER COLUMN email DROP NOT NULL'
            ))
            print('[MIGRATE] PostgreSQL: phone 列已添加（或已存在）')
        else:
            for stmt in [
                'ALTER TABLE "user" ADD COLUMN phone VARCHAR(20)',
                'ALTER TABLE verify_code ADD COLUMN phone VARCHAR(20)',
            ]:
                try:
                    db.session.execute(db.text(stmt))
                    print(f'[MIGRATE] SQLite: {stmt}')
                except Exception:
                    print(f'[MIGRATE] SQLite: 列已存在，跳过')
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print('[MIGRATE] 迁移: ' + str(e))

    # 安全添加 password_hash、subscription_type、subscription_expires_at 列到 user 表
    try:
        _db_url = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if 'postgresql' in _db_url:
            for col_stmt in [
                'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS password_hash VARCHAR(256)',
                'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS subscription_type VARCHAR(10)',
                'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMP',
            ]:
                db.session.execute(db.text(col_stmt))
            print('[MIGRATE] PostgreSQL: 新字段已添加（或已存在）')
        else:
            for col_stmt in [
                'ALTER TABLE "user" ADD COLUMN password_hash VARCHAR(256)',
                'ALTER TABLE "user" ADD COLUMN subscription_type VARCHAR(10)',
                'ALTER TABLE "user" ADD COLUMN subscription_expires_at TIMESTAMP',
            ]:
                try:
                    db.session.execute(db.text(col_stmt))
                    print(f'[MIGRATE] SQLite: {col_stmt}')
                except Exception:
                    print(f'[MIGRATE] SQLite: 列已存在，跳过')
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print('[MIGRATE] 新字段迁移: ' + str(e))

    init_admin()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)  # 安全：关闭debug模式
