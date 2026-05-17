#!/usr/bin/env python3
"""
IMA 下载助手 Pro - 服务端
功能：用户认证（邮箱+验证码）、配额管理、管理后台
"""

import os
import re
import smtplib
import secrets
import random
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
    # LeapCell/Render 的 PostgreSQL URL 可能以 postgres:// 开头，SQLAlchemy 需要 postgresql://
    if _db_url.startswith('postgres://'):
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ima_pro.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

CORS(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)

# ============================================================
# 数据模型
# ============================================================

class User(db.Model):
    """用户表"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), default='')
    quota_total = db.Column(db.Integer, default=0)     # 总配额（新用户默认0，管理员手动分配）
    quota_used = db.Column(db.Integer, default=0)      # 已使用
    role = db.Column(db.String(20), default='user')     # user / admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    @property
    def quota_remaining(self):
        return max(0, self.quota_total - self.quota_used)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'quota_total': self.quota_total,
            'quota_used': self.quota_used,
            'quota_remaining': self.quota_remaining,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class VerifyCode(db.Model):
    """验证码表"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)


class Order(db.Model):
    """订单表（付费充值）"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, default=0)         # 购买配额数量
    price = db.Column(db.Float, default=0)             # 金额
    status = db.Column(db.String(20), default='pending')  # pending / paid / cancelled
    trade_no = db.Column(db.String(100), unique=True)  # 支付流水号
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
    download_method = db.Column(db.String(20))  # direct / auth / notebook
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


def is_smtp_configured():
    """检查 SMTP 是否已配置"""
    return all([
        os.environ.get('SMTP_HOST', '').strip(),
        os.environ.get('SMTP_PORT', '').strip(),
        os.environ.get('SMTP_USER', '').strip(),
        os.environ.get('SMTP_PASSWORD', '').strip(),
    ])


def send_email_code(to_email, code):
    """
    发送验证码邮件
    环境变量：
    - SMTP_HOST: SMTP 服务器地址（如 smtp.qq.com）
    - SMTP_PORT: SMTP 端口（如 465 或 587）
    - SMTP_USER: 发件邮箱地址
    - SMTP_PASSWORD: 邮箱授权码（非登录密码）
    - SMTP_FROM_NAME: 发件人名称（可选，默认 IMA下载助手）
    """
    if not is_smtp_configured():
        # 开发模式：验证码打印到控制台 + 通用验证码 888888
        print(f"[EMAIL-DEV] 验证码 -> {to_email}: {code}")
        print(f"[EMAIL-DEV] 开发模式下，任意邮箱可用验证码 888888 登录")
        return True

    # 正式模式：通过 SMTP 发送邮件
    try:
        smtp_host = os.environ.get('SMTP_HOST', '').strip()
        smtp_port = int(os.environ.get('SMTP_PORT', '465').strip())
        smtp_user = os.environ.get('SMTP_USER', '').strip()
        smtp_password = os.environ.get('SMTP_PASSWORD', '').strip()
        from_name = os.environ.get('SMTP_FROM_NAME', 'IMA下载助手').strip()

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
        msg['From'] = f'{from_name} <{smtp_user}>'
        msg['To'] = to_email

        if smtp_port == 465:
            # SSL 模式
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
        else:
            # TLS 模式
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.starttls()

        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, [to_email], msg.as_string())
        server.quit()

        print(f"[EMAIL] 发送成功 -> {to_email}")
        return True

    except Exception as e:
        print(f"[EMAIL] 发送失败 -> {to_email}: {e}")
        return False


# ============================================================
# API 路由
# ============================================================

@app.route('/api/v1/auth/session-key', methods=['POST'])
def get_session_key():
    """返回客户端加密用的会话密钥（每次不同，比硬编码安全）"""
    import base64
    key = secrets.token_bytes(32)
    return jsonify({'key': base64.b64encode(key).decode()})


@app.route('/api/v1/auth/send-code', methods=['POST'])
def send_code():
    """发送验证码到邮箱"""
    email = request.json.get('email', '').strip().lower()
    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({'error': '请输入正确的邮箱地址'}), 400

    # 限制频率：同一邮箱60秒内只能发一次
    recent = VerifyCode.query.filter(
        VerifyCode.email == email,
        VerifyCode.expires_at > datetime.utcnow()
    ).order_by(VerifyCode.id.desc()).first()

    if recent and (datetime.utcnow() - (recent.expires_at.replace(tzinfo=None) if recent.expires_at.tzinfo else recent.expires_at)).total_seconds() > -240:
        return jsonify({'error': '发送太频繁，请稍后再试'}), 429

    code = str(random.randint(100000, 999999))
    verify = VerifyCode(
        email=email,
        code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )
    db.session.add(verify)
    db.session.commit()

    # 发送邮件
    send_email_code(email, code)

    return jsonify({'message': '验证码已发送'})


@app.route('/api/v1/auth/dev-status', methods=['GET'])
def dev_status():
    """调试端点：返回 SMTP 配置状态"""
    smtp_ok = is_smtp_configured()
    return jsonify({
        'dev_mode': not smtp_ok,
        'smtp_configured': smtp_ok,
        'smtp_host': os.environ.get('SMTP_HOST', ''),
        'smtp_user': os.environ.get('SMTP_USER', ''),
    })


@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """邮箱+验证码登录"""
    email = request.json.get('email', '').strip().lower()
    code = request.json.get('code', '').strip()

    if not email or not code:
        return jsonify({'error': '请输入邮箱和验证码'}), 400

    # 验证码校验
    verify = VerifyCode.query.filter(
        VerifyCode.email == email,
        VerifyCode.code == code,
        VerifyCode.used == False,
        VerifyCode.expires_at > datetime.utcnow()
    ).order_by(VerifyCode.id.desc()).first()

    # 开发模式：通用验证码 888888（SMTP 未配置时生效）
    dev_mode = not is_smtp_configured()
    if not verify and dev_mode and code == '888888':
        pass  # 允许通过
    elif not verify:
        return jsonify({'error': '验证码错误或已过期'}), 401

    if verify:
        verify.used = True

    # 查找或创建用户
    user = User.query.filter_by(email=email).first()
    if not user:
        # 新用户：默认配额为0，需要管理员分配
        email_prefix = email.split('@')[0]
        user = User(email=email, name=f'用户{email_prefix[:8]}', quota_total=0)
        db.session.add(user)
    elif not user.is_active:
        return jsonify({'error': '账号已被禁用，请联系管理员'}), 403

    user.last_login = datetime.utcnow()
    db.session.commit()

    # 生成 JWT
    token = create_access_token(identity=str(user.id))
    return jsonify({
        'token': token,
        'user': user.to_dict()
    })


@app.route('/api/v1/auth/admin-login', methods=['POST'])
def admin_login():
    """管理员固定密码登录"""
    email = request.json.get('email', '').strip().lower()
    password = request.json.get('password', '').strip()

    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '000000')

    if not email or not password:
        return jsonify({'error': '请输入邮箱和密码'}), 400

    if password != ADMIN_PASSWORD:
        return jsonify({'error': '密码错误'}), 401

    user = User.query.filter_by(email=email).first()
    if not user or user.role != 'admin':
        return jsonify({'error': '非管理员账号'}), 403

    user.last_login = datetime.utcnow()
    db.session.commit()

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

    count = request.json.get('count', 1)
    user.quota_used += count
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
        user.quota_total = quota_total

    quota_used = request.json.get('quota_used')
    if quota_used is not None:
        user.quota_used = quota_used

    db.session.commit()
    return jsonify(user.to_dict())


@app.route('/api/v1/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    """启用/禁用用户"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    user.is_active = not user.is_active
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
# 管理后台页面
# ============================================================

@app.route('/admin')
def admin_page():
    """管理后台 HTML 页面（内联，避免缓存问题）"""
    return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IMA 下载助手 Pro - 管理后台</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#0f0f1a;color:#e0e0e0;min-height:100vh}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:220px;background:#1a1a2e;padding:20px 0;border-right:1px solid #2d2d44}
.sidebar h2{font-size:16px;color:#a855f7;padding:0 20px;margin-bottom:24px}
.sidebar a{display:block;padding:12px 20px;color:#999;text-decoration:none;font-size:14px;transition:all 0.2s}
.sidebar a:hover,.sidebar a.active{color:white;background:#2d2d44;border-left:3px solid #a855f7}
.main{margin-left:220px;padding:24px}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:#1a1a2e;border-radius:12px;padding:20px;text-align:center}
.stat-card .num{font-size:32px;font-weight:700;color:#a855f7}
.stat-card .label{font-size:12px;color:#888;margin-top:4px}
.card{background:#1a1a2e;border-radius:12px;padding:20px;margin-bottom:20px}
.card h3{font-size:16px;color:#a855f7;margin-bottom:16px}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:left;font-size:13px;border-bottom:1px solid #2d2d44}
th{color:#888;font-weight:600}
tr:hover td{background:#1e1e32}
.btn{padding:6px 14px;border-radius:6px;border:none;cursor:pointer;font-size:12px;transition:all 0.2s}
.btn-primary{background:#a855f7;color:white}
.btn-danger{background:#dc3545;color:white}
.btn-success{background:#28a745;color:white}
.btn-sm{padding:4px 10px;font-size:11px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:500}
.badge-active{background:rgba(40,167,69,0.2);color:#28a745}
.badge-disabled{background:rgba(220,53,69,0.2);color:#dc3545}
.badge-admin{background:rgba(168,85,247,0.2);color:#a855f7}
input[type="number"]{background:#2d2d44;border:1px solid #3d3d5c;border-radius:6px;padding:6px 10px;color:#e0e0e0;font-size:13px;width:80px;outline:none}
input[type="number"]:focus{border-color:#a855f7}
.login-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(15,15,26,0.95);z-index:9999;display:flex;align-items:center;justify-content:center}
.login-box{background:#1a1a2e;border-radius:16px;padding:32px;width:360px}
.login-box h2{color:#a855f7;margin-bottom:20px;text-align:center}
.login-box input{width:100%;background:#2d2d44;border:1px solid #3d3d5c;border-radius:8px;padding:12px;color:#e0e0e0;font-size:14px;margin-bottom:12px;outline:none}
.login-box input:focus{border-color:#a855f7}
.login-box .btn{width:100%;padding:12px;font-size:14px}
.login-box .hint{font-size:11px;color:#888;text-align:center;margin-top:8px}
.hidden{display:none!important}
</style>
</head>
<body>
<div class="login-overlay" id="loginOverlay">
  <div class="login-box">
    <h2>&#128272; 管理员登录</h2>
    <input type="email" id="adminEmail" placeholder="管理员邮箱" value="2051645018@qq.com" />
    <input type="password" id="adminPassword" placeholder="管理员密码" />
    <button class="btn btn-primary" id="adminLoginBtn">登录</button>
    <p class="hint">管理员使用固定密码登录</p>
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
      <h3>用户列表</h3>
      <p style="font-size:12px;color:#888;margin-bottom:12px;">&#128161; 新用户默认配额为0，请手动分配下载配额。</p>
      <table><thead><tr><th>ID</th><th>邮箱</th><th>配额</th><th>已用</th><th>剩余</th><th>状态</th><th>注册时间</th><th>操作</th></tr></thead><tbody id="userTableBody"></tbody></table>
    </div>
  </div>
</div>
<script>
const API=window.location.origin+"/api/v1";let authToken="";
document.getElementById("adminLoginBtn").addEventListener("click",async()=>{
  const email=document.getElementById("adminEmail").value.trim();
  const password=document.getElementById("adminPassword").value.trim();
  if(!email||!password){alert("请输入邮箱和密码");return}
  try{
    const resp=await fetch(API+"/auth/admin-login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password})});
    const data=await resp.json();
    if(data.token&&data.user&&data.user.role==="admin"){
      authToken=data.token;
      document.getElementById("loginOverlay").classList.add("hidden");
      document.getElementById("sidebar").classList.remove("hidden");
      document.getElementById("mainContent").classList.remove("hidden");
      loadDashboard();loadUsers();
    }else{alert(data.error||"登录失败或非管理员账号")}
  }catch(e){alert("登录失败: "+e.message)}
});
function apiFetch(path,options={}){
  return fetch(API+path,{...options,headers:{"Content-Type":"application/json","Authorization":"Bearer "+authToken,...(options.headers||{})}}).then(r=>r.json());
}
async function loadDashboard(){
  const data=await apiFetch("/admin/stats");
  if(data.total_users!==undefined){
    document.getElementById("s-totalUsers").textContent=data.total_users;
    document.getElementById("s-activeUsers").textContent=data.active_users;
    document.getElementById("s-totalDownloads").textContent=data.total_downloads;
    document.getElementById("s-quotaUsed").textContent=data.total_quota_used;
  }
}
async function loadUsers(){
  const data=await apiFetch("/admin/users?per_page=100");
  const tbody=document.getElementById("userTableBody");tbody.innerHTML="";
  (data.users||[]).forEach(u=>{
    const tr=document.createElement("tr");
    tr.innerHTML="<td>"+u.id+"</td><td>"+u.email+"</td><td><input type='number' value='"+u.quota_total+"' id='qt-"+u.id+"' style='width:70px' /></td><td>"+u.quota_used+"</td><td style='color:#a855f7;font-weight:600'>"+u.quota_remaining+"</td><td><span class='badge "+(u.is_active?"badge-active":"badge-disabled")+"'>"+(u.is_active?"活跃":"禁用")+"</span>"+(u.role==="admin"?"<span class='badge badge-admin'>管理员</span>":"")+"</td><td style='font-size:11px;color:#666'>"+((u.created_at||"").split("T")[0]||"-")+"</td><td><button class='btn btn-primary btn-sm' onclick='updateQuota("+u.id+")'>💾</button> <button class='btn "+(u.is_active?"btn-danger":"btn-success")+" btn-sm' onclick='toggleUser("+u.id+")'>"+(u.is_active?"禁用":"启用")+"</button></td>";
    tbody.appendChild(tr);
  });
}
async function updateQuota(userId){const qt=document.getElementById("qt-"+userId).value;await apiFetch("/admin/users/"+userId+"/quota",{method:"PUT",body:JSON.stringify({quota_total:parseInt(qt)})});loadUsers()}
async function toggleUser(userId){await apiFetch("/admin/users/"+userId+"/toggle",{method:"POST"});loadUsers()}
function showPage(page){document.querySelectorAll("[id^='page-']").forEach(el=>el.classList.add("hidden"));document.getElementById("page-"+page).classList.remove("hidden");document.querySelectorAll(".sidebar a").forEach(a=>a.classList.remove("active"));event.target.classList.add("active")}
</script>
</body>
</html>"""


# ============================================================
# 初始化
# ============================================================

def init_admin():
    """创建默认管理员"""
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        admin = User(
            email='admin@ima-pro.local',
            name='管理员',
            role='admin',
            quota_total=999999,
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print(f"[INIT] 管理员账号已创建: admin@ima-pro.local")
        print(f"[INIT] 开发模式下可用验证码 888888 登录")


with app.app_context():
    # 检查是否存在旧的 phone 列（从手机号方案迁移到邮箱方案）
    try:
        result = db.session.execute(db.text("SELECT column_name FROM information_schema.columns WHERE table_name='user' AND column_name='phone'"))
        old_phone_col = result.fetchone()
        if old_phone_col:
            print('[MIGRATE] 检测到旧表结构(phone列)，删除旧表重建...')
            db.drop_all()
    except Exception as e:
        print('[MIGRATE] 检查表结构异常: ' + str(e))
        # 如果表不存在也会报错，直接继续 create_all
    try:
        db.create_all()
    except Exception as e:
        print('[INIT] db.create_all() failed: ' + str(e) + ', dropping and recreating...')
        db.drop_all()
        db.create_all()
    init_admin()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
