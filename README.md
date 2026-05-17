# IMA 下载助手 Pro - 服务端

基于 Python Flask 的后端服务，负责：
- 用户认证（邮箱+验证码登录）
- 配额管理（管理员手动分配）
- 管理后台（/admin）

## 业务流程

1. 用户在扩展中输入邮箱 → 获取验证码 → 登录
2. 新用户默认配额为 0，无法下载
3. 用户联系卖家（你）告知邮箱和所需下载数量
4. 你在管理后台（/admin）找到该用户，手动设置配额
5. 用户即可开始下载，配额自动递减

## 部署方式

### 方式一：LeapCell（推荐，永久免费）

1. 注册 [LeapCell](https://leapcell.io)
2. 新建项目 → 连接 GitHub 仓库
3. Root Directory 设为 `server`，分支选 `master`
4. 配置环境变量（见下方）
5. 部署完成，获取 URL

### 方式二：本地运行

```bash
cd server
pip install -r requirements.txt
cp .env.example .env    # 编辑 .env 填入配置
python app.py
```

## 环境变量

| 变量 | 说明 | 必填 |
|---|---|---|
| `SECRET_KEY` | Flask 密钥 | 是 |
| `JWT_SECRET_KEY` | JWT 密钥 | 是 |
| `DATABASE_URL` | PostgreSQL 连接串 | LeapCell 自动注入 |
| `SMTP_HOST` | SMTP 服务器地址 | 上线后必填 |
| `SMTP_PORT` | SMTP 端口 | 上线后必填 |
| `SMTP_USER` | 发件邮箱地址 | 上线后必填 |
| `SMTP_PASSWORD` | 邮箱授权码 | 上线后必填 |
| `SMTP_FROM_NAME` | 发件人名称 | 否 |

**开发模式**：不配置 SMTP 时，验证码打印到控制台，通用验证码 `888888` 可登录任意邮箱。

## 管理后台

部署后访问 `https://your-app.leapcell.dev/admin`

- 默认管理员邮箱: `admin@ima-pro.local`
- 开发模式下验证码: `888888`

### 管理员操作流程

1. 用管理员邮箱登录后台
2. 在"用户管理"中查看所有用户
3. 找到需要充值的用户，在"配额"列输入数量，点击 💾 保存
4. 用户配额立即生效

## API 文档

| 路由 | 方法 | 说明 |
|---|---|---|
| `/api/v1/auth/session-key` | POST | 获取加密会话密钥 |
| `/api/v1/auth/send-code` | POST | 发送验证码到邮箱 |
| `/api/v1/auth/login` | POST | 邮箱+验证码登录 |
| `/api/v1/quotas` | GET | 获取配额 |
| `/api/v1/quotas/consume` | POST | 消耗配额 |
| `/api/v1/user` | GET | 获取用户信息 |
| `/api/v1/admin/stats` | GET | 管理统计 |
| `/api/v1/admin/users` | GET | 用户列表 |
| `/api/v1/admin/users/:id/quota` | PUT | 修改配额 |
| `/api/v1/admin/users/:id/toggle` | POST | 启用/禁用用户 |
