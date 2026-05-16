# IMA 下载助手 Pro - 服务端

基于 Python Flask 的后端服务，负责：
- 用户认证（腾讯云SMS手机验证码登录）
- 配额管理（管理员可调整）
- 付费验证（预留支付接口）
- 管理后台（/admin）

## 部署方式

### 方式一：Render.com（推荐，免费起步）

1. 注册 [Render.com](https://render.com)
2. 新建 Web Service → 连接 GitHub 仓库
3. Root Directory 设为 `server`
4. Render 自动检测 `render.yaml` 配置
5. 在环境变量中填入腾讯云SMS密钥
6. 部署完成，获取 URL

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
| `SECRET_KEY` | Flask密钥 | 是 |
| `JWT_SECRET_KEY` | JWT密钥 | 是 |
| `TENCENT_SMS_SECRET_ID` | 腾讯云SecretId | 上线后必填 |
| `TENCENT_SMS_SECRET_KEY` | 腾讯云SecretKey | 上线后必填 |
| `TENCENT_SMS_SDK_APP_ID` | 短信应用AppId | 上线后必填 |
| `TENCENT_SMS_SIGN_NAME` | 短信签名 | 上线后必填 |
| `TENCENT_SMS_TEMPLATE_ID` | 短信模板ID | 上线后必填 |

**开发模式**：不配置腾讯云密钥时，验证码打印到控制台，通用验证码 `888888` 可登录。

## 管理后台

部署后访问 `https://your-app.onrender.com/admin`

管理员账号自动创建，首次使用通用验证码 `888888` 登录。

## API 文档

| 路由 | 方法 | 说明 |
|---|---|---|
| `/api/v1/auth/session-key` | POST | 获取加密会话密钥 |
| `/api/v1/auth/send-code` | POST | 发送验证码 |
| `/api/v1/auth/login` | POST | 验证码登录 |
| `/api/v1/quotas` | GET | 获取配额 |
| `/api/v1/quotas/consume` | POST | 消耗配额 |
| `/api/v1/user` | GET | 获取用户信息 |
| `/api/v1/admin/stats` | GET | 管理统计 |
| `/api/v1/admin/users` | GET | 用户列表 |
| `/api/v1/admin/users/:id/quota` | PUT | 修改配额 |
| `/api/v1/admin/users/:id/toggle` | POST | 启用/禁用用户 |
