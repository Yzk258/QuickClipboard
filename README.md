# QuickClipboard (LCECP)

轻量级云加密剪贴板 —— 在多台设备之间安全传递密码、API Key、SSH 密钥和代码片段。

- **端到端加密**：内容在本地加密后才上传，服务器只存储密文，无法得知你的数据
- **即存即取**：设备 A 上传，设备 B 一键取回并自动写入剪贴板
- **自动过期**：密文 1 小时后自动销毁，不留痕迹
- **开箱即用**：提供免安装的单文件 exe，也提供命令行客户端

> 默认配置指向作者的演示服务器（可能随时重启或下线），正式使用建议按本文档自建服务端。

---

## 快速开始

### 方式一：直接使用仓库自带的 exe（推荐，免安装）

仓库的 `dist/` 目录中已附带打包好的 `LCECP.exe`（约 15 MB），**无需安装 Python 和任何依赖**：

1. 下载本仓库（绿色 Code 按钮 → Download ZIP，或 `git clone`）
2. 进入 `dist/` 目录，**双击 `LCECP.exe`** 即可启动图形界面
3. 填入服务器地址、用户名和密码即可登录

```
QuickClipboard/
└── dist/
    └── LCECP.exe   ← 双击直接运行
```

> 该 exe 为独立单文件程序，也可单独拷贝到其他 Windows 电脑使用（首次启动需解压，稍等 2~3 秒属正常现象）。

### 方式二：从源码运行

```bash
git clone https://github.com/<your-name>/QuickClipboard.git
cd QuickClipboard
pip install -r requirements.txt

# 终端 1：启动服务器（如果用演示服务器可跳过）
python src/server.py

# 终端 2：启动图形客户端
python src/gui_client.py
```

需要 Python 3.8+；Tkinter 已内置于标准 Python 安装。

---

## 使用指南

### 登录

| 字段 | 说明 |
|------|------|
| 服务器地址 | 本机测试填 `127.0.0.1`；自建服务器填其公网 IP；默认已填演示服务器 |
| 端口 | 默认 `9000` |
| 用户名 / 密码 | 首次登录自动注册；**密码同时是解密密钥，遗忘后数据无法找回** |

> 若登录时提示「该账号已存在」而你以为自己是首次注册，说明有他人使用了相同的用户名和密码（对方将能解密你的数据），请立即更换凭据。多设备登录同一账户时出现该提示属正常现象。

### 主界面

| 操作 | 说明 |
|------|------|
| 从系统剪贴板粘贴 → 加密上传 | 把本机剪贴板内容加密存到服务器 |
| 获取并解密 → 复制到系统剪贴板 | 取回密文、本地解密、写回剪贴板 |
| PING | 检测连接状态 |
| 断开连接 | 发送退出指令并返回登录页 |

### 典型场景

```
设备 A：复制 Token → 粘贴到输入框 → 加密上传
设备 B：登录同一账号 → 获取并解密 → 复制到剪贴板 → 直接使用
```

---

## 部署自己的服务器

以阿里云 ECS（Linux）为例：

```bash
# 1. 上传两个文件
scp src/protocol.py src/server.py root@<服务器IP>:~/lcecp/

# 2. 安装依赖并后台启动
ssh root@<服务器IP>
pip install cryptography
cd ~/lcecp
nohup python3 server.py > server.log 2>&1 &

# 3. 放行 TCP 9000 端口
#    云控制台安全组添加入方向规则 TCP/9000，
#    本机防火墙（如有）：firewall-cmd --permanent --add-port=9000/tcp && firewall-cmd --reload
```

客户端「服务器地址」填服务器公网 IP 即可。停止服务：`pkill -f server.py`。

### 数据保留策略

| 数据 | 保留时长 | 释放方式 |
|------|---------|---------|
| 剪贴板密文 + salt | 1 小时 | 后台线程每 60 秒主动清除（另有 GET 惰性兜底） |
| 空置账户（无密文且 24h 无活动） | 24 小时 | 自动删除，之后登录会创建全新账户 |
| 服务器进程退出 | 立即 | 全部清空（纯内存，无持久化） |

---

## 安全模型

**加密流程**：客户端用 PBKDF2-HMAC-SHA256（10 万次迭代）从你的密码派生密钥，配合随机 128 位盐值做 Fernet 对称加密；每次上传使用新盐。服务器只看到密文和盐值。

**各方的可见性**：

| 角色 | 能看到 | 不能看到 |
|------|--------|---------|
| 服务器 | 用户名、密码哈希、密文、盐值、IP | 明文内容 |
| 网络窃听者 | 密文流量 | 明文内容 |
| 知道你密码的人 | 全部明文 | — |

**当前局限**（教育/实验项目，使用前请知悉）：

- 密码即密钥：无找回机制，弱密码等同于明文存储
- 服务器密码哈希为无盐 SHA-256，仅用于登录校验，不参与加密
- 传输层为明文 TCP，加密依赖应用层；如需信道加密可自行套一层 TLS
- 每账户仅一个剪贴板槽位，后上传覆盖先上传
- 内存存储，服务器重启后所有账户与数据清空

---

## 协议简介

帧格式（共 12 字节头，大端序，正文为 JSON，上限 64 KB）：

```
+---------+----------+-----------+----------+----------+
| version | msg_type | status(2) | body_len | reserved |
|  1 B    |   1 B    |   2 B     |   4 B    |   4 B    |
+---------+----------+-----------+----------+----------+
|                JSON body (<= 64 KB)                  |
+------------------------------------------------------+
```

| 消息类型 | 值 | 方向 | 说明 |
|---------|----|----|------|
| LOGIN | 0x01 | C→S | 登录 / 自动注册，响应含 `new_account` 标志 |
| PUT | 0x02 | C→S | 上传密文 + salt |
| GET | 0x03 | C→S | 取回密文 + salt |
| RESP | 0x04 | S→C | 通用响应 |
| PING | 0x05 | C→S | 心跳 |
| EXIT | 0x06 | C→S | 断开 |

状态码沿用 HTTP 语义：200 / 400 / 401 / 404 / 413 / 500。

---

## 项目结构

```
QuickClipboard/
├── src/                # 源码
│   ├── protocol.py     # 协议定义：帧头 / 消息类型 / 状态码
│   ├── server.py       # 服务器：多线程、TTL 与闲置清理
│   ├── client.py       # 控制台客户端
│   └── gui_client.py   # GUI 客户端（Tkinter）
├── assets/             # app.ico 程序图标
├── tools/make_icon.py  # 图标生成脚本
├── LCECP.spec          # PyInstaller 打包配置
└── requirements.txt    # 依赖：cryptography
```

## 从源码打包 exe

仓库 `dist/` 中已附带现成的 exe，一般无需自行打包。如修改了源码想重新打包：

```powershell
pip install pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --icon=assets/app.ico --name=LCECP src/gui_client.py
```

生成 `dist\LCECP.exe`；改图标可编辑 `tools/make_icon.py` 后重新生成。

## 常见问题

<details>
<summary>连接报「目标计算机积极拒绝」</summary>

该地址/端口没有服务器在监听：确认服务端已启动、地址正确（本机填 `127.0.0.1`，不要填 `0.0.0.0`）、端口一致、防火墙/安全组放行 9000。
</details>

<details>
<summary>登录失败：wrong password</summary>

该用户名已存在但密码不同。用正确密码，或换新用户名。
</details>

<details>
<summary>解密失败</summary>

密码与上传时不一致。密码即密钥，无法找回。
</details>

<details>
<summary>Linux 服务器上 GUI 空白</summary>

无桌面环境需安装 `python3-tk`；或直接使用控制台客户端 `python src/client.py`。
</details>
