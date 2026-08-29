import socket
import threading
import time
import traceback

from protocol import *

HOST = "0.0.0.0"
PORT = 9000

TTL_SECONDS = 3600              # 剪贴板密文过期时间

CLEANUP_INTERVAL = 60           # 后台清理线程的扫描间隔（秒）
ACCOUNT_IDLE_SECONDS = 24 * 3600  # 空账户（无密文且无活动）的保留时间，超时后删除

# ===== 基础流量防护（可按需调整） =====
HANDSHAKE_TIMEOUT = 30            # 连接后允许完成登录的最长时间（秒）
IDLE_TIMEOUT = 120                # 登录后两条消息之间的最大间隔（秒）
MAX_CONN_LIFETIME = 1800          # 单条连接最长存活时间（秒），防止慢速攻击长期占用
MAX_CONNECTIONS_GLOBAL = 500      # 全局最大并发连接数
MAX_CONNECTIONS_PER_IP = 8        # 单个 IP 最大并发连接数
CONNECT_RATE_LIMIT = 30           # 单个 IP 在统计窗口内允许的新建连接次数
CONNECT_RATE_WINDOW = 60          # 连接频率统计窗口（秒）
MAX_MSG_RATE = 50                 # 单条连接每秒允许的最大消息数，超限强制断开
MAX_LOGIN_FAILS = 5               # 单个 IP 在统计窗口内允许的登录失败次数
LOGIN_FAIL_WINDOW = 300           # 登录失败统计窗口（秒）
BAN_SECONDS = 600                 # 触发封禁后的封禁时长（秒）

user_database = {}

db_lock = threading.Lock()

# ===== 流量防护状态 =====
guard_lock = threading.Lock()
active_global = 0                 # 当前全局并发连接数
per_ip_conns = {}                 # ip -> 当前并发连接数
connect_times = {}                # ip -> 窗口内新建连接的时间戳
login_fails = {}                  # ip -> 窗口内登录失败的时间戳
banned_until = {}                 # ip -> 封禁截止时间戳

def send_response( # 向客户端发送响应
    conn,
    status,
    body = None
):
    
    if body is None:
        body = {}

    packet = make_packet(
        msg_type = MSG_TYPE_RESP,
        body = body,
        status = status
    )

    conn.sendall(packet)


def current_time():
    return int(time.time())


def is_banned(ip): # 判断 IP 是否处于封禁期内

    with guard_lock:

        return current_time() < banned_until.get(ip, 0)


def try_accept_connection(ip): # 连接准入检查：封禁 / 连接频率 / 并发上限，通过则计数

    global active_global

    now = current_time()

    with guard_lock:

        if now < banned_until.get(ip, 0):
            return False, "ip banned"

        recent = [t for t in connect_times.get(ip, []) if now - t < CONNECT_RATE_WINDOW]

        connect_times[ip] = recent

        if len(recent) >= CONNECT_RATE_LIMIT:
            return False, "connect rate limit"

        if per_ip_conns.get(ip, 0) >= MAX_CONNECTIONS_PER_IP:
            return False, "too many connections from ip"

        if active_global >= MAX_CONNECTIONS_GLOBAL:
            return False, "server busy"

        recent.append(now)
        per_ip_conns[ip] = per_ip_conns.get(ip, 0) + 1
        active_global += 1

        return True, ""


def release_connection(ip): # 连接结束时归还并发计数

    global active_global

    with guard_lock:

        count = per_ip_conns.get(ip, 1) - 1

        if count <= 0:
            per_ip_conns.pop(ip, None)
        else:
            per_ip_conns[ip] = count

        active_global = max(0, active_global - 1)


def record_login_fail(ip): # 记录一次登录失败；窗口内失败次数达到阈值则封禁该 IP，返回是否触发封禁

    now = current_time()

    with guard_lock:

        fails = [t for t in login_fails.get(ip, []) if now - t < LOGIN_FAIL_WINDOW]

        fails.append(now)

        login_fails[ip] = fails

        if len(fails) >= MAX_LOGIN_FAILS:
            banned_until[ip] = now + BAN_SECONDS
            login_fails[ip] = []
            return True

        return False


def record_login_success(ip): # 登录成功后清除该 IP 的失败记录

    with guard_lock:

        login_fails.pop(ip, None)


def guard_cleanup(): # 清理防护状态中的过期记录，防止长期占用内存

    now = current_time()

    with guard_lock:

        for ip in list(connect_times.keys()):
            connect_times[ip] = [t for t in connect_times[ip] if now - t < CONNECT_RATE_WINDOW]
            if not connect_times[ip]:
                del connect_times[ip]

        for ip in list(login_fails.keys()):
            login_fails[ip] = [t for t in login_fails[ip] if now - t < LOGIN_FAIL_WINDOW]
            if not login_fails[ip]:
                del login_fails[ip]

        for ip in list(banned_until.keys()):
            if now >= banned_until[ip]:
                del banned_until[ip]


def cleanup_once(): # 扫描一遍账户数据库：清除过期密文，删除闲置空账户

    now = current_time()
    expired_cleared = []
    accounts_deleted = []

    with db_lock:

        for username in list(user_database.keys()):

            data = user_database[username]

            if data["expire_time"] != 0 and now > data["expire_time"]:

                data["ciphertext"] = ""
                data["salt"] = ""
                data["expire_time"] = 0

                expired_cleared.append(username)

            last_active = data.get("last_active")

            if (
                not data["ciphertext"]
                and last_active is not None
                and now - last_active > ACCOUNT_IDLE_SECONDS
            ):
                del user_database[username]

                accounts_deleted.append(username)

    if expired_cleared:

        print(f"[CLEANUP] 已主动清除过期密文：{expired_cleared}")

    if accounts_deleted:

        print(f"[CLEANUP] 已删除闲置空账户：{accounts_deleted}")


def cleanup_loop(): # 后台清理线程入口，周期性执行清理

    while True:

        time.sleep(CLEANUP_INTERVAL)

        try:

            cleanup_once()

            guard_cleanup()

        except Exception:

            print("[!] 清理线程出错！")
            traceback.print_exc()


def handle_client(conn, addr): # 处理客户端连接的函数，接收请求并根据消息类型进行处理，发送响应

    ip = addr[0]

    print(f"[+] 新用户连接：{addr}")

    authenticated = False
    current_user = None
    conn_start = time.time()
    msg_times = []

    try:

        while True:

            now_ts = time.time()

            remaining = MAX_CONN_LIFETIME - (now_ts - conn_start)

            if remaining <= 0:
                print(f"[GUARD] 连接存活时间超限，强制断开：{addr}")
                break

            conn.settimeout(
                min(HANDSHAKE_TIMEOUT if not authenticated else IDLE_TIMEOUT, remaining)
            )

            header, body = recv_packet(conn)

            if header is None:
                print(f"[-] 账户断开连接！{addr}")
                break

            while msg_times and now_ts - msg_times[0] > 1.0:
                msg_times.pop(0)

            msg_times.append(now_ts)

            if len(msg_times) > MAX_MSG_RATE:
                print(f"[GUARD] 消息频率超限，强制断开：{addr}")
                break

            print(f"[DEBUG] msg_type = {header.msg_type}")    


            if header.msg_type == MSG_TYPE_LOGIN:

                username = body.get("username")
                password_hash = body.get("password_hash")

                if not username or not password_hash:

                    send_response(
                        conn,
                        STATUS_BAD_REQUEST,
                        {
                            "error": "invalid login request"
                        }
                    )

                    continue
                
                created_new_account = False
                wrong_password = False

                with db_lock:

                    if username not in user_database:

                        user_database[username] = {
                            "password_hash": password_hash,
                            "ciphertext": "",
                            "salt": "",
                            "expire_time": 0,
                            "last_active": current_time()
                        }

                        created_new_account = True

                    else:

                        user_database[username]["last_active"] = current_time()
                
                    if user_database[username]["password_hash"] != password_hash:

                        wrong_password = True

                if wrong_password:

                    if record_login_fail(ip):

                        print(f"[GUARD] IP 登录失败次数过多，已封禁：{ip}")

                        send_response(
                            conn,
                            STATUS_UNAUTHORIZED,
                            {
                                "error": "too many login failures, your ip is banned"
                            }
                        )

                        break

                    send_response(
                        conn,
                        STATUS_UNAUTHORIZED,
                        {
                            "error": "wrong password"
                        }
                    )

                    continue

                record_login_success(ip)

                authenticated = True
                current_user = username

                print(f"[+] 用户登陆成功：{username}")

                send_response(
                    conn,
                    STATUS_OK,
                    {
                        "message": "login success",
                        "new_account": created_new_account
                    }
                )
            
            elif header.msg_type == MSG_TYPE_PUT:

                if not authenticated:

                    send_response(
                        conn,
                        STATUS_UNAUTHORIZED,
                        {
                            "error": "not login yet"
                        }
                    )

                    continue
                
                ciphertext = body.get("ciphertext")
                salt = body.get("salt")

                if ciphertext is None or salt is None:
                    send_response(
                        conn,
                        STATUS_BAD_REQUEST,
                        {
                            "error": "no ciphertext or salt"
                        }
                    )

                    continue

                with db_lock:

                    user_data = user_database.get(current_user)

                    if user_data is None:

                        send_response(
                            conn,
                            STATUS_UNAUTHORIZED,
                            {
                                "error": "account expired, please re-login"
                            }
                        )

                        continue

                    user_data["ciphertext"] = ciphertext

                    user_data["expire_time"] = (
                        current_time() + TTL_SECONDS
                    )

                    user_data["salt"] = salt

                    user_data["last_active"] = current_time()

                print(f"[+] 密文上传成功！账户{current_user}")

                send_response(
                    conn,
                    STATUS_OK,
                    {
                        "message": "put success"
                    }
                )

                
            elif header.msg_type == MSG_TYPE_GET:
                
                if not authenticated:

                    send_response(
                        conn,
                        STATUS_UNAUTHORIZED,
                        {
                            "error": "not login yet"
                        }
                    )

                    continue


                with db_lock:

                    user_data = user_database.get(current_user)

                    if user_data is not None:

                        user_data["last_active"] = current_time()

                    if user_data is None or not user_data["ciphertext"]:

                        send_response(
                            conn,
                            STATUS_NOT_FOUND,
                            {
                                "error": "no ciphertext yet (may be empty or expired)"
                            }
                        )

                        continue

                    if user_data["expire_time"] != 0 and current_time() > user_data["expire_time"]:
                        
                        print(f"[TTL] 已删除过期密文！账户：{current_user}")

                        user_data["ciphertext"] = ""
                        user_data["salt"] = ""
                        user_data["expire_time"] = 0

                        send_response(
                            conn,
                            STATUS_NOT_FOUND,
                            {
                                "error": "clipboard expired"
                            }
                        )

                        continue

                    ciphertext = user_data["ciphertext"]
                    salt = user_data["salt"]

                send_response(
                    conn,
                    STATUS_OK,
                    {
                        "ciphertext": ciphertext,
                        "salt": salt
                    }
                )


            elif header.msg_type == MSG_TYPE_PING:
                
                send_response(
                    conn,
                    STATUS_OK,
                    {
                        "message": "ping"
                    }
                )
            elif header.msg_type == MSG_TYPE_EXIT:

                send_response(
                    conn,
                    STATUS_OK,
                    {
                        "message": "goodbye"
                    }
                )

                print(f"[+] 用户退出：{current_user}")

                break
            
            else:
                
                send_response(
                    conn,
                    STATUS_BAD_REQUEST,
                    {
                        "error": "unknown msg_type"
                    }
                )

    except socket.timeout:

        print(f"[!] 连接超时（无响应或响应过慢），断开：{addr}")

    except ValueError as e:

        print(f"[!] 协议错误！原因：{e}")

        send_response(
            conn,
            STATUS_TOO_LARGE,
            {
                "error": str(e)
            }
        )

    except Exception:

        print("[!] 服务器内部出错！")
        traceback.print_exc()

        try:
            send_response(
                conn,
                STATUS_INTERNAL_ERROR,
                {
                    "error":"internal server error"
                }

            )

        except:
            pass

    
    finally:

        conn.close()

        release_connection(ip)

        print(f"[x] 连接断开：{addr}")


def start_server():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((HOST, PORT))

    server.listen()

    cleaner = threading.Thread(
        target = cleanup_loop,
        daemon = True
    )

    cleaner.start()

    print("==================================")
    print(f"服务器正在监听 {HOST}:{PORT}")
    print(f"流量防护已启用：全局并发 ≤ {MAX_CONNECTIONS_GLOBAL}（单 IP ≤ {MAX_CONNECTIONS_PER_IP}），"
          f"连接 ≤ {CONNECT_RATE_LIMIT} 次/{CONNECT_RATE_WINDOW}s，"
          f"登录失败 {MAX_LOGIN_FAILS} 次封禁 {BAN_SECONDS}s")
    print(f"后台清理线程已启动（间隔 {CLEANUP_INTERVAL}s，闲置账户保留 {ACCOUNT_IDLE_SECONDS}s）")
    print("==================================")

    while True:

        conn, addr = server.accept()

        ip = addr[0]

        if is_banned(ip):

            print(f"[GUARD] 拒绝被封禁的 IP：{addr}")

            conn.close()

            continue

        allowed, reason = try_accept_connection(ip)

        if not allowed:

            print(f"[GUARD] 拒绝连接（{reason}）：{addr}")

            conn.close()

            continue

        thread = threading.Thread( # 创建新线程处理客户端连接
            target = handle_client,
            args = (conn, addr),
            daemon = True
        )

        thread.start()



if __name__ == "__main__":

    start_server()