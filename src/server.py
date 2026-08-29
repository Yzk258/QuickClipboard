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

user_database = {}

db_lock = threading.Lock()

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

        except Exception:

            print("[!] 清理线程出错！")
            traceback.print_exc()


def handle_client(conn, addr): # 处理客户端连接的函数，接收请求并根据消息类型进行处理，发送响应

    print(f"[+] 新用户连接：{addr}")

    authenticated = False
    current_user = None

    try:

        while True:

            header, body = recv_packet(conn)

            if header is None:
                print(f"[-] 账户断开连接！{addr}")
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

                        send_response(
                            conn,
                            STATUS_UNAUTHORIZED,
                            {
                                "error": "wrong password"
                            }
                        )

                        continue

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
    print(f"后台清理线程已启动（间隔 {CLEANUP_INTERVAL}s，闲置账户保留 {ACCOUNT_IDLE_SECONDS}s）")
    print("==================================")

    while True:

        conn, addr = server.accept()

        thread = threading.Thread( # 创建新线程处理客户端连接
            target = handle_client,
            args = (conn, addr),
            daemon = True
        )

        thread.start()



if __name__ == "__main__":

    start_server()