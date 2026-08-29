import socket
import hashlib
import base64
import getpass
from cryptography.fernet import Fernet
import os

from protocol import *

SERVER_IP = "39.106.126.188"
SERVER_PORT = 9000


def make_key(password: str, salt: bytes) -> bytes: # 从密码和盐值生成加密密钥，使用PBKDF2算法进行密钥派生

    key = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode(),
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(key)


def encrypt_text(password: str, plain_text: str): # 加密文本，返回盐值和密文
    
    salt = os.urandom(16)

    key = make_key(password, salt)

    cipher = Fernet(key)

    ciphertext = cipher.encrypt(plain_text.encode())

    return salt, ciphertext


def decrypt_text(password: str, salt: bytes, ciphertext: bytes) -> str: # 解密文本，返回明文

    key = make_key(password, salt)

    cipher = Fernet(key)

    plaintext = cipher.decrypt(ciphertext)

    return plaintext.decode()


def connect_server(): # 连接至服务器，返回套接字对象

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.connect((SERVER_IP, SERVER_PORT))

    print(f"[+] 已连接至服务器 {SERVER_IP}:{SERVER_PORT}")

    return sock



def login(sock): # 登录函数，向服务器发送登录请求，返回用户名和密码

    print("\n========== 请登录 ==========")

    username = input("用户名：").strip()

    password = getpass.getpass("密码：")

    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


    packet = make_packet(
        msg_type = MSG_TYPE_LOGIN,
        body = {
            "username": username,
            "password_hash": password_hash,
        }

    )

    sock.sendall(packet)

    header, body = recv_packet(sock)

    if header.status == STATUS_OK:

        print("[+] 登陆成功")

        if body.get("new_account") is False:

            print("[!] 注意：该账号已存在！如非本人注册，请更换用户名或密码！")

        return username, password
    
    else:

        print(f"[!] 登陆失败，原因: {body}")

        return None, None
    

def put_clipboard(sock, password): # 上传剪贴板内容，向服务器发送PUT请求，包含加密后的密文和盐值

    print("\n========== 上传 ==========")

    plain_text = input("输入密文：")

    salt, ciphertext = encrypt_text(password, plain_text)

    salt_b64 = base64.b64encode(salt).decode()

    packet = make_packet(
        msg_type = MSG_TYPE_PUT,
        body = {
            "salt": salt_b64,
            "ciphertext": ciphertext.decode()
        }
    )

    sock.sendall(packet)

    header, body = recv_packet(sock)

    if header.status == STATUS_OK:

        print("[+] 上传成功！")

    else:

        print(f"[!] 上传失败，原因: {body}")


def get_clipboard(sock, password): # 获取剪贴板内容，向服务器发送GET请求，接收加密后的密文和盐值，并尝试解密显示明文
    print("\n========== 获取 ==========")

    packet = make_packet(
        msg_type = MSG_TYPE_GET,
        body = {}
    )

    sock.sendall(packet)

    header, body = recv_packet(sock)

    if header.status != STATUS_OK:
        
        print(f"[!] 获取失败，原因: {body}")

        return
    
    ciphertext_str = body.get("ciphertext")

    if not ciphertext_str:

        print("[!] 密文为空！")

        return
    
    try:

        salt = base64.b64decode(
            body["salt"]
        )

        ciphertext = ciphertext_str.encode()

        plain_text = decrypt_text(
            password,
            salt,
            ciphertext
        )

        print("=====================")
        print("解密内容:", plain_text)
        print("=====================")


    except Exception as e: 

        print("[!] 解密失败！")
        print(f"[!] 原因：{e}")



def ping_server(sock): # 向服务器发送PING请求，测试连接是否正常

    packet = make_packet(
        msg_type=MSG_TYPE_PING,
        body={}
    )

    sock.sendall(packet)

    header, body = recv_packet(sock)

    print(body)


def print_menu(): # 打印操作菜单

    print("\n==============================")
    print("LCECP CLIENT-MENU")
    print("==============================")
    print("可用操作列表（输入对应序号表示进行相关操作）：")
    print("1. PUT clipboard")
    print("2. GET clipboard")
    print("3. PING server")
    print("4. Exit")
    print("==============================")



def main():

    try:
        sock = connect_server()

    except Exception as e:

        print(f"[!] 连接至服务器失败！原因: {e}")

        return

    username, password = login(sock)

    if username is None:

        sock.close()

        return

    while True:

        try:

            print_menu()

            choice = input("Select: ").strip()

            if choice == "1":

                put_clipboard(sock, password)

            elif choice == "2":

                get_clipboard(sock, password)

            elif choice == "3":

                ping_server(sock)

            elif choice == "4":

                packet = make_packet(
                    msg_type = MSG_TYPE_EXIT,
                    body = {}
                )

                sock.sendall(packet)

                header, body = recv_packet(sock)

                print(body.get("message"))

                break
            
            else:

                print("[!] 非法操作！请从1 ~ 4选择其一！")

        except KeyboardInterrupt:

            print("\n[+] Interrupted")

            break

        except Exception as e:

            print(f"[!] Error: {e}")

    sock.close()


if __name__ == "__main__":

    main()