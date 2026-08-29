import socket
import hashlib
import base64
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox

from protocol import (
    make_packet, recv_packet,
    MSG_TYPE_LOGIN, MSG_TYPE_PUT, MSG_TYPE_GET,
    MSG_TYPE_PING, MSG_TYPE_EXIT,
    STATUS_OK,
)
from client import encrypt_text, decrypt_text

COLOR_BG = "#1e1e2e"
COLOR_SURFACE = "#313244"
COLOR_SURFACE2 = "#45475a"
COLOR_PRIMARY = "#89b4fa"
COLOR_PRIMARY_HOVER = "#b4befe"
COLOR_TEXT = "#cdd6f4"
COLOR_TEXT_MUTED = "#a6adc8"
COLOR_SUCCESS = "#a6e3a1"
COLOR_ERROR = "#f38ba8"
COLOR_WARNING = "#f9e2af"

DEFAULT_IP = "127.0.0.1"
DEFAULT_PORT = "9000"


class LCECPClientGUI:

    def __init__(self, root):
        self.root = root
        self.sock = None
        self.username = None
        self.password = None
        self.connected = False
        self.authenticated = False
        self._ui_queue = queue.Queue()

        self._setup_window()
        self._setup_style()
        self._build_connection_frame()
        self._build_main_frame()
        self._show_connection()
        self.root.after(100, self._poll_queue)

    def _poll_queue(self):
        try:
            while True:
                func = self._ui_queue.get_nowait()
                func()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _ui(self, func):
        self._ui_queue.put(func)

    def _setup_window(self):
        self.root.title("LCECP — 轻量级云加密剪贴板")
        self.root.geometry("680x560")
        self.root.minsize(560, 480)
        self.root.configure(bg=COLOR_BG)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TFrame", background=COLOR_BG)
        style.configure("Surface.TFrame", background=COLOR_SURFACE)
        style.configure(
            "TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=("Microsoft YaHei UI", 10),
        )
        style.configure(
            "Surface.TLabel",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT,
            font=("Microsoft YaHei UI", 10),
        )
        style.configure(
            "Title.TLabel",
            background=COLOR_BG,
            foreground=COLOR_PRIMARY,
            font=("Microsoft YaHei UI", 16, "bold"),
        )
        style.configure(
            "Subtitle.TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT_MUTED,
            font=("Microsoft YaHei UI", 10),
        )
        style.configure(
            "Status.TLabel",
            background=COLOR_SURFACE,
            foreground=COLOR_TEXT_MUTED,
            font=("Microsoft YaHei UI", 9),
        )
        style.configure(
            "TEntry",
            fieldbackground=COLOR_SURFACE2,
            foreground=COLOR_TEXT,
            insertcolor=COLOR_TEXT,
            bordercolor=COLOR_SURFACE2,
            lightcolor=COLOR_SURFACE2,
            darkcolor=COLOR_SURFACE2,
            font=("Microsoft YaHei UI", 10),
        )
        style.configure(
            "TButton",
            background=COLOR_SURFACE2,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_SURFACE2,
            lightcolor=COLOR_SURFACE2,
            darkcolor=COLOR_SURFACE2,
            font=("Microsoft YaHei UI", 10),
            padding=(12, 6),
        )
        style.map(
            "TButton",
            background=[("active", COLOR_PRIMARY_HOVER), ("disabled", COLOR_SURFACE)],
            foreground=[("active", COLOR_BG), ("disabled", COLOR_TEXT_MUTED)],
        )
        style.configure(
            "Primary.TButton",
            background=COLOR_PRIMARY,
            foreground=COLOR_BG,
            bordercolor=COLOR_PRIMARY,
            lightcolor=COLOR_PRIMARY,
            darkcolor=COLOR_PRIMARY,
            font=("Microsoft YaHei UI", 10, "bold"),
            padding=(16, 8),
        )
        style.map(
            "Primary.TButton",
            background=[("active", COLOR_PRIMARY_HOVER), ("disabled", COLOR_SURFACE)],
            foreground=[("disabled", COLOR_TEXT_MUTED)],
        )
        style.configure(
            "Danger.TButton",
            background=COLOR_ERROR,
            foreground=COLOR_BG,
            bordercolor=COLOR_ERROR,
            lightcolor=COLOR_ERROR,
            darkcolor=COLOR_ERROR,
            font=("Microsoft YaHei UI", 10),
            padding=(12, 6),
        )
        style.map(
            "Danger.TButton",
            background=[("active", "#eba0ac"), ("disabled", COLOR_SURFACE)],
            foreground=[("disabled", COLOR_TEXT_MUTED)],
        )

    def _build_connection_frame(self):
        self.conn_frame = ttk.Frame(self.root, style="TFrame")
        self.conn_frame.pack(fill="both", expand=True)

        container = ttk.Frame(self.conn_frame, style="TFrame")
        container.place(relx=0.5, rely=0.45, anchor="center")

        title = ttk.Label(container, text="LCECP", style="Title.TLabel")
        title.grid(row=0, column=0, columnspan=2, pady=(0, 4))

        subtitle = ttk.Label(
            container,
            text="轻量级云加密剪贴板协议",
            style="Subtitle.TLabel",
        )
        subtitle.grid(row=1, column=0, columnspan=2, pady=(0, 28))

        ttk.Label(container, text="服务器地址").grid(
            row=2, column=0, sticky="w", pady=(0, 12),
        )
        self.ip_entry = ttk.Entry(container, width=34)
        self.ip_entry.insert(0, DEFAULT_IP)
        self.ip_entry.grid(row=2, column=1, pady=(0, 12), padx=(12, 0))

        ttk.Label(container, text="端口").grid(
            row=3, column=0, sticky="w", pady=(0, 12),
        )
        self.port_entry = ttk.Entry(container, width=34)
        self.port_entry.insert(0, DEFAULT_PORT)
        self.port_entry.grid(row=3, column=1, pady=(0, 12), padx=(12, 0))

        ttk.Label(container, text="用户名").grid(
            row=4, column=0, sticky="w", pady=(0, 12),
        )
        self.user_entry = ttk.Entry(container, width=34)
        self.user_entry.grid(row=4, column=1, pady=(0, 12), padx=(12, 0))

        ttk.Label(container, text="密码").grid(
            row=5, column=0, sticky="w", pady=(0, 20),
        )
        self.pwd_entry = ttk.Entry(container, width=34, show="*")
        self.pwd_entry.grid(row=5, column=1, pady=(0, 20), padx=(12, 0))

        self.connect_btn = ttk.Button(
            container,
            text="连接并登录",
            style="Primary.TButton",
            command=self._on_connect,
        )
        self.connect_btn.grid(row=6, column=0, columnspan=2, pady=(4, 0))

        self.conn_status = ttk.Label(
            container,
            text="请输入服务器信息后连接",
            style="Subtitle.TLabel",
        )
        self.conn_status.grid(row=7, column=0, columnspan=2, pady=(12, 0))

        self.root.bind("<Return>", lambda e: self._on_connect())

    def _build_main_frame(self):
        self.main_frame = ttk.Frame(self.root, style="TFrame")

        top_bar = ttk.Frame(self.main_frame, style="Surface.TFrame")
        top_bar.pack(fill="x", padx=12, pady=(12, 8))

        self.user_label = ttk.Label(
            top_bar,
            text="未登录",
            style="Surface.TLabel",
        )
        self.user_label.pack(side="left", padx=12, pady=8)

        self.ping_btn = ttk.Button(
            top_bar,
            text="PING",
            command=self._on_ping,
        )
        self.ping_btn.pack(side="right", padx=(4, 12), pady=6)

        self.disconnect_btn = ttk.Button(
            top_bar,
            text="断开连接",
            style="Danger.TButton",
            command=self._on_disconnect,
        )
        self.disconnect_btn.pack(side="right", padx=4, pady=6)

        body = ttk.Frame(self.main_frame, style="TFrame")
        body.pack(fill="both", expand=True, padx=12, pady=4)

        put_label = ttk.Label(body, text="上传内容（PUT）")
        put_label.grid(row=0, column=0, sticky="w", pady=(0, 4))

        paste_btn = ttk.Button(
            body,
            text="从系统剪贴板粘贴",
            command=self._paste_from_clipboard,
        )
        paste_btn.grid(row=0, column=1, sticky="e", pady=(0, 4))

        self.input_text = tk.Text(
            body,
            height=6,
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            selectbackground=COLOR_PRIMARY,
            selectforeground=COLOR_BG,
            relief="flat",
            font=("Consolas", 10),
            wrap="word",
            bd=0,
            highlightthickness=1,
            highlightbackground=COLOR_SURFACE2,
            highlightcolor=COLOR_PRIMARY,
            padx=8,
            pady=8,
        )
        self.input_text.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 8))

        self.put_btn = ttk.Button(
            body,
            text="加密上传",
            style="Primary.TButton",
            command=self._on_put,
        )
        self.put_btn.grid(row=2, column=0, columnspan=2, pady=(0, 16))

        sep = ttk.Separator(body, orient="horizontal")
        sep.grid(row=3, column=0, columnspan=2, sticky="ew", pady=4)

        get_label = ttk.Label(body, text="获取内容（GET）")
        get_label.grid(row=4, column=0, sticky="w", pady=(8, 4))

        copy_btn = ttk.Button(
            body,
            text="复制到系统剪贴板",
            command=self._copy_to_clipboard,
        )
        copy_btn.grid(row=4, column=1, sticky="e", pady=(8, 4))

        self.output_text = tk.Text(
            body,
            height=6,
            bg=COLOR_SURFACE,
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            selectbackground=COLOR_PRIMARY,
            selectforeground=COLOR_BG,
            relief="flat",
            font=("Consolas", 10),
            wrap="word",
            bd=0,
            highlightthickness=1,
            highlightbackground=COLOR_SURFACE2,
            highlightcolor=COLOR_PRIMARY,
            padx=8,
            pady=8,
        )
        self.output_text.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=(0, 8))

        self.get_btn = ttk.Button(
            body,
            text="获取并解密",
            style="Primary.TButton",
            command=self._on_get,
        )
        self.get_btn.grid(row=6, column=0, columnspan=2, pady=(0, 8))

        clear_btn = ttk.Button(
            body,
            text="清空输入/输出",
            command=self._on_clear,
        )
        clear_btn.grid(row=7, column=0, columnspan=2)

        body.grid_rowconfigure(1, weight=1)
        body.grid_rowconfigure(5, weight=1)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)

        status_bar = ttk.Frame(self.main_frame, style="Surface.TFrame")
        status_bar.pack(fill="x", side="bottom", padx=12, pady=(4, 12))

        self.status_label = ttk.Label(
            status_bar,
            text="就绪",
            style="Status.TLabel",
        )
        self.status_label.pack(side="left", padx=12, pady=6)

    def _show_connection(self):
        self.main_frame.pack_forget()
        self.conn_frame.pack(fill="both", expand=True)

    def _show_main(self):
        self.conn_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)

    def _set_status(self, text, level="info"):
        colors = {
            "info": COLOR_TEXT_MUTED,
            "success": COLOR_SUCCESS,
            "error": COLOR_ERROR,
            "warning": COLOR_WARNING,
        }
        self.status_label.configure(text=text, foreground=colors.get(level, COLOR_TEXT_MUTED))

    def _set_conn_status(self, text, level="info"):
        colors = {
            "info": COLOR_TEXT_MUTED,
            "success": COLOR_SUCCESS,
            "error": COLOR_ERROR,
            "warning": COLOR_WARNING,
        }
        self.conn_status.configure(text=text, foreground=colors.get(level, COLOR_TEXT_MUTED))

    def _set_main_busy(self, busy):
        state = "disabled" if busy else "normal"
        if hasattr(self, "put_btn"):
            self.put_btn.configure(state=state)
            self.get_btn.configure(state=state)
            self.ping_btn.configure(state=state)
            self.disconnect_btn.configure(state=state)

    def _run_in_thread(self, task):
        def worker():
            try:
                task()
            except Exception as e:
                err_str = str(e)
                def on_error():
                    if self.authenticated:
                        self._set_main_busy(False)
                    else:
                        self.connect_btn.configure(state="normal")
                    self._set_status(f"错误: {err_str}", "error")
                self._ui(on_error)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _on_connect(self):
        ip = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()
        username = self.user_entry.get().strip()
        password = self.pwd_entry.get()

        if not ip or not port_str or not username or not password:
            self._set_conn_status("请填写所有字段", "warning")
            return

        try:
            port = int(port_str)
        except ValueError:
            self._set_conn_status("端口号必须为整数", "error")
            return

        self.connect_btn.configure(state="disabled")
        self._set_conn_status("正在连接...", "info")

        def task():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((ip, port))
                sock.settimeout(None)
                self.sock = sock

                self._ui(lambda: self._set_conn_status("已连接，正在登录...", "info"))

                password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
                packet = make_packet(
                    msg_type=MSG_TYPE_LOGIN,
                    body={
                        "username": username,
                        "password_hash": password_hash,
                    },
                )
                sock.sendall(packet)

                header, body = recv_packet(sock)
                if header is None:
                    self._ui(lambda: self._on_connect_fail("服务器断开连接"))
                    return

                if header.status == STATUS_OK:
                    self.username = username
                    self.password = password
                    self.connected = True
                    self.authenticated = True
                    new_account = bool(body.get("new_account", True))
                    self._ui(lambda: self._on_connect_success(new_account))
                else:
                    err = body.get("error", "登录失败") if body else "登录失败"
                    self.sock.close()
                    self.sock = None
                    self._ui(lambda: self._on_connect_fail(err))

            except Exception as e:
                err_str = str(e)
                self._ui(lambda: self._on_connect_fail(err_str))

        self._run_in_thread(task)

    def _on_connect_success(self, new_account):
        self.user_label.configure(text=f"用户: {self.username}")
        self._show_main()
        if new_account:
            self._set_status("登录成功（新账户已创建）", "success")
        else:
            self._set_status("登录成功（已存在账户）", "warning")
            messagebox.showwarning(
                "该账号已存在",
                "该账号此前已被注册。\n\n"
                "如果这不是您本人创建的账户，说明有他人使用相同的用户名和密码，"
                "对方可以读取您上传的全部内容。\n\n"
                "建议立即断开连接，更换用户名和密码后重新登录。",
            )

    def _on_connect_fail(self, reason):
        self.connect_btn.configure(state="normal")
        self._set_conn_status(f"失败: {reason}", "error")

    def _on_put(self):
        if not self.authenticated or self.sock is None:
            self._set_status("未连接", "error")
            return

        plain_text = self.input_text.get("1.0", "end").strip()
        if not plain_text:
            self._set_status("请输入要上传的内容", "warning")
            return

        self._set_main_busy(True)
        self._set_status("正在加密上传...", "info")

        def task():
            try:
                salt, ciphertext = encrypt_text(self.password, plain_text)
                salt_b64 = base64.b64encode(salt).decode()

                packet = make_packet(
                    msg_type=MSG_TYPE_PUT,
                    body={
                        "salt": salt_b64,
                        "ciphertext": ciphertext.decode(),
                    },
                )
                self.sock.sendall(packet)

                header, body = recv_packet(self.sock)
                if header is None:
                    self._ui(lambda: self._on_net_error("服务器断开连接"))
                    return

                if header.status == STATUS_OK:
                    self._ui(self._on_put_success)
                else:
                    err = body.get("error", "上传失败") if body else "上传失败"
                    self._ui(lambda: self._on_put_fail(err))
            except Exception as e:
                err_str = str(e)
                self._ui(lambda: self._on_net_error(err_str))

        self._run_in_thread(task)

    def _on_put_success(self):
        self._set_main_busy(False)
        self._set_status("上传成功，内容已加密存储", "success")

    def _on_put_fail(self, reason):
        self._set_main_busy(False)
        self._set_status(f"上传失败: {reason}", "error")

    def _on_get(self):
        if not self.authenticated or self.sock is None:
            self._set_status("未连接", "error")
            return

        self._set_main_busy(True)
        self._set_status("正在获取并解密...", "info")
        self.output_text.delete("1.0", "end")

        def task():
            try:
                packet = make_packet(msg_type=MSG_TYPE_GET, body={})
                self.sock.sendall(packet)

                header, body = recv_packet(self.sock)
                if header is None:
                    self._ui(lambda: self._on_net_error("服务器断开连接"))
                    return

                if header.status != STATUS_OK:
                    err = body.get("error", "获取失败") if body else "获取失败"
                    self._ui(lambda: self._on_get_fail(err))
                    return

                ciphertext = body.get("ciphertext")
                if not ciphertext:
                    self._ui(lambda: self._on_get_fail("密文为空"))
                    return

                try:
                    salt = base64.b64decode(body["salt"])
                    ct = body["ciphertext"].encode()
                    plain_text = decrypt_text(self.password, salt, ct)
                    self._ui(lambda pt=plain_text: self._on_get_success(pt))
                except Exception as e:
                    err_str = str(e)
                    self._ui(lambda: self._on_get_fail(f"解密失败: {err_str}"))
            except Exception as e:
                err_str = str(e)
                self._ui(lambda: self._on_net_error(err_str))

        self._run_in_thread(task)

    def _on_get_success(self, plain_text):
        self._set_main_busy(False)
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", plain_text)
        self._set_status("获取并解密成功", "success")

    def _on_get_fail(self, reason):
        self._set_main_busy(False)
        self._set_status(reason, "error")

    def _on_ping(self):
        if not self.authenticated or self.sock is None:
            self._set_status("未连接", "error")
            return

        self._set_main_busy(True)
        self._set_status("正在 PING...", "info")

        def task():
            try:
                packet = make_packet(msg_type=MSG_TYPE_PING, body={})
                self.sock.sendall(packet)

                header, body = recv_packet(self.sock)
                if header is None:
                    self._ui(lambda: self._on_net_error("服务器断开连接"))
                    return

                if header.status == STATUS_OK:
                    self._ui(self._on_ping_success)
                else:
                    self._ui(self._on_ping_fail)
            except Exception as e:
                err_str = str(e)
                self._ui(lambda: self._on_net_error(err_str))

        self._run_in_thread(task)

    def _on_ping_success(self):
        self._set_main_busy(False)
        self._set_status("PING 成功，连接正常", "success")

    def _on_ping_fail(self):
        self._set_main_busy(False)
        self._set_status("PING 失败", "error")

    def _on_disconnect(self):
        if self.sock is not None:
            try:
                packet = make_packet(msg_type=MSG_TYPE_EXIT, body={})
                self.sock.sendall(packet)
                recv_packet(self.sock)
            except Exception:
                pass
            finally:
                self.sock.close()
                self.sock = None

        self.connected = False
        self.authenticated = False
        self.username = None
        self.password = None
        self.input_text.delete("1.0", "end")
        self.output_text.delete("1.0", "end")
        self._show_connection()
        self.connect_btn.configure(state="normal")
        self._set_conn_status("已断开连接", "info")

    def _on_clear(self):
        self.input_text.delete("1.0", "end")
        self.output_text.delete("1.0", "end")

    def _paste_from_clipboard(self):
        try:
            clip = self.root.clipboard_get()
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", clip)
            self._set_status("已从系统剪贴板粘贴", "info")
        except tk.TclError:
            self._set_status("系统剪贴板为空", "warning")

    def _copy_to_clipboard(self):
        text = self.output_text.get("1.0", "end").strip()
        if not text:
            self._set_status("没有可复制的内容", "warning")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._set_status("已复制到系统剪贴板", "success")

    def _on_net_error(self, reason):
        self._set_main_busy(False)
        self._set_status(f"网络错误: {reason}", "error")
        messagebox.showwarning("连接断开", reason)
        self._on_disconnect()

    def _on_close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = LCECPClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
