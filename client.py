import socket, random, string, sys, time, json, hashlib, hmac
import tkinter as tk
import tkinter.messagebox as errbox
from threading import Thread
from queue import Queue
from Crypto.Cipher import AES
from datetime import datetime
from PIL import Image, ImageTk  # 确保安装了 Pillow
import tkinter as tk
import socket, json, tkinter.messagebox as errbox

HEIGHT = 900
WIDTH = 900

HEADER_LENGTH = 90
broadcast_port = 37020

def encryptMessage(msg):
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    return obj.encrypt(msg.encode('utf-8'))


def decryptMessage(msg):
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    return obj.decrypt(msg).decode('utf-8')


def makeDigest(msg):

    return hmac.new(b'shared secret key', msg, hashlib.sha3_256).hexdigest()


def recvMessage(conn):
    try:
        dataHeader = decryptMessage(conn.recv(HEADER_LENGTH))
        if not dataHeader:
            sys.exit()  # 如果收到空数据，认为连接中断

        # 从解密后的 header 中解析消息长度和接收的 HMAC 摘要
        length, hashed = dataHeader.strip().split(':')
        messageLength = int(length)

        # 读取加密的消息主体
        msg = conn.recv(messageLength)

        # 重新计算摘要，与接收到的摘要比对，确保消息未被篡改
        if makeDigest(msg) == hashed:
            return decryptMessage(msg)  # 校验通过则解密后返回
        else:
            print("Message integrity compromised!")
    except ConnectionResetError:
        conn.close()


def sendMessage(conn, msgToSend):
    encrypted = encryptMessage(msgToSend)

    header = encryptMessage((str(len(msgToSend)) + ':' + makeDigest(encrypted)).ljust(HEADER_LENGTH))
    conn.sendall(header + encrypted)


def discover_server(timeout=5):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_sock.bind(('', broadcast_port))
    udp_sock.settimeout(timeout)

    try:
        while True:
            data, addr = udp_sock.recvfrom(1024)
            message = data.decode()
            if message.startswith("CHAT_SERVER"):
                _, ip, port = message.split(':')
                return ip, int(port)  # 成功解析出服务器地址和端口
    except socket.timeout:
        print("Server discovery timed out.")
        return None, None


# --- GUI界面 ---

class connectPage:
    def __init__(self, master):
        self.master = master

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        bg_raw = Image.open("./images/se.png").resize((WIDTH, HEIGHT))
        self.bg_img = ImageTk.PhotoImage(bg_raw)
        self.canvas.create_image(0, 0, anchor='nw', image=self.bg_img)
        self.canvas.image = self.bg_img

        # Welcome 标题
        
        self.canvas.create_text(WIDTH//2, 90,text="Welcome",fill="black",font=("Calibri", 44, "bold"))

        

        # 用户名
        self.canvas.create_text(WIDTH//2-160, 220,text="USERNAME",fill="black",font=("Calibri", 30, "bold"))
        
        self.usernameEntry = tk.Entry(master, font=("Calibri", 30))
        self.canvas.create_window(WIDTH//2 + 110, 220, width=260, window=self.usernameEntry)

        # 密码
        self.canvas.create_text(WIDTH//2-160, 340,text="PASSWORD",fill="black",font=("Calibri", 30, "bold"))

        self.passEntry = tk.Entry(master, font=("Calibri", 30), show='•')
        self.canvas.create_window(WIDTH//2 + 110, 340, width=260, window=self.passEntry)

        # 登录按钮
        self.button = tk.Button(master, text="Connect", font=("Calibri", 30),
                                command=lambda: self.onClick(self.master, self.usernameEntry.get(), self.passEntry.get()))
        self.canvas.create_window(WIDTH//2 - 120, 500, window=self.button)

        # 注册按钮
        self.button2 = tk.Button(master, text="Register", font=("Calibri", 30), command=self.gotoAccountPage)
        self.canvas.create_window(WIDTH//2 + 120, 500, window=self.button2)

    def onClick(self, m, username, password):
        if len(username) and len(password):
            controller(m, username, password)
            self.canvas.destroy()
        else:
            errbox.showerror('Error', 'Entries cannot be empty.')

    def gotoAccountPage(self):
        server_ip, server_port = discover_server()
        if server_ip is None:
            errbox.showerror('Error', 'Could not find server, please check your LAN.')
            return

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))

        self.canvas.destroy()
        createAccount(self.master, client_socket)


class createAccount:
    def __init__(self, master, conn):
        self.master = master
        self.conn = conn

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()
        bg_raw = Image.open("./images/se.png").resize((WIDTH, HEIGHT))
        self.bg_img = ImageTk.PhotoImage(bg_raw)
        self.canvas.create_image(0, 0, anchor='nw', image=self.bg_img)
        self.canvas.image = self.bg_img

        # Register 标题
        self.title = tk.Label(master, text="Register", font=("Calibri", 42, "bold"), bg='white')
        self.canvas.create_window(WIDTH//2, 90, window=self.title)

        # 用户名
        self.userLabel = tk.Label(master, text="USERNAME:", font=('Calibri', 20), bg='white')
        self.canvas.create_window(WIDTH//2 - 110, 180, window=self.userLabel)

        self.usernameEntry = tk.Entry(master, font=("Calibri", 16))
        self.canvas.create_window(WIDTH//2 + 70, 180, width=260, window=self.usernameEntry)

        # 密码
        self.passLabel = tk.Label(master, text="PASSWORD:", font=('Calibri', 20), bg='white')
        self.canvas.create_window(WIDTH//2 - 110, 240, window=self.passLabel)

        self.passEntry = tk.Entry(master, font=("Calibri", 16), show='•')
        self.canvas.create_window(WIDTH//2 + 70, 240, width=260, window=self.passEntry)

        # 注册按钮
        self.button = tk.Button(master, text="Create", font=("Calibri", 14), command=self.onClick)
        self.canvas.create_window(WIDTH//2 - 80, 320, window=self.button)

        # 返回按钮
        self.backButton = tk.Button(master, text="Back", font=("Calibri", 14), command=self.backToLogin)
        self.canvas.create_window(WIDTH//2 + 80, 320, window=self.backButton)

    def backToLogin(self):
        self.canvas.destroy()
        connectPage(self.master)

    def onClick(self):
        username = self.usernameEntry.get()
        password = self.passEntry.get()
        if len(username) and len(password):
            data = {username: password, 'create': True}
            data = json.dumps(data)
            sendMessage(self.conn, data)
            serverResponse = recvMessage(self.conn)
            if serverResponse == "success":
                errbox.showinfo('Info', 'Account created successfully!')
                self.canvas.destroy()
                connectPage(self.master)
            elif serverResponse == "dupuser":
                errbox.showerror('Error', 'User already exists.')
                self.usernameEntry.delete(0, tk.END)
                self.passEntry.delete(0, tk.END)
        else:
            errbox.showerror('Error', 'Entries cannot be empty.')


class chatPage:
    def __init__(self, master, que, conn, clientAlias):
        self.master = master
        self.que = que
        self.conn = conn
        self.clientAlias = clientAlias

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        self.frame = tk.Frame(self.master, bg='#242424')
        self.frame.place(relwidth=1, relheight=1)

        # ----------------------------
        # 消息显示区域（Text 组件）
        # ----------------------------
        self.text = tk.Text(
            self.frame,
            bg='#141414',
            fg="#fffdfb",
            font=("TkDefaultFont", 15),
            wrap=tk.WORD
        )
        self.text.tag_configure("sender", foreground="#04ffd9")
        self.text.tag_configure("receiver", foreground="#ff8b16")
        self.text.tag_configure("info", foreground="#03ff07")

        self.text.place(relx=0.025, rely=0.025, relwidth=0.95, relheight=0.85)

        self.text.insert('end', f"Connected at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", 'info')


        # ----------------------------
        # 用户输入框（Entry）
        # ----------------------------
        self.entry = tk.Entry(self.frame, font=("TkDefaultFont", 15))
        self.entry.place(relx=0.025, rely=0.9, relwidth=0.825, relheight=0.06)

        self.button = tk.Button(
            self.frame, text="Send", font=("TkDefaultFont", 12),
            command=self.sendAndPrintMessage
        )
        self.button.place(relx=0.875, rely=0.9, relwidth=0.1, relheight=0.06)

    def processIncoming(self):
        while not self.que.empty():
            data = self.que.get()
            sender = data.get("sender", "Unknown")
            msg = data.get("message", "")
            time_str = data.get("time", "[Unknown Time]")

            self.text.insert('end', f"\n{time_str} {sender}> ", 'sender')
            self.text.insert('end', msg)
            self.text.see('end')

    def sendAndPrintMessage(self):
        msgToSend = self.entry.get()
        if msgToSend:
            data = {
                "sender": self.clientAlias,
                "message": msgToSend,
                "time": datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            }
            sendMessage(self.conn, json.dumps(data))
            self.entry.delete(0, tk.END)

            self.text.insert('end', f"\n{data['time']} {self.clientAlias}> ", 'receiver')
            self.text.insert('end', msgToSend)
            self.text.see('end')


class controller:
    def __init__(self, master, username, password):
        self.master = master
        self.username = username
        self.password = password

        # -----------------------------
        # 自动发现服务器地址与端口
        # -----------------------------
        server_ip, server_port = discover_server()
        if server_ip is None:
            errbox.showerror('Error', 'Could not find server.')
            return

        # -----------------------------
        # 与服务器建立 TCP 连接
        # -----------------------------
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((server_ip, server_port))

        # -----------------------------
        # 构造登录请求并发送
        # -----------------------------
        data = {
            self.username: self.password,
            "create": False
        }
        data = json.dumps(data)
        sendMessage(self.conn, data)
        # -----------------------------
        # 等待服务器返回认证结果
        # -----------------------------
        serverResponse = recvMessage(self.conn)

        if serverResponse == "Y":

            threadedRecv(self.master, self.conn, self.username)
        else:

            errbox.showerror('Error', 'Login failed.')
            self.conn.close()
            connectPage(self.master)


class threadedRecv:
    def __init__(self, master, conn, clientAlias):
        self.master = master
        self.que = Queue()
        self.conn = conn

        self.gui = chatPage(master, self.que, conn, clientAlias)

        self.thread = Thread(target=self.recvAndQueueMessages, daemon=True)
        self.thread.start()

        self.checkQueue()

    def checkQueue(self):
        self.gui.processIncoming()

        self.master.after(200, self.checkQueue)

    def recvAndQueueMessages(self):
        while True:
            try:
                messageRcvd = recvMessage(self.conn)

                messageRcvd = json.loads(messageRcvd)

                self.que.put(messageRcvd)

                time.sleep(0.2)

            except ConnectionResetError:
                errbox.showinfo('INFO', 'Server closed the connection.')
                return

def main():
    root = tk.Tk()
    root.title("Secure Chat Client")
    connectPage(root)
    root.mainloop()

if __name__ == '__main__':
    main()