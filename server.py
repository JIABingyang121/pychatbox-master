import socket, random, string, sys, time, json, hashlib, hmac, sqlite3
import tkinter as tk
import tkinter.messagebox as errbox
from queue import Queue
from threading import Thread
from Crypto.Cipher import AES
from datetime import datetime

HEIGHT = 900
WIDTH = 900

host = ''
port = 5555
broadcast_port = 37020
HEADER_LENGTH = 90
activeConnections = {}
messageQueue = Queue()


# Initialize the SQLite database and create the authentication table if it doesn't exist
def init_db():
    conn = sqlite3.connect('auth.db')  # Connect to SQLite database (or create it)
    cursor = conn.cursor()

    # Create a table to store user alias, password hash, and salt
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS authinfo (
            alias TEXT PRIMARY KEY,
            passhash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Generate a random salt of specified length (used for password hashing)
def salt(length):
    letters = string.ascii_letters + string.digits
    return (''.join(random.choice(letters) for _ in range(length))).encode("utf-8")

# Create a HMAC digest of the given message using a shared secret key
def makeDigest(msg):
    return hmac.new(b'shared secret key', msg, hashlib.sha3_256).hexdigest()

# Hash a password with a new salt using PBKDF2-HMAC-SHA256
# Returns the hashed password and salt (used for account creation)
def passDigest(password):
    passalt = salt(16)  # Generate a 16-byte random salt
    hashed = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), passalt, 100000
    ).hex()
    return hashed, passalt.decode("utf-8")

# Recompute hash from password and stored salt (used for login verification)
def calculateHash(password, passalt):
    return hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), passalt.encode("utf-8"), 100000
    ).hex()

# Encrypt a plaintext message using AES-CFB mode
def encryptMessage(msg):
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    return obj.encrypt(msg.encode('utf-8'))

# Decrypt an AES-encrypted message
def decryptMessage(msg):
    obj = AES.new(b'This is a key123', AES.MODE_CFB, b'This is an IV456')
    return obj.decrypt(msg).decode('utf-8')

# Securely receive a message from a connection, with integrity verification
def recvMessage(conn):
    try:
        # Receive and decrypt header (contains message length and digest)
        dataHeader = decryptMessage(conn.recv(HEADER_LENGTH))
        if not dataHeader:
            print("Connection closed by the client")
            sys.exit()

        length, hashed = dataHeader.strip().split(':')
        messageLength = int(length)

        # Receive actual encrypted message
        actualMsg = conn.recv(messageLength)

        # Verify message integrity
        actualDigest = makeDigest(actualMsg)
        if actualDigest == hashed:
            return decryptMessage(actualMsg)
        else:
            print("Message integrity compromised!")
    except ConnectionResetError:
        print("Client disconnected!")

# Send a secure message with encrypted header and body
def sendMessage(conn, msgToSend):
    try:
        encryptedStuff = encryptMessage(msgToSend)

        # Encrypt a padded header that includes message length and digest
        msgToSend = encryptMessage(
            (str(len(msgToSend)) + ':' + makeDigest(encryptedStuff)).ljust(HEADER_LENGTH)
        ) + encryptedStuff

        conn.sendall(msgToSend)
    except socket.error as e:
        print(f"Error sending message: {e}")

def udp_broadcast():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    ip = socket.gethostbyname(socket.gethostname())

    message = f"CHAT_SERVER:{ip}:{port}".encode('utf-8')

    while True:
        udp_sock.sendto(message, ('<broadcast>', broadcast_port))
        time.sleep(2)


def createSocket():
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()


def acceptClients():
    activeConnections.clear()
    while True:
        conn, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        Thread(target=clientThread, args=(conn, messageQueue)).start()


def main():
    try:
        init_db()
        createSocket()
        Thread(target=udp_broadcast, daemon=True).start()
        Thread(target=acceptClients, daemon=True).start()
        root = tk.Tk()
        root.title("Server")
        updateGUI(root, "Server", messageQueue)
        root.mainloop()

    except KeyboardInterrupt:
        server_socket.close()
        sys.exit()


class createGUI:
    def __init__(self, master, que, serverAlias):
        self.master = master
        self.que = que
        self.serverAlias = serverAlias

        self.canvas = tk.Canvas(self.master, height=HEIGHT, width=WIDTH)
        self.canvas.pack()

        self.frame = tk.Frame(self.master, bg='#242424')
        self.frame.place(relwidth=1, relheight=1)

        # ----------------------------
        # 聊天信息展示区（Text 组件）
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
        self.text.tag_configure("right", justify="right")
        self.text.tag_configure("left", justify="left")

        self.text.place(relx=0.025, rely=0.025, relwidth=0.950, relheight=0.850)

        self.text.insert("end", "Welcome to the chat application!", "info")
        # ----------------------------
        # 消息输入框（Entry）
        # ----------------------------
        self.entry = tk.Entry(self.frame, font=("TkDefaultFont", 15))
        self.entry.place(relx=0.025, rely=0.9, relwidth=0.825, relheight=0.060)

        self.button = tk.Button(
            self.frame,
            text="send",
            font=("TkDefaultFont", 12),
            command=lambda: self.sendAndPrintMessage(self.entry.get())
        )
        self.button.place(relx=0.875, rely=0.9, relwidth=0.1, relheight=0.060)

    def processIncoming(self):
        while not self.que.empty():
            data = self.que.get()
            if isinstance(data, dict):
                sender = data.get("sender", "Unknown")
                msg = data.get("message", "")
                time_str = data.get("time", "[Unknown Time]")
                self.text.insert('end', f"\n{time_str} {sender}> ", 'sender')
                self.text.insert('end', msg)
                self.text.see('end')
            else:
                self.text.insert('end', f"\n\n{data}\n", 'info')

    def sendAndPrintMessage(self, msgToSend):
        if not msgToSend:
            return

        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        data = {
            "sender": self.serverAlias,
            "message": msgToSend,
            "time": timestamp
        }
        dataString = json.dumps(data)

        for conn in activeConnections:
            sendMessage(conn, dataString)

        self.clearEntry()
        self.text.insert('end', f"\n{timestamp} {self.serverAlias}> ", 'receiver')
        self.text.insert('end', msgToSend)
        self.text.see('end')

        time.sleep(0.2)

    def clearEntry(self):
        self.entry.delete(0, tk.END)


class updateGUI:
    def __init__(self, master, serverAlias, que):
        self.master = master
        self.serverAlias = serverAlias  # 服务器别名（用于界面显示）
        self.que = que

        self.gui = createGUI(master, self.que, self.serverAlias)

        self.checkQueue()

    def checkQueue(self):
        self.gui.processIncoming()

        self.master.after(200, self.checkQueue)


class clientThread:
    def __init__(self, conn, que):
        self.conn = conn
        self.que = que
        self.createChatService(self.conn, self.que)

    def getClientAlias(self, conn):
        # Connect to the SQLite database that stores user credentials
        connectionString = sqlite3.connect('auth.db')
        curs = connectionString.cursor()

        while True:
            try:
                # Step 1: Receive and decode authentication data from client
                data = recvMessage(conn)
                data = json.loads(data)
                print(data)

                # Step 2: Extract keys from received JSON (e.g., {"username": "password", "create": True/False})
                clientAlias, createAccount = data.keys()

                if not data[createAccount]:  # Login attempt
                    # Validate user credentials against the database
                    if self.checkValidClient(clientAlias, data[clientAlias], conn, connectionString, curs):
                        # Store this connection with its authenticated alias
                        activeConnections[conn] = clientAlias
                        print(activeConnections)
                        return  # Exit loop if login is successful

                else:  # Registration attempt
                    # Check if alias already exists in the database
                    query = f"SELECT alias FROM authinfo WHERE alias LIKE '{clientAlias}'"
                    curs.execute(query)
                    result = curs.fetchone()

                    if not result:
                        # If user doesn't exist, create new record with hashed password and salt
                        digest, passSalt = passDigest(data[clientAlias])
                        query = (
                            f"INSERT INTO authinfo (alias, passhash, salt) "
                            f"VALUES ('{clientAlias}', '{digest}', '{passSalt}')"
                        )
                        curs.execute(query)
                        connectionString.commit()
                        sendMessage(conn, "success")  # Notify client of successful registration
                    else:
                        sendMessage(conn, "dupuser")  # Notify client that alias already exists

            except socket.timeout as e:
                print(f"Encountered an error! {e} No worries")
                server_socket.close()
                sys.exit()

    def checkValidClient(self, clientAlias, password, conn, connstr, cs):
        try:
            # Query the database for a user record that matches the provided alias
            query = f"SELECT alias, passhash, salt FROM authinfo WHERE alias LIKE '{clientAlias}'"
            cs.execute(query)
            result = cs.fetchone()  # Fetch the result (if any)

            # Unpack result into variables
            alias, passhash, passalt = result

            if result:
                print(alias)  # Print found alias for debug/logging

                # Recompute password hash using stored salt and submitted password
                givenPassHash = calculateHash(password, passalt)

                # Check if computed hash matches stored hash
                if passhash == givenPassHash:
                    print("User is in the list")
                    sendMessage(conn, "Y")  # Notify client: login successful
                    return True
                else:
                    print("User not in our list")
                    sendMessage(conn, "N")  # Notify client: wrong password
                    return False

        except:
            # Handle unexpected issues (e.g., user not found or unpacking error)
            print("Here! User not in our list")
            sendMessage(conn, "N")  # Notify client: login failed
            return False

    def verifyUsername(self, conn):
        authThread = Thread(target=self.getClientAlias, args=(conn,))
        authThread.start()
        authThread.join()
        self.que.put(f"Connected to {activeConnections[conn]} at {str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}")

    def recvFromClient(self, conn):
        # Continuously receive messages from this client and forward them to others
        while True:
            try:
                raw_msg = recvMessage(self.conn)
                parsed_msg = json.loads(raw_msg)
                for connection in activeConnections.copy():
                    if connection is not self.conn:
                        sendMessage(connection, json.dumps(parsed_msg))
                self.que.put(parsed_msg)
                time.sleep(0.2)

            except socket.error:
                # If the client has disconnected, notify the server GUI and stop the loop
                errbox.showinfo('INFO', f'Client {activeConnections[conn]} has closed the connection')
                return

    def createChatService(self, conn, que):
        self.verifyUsername(conn)
        recvThread = Thread(target=self.recvFromClient, args=(conn,))
        recvThread.start()
        recvThread.join()

        del activeConnections[conn]
        conn.close()


if __name__ == "__main__":
    main()