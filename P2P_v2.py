import socket
import threading
import sqlite3

# 用户信息数据库
conn = sqlite3.connect('users.db')
conn.execute('''CREATE TABLE IF NOT EXISTS users
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL)''')
conn.commit()

# 用户列表
users = {}

# 用户连接列表
connections = {}

# 发送消息
def send_message(conn, addr, message):
    conn.send(message.encode())

# 接收消息
def receive_message(conn, addr):
    while True:
        try:
            data = conn.recv(1024).decode()
            if data:
                message = f"{addr[0]}:{addr[1]} said: {data}"
                print(message)
                for user, user_conn in connections.items():
                    if user_conn != conn:
                        send_message(user_conn, addr, message)
        except:
            break

    # 断开连接
    disconnect_from_peer(conn, addr)

# 发现其他在线用户
def discover_peers():
    while True:
        try:
            user = input("Enter the username of the user you want to connect to (or 'q' to quit): ")
            if user == 'q':
                break
            elif user in users and user not in connections:
                host, port = users[user]
                connect_to_peer(host, port)
            elif user in connections:
                print("You are already connected to that user.")
            else:
                print("User not found.")
        except:
            break

# 与其他用户建立连接
def connect_to_peer(host, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    conn.connect((host, port))
    connections[host] = conn

    # 启动接收线程
    threading.Thread(target=receive_message, args=(conn, (host, port))).start()

    print(f"Connected to {host}:{port}.")

# 断开与其他用户的连接
def disconnect_from_peer(conn, addr):
    conn.close()
    connections.pop(addr[0])
    print(f"Disconnected from {addr[0]}.")

# 用户登录
def login():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    cursor = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    if cursor.fetchone() is None:
        print("Invalid username or password.")
        return False
    else:
        users[username] = get_my_address()
        return True

# 获取本机IP地址和端口号
def get_my_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip = s.getsockname()[0]
    s.close()
    return ip, 9999

# 主函数
def main():
    # 登录
    while not login():
        pass

    # 发现其他在线用户
    threading.Thread(target=discover_peers).start()

    # 创建监听Socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(get_my_address())
    s.listen()

    while True:
        conn, addr = s.accept()
        connections[addr[0]] = conn

        # 启动接收线程
        threading.Thread(target=receive_message, args=(conn, addr)).start()

        print(f"Connected to {addr[0]}:{addr[1]}.")

if __name__ == '__main__':
    main()