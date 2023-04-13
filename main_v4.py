import sqlite3
import socket
import threading
import tkinter as tk
from kademlia.utils import digest


class Node:
    def __init__(self, node_id, addr):
        self.node_id = digest(node_id.encode())
        self.addr = addr
        self.connections = {}
        self.db = sqlite3.connect(f'{node_id}.db')
        self.db.execute('CREATE TABLE IF NOT EXISTS messages (node_id BLOB, content TEXT)')
        self.db_lock = threading.Lock()   # SQLite连接只能在创建它的线程中使用

    def start(self):
        threading.Thread(target=self.listen).start()

    def listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(self.addr)
            s.listen()
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_connection, args=(conn, addr)).start()

    def handle_connection(self, conn, addr):
        data = conn.recv(1024)
        message = data.decode()
        if message.startswith('connect'):
            _, node_id, ip, port = message.split(' ', 3)
            node_id = digest(node_id.encode())
            self.connections[node_id] = (ip, int(port))
            conn.sendall('connected'.encode())
            self.send_offline_messages(node_id)
        elif message.startswith('send'):
            _, node_id, content = message.split(' ', 2)
            node_id = digest(node_id.encode())
            if node_id in self.connections:
                ip, port = self.connections[node_id]
                with socket.create_connection((ip, port)) as s:
                    s.sendall(content.encode())
                    response = s.recv(1024).decode()
                    conn.sendall(response.encode())
                if response == 'message received':
                    self.db.execute('DELETE FROM messages WHERE node_id=? AND content=?', (node_id, content))
                    self.db.commit()
            else:
                self.db.execute('INSERT INTO messages (node_id, content) VALUES (?, ?)', (node_id, content))
                self.db.commit()
                conn.sendall('node not found'.encode())
        elif message == 'list':
            nodes = [f'{id.hex()} {ip} {port}' for id, (ip, port) in self.connections.items()]
            node_list = '\n'.join(nodes)
            conn.sendall(node_list.encode())
        elif message == 'leave':
            node_id = self.node_id
            self.broadcast(f'node {node_id.hex()} has left'.encode())
            self.disconnect()
            conn.sendall('node left'.encode())

    def broadcast(self, data):
        for id, (ip, port) in self.connections.items():
            with socket.create_connection((ip, port)) as s:
                s.sendall(data)

    def disconnect(self):
        for id, (ip, port) in self.connections.items():
            with socket.create_connection((ip, port)) as s:
                s.sendall(f'disconnect {self.node_id.hex()}'.encode())
        self.connections = {}

    # def send_offline_messages(self, node_id):
    #     cursor = self.db.cursor()
    #     cursor.execute('SELECT content FROM messages WHERE node_id=?', (node_id,))
    #     messages = cursor.fetchall()
    #     for content in messages:
    #         ip, port = self.connections[node_id]
    #         with socket.create_connection((ip, port)) as s:
    #             s.sendall(content[0].encode())
    #             response = s.recv(1024).decode()
    #         if response == 'message received':
    #             self.db.execute('DELETE FROM messages WHERE node_id=? AND content=?', (node_id, content[0]))
    #             self.db.commit()

    def send_offline_messages(self, node_id):
        with self.db_lock:
            cursor = self.db.cursor()
            cursor.execute('SELECT content FROM messages WHERE node_id=?', (node_id,))
            messages = cursor.fetchall()
        for content in messages:
            ip, port = self.connections[node_id]
            with socket.create_connection((ip, port)) as s:
                s.sendall(content[0].encode())
                response = s.recv(1024).decode()
            if response == 'message received':
                with self.db_lock:
                    self.db.execute('DELETE FROM messages WHERE node_id=? AND content=?', (node_id, content[0]))
                    self.db.commit()


def start_node(node_id, addr, known_node=None):
    node = Node(node_id, addr)
    node.start()

    if known_node:
        known_addr = (known_node['host'], known_node['port'])
        with socket.create_connection(known_addr) as s:
            s.sendall(f'connect {node_id} {addr[0]} {addr[1]}'.encode())
            response = s.recv(1024).decode()
            if response != 'connected':
                print(response)

    return node

def create_window(node_id, addr):
    window = tk.Tk()
    window.title(node_id)
    messages = tk.Text(window)
    messages.pack()

    def send_message():
        content = message_input.get()
        with socket.create_connection(addr) as s:
            s.sendall(f'send {node_id} {content}'.encode())
            response = s.recv(1024).decode()
            messages.insert(tk.END, response + '\n')
        message_input.delete(0, tk.END)

    def list_nodes():
        with socket.create_connection(addr) as s:
            s.sendall('list'.encode())
            node_list = s.recv(1024).decode()
            messages.insert(tk.END, node_list + '\n')

    def leave_network():
        with socket.create_connection(addr) as s:
            s.sendall('leave'.encode())
            response = s.recv(1024).decode()
            messages.insert(tk.END, response + '\n')
        window.destroy()

    message_input = tk.Entry(window)
    message_input.pack()

    send_button = tk.Button(window, text='Send', command=send_message)
    send_button.pack()

    list_button = tk.Button(window, text='List Nodes', command=list_nodes)
    list_button.pack()

    leave_button = tk.Button(window, text='Leave Network', command=leave_network)
    leave_button.pack()

    window.protocol("WM_DELETE_WINDOW", leave_network)
    window.mainloop()

def main():
    node1_id, node1_host, node1_port = 'node1', '127.0.0.1', 10001
    node2_id, node2_host, node2_port = 'node2', '127.0.0.1', 10002
    node3_id, node3_host, node3_port = 'node3', '127.0.0.1', 10003

    node1_addr = (node1_host, node1_port)
    node2_addr = (node2_host, node2_port)
    node3_addr = (node3_host, node3_port)

    nodes = {
        node1_id: start_node(node1_id, node1_addr),
        node2_id: start_node(node2_id, node2_addr, known_node={'host': node1_host, 'port': node1_port}),
        node3_id: start_node(node3_id, node3_addr, known_node={'host': node1_host, 'port': node1_port})
    }

    windows = {
        node1_id: create_window(node1_id, node1_addr),
        node2_id: create_window(node2_id, node2_addr),
        node3_id: create_window(node3_id, node3_addr)
    }

if __name__ == '__main__':
    main()
