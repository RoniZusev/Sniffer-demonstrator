import socket
import threading


class Server:

    def __init__(self):
        self.ip = '0.0.0.0'
        self.port = 12345

    def handle_client(self,conn, addr):
        print(f"[NEW CONNECTION] {addr} connected.")

        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"[{addr}] {data.decode()}")
                conn.sendall(f"Server received: {data.decode()}".encode())
            except ConnectionResetError:
                break

        print(f"[DISCONNECTED] {addr} disconnected.")
        conn.close()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.ip, self.port))
        server_socket.listen()
        print(f"[LISTENING] Server is listening on {self.ip}:{self.port}")

        while True:
            conn, addr = server_socket.accept()
            # Start a new thread for each client
            client_thread = threading.Thread(target=self.handle_client(), args=(conn, addr))
            client_thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")  # subtract main thread


if __name__ == "__main__":
    server = Server()
    server.start_server()
