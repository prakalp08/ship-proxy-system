"""
Ship Proxy (client-side)
Listens on local port (default 8080). Forwards requests sequentially over
a single persistent TCP connection to the offshore proxy.
Supports CONNECT tunneling (HTTPS) by allocating exclusive access to the
offshore link during the tunnel.
"""

import socket
import threading
import argparse
import struct
import time
import uuid
import sys

MSG_REQUEST = 0
MSG_RESPONSE = 1
MSG_TUNNEL = 2
MSG_TUNNEL_BACK = 3
MSG_TUNNEL_CLOSE = 4

def recvall(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def send_frame(sock, msg_type, client_id, payload=b''):
    cid = client_id.encode('utf-8')
    header_rest = struct.pack('!B I', msg_type, len(cid))
    body = cid + payload
    frame_len = len(header_rest) + len(body)
    sock.sendall(struct.pack('!I', frame_len) + header_rest + body)

def recv_frame(sock):
    raw = recvall(sock, 4)
    if not raw:
        return None
    (frame_len,) = struct.unpack('!I', raw)
    rest = recvall(sock, frame_len)
    if rest is None:
        return None
    msg_type = rest[0]
    client_id_len = struct.unpack('!I', rest[1:5])[0]
    client_id = rest[5:5+client_id_len].decode('utf-8')
    payload = rest[5+client_id_len:]
    return (msg_type, client_id, payload)

class ShipProxy:
    def __init__(self, offshore_host, offshore_port, listen_port=8080, reconnect_delay=3):
        self.offshore_host = offshore_host
        self.offshore_port = offshore_port
        self.listen_port = listen_port
        self.reconnect_delay = reconnect_delay

        self.offshore_sock = None
        self.offshore_lock = threading.Lock()  # ensures sequential use of offshore link
        self.keep_running = True

    def connect_offshore(self):
        while self.keep_running:
            try:
                print(f"[ship] Connecting to offshore {self.offshore_host}:{self.offshore_port}...")
                s = socket.create_connection((self.offshore_host, self.offshore_port))
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.offshore_sock = s
                print("[ship] Connected to offshore.")
                return
            except Exception as e:
                print(f"[ship] Offshore connect failed: {e}. Retrying in {self.reconnect_delay}s")
                time.sleep(self.reconnect_delay)

    def start(self):
        # Ensure offshore connected before accepting local clients
        self.connect_offshore()

        t = threading.Thread(target=self._listen_local, daemon=True)
        t.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Shutting down ship proxy...")
            self.keep_running = False
            try:
                if self.offshore_sock:
                    self.offshore_sock.close()
            except:
                pass
            sys.exit(0)

    def _listen_local(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.listen_port))
        srv.listen(200)
        print(f"[ship] Listening on 0.0.0.0:{self.listen_port}")
        while True:
            client_sock, addr = srv.accept()
            print(f"[ship] Accepted {addr}")
            threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True).start()

    def _handle_client(self, client_sock):
        try:
            client_sock.settimeout(5.0)
            data = b''
            while True:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
            if not data:
                client_sock.close()
                return
            first_line = data.split(b'\r\n',1)[0].decode('utf-8', errors='ignore')
            method = first_line.split()[0] if first_line else ''
            client_id = str(uuid.uuid4())
            if method.upper() == 'CONNECT':
                print(f"[ship] CONNECT from client -> establishing tunnel (client_id={client_id})")
                with self.offshore_lock:
                    send_frame(self.offshore_sock, MSG_REQUEST, client_id, data)
                    frame = recv_frame(self.offshore_sock)
                    if frame is None:
                        print("[ship] offshore disconnected while waiting for CONNECT response")
                        client_sock.close()
                        self.connect_offshore()
                        return
                    msg_type, cid, payload = frame
                    if cid != client_id or msg_type not in (MSG_RESPONSE,):
                        print("[ship] unexpected frame on CONNECT response")
                        client_sock.close()
                        return
                    client_sock.sendall(payload)
                    if payload.startswith(b"HTTP/1.1 200") or payload.startswith(b"HTTP/1.0 200"):
                        stop_event = threading.Event()
                        def client_to_offshore():
                            try:
                                client_sock.settimeout(None)
                                while not stop_event.is_set():
                                    chunk = client_sock.recv(4096)
                                    if not chunk:
                                        break
                                    send_frame(self.offshore_sock, MSG_TUNNEL, client_id, chunk)
                            except Exception:
                                pass
                            finally:
                                try:
                                    send_frame(self.offshore_sock, MSG_TUNNEL_CLOSE, client_id, b'')
                                except:
                                    pass
                                stop_event.set()
                        def offshore_to_client():
                            try:
                                while not stop_event.is_set():
                                    frame2 = recv_frame(self.offshore_sock)
                                    if frame2 is None:
                                        break
                                    msg_type2, cid2, payload2 = frame2
                                    if cid2 != client_id:
                                        continue
                                    if msg_type2 == MSG_TUNNEL_BACK:
                                        if payload2:
                                            client_sock.sendall(payload2)
                                    elif msg_type2 == MSG_TUNNEL_CLOSE:
                                        break
                            except Exception:
                                pass
                            finally:
                                stop_event.set()
                        t1 = threading.Thread(target=client_to_offshore, daemon=True)
                        t2 = threading.Thread(target=offshore_to_client, daemon=True)
                        t1.start(); t2.start()
                        t1.join(); t2.join()
                    client_sock.close()
            else:
                headers_end = data.find(b"\r\n\r\n")+4
                headers = data[:headers_end].decode('iso-8859-1', errors='ignore')
                content_length = 0
                for line in headers.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        try:
                            content_length = int(line.split(":",1)[1].strip())
                        except:
                            content_length = 0
                        break
                body_received = len(data) - headers_end
                if body_received < content_length:
                    remain = content_length - body_received
                    while remain > 0:
                        chunk = client_sock.recv(min(4096, remain))
                        if not chunk:
                            break
                        data += chunk
                        remain -= len(chunk)
                with self.offshore_lock:
                    send_frame(self.offshore_sock, MSG_REQUEST, client_id, data)
                    while True:
                        frame = recv_frame(self.offshore_sock)
                        if frame is None:
                            print("[ship] offshore disconnected while waiting for response")
                            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                            client_sock.close()
                            self.connect_offshore()
                            return
                        msg_type, cid, payload = frame
                        if cid != client_id:
                            continue
                        if msg_type == MSG_RESPONSE:
                            client_sock.sendall(payload)
                            break
                client_sock.close()
        except Exception as e:
            print(f"[ship] client handler error: {e}")
            try:
                client_sock.close()
            except:
                pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--offshore-host", default="127.0.0.1")
    parser.add_argument("--offshore-port", default=9090, type=int)
    parser.add_argument("--listen-port", default=8080, type=int)
    args = parser.parse_args()
    sp = ShipProxy(args.offshore_host, args.offshore_port, args.listen_port)
    sp.start()
