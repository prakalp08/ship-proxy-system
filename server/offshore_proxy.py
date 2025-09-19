"""
Offshore Proxy (server-side)
Accepts ship connection(s). For each framed request from ship it either performs an
HTTP request and returns the full response as one MSG_RESPONSE frame, or for CONNECT
establishes a TCP connection to target and then exchanges framed tunnel data.
"""

import socket
import threading
import argparse
import struct
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

def read_full_http_response(sock):
    buf = b''
    sock.settimeout(10.0)
    try:
        while b'\r\n\r\n' not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    except Exception:
        pass

    if not buf:
        return b''

    headers_end = buf.find(b'\r\n\r\n') + 4
    headers = buf[:headers_end].decode('iso-8859-1', errors='ignore')
    body = buf[headers_end:]

    cl = None
    chunked = False
    for line in headers.split('\r\n'):
        if ':' not in line:
            continue
        k, v = line.split(':',1)
        k = k.strip().lower()
        v = v.strip().lower()
        if k == 'content-length':
            try:
                cl = int(v)
            except:
                cl = None
        if k == 'transfer-encoding' and 'chunked' in v:
            chunked = True


    if cl is not None:
        to_read = cl - len(body)
        while to_read > 0:
            chunk = sock.recv(min(4096, to_read))
            if not chunk:
                break
            body += chunk
            to_read -= len(chunk)
        return headers.encode('iso-8859-1') + body

    # If chunked, read chunks until zero-length chunk found
    if chunked:
        
        data = body
        try:
            while True:
                # read until we find \r\n0\r\n or \r\n0\r\n\r\n sequence present
                if b'\r\n0\r\n' in data or b'\r\n0\r\n\r\n' in data:
                    # might still have trailing headers; read short time to flush
                    break
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except Exception:
            pass
        return headers.encode('iso-8859-1') + data


    sock.settimeout(0.5)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
    except Exception:
        pass
    finally:
        try:
            sock.settimeout(None)
        except:
            pass
    return headers.encode('iso-8859-1') + body

def handle_ship(sock, addr):
    print(f"[offshore] Ship connected from {addr}")
    try:
        while True:
            frame = recv_frame(sock)
            if frame is None:
                print("[offshore] ship disconnected")
                break
            msg_type, client_id, payload = frame
            if msg_type == MSG_REQUEST:
                # Parse initial request line to detect CONNECT
                try:
                    first_line = payload.split(b'\r\n',1)[0].decode('utf-8', errors='ignore')
                    method = first_line.split()[0] if first_line else ''
                except:
                    method = ''
                if method.upper() == 'CONNECT':
                    # For CONNECT: open connection to target and respond with 200 then tunnel
                    try:
                        path = first_line.split()[1]  # host:port
                        if ':' in path:
                            host, port_s = path.split(':',1)
                            port = int(port_s)
                        else:
                            host = path; port = 443
                    except Exception as e:
                        print(f"[offshore] malformed CONNECT: {e}")
                        send_frame(sock, MSG_RESPONSE, client_id, b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        continue
                    try:
                        target = socket.create_connection((host, port))
                    except Exception as e:
                        print(f"[offshore] Connect to target failed: {e}")
                        send_frame(sock, MSG_RESPONSE, client_id, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        continue
                    # Send 200 OK back to ship (will be forwarded to browser)
                    send_frame(sock, MSG_RESPONSE, client_id, b"HTTP/1.1 200 Connection established\r\n\r\n")
                    # Now start tunneling between target and ship using framed messages
                    stop_event = threading.Event()
                    def target_to_ship():
                        try:
                            while not stop_event.is_set():
                                data = target.recv(4096)
                                if not data:
                                    break
                                send_frame(sock, MSG_TUNNEL_BACK, client_id, data)
                        except Exception:
                            pass
                        finally:
                            try:
                                send_frame(sock, MSG_TUNNEL_CLOSE, client_id, b'')
                            except:
                                pass
                            stop_event.set()
                    t = threading.Thread(target=target_to_ship, daemon=True)
                    t.start()
                    # Read tunnel frames from ship
                    try:
                        while not stop_event.is_set():
                            f = recv_frame(sock)
                            if f is None:
                                break
                            mt, cid, pl = f
                            if cid != client_id:
                                continue
                            if mt == MSG_TUNNEL:
                                if pl:
                                    target.sendall(pl)
                            elif mt == MSG_TUNNEL_CLOSE:
                                break
                            else:
                                pass
                    except Exception:
                        pass
                    finally:
                        stop_event.set()
                        try:
                            target.close()
                        except:
                            pass
                else:
                    # Normal HTTP request: forward to destination (parse Host header)
                    try:
                        headers_end = payload.find(b"\r\n\r\n") + 4
                        headers = payload[:headers_end].decode('iso-8859-1', errors='ignore')
                        host = None; port = 80
                        for line in headers.split('\r\n'):
                            if line.lower().startswith('host:'):
                                host_line = line.split(':',1)[1].strip()
                                if ':' in host_line:
                                    host, port_s = host_line.split(':',1); port = int(port_s)
                                else:
                                    host = host_line; port = 80
                                break
                        if not host:
                            send_frame(sock, MSG_RESPONSE, client_id, b"HTTP/1.1 400 Bad Request\r\n\r\n")
                            continue
                        server = socket.create_connection((host, port))
                        # forward entire request payload
                        server.sendall(payload)
                        # Read full response
                        response_bytes = read_full_http_response(server)
                        if not response_bytes:
                            send_frame(sock, MSG_RESPONSE, client_id, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        else:
                            send_frame(sock, MSG_RESPONSE, client_id, response_bytes)
                        server.close()
                    except Exception as e:
                        print(f"[offshore] HTTP forward error: {e}")
                        try:
                            send_frame(sock, MSG_RESPONSE, client_id, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        except:
                            pass
            else:
                # ignore other kinds of frames at top-level
                pass
    except Exception as e:
        print(f"[offshore] connection handling error: {e}")
    finally:
        try:
            sock.close()
        except:
            pass
        print("[offshore] handler exit for ship connection")

def start_offshore(listen_host, listen_port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_host, listen_port))
    srv.listen(5)
    print(f"[offshore] listening on {listen_host}:{listen_port}")
    try:
        while True:
            client_sock, addr = srv.accept()
            threading.Thread(target=handle_ship, args=(client_sock, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("Shutting down offshore proxy")
        srv.close()
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=9090, type=int)
    args = parser.parse_args()
    start_offshore(args.host, args.port)
