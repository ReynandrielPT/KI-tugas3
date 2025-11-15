import socket
import threading
import json
from urllib.parse import urlparse, parse_qs
from datetime import datetime

inboxes: dict[str, list[dict]] = {}
pubs: dict[str, dict] = {}
cond = threading.Condition()


def log_event(kind: str, info: str):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"{ts} [{kind}] {info}"
    print(line, flush=True)
    try:
        with open('server.log', 'a', encoding='utf-8') as f:
            f.write(line + "\n")
    except Exception:
        pass


def log_packet(direction: str, text: str):
    # direction: IN or OUT
    border = f"----- {direction} PACKET -----"
    print(border)
    print(text.rstrip('\n'))
    print("----- END PACKET -----", flush=True)
    try:
        with open('server.log', 'a', encoding='utf-8') as f:
            f.write(border + "\n" + text + "\n----- END PACKET -----\n")
    except Exception:
        pass


def enqueue(recipient: str, payload: dict):
    with cond:
        inboxes.setdefault(recipient, []).append(payload)
        cond.notify_all()


def dequeue(recipient: str):
    with cond:
        q = inboxes.get(recipient, [])
        if q:
            return q.pop(0)
        return None


def parse_request(conn) -> tuple[str, str, str, dict, bytes, bytes]:
    # Returns: method, path, version, headers, body, raw_request
    data = b''
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    header_part, _, rest = data.partition(b"\r\n\r\n")
    lines = header_part.decode('iso-8859-1').split("\r\n")
    if not lines:
        return '', '', '', {}, b'', data
    request_line = lines[0]
    try:
        method, path, version = request_line.split(' ', 2)
    except ValueError:
        return '', '', '', {}, b'', data
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    length = int(headers.get('content-length', '0') or '0')
    body = rest
    while len(body) < length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body += chunk
    raw = header_part + b"\r\n\r\n" + body[:length]
    return method, path, version, headers, body[:length], raw


def send_response(conn, status: int, reason: str, headers: dict, body: bytes, packet_preview: bool = True):
    # Ensure mandatory headers
    hdrs = dict(headers or {})
    if 'Content-Length' not in {k.title(): v for k, v in hdrs.items()}:
        hdrs['Content-Length'] = str(len(body or b''))
    # Be explicit for client behavior
    if 'Connection' not in {k.title(): v for k, v in hdrs.items()}:
        hdrs['Connection'] = 'close'

    lines = [f"HTTP/1.1 {status} {reason}\r\n"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}\r\n")
    lines.append("\r\n")
    payload = ''.join(lines).encode('iso-8859-1') + (body or b'')
    if packet_preview:
        # Log a textual version of the response for visibility (truncate body to 512 bytes)
        preview_body = (body or b'')[:512]
        text = ''.join(lines) + (preview_body.decode('utf-8', errors='replace'))
        log_packet('OUT', text)
    try:
        conn.sendall(payload)
    except Exception:
        # Ignore send errors; connection might be gone
        pass


def handle_client(conn, addr):
    try:
        method, path, version, headers, body, raw_req = parse_request(conn)
        if not method:
            send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
            return
        # Log the incoming packet (truncate body preview)
        try:
            # Limit to first 1024 bytes for log
            header_part = raw_req.split(b"\r\n\r\n", 1)[0].decode('iso-8859-1', errors='replace')
            body_part = raw_req.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw_req else b''
            preview = body_part[:512]
            text = header_part + "\r\n\r\n" + preview.decode('utf-8', errors='replace')
            log_packet('IN', text)
        except Exception:
            pass
        parsed = urlparse(path)
        if method == 'POST' and parsed.path == '/register':
            # Register RSA public key for a client id
            try:
                payload = json.loads(body.decode('utf-8'))
                cid = str(payload.get('id') or '').strip()
                pub = payload.get('pub') or {}
                n = pub.get('n')
                e = pub.get('e')
                if not cid or n is None or e is None:
                    raise ValueError('invalid')
                with cond:
                    pubs[cid] = {'n': str(n), 'e': int(e)}
                send_response(conn, 200, 'OK', {'Content-Type': 'application/json'}, json.dumps({'ok': True}).encode('utf-8'))
            except Exception:
                send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
            return
        if method == 'GET' and parsed.path == '/pub':
            # Retrieve RSA public key for a client id
            qs = parse_qs(parsed.query or '')
            cid = (qs.get('client') or [''])[0]
            with cond:
                pub = pubs.get(cid)
            if not cid or not pub:
                send_response(conn, 404, 'Not Found', {'Content-Type': 'application/json'}, json.dumps({}).encode('utf-8'))
                return
            send_response(conn, 200, 'OK', {'Content-Type': 'application/json'}, json.dumps(pub).encode('utf-8'))
            return
        if method == 'POST' and parsed.path == '/send':
            try:
                payload = json.loads(body.decode('utf-8'))
            except Exception:
                send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
                return
            required = {'from', 'to'}
            if not required.issubset(payload.keys()):
                send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
                return
            # Accept 'cipher' or legacy 'msg' key
            cipher_hex = payload.get('cipher') or payload.get('msg')
            if not isinstance(cipher_hex, str):
                send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
                return
            # Log the received message (encrypted hex)
            try:
                msg_hex = str(cipher_hex)
                msg_bytes = len(msg_hex) // 2
            except Exception:
                msg_hex = '<invalid>'
                msg_bytes = 0
            log_event('RECV', f"from={payload.get('from','')} to={payload.get('to','')} bytes={msg_bytes} msg={msg_hex}")
            # Pass through extra fields (e.g., type, filename, mimetype, size)
            forwarded = {'from': payload['from'], 'msg': cipher_hex}
            for k in ('type', 'filename', 'mimetype', 'size'):
                if k in payload:
                    forwarded[k] = payload[k]
            enqueue(payload['to'], forwarded)
            resp = json.dumps({'queued': True}).encode('utf-8')
            send_response(conn, 200, 'OK', {'Content-Type': 'application/json', 'Content-Length': str(len(resp))}, resp)
            return
        if method == 'GET' and parsed.path == '/recv':
            qs = parse_qs(parsed.query or '')
            client_id = (qs.get('client') or [''])[0]
            wait_param = (qs.get('wait') or ['0'])[0]
            try:
                wait_secs = max(0, min(60, int(wait_param)))
            except ValueError:
                wait_secs = 0
            if not client_id:
                send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
                return
            msg = dequeue(client_id)
            if msg is None and wait_secs > 0:
                with cond:
                    cond.wait(timeout=wait_secs)
                msg = dequeue(client_id)
            if msg is None:
                send_response(conn, 204, 'No Content', {'Content-Type': 'text/plain'}, b'')
                return
            # Log the sending event when delivering to receiver
            try:
                msg_hex = str(msg.get('msg', ''))
                msg_bytes = len(msg_hex) // 2
            except Exception:
                msg_hex = '<invalid>'
                msg_bytes = 0
            log_event('SEND', f"to={client_id} from={msg.get('from','')} bytes={msg_bytes} msg={msg_hex}")
            resp = json.dumps(msg).encode('utf-8')
            send_response(conn, 200, 'OK', {'Content-Type': 'application/json', 'Content-Length': str(len(resp))}, resp)
            return
        # Not Found
        send_response(conn, 404, 'Not Found', {'Content-Type': 'text/plain'}, b'')
    finally:
        # Avoid shutdown(SHUT_RDWR) on Windows to prevent RST (WinError 10054)
        try:
            conn.close()
        except Exception:
            pass


def run(host='0.0.0.0', port=8002):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        print(f"Relay server listening on http://{host}:{port}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == '__main__':
    import sys
    host = '0.0.0.0'
    port = 8002
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            pass
    print(f"Starting relay on http://{host}:{port}")
    run(host, port)
