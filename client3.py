import socket, sys, json, threading, time, os, hashlib
from urllib.request import Request, urlopen
from urllib.parse import urlparse
from des_traditional import encrypt_ecb_bytes, decrypt_ecb_bytes
import rsa_small

SERVER_DEFAULT = 'http://127.0.0.1:8002'
_embedded_started = False

def http_post_json(url, obj):
    data = json.dumps(obj).encode('utf-8')
    req = Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
    with urlopen(req) as resp:
        return resp.getcode(), resp.read()

def http_get(url):
    req = Request(url, method='GET')
    with urlopen(req) as resp:
        return resp.getcode(), resp.read()

def _embedded_parse_request(conn):
    data = b''
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk: break
        data += chunk
    header_part, _, rest = data.partition(b"\r\n\r\n")
    lines = header_part.decode('iso-8859-1', errors='replace').split('\r\n')
    if not lines or ' ' not in lines[0]:
        return '', '', '', {}, b'', data
    method, path, version = (lines[0].split(' ') + ['',''])[:3]
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    length = int(headers.get('content-length', '0') or '0')
    body = rest
    while len(body) < length:
        chunk = conn.recv(4096)
        if not chunk: break
        body += chunk
    raw = header_part + b"\r\n\r\n" + body[:length]
    return method, path, version, headers, body[:length], raw

def _embedded_send_response(conn, status, reason, headers, body):
    hdrs = dict(headers or {})
    hdrs.setdefault('Content-Length', str(len(body or b'')))
    hdrs.setdefault('Connection', 'close')
    lines = [f"HTTP/1.1 {status} {reason}\r\n"]
    for k, v in hdrs.items(): lines.append(f"{k}: {v}\r\n")
    lines.append("\r\n")
    try: conn.sendall(''.join(lines).encode('iso-8859-1') + (body or b''))
    except Exception: pass

def _embedded_server_loop(host, port):
    from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
    inboxes = {}
    cond = threading.Condition()
    def enqueue(recipient, payload):
        with cond:
            inboxes.setdefault(recipient, []).append(payload)
            cond.notify_all()
    def dequeue(recipient):
        with cond:
            q = inboxes.get(recipient, [])
            return q.pop(0) if q else None
    def handle(conn, addr):
        try:
            method, path, version, headers, body, raw = _embedded_parse_request(conn)
            if not method:
                _embedded_send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
                return
            parsed = _urlparse(path)
            if method == 'POST' and parsed.path == '/send':
                try: payload = json.loads(body.decode('utf-8'))
                except Exception:
                    _embedded_send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b''); return
                if not {'from','to','type'}.issubset(payload.keys()):
                    _embedded_send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b''); return
                forwarded = {'from': payload['from'], 'type': payload.get('type','text'), 'msg': payload.get('msg') or payload.get('cipher') or '', 'size': payload.get('size',0)}
                enqueue(payload['to'], forwarded)
                resp = json.dumps({'queued': True}).encode('utf-8')
                _embedded_send_response(conn, 200, 'OK', {'Content-Type': 'application/json'}, resp); return
            if method == 'GET' and parsed.path == '/recv':
                qs = _parse_qs(parsed.query or '')
                client_id = (qs.get('client') or [''])[0]
                wait_param = (qs.get('wait') or ['0'])[0]
                try: wait_secs = max(0, min(60, int(wait_param)))
                except ValueError: wait_secs = 0
                if not client_id:
                    _embedded_send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b''); return
                msg = dequeue(client_id)
                if msg is None and wait_secs > 0:
                    with cond: cond.wait(timeout=wait_secs)
                    msg = dequeue(client_id)
                if msg is None:
                    _embedded_send_response(conn, 204, 'No Content', {'Content-Type': 'text/plain'}, b''); return
                resp = json.dumps(msg).encode('utf-8')
                _embedded_send_response(conn, 200, 'OK', {'Content-Type': 'application/json'}, resp); return
            _embedded_send_response(conn, 404, 'Not Found', {'Content-Type': 'text/plain'}, b'')
        finally:
            try: conn.close()
            except Exception: pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen(5)
        except Exception: return
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

def start_embedded_server_if_needed(base_url):
    global _embedded_started
    if _embedded_started: return
    try:
        status, _ = http_get(base_url + '/recv?client=__probe__&wait=0')
        if status in (200,204,400):
            _embedded_started = True; return
    except Exception: pass
    parsed = urlparse(base_url)
    host = '0.0.0.0'
    port = int(parsed.port or (443 if parsed.scheme == 'https' else 80))
    try:
        threading.Thread(target=_embedded_server_loop, args=(host, port), daemon=True).start()
        _embedded_started = True
        print(f'[info] Embedded relay started on http://{host}:{port}')
    except Exception as e:
        print(f'[warn] Failed to start embedded relay: {e}')

def pub_fingerprint(p):
    try:
        ser = rsa_small.serialize_pub(p)
        data = json.dumps(ser, sort_keys=True).encode('utf-8')
    except Exception:
        data = repr(p).encode('utf-8')
    return hashlib.sha256(data).hexdigest()[:16]

def main():
    base = SERVER_DEFAULT
    args = sys.argv[1:]
    if len(args) < 1:
        print('Usage: python client3.py <my_id> [peer_id]'); return
    my_id = args[0]
    peer_id = args[1] if len(args) >= 2 else None
    start_embedded_server_if_needed(base)
    print(f'[info] my_id={my_id}')
    if peer_id: print(f'[info] peer={peer_id}')
    else:
        try:
            p = input('[setup] Enter peer id (Enter to wait): ').strip()
            if p: peer_id = p; print(f'[info] peer={peer_id}')
        except (EOFError, KeyboardInterrupt): pass
    print('[info] Generating RSA keypair...')
    pub, priv = rsa_small.generate_keypair(1024)
    my_pub_fp = pub_fingerprint(pub)
    print('[info] RSA pub n bits=', pub[0].bit_length())
    print(f'[info] Our RSA pub fp={my_pub_fp}')
    session_key = os.urandom(8)
    have_peer_pub = False
    peer_pub = None
    peer_pub_fp = None
    session_established = False
    my_pub_sent = False
    key_sent = False
    stop_flag = {'stop': False}
    outgoing_queue = []
    queue_lock = threading.Lock()
    def send_payload(obj):
        try:
            status, body = http_post_json(base + '/send', obj)
            if status != 200:
                print(f'[send] HTTP {status} {body[:80]!r}')
        except Exception as e:
            print(f'[send] error: {e}')
    def flush_outgoing_queue():
        if not session_established or not peer_id: return
        with queue_lock:
            batch = list(outgoing_queue)
            outgoing_queue.clear()
        for data in batch:
            cipher = encrypt_ecb_bytes(data, session_key)
            send_payload({'from': my_id, 'to': peer_id, 'type': 'text', 'cipher': cipher.hex(), 'size': len(data)})
            print('[send] (queued) plaintext:', data.decode('utf-8','replace'))
            print('[send] (queued) encrypted:', cipher.hex())
    def maybe_send_pub():
        nonlocal my_pub_sent
        if peer_id and not my_pub_sent:
            send_payload({'from': my_id, 'to': peer_id, 'type': 'pub', 'msg': json.dumps(rsa_small.serialize_pub(pub))})
            my_pub_sent = True
            print(f'[handshake] Sent our public key fp={my_pub_fp} to {peer_id}')
    def maybe_send_session_key():
        nonlocal key_sent
        if have_peer_pub and not key_sent:
            enc_key_bytes = rsa_small.encrypt(session_key, peer_pub)
            send_payload({'from': my_id, 'to': peer_id, 'type': 'keyx', 'msg': enc_key_bytes.hex(), 'size': len(session_key)})
            key_sent = True
            sk_fp = hashlib.sha256(session_key).hexdigest()[:16]
            peer_fp = peer_pub_fp or 'unknown'
            print(f'[handshake] Sent encrypted session key (sk_fp={sk_fp}) using peer fp={peer_fp}')
    def receiver_loop():
        nonlocal have_peer_pub, peer_pub, peer_pub_fp, session_established, session_key
        while not stop_flag['stop']:
            try:
                status, body = http_get(base + f'/recv?client={my_id}&wait=30')
            except Exception as e:
                if not stop_flag['stop']: print(f'[recv] error: {e}')
                time.sleep(1); continue
            if status == 200:
                try: payload = json.loads(body.decode('utf-8'))
                except Exception as e: print(f'[recv] invalid JSON {e}'); continue
                mtype = payload.get('type','text')
                raw = payload.get('msg','')
                sender = payload.get('from')
                if mtype == 'pub' and sender == peer_id:
                    try:
                        peer_pub = rsa_small.deserialize_pub(json.loads(raw))
                        have_peer_pub = True
                        peer_pub_fp = pub_fingerprint(peer_pub)
                        print(f'[handshake] Received peer public key fp={peer_pub_fp}')
                        maybe_send_session_key()
                    except Exception as e:
                        print(f'[handshake] bad pub key: {e}')
                elif mtype == 'keyx' and sender == peer_id:
                    if not session_established:
                        try:
                            key_bytes = bytes.fromhex(raw)
                            sk = rsa_small.decrypt(key_bytes, priv)
                            if len(sk) == 8:
                                session_key = sk
                                session_established = True
                                sk_fp = hashlib.sha256(session_key).hexdigest()[:16]
                                print(f'[handshake] Session key established (sk_fp={sk_fp})')
                                flush_outgoing_queue()
                            else:
                                print('[handshake] Invalid session key length')
                        except Exception as e:
                            print(f'[handshake] key decrypt error: {e}')
                elif mtype == 'text':
                    print(f'\n[recv] Encrypted from {sender}: {raw}')
                    if session_established:
                        try:
                            pt = decrypt_ecb_bytes(bytes.fromhex(raw), session_key)
                            print('[recv] Decrypted:', pt.decode('utf-8','replace'))
                        except Exception as e:
                            print(f'[recv] decrypt error: {e}')
                    else:
                        print('[recv] (no session key yet)')
            maybe_send_pub(); maybe_send_session_key()
    threading.Thread(target=receiver_loop, daemon=True).start()
    print('[chat] Type messages. /to <peer> to switch, /quit to exit.')
    maybe_send_pub()
    while True:
        try: line = input('> ').strip()
        except (EOFError, KeyboardInterrupt): line = '/quit'
        if not line: continue
        if line.lower().startswith('/quit'):
            stop_flag['stop'] = True
            print('[chat] Quit.')
            return
        if line.lower().startswith('/to '):
            peer_id = line.split(None,1)[1].strip()
            have_peer_pub = False
            peer_pub = None
            peer_pub_fp = None
            session_established = False
            my_pub_sent = False
            key_sent = False
            session_key = os.urandom(8)
            print(f'[chat] peer={peer_id} (handshake reset)')
            maybe_send_pub(); maybe_send_session_key(); flush_outgoing_queue(); continue
        if not peer_id:
            print('[chat] set peer first with /to <id>'); continue
        if not session_established:
            data = line.encode('utf-8')
            with queue_lock: outgoing_queue.append(data)
            print('[chat] queued (waiting handshake)')
            maybe_send_pub(); maybe_send_session_key(); continue
        data = line.encode('utf-8')
        cipher = encrypt_ecb_bytes(data, session_key)
        send_payload({'from': my_id, 'to': peer_id, 'type': 'text', 'cipher': cipher.hex(), 'size': len(data)})
        print('[send] plaintext:', line)
        print('[send] encrypted:', cipher.hex())

if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt:
        print('\n[exit] Interrupted.')
        try: sys.exit(0)
        except SystemExit: pass

def _embedded_send_response(conn, status, reason, headers, body):
    hdrs = dict(headers or {})
    hdrs.setdefault('Content-Length', str(len(body or b'')))
    hdrs.setdefault('Connection', 'close')
    lines = [f"HTTP/1.1 {status} {reason}\r\n"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}\r\n")
    lines.append("\r\n")
    try:
        conn.sendall(''.join(lines).encode('iso-8859-1') + (body or b''))
    except Exception:
        pass

def _embedded_server_loop(host: str, port: int):
    import threading as _th
    from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
    inboxes = {}
    cond = _th.Condition()

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

    def handle(conn, addr):
        try:
            method, path, version, headers, body, raw = _embedded_parse_request(conn)
            if not method:
                _embedded_send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
                return
            parsed = _urlparse(path)
            if method == 'POST' and parsed.path == '/send':
                try:
                    payload = json.loads(body.decode('utf-8'))
                except Exception:
                    _embedded_send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
                    return
                if not {'from','to','type'}.issubset(payload.keys()):
                    _embedded_send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
                    return
                forwarded = {
                    'from': payload['from'],
                    'type': payload.get('type','text'),
                    'msg': payload.get('msg') or payload.get('cipher') or '',
                    'size': payload.get('size',0)
                }
                enqueue(payload['to'], forwarded)
                resp = json.dumps({'queued': True}).encode('utf-8')
                _embedded_send_response(conn, 200, 'OK', {'Content-Type': 'application/json'}, resp)
                return
            if method == 'GET' and parsed.path == '/recv':
                qs = _parse_qs(parsed.query or '')
                client_id = (qs.get('client') or [''])[0]
                wait_param = (qs.get('wait') or ['0'])[0]
                try:
                    wait_secs = max(0, min(60, int(wait_param)))
                except ValueError:
                    wait_secs = 0
                if not client_id:
                    _embedded_send_response(conn, 400, 'Bad Request', {'Content-Type': 'text/plain'}, b'')
                    return
                msg = dequeue(client_id)
                if msg is None and wait_secs > 0:
                    with cond:
                        cond.wait(timeout=wait_secs)
                    msg = dequeue(client_id)
                if msg is None:
                    _embedded_send_response(conn, 204, 'No Content', {'Content-Type': 'text/plain'}, b'')
                    return
                resp = json.dumps(msg).encode('utf-8')
                _embedded_send_response(conn, 200, 'OK', {'Content-Type': 'application/json'}, resp)
                return
            _embedded_send_response(conn, 404, 'Not Found', {'Content-Type': 'text/plain'}, b'')
        finally:
            try: conn.close()
            except Exception: pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen(5)
        except Exception:
            return
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

def start_embedded_server_if_needed(base_url: str):
    global _embedded_started
    if _embedded_started:
        return
    try:
        status, _ = http_get(base_url + f"/recv?client=__probe__&wait=0")
        if status in (200, 204, 400):
            _embedded_started = True
            return
    except Exception:
        pass
    parsed = urlparse(base_url)
    host = '0.0.0.0'
    port = int(parsed.port or (443 if parsed.scheme == 'https' else 80))
    try:
        threading.Thread(target=_embedded_server_loop, args=(host, port), daemon=True).start()
        _embedded_started = True
        print(f"[info] Embedded relay started on http://{host}:{port}")
    except Exception as e:
        print(f"[warn] Failed to start embedded relay: {e}")

def usage():
    print("Usage: python client3.py <my_id> [peer_id]\nCommands: /to <peer> | /quit")

def main():
    base = SERVER_DEFAULT
    args = sys.argv[1:]
    if len(args) < 1:
        usage(); return
    my_id = args[0]
    peer_id = args[1] if len(args) >= 2 else None
    start_embedded_server_if_needed(base)
    print(f"[info] my_id={my_id}")
    if peer_id: print(f"[info] peer={peer_id}")
    else:
        try:
            p = input("[setup] Enter peer id (Enter to wait): ").strip()
            if p: peer_id = p; print(f"[info] peer={peer_id}")
        except (EOFError, KeyboardInterrupt): pass

    print("[info] Generating RSA keypair...")
    pub, priv = rsa_small.generate_keypair(1024)
    def pub_fingerprint(p):
        try:
            ser = rsa_small.serialize_pub(p)
            data = json.dumps(ser, sort_keys=True).encode('utf-8')
        except Exception:
            data = repr(p).encode('utf-8')
        return hashlib.sha256(data).hexdigest()[:16]

    my_pub_fp = pub_fingerprint(pub)
    print("[info] RSA pub n bits=", (pub[0].bit_length()))
    print(f"[info] Our RSA pub fp={my_pub_fp}")
    session_key = os.urandom(8)
    have_peer_pub = False
    peer_pub = None
    peer_pub_fp = None
    session_established = False
    my_pub_sent = False
    key_sent = False
    stop_flag = {'stop': False}

    # Outgoing message queue (idle typing before session ready)
    outgoing_queue = []
    queue_lock = threading.Lock()

    def send_payload(obj: dict):
        try:
            status, body = http_post_json(base + '/send', obj)
            if status != 200:
                print(f"[send] HTTP {status} {body[:80]!r}")
        except Exception as e:
            print(f"[send] error: {e}")

    def flush_outgoing_queue():
        if not session_established or not peer_id:
            return
        with queue_lock:
            batch = list(outgoing_queue)
            outgoing_queue.clear()
        for data in batch:
            cipher = encrypt_ecb_bytes(data, session_key)
            send_payload({'from': my_id, 'to': peer_id, 'type': 'text', 'cipher': cipher.hex(), 'size': len(data)})
            print('[send] (queued) plaintext:', data.decode('utf-8', 'replace'))
            print('[send] (queued) encrypted:', cipher.hex())

    def maybe_send_pub():
        nonlocal my_pub_sent
        if peer_id and not my_pub_sent:
            send_payload({'from': my_id, 'to': peer_id, 'type': 'pub', 'msg': json.dumps(rsa_small.serialize_pub(pub))})
            my_pub_sent = True
            print(f"[handshake] Sent our public key fp={my_pub_fp} to {peer_id}")

    def maybe_send_session_key():
        nonlocal key_sent
        if have_peer_pub and not key_sent:
            enc_key_bytes = rsa_small.encrypt(session_key, peer_pub)
            send_payload({'from': my_id, 'to': peer_id, 'type': 'keyx', 'msg': enc_key_bytes.hex(), 'size': len(session_key)})
            key_sent = True
            # Show short fingerprints for visibility (not secure, for demo)
            sk_fp = hashlib.sha256(session_key).hexdigest()[:16]
            peer_fp = peer_pub_fp or "unknown"
            print(f"[handshake] Sent encrypted session key (sk_fp={sk_fp}) using peer fp={peer_fp}")

    def receiver_loop():
        nonlocal have_peer_pub, peer_pub, session_established, session_key
        while not stop_flag['stop']:
            try:
                status, body = http_get(base + f"/recv?client={my_id}&wait=30")
            except Exception as e:
                if not stop_flag['stop']:
                    print(f"[recv] error: {e}")
                time.sleep(1); continue
            if status == 200:
                try:
                    payload = json.loads(body.decode('utf-8'))
                except Exception as e:
                    print(f"[recv] invalid JSON {e}")
                    continue
                mtype = payload.get('type','text')
                raw = payload.get('msg','')
                sender = payload.get('from')
                if mtype == 'pub' and sender == peer_id:
                    try:
                        peer_pub = rsa_small.deserialize_pub(json.loads(raw))
                        have_peer_pub = True
                        peer_pub_fp = pub_fingerprint(peer_pub)
                        print(f"[handshake] Received peer public key fp={peer_pub_fp}")
                        maybe_send_session_key()
                    except Exception as e:
                        print(f"[handshake] bad pub key: {e}")
                elif mtype == 'keyx' and sender == peer_id:
                    if not session_established:
                        try:
                            key_bytes = bytes.fromhex(raw)
                            sk = rsa_small.decrypt(key_bytes, priv)
                            if len(sk) == 8:
                                session_key = sk
                                session_established = True
                                sk_fp = hashlib.sha256(session_key).hexdigest()[:16]
                                print(f"[handshake] Session key established (sk_fp={sk_fp})")
                                flush_outgoing_queue()
                            else:
                                print("[handshake] Invalid session key length")
                        except Exception as e:
                            print(f"[handshake] key decrypt error: {e}")
                    else:
                        pass
                elif mtype == 'text':
                    print(f"\n[recv] Encrypted from {sender}: {raw}")
                    if session_established:
                        try:
                            pt = decrypt_ecb_bytes(bytes.fromhex(raw), session_key)
                            print("[recv] Decrypted:", pt.decode('utf-8','replace'))
                        except Exception as e:
                            print(f"[recv] decrypt error: {e}")
                    else:
                        print("[recv] (no session key yet)")
            elif status == 204:
                pass
            maybe_send_pub()
            maybe_send_session_key()

    threading.Thread(target=receiver_loop, daemon=True).start()
    print("[chat] Waiting. Handshake uses messages of type pub, keyx.")
    maybe_send_pub()
    while True:
        try:
            line = input('> ').strip()
        except (EOFError, KeyboardInterrupt):
            line = '/quit'
        if not line: continue
        if line.lower().startswith('/quit'):
            stop_flag['stop'] = True
            print('[chat] Quit.')
            return
        if line.lower().startswith('/to '):
            peer_id = line.split(None,1)[1].strip()
            # reset handshake state for new peer
            have_peer_pub = False
            peer_pub = None
            peer_pub_fp = None
            session_established = False
            my_pub_sent = False
            key_sent = False
            # rotate a fresh session key per peer
            session_key = os.urandom(8)
            print(f"[chat] peer={peer_id} (handshake reset)")
            maybe_send_pub(); maybe_send_session_key(); flush_outgoing_queue(); continue
        if not peer_id:
            print('[chat] set peer first with /to <id>'); continue
        if not session_established:
            data = line.encode('utf-8')
            with queue_lock:
                outgoing_queue.append(data)
            print('[chat] queued (waiting handshake)')
            maybe_send_pub(); maybe_send_session_key(); continue
        data = line.encode('utf-8')
        cipher = encrypt_ecb_bytes(data, session_key)
        send_payload({'from': my_id, 'to': peer_id, 'type': 'text', 'cipher': cipher.hex(), 'size': len(data)})
        print('[send] plaintext:', line)
        print('[send] encrypted:', cipher.hex())

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n[exit] Interrupted.')
        try: sys.exit(0)
        except SystemExit: pass
