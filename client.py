import socket, sys, json, threading, time, os, hashlib
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import urlparse
from des_traditional import encrypt_ecb_bytes, decrypt_ecb_bytes
import rsa_small
from build_http import http_post_json, http_get

SERVER_DEFAULT = 'http://127.0.0.1:8002'
VERBOSE = False
_embedded_started = False


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
    if peer_id:
        print(f'[info] peer={peer_id}')
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
    
    try:
        reg_payload = {'id': my_id, 'pub': rsa_small.serialize_pub(pub)}
        status, body = http_post_json(base + '/register', reg_payload)
        if status == 200:
            if VERBOSE:
                print('[pka] Registered public key with server')
        else:
            print(f'[pka] register failed HTTP {status}: {body[:120]!r}')
    except Exception as e:
        print(f'[pka] register error: {e}')
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
            ui_print(f'[handshake] Sent our public key fp={my_pub_fp} to {peer_id}', reprompt=True)
    def am_initiator() -> bool:
        try:
            return bool(peer_id) and str(my_id) < str(peer_id)
        except Exception:
            return False

    def maybe_send_session_key():
        nonlocal key_sent, session_established
        
        if have_peer_pub and not key_sent and am_initiator():
            enc_key_bytes = rsa_small.encrypt(session_key, peer_pub)
            send_payload({'from': my_id, 'to': peer_id, 'type': 'keyx', 'msg': enc_key_bytes.hex(), 'size': len(session_key)})
            key_sent = True
            sk_fp = hashlib.sha256(session_key).hexdigest()[:16]
            peer_fp = peer_pub_fp or 'unknown'
            ui_print(f'[handshake] Sent encrypted session key (sk_fp={sk_fp}) using peer fp={peer_fp}', reprompt=False)
            
            if not session_established:
                session_established = True
                ui_print(f'[handshake] Session key established (sk_fp={sk_fp})', reprompt=False)
                flush_outgoing_queue()
    def maybe_fetch_peer_pub():
        nonlocal have_peer_pub, peer_pub, peer_pub_fp
        if not peer_id or have_peer_pub:
            return
        try:
            status, body = http_get(base + f'/pub?client={peer_id}', timeout=8.0)
            if status == 200:
                try:
                    obj = json.loads(body.decode('utf-8'))
                    pp = rsa_small.deserialize_pub(obj)
                    peer_pub = pp
                    peer_pub_fp = pub_fingerprint(peer_pub)
                    have_peer_pub = True
                    ui_print(f'[pka] Retrieved peer pub from server (fp={peer_pub_fp})', reprompt=False, newline_before=True)
                except Exception as e:
                    if VERBOSE:
                        print(f'[pka] bad pub parse: {e}')
            elif status == 404:
                
                if VERBOSE:
                    print('[pka] peer pub not found yet')
            else:
                if VERBOSE:
                    print(f'[pka] HTTP {status} fetching pub')
        except Exception as e:
            if VERBOSE:
                print(f'[pka] fetch error: {e}')
    def reset_handshake(new_session_key: bytes | None = None):
        nonlocal have_peer_pub, peer_pub, peer_pub_fp, session_established, my_pub_sent, key_sent, session_key
        have_peer_pub = False
        peer_pub = None
        peer_pub_fp = None
        session_established = False
        my_pub_sent = False
        key_sent = False
        session_key = new_session_key or os.urandom(8)

    
    prompt_state = {'active': False}
    def ui_print(msg: str, reprompt: bool = False, newline_before: bool = False):
        try:
            if newline_before:
                sys.stdout.write('\n')
            sys.stdout.write(msg + '\n')
            sys.stdout.flush()
            
        except Exception:
            pass

    def receiver_loop():
        nonlocal have_peer_pub, peer_pub, peer_pub_fp, session_established, session_key, peer_id, my_pub_sent, key_sent
        poll_wait = 30
        http_timeout = poll_wait + 5
        def _is_timeout_error(err: Exception) -> bool:
            try:
                import socket as _socket
                from urllib.error import URLError as _URLError
                if isinstance(err, _socket.timeout):
                    return True
                if isinstance(err, _URLError) and isinstance(getattr(err, 'reason', None), _socket.timeout):
                    return True
            except Exception:
                pass
            return 'timed out' in str(err).lower()
        while not stop_flag['stop']:
            try:
                status, body = http_get(base + f'/recv?client={my_id}&wait={poll_wait}', timeout=http_timeout)
            except Exception as e:
                
                if not stop_flag['stop'] and not _is_timeout_error(e):
                    ui_print(f'[recv] error: {e}')
                
                time.sleep(0.2)
                continue
            if status == 200:
                try: payload = json.loads(body.decode('utf-8'))
                except Exception as e: ui_print(f'[recv] invalid JSON {e}'); continue
                mtype = payload.get('type','text')
                raw = payload.get('msg','')
                sender = payload.get('from')
                if mtype == 'pub':
                    
                    if not peer_id and sender:
                        peer_id = sender
                        ui_print(f'[handshake] Auto-selected peer: {peer_id}', reprompt=False)
                    if sender == peer_id:
                        try:
                            incoming_pub = rsa_small.deserialize_pub(json.loads(raw))
                            incoming_fp = pub_fingerprint(incoming_pub)
                            
                            if peer_pub_fp and incoming_fp != peer_pub_fp:
                                ui_print(f'[handshake] Peer pub changed (old={peer_pub_fp} new={incoming_fp}); resetting session', reprompt=False)
                                reset_handshake()
                            peer_pub = incoming_pub
                            peer_pub_fp = incoming_fp
                            have_peer_pub = True
                            ui_print(f'[handshake] Received peer public key fp={peer_pub_fp}', reprompt=False)
                            maybe_send_session_key()
                        except Exception as e:
                            ui_print(f'[handshake] bad pub key: {e}', reprompt=False)
                elif mtype == 'keyx' and sender == peer_id:
                    
                    if not am_initiator() and not session_established:
                        try:
                            key_bytes = bytes.fromhex(raw)
                            sk = rsa_small.decrypt(key_bytes, priv)
                            if len(sk) == 8:
                                session_key = sk
                                session_established = True
                                sk_fp = hashlib.sha256(session_key).hexdigest()[:16]
                                ui_print(f'[handshake] Session key established (sk_fp={sk_fp})', reprompt=False)
                                flush_outgoing_queue()
                            else:
                                ui_print('[handshake] Invalid session key length')
                        except Exception as e:
                            ui_print(f'[handshake] key decrypt error: {e}')
                    else:
                        if VERBOSE:
                            ui_print('[handshake] Ignoring unexpected keyx (we are initiator or already established)')
                elif mtype == 'text':
                    ui_print(f'[recv] Encrypted from {sender}: {raw}', reprompt=False, newline_before=True)
                    if session_established:
                        try:
                            pt = decrypt_ecb_bytes(bytes.fromhex(raw), session_key)
                            
                            try:
                                size = int(payload.get('size', len(pt)))
                                if 0 <= size <= len(pt):
                                    pt = pt[:size]
                            except Exception:
                                pass
                            ui_print('[recv] Decrypted: ' + pt.decode('utf-8','replace'), reprompt=True)
                        except Exception as e:
                            ui_print(f'[recv] decrypt error: {e}')
                    else:
                        ui_print('[recv] (no session key yet)')
                elif mtype == 'bye' and sender == peer_id:
                    
                    ui_print(f"[info] Peer {sender} quit.", reprompt=False)
                    have_peer_pub = False
                    peer_pub = None
                    peer_pub_fp = None
                    session_established = False
                    my_pub_sent = False
                    key_sent = False
                    peer_id = None
                    session_key = os.urandom(8)
                    try:
                        
                        sys.stdout.write('[setup] Enter peer id (Enter to wait): ')
                        sys.stdout.flush()
                    except Exception:
                        pass
            elif status == 204:
                
                if VERBOSE:
                    ui_print('[recv] no messages (poll)', reprompt=False)
            
            maybe_fetch_peer_pub(); maybe_send_pub(); maybe_send_session_key()
    threading.Thread(target=receiver_loop, daemon=True).start()
    print('[chat] Type messages. /to <peer> to switch, /quit to exit.')
    maybe_send_pub()
    while True:
        try:
            prompt_state['active'] = True
            line = input().strip()
        except (EOFError, KeyboardInterrupt): line = '/quit'
        finally:
            prompt_state['active'] = False
        if not line: continue
        if line.lower().startswith('/dc'):
            
            if peer_id:
                try:
                    send_payload({'from': my_id, 'to': peer_id, 'type': 'bye', 'msg': ''})
                except Exception:
                    pass
                reset_handshake()
                peer_id = None
                print('[chat] Disconnected.')
                try:
                    sys.stdout.write('[setup] Enter peer id (Enter to wait): ')
                    sys.stdout.flush()
                except Exception:
                    pass
            else:
                print('[chat] Not connected.')
            continue
        if line.lower().startswith('/quit'):
            
            if peer_id:
                try:
                    send_payload({'from': my_id, 'to': peer_id, 'type': 'bye', 'msg': ''})
                except Exception:
                    pass
            stop_flag['stop'] = True
            print('[chat] Quit.')
            return
        
        if stop_flag['stop']:
            print('[chat] Quit.')
            return
        if line.lower().startswith('/to '):
            peer_id = line.split(None,1)[1].strip()
            reset_handshake()
            print(f'[chat] peer={peer_id} (handshake reset)')
            
            maybe_fetch_peer_pub(); maybe_send_pub(); maybe_send_session_key(); flush_outgoing_queue(); continue
        if not peer_id:
            
            candidate = line
            if candidate.lower().startswith('/dc'):
                print('[chat] Not connected.')
                continue
            if candidate.lower().startswith('/quit'):
                
                stop_flag['stop'] = True
                print('[chat] Quit.')
                return
            if candidate.lower().startswith('/to '):
                candidate = candidate.split(None,1)[1].strip()
            if not candidate:
                print('[chat] set peer first with /to <id>')
                continue
            peer_id = candidate.strip()
            reset_handshake()
            print(f'[info] peer={peer_id}')
            maybe_fetch_peer_pub(); maybe_send_pub(); maybe_send_session_key(); flush_outgoing_queue(); continue
        if not session_established:
            data = line.encode('utf-8')
            with queue_lock: outgoing_queue.append(data)
            print('[chat] queued (waiting handshake)')
            maybe_fetch_peer_pub(); maybe_send_pub(); maybe_send_session_key(); continue
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
        try:
            sys.exit(0)
        except SystemExit:
            pass

