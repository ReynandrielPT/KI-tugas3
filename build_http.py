from urllib.request import Request, urlopen
from urllib.parse import urlencode, urljoin
from typing import Dict, Any, Tuple, Optional

DEFAULT_HEADERS = {
    'Content-Type': 'application/json',
}


def http_post_json(url: str, obj: Dict[str, Any], headers: Optional[Dict[str, str]] = None, timeout: float = 10.0) -> Tuple[int, bytes]:
    hdrs = dict(DEFAULT_HEADERS)
    if headers:
        hdrs.update(headers)
    data = None
    if obj is not None:
        import json as _json
        data = _json.dumps(obj).encode('utf-8')
    req = Request(url, data=data, headers=hdrs, method='POST')
    with urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read()


def http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 10.0) -> Tuple[int, bytes]:
    hdrs = {}
    if headers:
        hdrs.update(headers)
    req = Request(url, headers=hdrs, method='GET')
    with urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read()


def build_url(base: str, path: str, query: Optional[Dict[str, Any]] = None) -> str:
    if not base.endswith('/') and not path.startswith('/'):
        base = base + '/'
    url = urljoin(base, path)
    if query:
        url = url + ('?' + urlencode(query))
    return url
