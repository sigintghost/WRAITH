import ssl, urllib.request, json, os

VERIFY = os.environ.get("WRAITH_TLS_VERIFY", "1") != "0"

def _ctx():
    ctx = ssl.create_default_context()
    if not VERIFY:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def get(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, context=_ctx(), timeout=timeout) as r:
        return json.loads(r.read().decode())

def post(url, payload, headers=None, timeout=10):
    data = json.dumps(payload).encode()
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, context=_ctx(), timeout=timeout) as r:
        return json.loads(r.read().decode())
