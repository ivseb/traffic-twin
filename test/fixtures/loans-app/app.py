"""Library loans API (my service). Run: uvicorn app:app --port 8000"""
import base64, hashlib, hmac, json, os, time, uuid
import httpx
from fastapi import FastAPI, Header, HTTPException

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret").encode()
CATALOG = os.environ.get("CATALOG_BASE_URL", "http://127.0.0.1:9511")
NOTIFY = os.environ.get("NOTIFY_BASE_URL", "http://127.0.0.1:9512")
SESSION = os.environ.get("TT_SESSION")  # optional: forwarded as X-TT-Session to the mock

app = FastAPI(title="library-loans")
LOANS: dict = {}
client = httpx.Client(timeout=5.0)

def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def member_from(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer")
    try:
        h, p, sig = authorization[7:].split(".")
        exp = hmac.new(JWT_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(exp, _b64d(sig)):
            raise ValueError
        return json.loads(_b64d(p))["sub"]
    except Exception:
        raise HTTPException(401, "bad token")

def ext_headers():
    h = {"x-api-key": "fake-key"}
    sid = os.environ.get("TT_SESSION")
    if sid:
        h["X-TT-Session"] = sid
    return h

@app.post("/loans", status_code=201)
def create_loan(body: dict, authorization: str | None = Header(None)):
    member = member_from(authorization)
    book = body.get("bookId")
    if not book:
        raise HTTPException(422, "bookId required")
    try:
        r = client.post(f"{CATALOG}/v1/reservations", json={"bookId": book, "memberId": member}, headers=ext_headers())
    except httpx.HTTPError:
        raise HTTPException(502, "catalog unreachable")
    if r.status_code == 409:
        raise HTTPException(409, "book not available")
    if r.status_code >= 500:
        raise HTTPException(503, "catalog unavailable")
    res = r.json()
    n = client.post(f"{NOTIFY}/v1/messages", json={"channel": "email", "template": "loan_confirmation", "memberId": member}, headers=ext_headers())
    nid = n.json().get("id") if n.status_code < 300 else None
    loan = {"id": "L-" + uuid.uuid4().hex[:10], "memberId": member, "bookId": book, "reservationId": res["id"],
            "notificationId": nid, "status": "active", "notification": "queued", "createdAt": time.time()}
    LOANS[loan["id"]] = loan
    return loan

def _refresh(loan):
    if loan.get("notificationId") and loan["notification"] in ("queued",):
        r = client.get(f"{NOTIFY}/v1/messages/{loan['notificationId']}", headers=ext_headers())
        if r.status_code == 200:
            loan["notification"] = r.json()["status"]
    return loan

@app.get("/loans/{loan_id}")
def get_loan(loan_id: str, authorization: str | None = Header(None)):
    member = member_from(authorization)
    loan = LOANS.get(loan_id)
    if not loan or loan["memberId"] != member:
        raise HTTPException(404, "not found")
    return _refresh(loan)

@app.get("/members/{member_id}/loans")
def member_loans(member_id: str, authorization: str | None = Header(None)):
    member = member_from(authorization)
    if member != member_id:
        raise HTTPException(403, "forbidden")
    return {"items": [_refresh(l) for l in LOANS.values() if l["memberId"] == member_id]}
