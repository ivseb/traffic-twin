"""Fake NOTIFICATIONS external API (fake data only). Port 9512.
POST /v1/messages -> 202 queued. GET /v1/messages/{id} -> queued, then delivered (~90%) or bounced (~10%) after 3s."""
import random, time, uuid
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
MSG = {}

@app.post("/v1/messages")
async def send(req: Request):
    body = await req.json()
    mid = "MSG-" + uuid.uuid4().hex[:10]
    MSG[mid] = {"id": mid, "channel": body.get("channel", "email"), "template": body.get("template"),
                "created": time.time(), "final": "bounced" if random.random() < 0.10 else "delivered"}
    return JSONResponse({"id": mid, "status": "queued"}, status_code=202)

@app.get("/v1/messages/{mid}")
def get_msg(mid: str):
    m = MSG.get(mid)
    if not m:
        return JSONResponse({"error": {"code": "not_found"}}, status_code=404)
    st = m["final"] if time.time() - m["created"] > 3 else "queued"
    out = {"id": mid, "status": st, "channel": m["channel"]}
    if st == "bounced":
        out["reason"] = random.choice(["mailbox_full", "invalid_address"])
    return out
