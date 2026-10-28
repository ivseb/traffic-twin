"""Fake CATALOG external API (fake data only). Port 9511."""
import random, uuid, os
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI()
RES = {}
BOOKS = [f"BK-{i:04d}" for i in range(1, 201)]

@app.get("/v1/books/{book_id}")
def book(book_id: str):
    return {"id": book_id, "title": f"Libro {book_id}", "copies": random.randint(0, 5), "genre": random.choice(["giallo", "fantasy", "storia", "scienza"])}

@app.post("/v1/reservations")
async def reserve(req: Request):
    body = await req.json()
    r = random.random()
    if r < 0.01:
        return JSONResponse({"error": {"code": "unavailable", "message": "catalog down"}}, status_code=503)
    if r < 0.06:
        return JSONResponse({"error": {"code": "not_available", "message": "no copies left"}}, status_code=409)
    rid = "RSV-" + uuid.uuid4().hex[:10]
    RES[rid] = {"id": rid, "bookId": body.get("bookId"), "status": "reserved", "dueDays": 21}
    return JSONResponse(RES[rid], status_code=201)

@app.get("/v1/reservations/{rid}")
def get_res(rid: str):
    if rid not in RES:
        return JSONResponse({"error": {"code": "not_found"}}, status_code=404)
    return RES[rid]
