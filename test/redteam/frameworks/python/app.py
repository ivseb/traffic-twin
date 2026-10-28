# Red team round 3: FastAPI app with the Python SDK installed as documented
# (traffic_twin.install(app): ASGI middleware, outermost). The app never logs
# request data itself: a canary in the logs comes from the SDK (or uvicorn).
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

import traffic_twin

app = FastAPI()


@app.get("/health")
def health():
    return PlainTextResponse("ok")


@app.post("/orders/{id}")
async def order(id: str, request: Request):
    b = await request.json()
    r = JSONResponse(status_code=201, content={"id": id, "status": "created", "echo": b.get("secret"),
                                                "email": (b.get("nested") or {}).get("email")})
    r.headers["x-echo"] = request.headers.get("x-secret", "")
    r.set_cookie("sess", str(b.get("secret", "")))
    return r


@app.get("/fail/{v}")
def fail(v: str):
    return JSONResponse(status_code=500, content={"error": {"code": "E_FAIL", "message": f"order {v} failed"}})


@app.get("/boom/{v}")
def boom(v: str):
    raise RuntimeError(f"boom {v}")  # unhandled: 500, traceback logged by uvicorn


app = traffic_twin.install(app)
