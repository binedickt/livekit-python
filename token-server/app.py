import os
import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from livekit import api

app = FastAPI()

LIVEKIT_URL = os.getenv("LIVEKIT_URL", "https://your.domain.example")
API_KEY = os.getenv("LIVEKIT_API_KEY")
API_SECRET = os.getenv("LIVEKIT_API_SECRET")

if not API_KEY or not API_SECRET:
    raise RuntimeError("LIVEKIT_API_KEY and LIVEKIT_API_SECRET must be set")

class TokenRequest(BaseModel):
    room: str
    identity: str | None = None
    name: str | None = None
    ttl_seconds: int = 60  # short lived by default

@app.post("/api/token")
def create_token(req: TokenRequest):
    identity = req.identity or f"user-{os.urandom(4).hex()}"
    at = api.AccessToken(API_KEY, API_SECRET)
    # set expiry
    at.with_ttl(datetime.timedelta(seconds=req.ttl_seconds))
    # set identity & name
    at.with_identity(identity)
    if req.name:
        at.with_name(req.name)
    # grant room join to a specific room
    grants = api.VideoGrants(room_join=True, room=req.room)
    at.with_grants(grants)
    token = at.to_jwt()
    return {"token": token, "url": LIVEKIT_URL, "identity": identity}
