import os
import datetime
from fastapi import FastAPI, HTTPException, Query
from livekit import api

app = FastAPI()

API_KEY = os.getenv("LIVEKIT_API_KEY")
API_SECRET = os.getenv("LIVEKIT_API_SECRET")

if not API_KEY or not API_SECRET:
    raise RuntimeError("LIVEKIT_API_KEY and LIVEKIT_API_SECRET must be set")


@app.get("/token")
def get_token(
    room: str = Query(..., description="Room name"),
    username: str = Query(..., description="Participant name"),
    ttl_seconds: int = Query(60, description="Token lifetime in seconds")
):
    try:
        at = api.AccessToken(API_KEY, API_SECRET)
        at.with_ttl(datetime.timedelta(seconds=ttl_seconds))
        at.with_identity(username)
        at.with_name(username)
        grants = api.VideoGrants(room_join=True, room=room)
        at.with_grants(grants)
        token = at.to_jwt()
        return {"token": token}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))