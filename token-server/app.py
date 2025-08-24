import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, Depends, status, Request, Response, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from livekit import api
import jwt
import asyncpg
from contextlib import asynccontextmanager

app = FastAPI(title="LiveKit Secure Token Server", version="1.0.0")

# Jinja2 templates for serving admin.html
templates = Jinja2Templates(directory="/srv/www")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://viken.stream:8443"],  # Restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
API_KEY = os.getenv("LIVEKIT_API_KEY")
API_SECRET = os.getenv("LIVEKIT_API_SECRET")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
LIVEKIT_URL = os.getenv("LIVEKIT_URL", "ws://livekit:7880")
DB_URL = os.getenv("DATABASE_URL")

if not API_KEY or not API_SECRET:
    raise RuntimeError("LIVEKIT_API_KEY and LIVEKIT_API_SECRET must be set")

# Database connection pool
async def init_db():
    app.state.db_pool = await asyncpg.create_pool(DB_URL)
    async with app.state.db_pool.acquire() as conn:
        # Create tables if they don't exist
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(50) PRIMARY KEY,
                password_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                permissions TEXT[] NOT NULL
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS rooms (
                room_name VARCHAR(100) PRIMARY KEY,
                allowed_users TEXT[] NOT NULL
            )
        ''')

@asynccontextmanager
async def get_db():
    async with app.state.db_pool.acquire() as conn:
        yield conn

### Initialize database on startup
@app.on_event("startup")
async def startup_event():
    await init_db()

# Security
security = HTTPBearer(auto_error=False)

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    success: bool
    access_token: str
    user: Dict

class UserResponse(BaseModel):
    username: str
    name: str
    permissions: List[str]

class RoomInfo(BaseModel):
    name: str
    display_name: str
    allowed_users: List[str]

class TokenResponse(BaseModel):
    token: str
    url: str
    room: str
    participant: str

class CreateRoomRequest(BaseModel):
    room_name: str
    allowed_users: List[str] = []

class CreateUserRequest(BaseModel):
    username: str
    password: str
    name: str
    permissions: List[str] = []

class UpdatePermissionsRequest(BaseModel):
    permissions: List[str]

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == password_hash

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    token = None
    if credentials:
        token = credentials.credentials
    if not token:
        token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    payload = verify_token(token)
    username = payload.get("sub")
    
    async with get_db() as conn:
        user = await conn.fetchrow(
            'SELECT username, name, permissions FROM users WHERE username = $1',
            username
        )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user"
        )
    
    return {
        "username": user["username"],
        "name": user["name"],
        "permissions": user["permissions"]
    }

# Middleware to enforce admin access for admin panel
@app.middleware("http")
async def admin_auth_middleware(request: Request, call_next):
    if request.url.path == "/admin":
        token = request.cookies.get("access_token")
        if not token:
            return Response(content="Unauthorized", status_code=401)
        payload = verify_token(token)
        username = payload.get("sub")
        async with get_db() as conn:
            user = await conn.fetchrow(
                'SELECT permissions FROM users WHERE username = $1',
                username
            )
        if not user or "manage_permissions" not in user["permissions"]:
            return Response(content="Forbidden: Admin access required", status_code=403)
    response = await call_next(request)
    return response

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(current_user: dict = Depends(get_current_user)):
    permissions = current_user.get("permissions", [])
    if "manage_permissions" not in permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Admin access required"
        )
    return FileResponse("/srv/www/admin.html")

@app.post("/login", response_model=LoginResponse)
async def login(login_data: LoginRequest, response: Response):
    async with get_db() as conn:
        user = await conn.fetchrow(
            'SELECT username, password_hash, name, permissions FROM users WHERE username = $1',
            login_data.username
        )
    
    if not user or not verify_password(login_data.password, user['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    token_data = {
        "sub": user["username"],
        "name": user["name"],
        "permissions": user["permissions"],
        "iat": datetime.utcnow()
    }
    access_token = create_access_token(token_data)
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=86400,
        samesite="lax",
        secure=True  # Ensure this is set if using HTTPS
    )
    
    return LoginResponse(
        success=True,
        access_token=access_token,
        user={
            "username": user["username"],
            "name": user["name"],
            "permissions": user["permissions"]
        }
    )

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"success": True}

@app.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

@app.get("/rooms")
async def get_available_rooms(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    permissions = current_user["permissions"]
    
    async with get_db() as conn:
        rooms = await conn.fetch('SELECT room_name, allowed_users FROM rooms')
    
    available_rooms = []
    for room in rooms:
        if ('*' in room['allowed_users'] or 
            username in room['allowed_users'] or 
            'join_any_room' in permissions):
            available_rooms.append(RoomInfo(
                name=room['room_name'],
                display_name=room['room_name'].replace('-', ' ').title(),
                allowed_users=room['allowed_users']
            ))
    
    return {"rooms": available_rooms}

@app.get("/token", response_model=TokenResponse)
async def get_token(
    room: str = Query(..., description="Room name"),
    username: Optional[str] = Query(None, description="Participant name (optional)"),
    ttl_seconds: int = Query(3600, description="Token lifetime in seconds"),
    current_user: dict = Depends(get_current_user)
):
    user_username = current_user["username"]
    user_permissions = current_user["permissions"]
    participant_name = username or user_username
    
    async with get_db() as conn:
        room_data = await conn.fetchrow(
            'SELECT allowed_users FROM rooms WHERE room_name = $1',
            room
        )
    
    if not room_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Room not found: {room}"
        )
    
    allowed_users = room_data['allowed_users']
    if not ('*' in allowed_users or 
            user_username in allowed_users or 
            'join_any_room' in user_permissions):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied to room: {room}"
        )
    
    try:
        at = api.AccessToken(API_KEY, API_SECRET)
        at.with_ttl(timedelta(seconds=ttl_seconds))
        at.with_identity(participant_name)
        at.with_name(current_user["name"])
        
        grants = api.VideoGrants(
            room_join=True,
            room=room,
            can_publish=True,
            can_subscribe=True,
            can_publish_data=True,
        )
        
        if 'moderate' in user_permissions:
            grants.room_admin = True
            grants.can_update_own_metadata = True
        
        at.with_grants(grants)
        token = at.to_jwt()
        
        return TokenResponse(
            token=token,
            url=LIVEKIT_URL,
            room=room,
            participant=participant_name
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate token: {str(e)}"
        )

@app.post("/create-room")
async def create_room(
    room_data: CreateRoomRequest,
    current_user: dict = Depends(get_current_user)
):
    if 'create_room' not in current_user["permissions"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: cannot create rooms"
        )
    
    room_name = room_data.room_name
    allowed_users = room_data.allowed_users or [current_user["username"]]
    
    if not room_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Room name required"
        )
    
    async with get_db() as conn:
        try:
            await conn.execute(
                'INSERT INTO rooms (room_name, allowed_users) VALUES ($1, $2)',
                room_name, allowed_users
            )
        except asyncpg.exceptions.UniqueViolationError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Room already exists"
            )
    
    return {
        "success": True,
        "room_name": room_name,
        "allowed_users": allowed_users
    }

@app.post("/users")
async def create_user(
    user_data: CreateUserRequest,
    current_user: dict = Depends(get_current_user)
):
    if 'create_user' not in current_user["permissions"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: cannot create users"
        )
    
    async with get_db() as conn:
        try:
            await conn.execute(
                '''
                INSERT INTO users (username, password_hash, name, permissions)
                VALUES ($1, $2, $3, $4)
                ''',
                user_data.username,
                hash_password(user_data.password),
                user_data.name,
                user_data.permissions
            )
        except asyncpg.exceptions.UniqueViolationError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
    
    return {"success": True, "username": user_data.username}

@app.delete("/users/{username}")
async def delete_user(
    username: str,
    current_user: dict = Depends(get_current_user)
):
    if 'delete_user' not in current_user["permissions"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: cannot delete users"
        )
    
    async with get_db() as conn:
        result = await conn.execute(
            'DELETE FROM users WHERE username = $1',
            username
        )
    
    if result == "DELETE 0":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {"success": True}

@app.delete("/rooms/{room_name}")
async def delete_room(
    room_name: str,
    current_user: dict = Depends(get_current_user)
):
    if 'delete_room' not in current_user["permissions"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: cannot delete rooms"
        )
    
    async with get_db() as conn:
        result = await conn.execute(
            'DELETE FROM rooms WHERE room_name = $1',
            room_name
        )
    
    if result == "DELETE 0":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Room not found"
        )
    
    return {"success": True}

@app.put("/users/{username}/permissions")
async def update_user_permissions(
    username: str,
    permissions_data: UpdatePermissionsRequest,
    current_user: dict = Depends(get_current_user)
):
    if 'manage_permissions' not in current_user["permissions"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: cannot manage permissions"
        )
    
    async with get_db() as conn:
        result = await conn.execute(
            'UPDATE users SET permissions = $1 WHERE username = $2',
            permissions_data.permissions,
            username
        )
    
    if result == "UPDATE 0":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {"success": True, "username": username}

@app.put("/rooms/{room_name}/allowed-users")
async def update_room_allowed_users(
    room_name: str,
    allowed_users: List[str] = Body(...),
    current_user: dict = Depends(get_current_user)
):
    if 'manage_permissions' not in current_user["permissions"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: cannot manage room permissions"
        )
    
    async with get_db() as conn:
        result = await conn.execute(
            'UPDATE rooms SET allowed_users = $1 WHERE room_name = $2',
            allowed_users,
            room_name
        )
    
    if result == "UPDATE 0":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Room not found"
        )
    
    return {"success": True, "room_name": room_name}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "livekit-auth-server"}

@app.get("/token-legacy")
async def get_token_legacy(
    room: str = Query(..., description="Room name"),
    username: str = Query(..., description="Participant name"),
    ttl_seconds: int = Query(60, description="Token lifetime in seconds")
):
    try:
        at = api.AccessToken(API_KEY, API_SECRET)
        at.with_ttl(timedelta(seconds=ttl_seconds))
        at.with_identity(username)
        at.with_name(username)
        grants = api.VideoGrants(room_join=True, room=room)
        at.with_grants(grants)
        token = at.to_jwt()
        return {"token": token}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    try:
        async with get_db() as conn:
            user_data = await conn.fetch('SELECT username, name, permissions FROM users')
            users = [dict(row) for row in user_data]
            return {"users": users}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching users: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)