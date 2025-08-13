import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Depends, status, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from livekit import api
import jwt

app = FastAPI(title="LiveKit Secure Token Server", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
API_KEY = os.getenv("LIVEKIT_API_KEY")
API_SECRET = os.getenv("LIVEKIT_API_SECRET")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
LIVEKIT_URL = os.getenv("LIVEKIT_URL", "ws://livekit:7880")

if not API_KEY or not API_SECRET:
    raise RuntimeError("LIVEKIT_API_KEY and LIVEKIT_API_SECRET must be set")

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

class TokenResponse(BaseModel):
    token: str
    url: str
    room: str
    participant: str

class CreateRoomRequest(BaseModel):
    room_name: str
    allowed_users: List[str] = []

# In-memory user store (replace with database in production)
USERS = {
    'admin': {
        'password_hash': hashlib.sha256('admin123madin'.encode()).hexdigest(),
        'permissions': ['join_any_room', 'create_room', 'moderate'],
        'name': 'Admin User'
    },
    'user1': {
        'password_hash': hashlib.sha256('password123'.encode()).hexdigest(),
        'permissions': ['join_room'],
        'name': 'Regular User'
    },
    'guest': {
        'password_hash': hashlib.sha256('guest123'.encode()).hexdigest(),
        'permissions': ['join_room'],
        'name': 'Guest User'
    },
    'mama': {
        'password_hash': hashlib.sha256('Marina#08'.encode()).hexdigest(),
        'permissions': ['join_room'],
        'name': 'Mama'
    }
}

# Room permissions (who can join which rooms)
ROOM_PERMISSIONS = {
    'public-room': ['*'],  # Anyone can join
    'private-room': ['admin', 'user1'],  # Only specific users
    'admin-room': ['admin'],  # Admin only,
    'family': ['admin', 'mama']
}

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
    """
    Get current user from JWT token (Bearer) or session cookie
    """
    token = None
    
    # Try to get token from Authorization header
    if credentials:
        token = credentials.credentials
    
    # Try to get token from cookie as fallback
    if not token:
        token = request.cookies.get("access_token")
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    payload = verify_token(token)
    username = payload.get("sub")
    
    if not username or username not in USERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user"
        )
    
    user_data = USERS[username]
    return {
        "username": username,
        "name": user_data["name"],
        "permissions": user_data["permissions"]
    }

@app.post("/login", response_model=LoginResponse)
async def login(login_data: LoginRequest, response: Response):
    """
    Authenticate user and return JWT token
    """
    username = login_data.username
    password = login_data.password
    
    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password required"
        )
    
    user = USERS.get(username)
    if not user or not verify_password(password, user['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Create JWT token
    token_data = {
        "sub": username,
        "name": user["name"],
        "permissions": user["permissions"],
        "iat": datetime.utcnow()
    }
    access_token = create_access_token(token_data)
    
    # Set cookie for browser compatibility
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True, 
        max_age=86400,  # 24 hours
        samesite="lax"
    )
    
    return LoginResponse(
        success=True,
        access_token=access_token,
        user={
            "username": username,
            "name": user["name"],
            "permissions": user["permissions"]
        }
    )

@app.post("/logout")
async def logout(response: Response):
    """
    Logout user by clearing the cookie
    """
    response.delete_cookie(key="access_token")
    return {"success": True}

@app.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Get current authenticated user information
    """
    return UserResponse(**current_user)

@app.get("/rooms")
async def get_available_rooms(current_user: dict = Depends(get_current_user)):
    """
    Get list of rooms the current user can access
    """
    username = current_user["username"]
    permissions = current_user["permissions"]
    
    available_rooms = []
    
    for room_name, allowed_users in ROOM_PERMISSIONS.items():
        # Check if user can join this room
        if ('*' in allowed_users or 
            username in allowed_users or 
            'join_any_room' in permissions):
            available_rooms.append(RoomInfo(
                name=room_name,
                display_name=room_name.replace('-', ' ').title()
            ))
    
    return {"rooms": available_rooms}

@app.get("/token", response_model=TokenResponse)
async def get_token(
    room: str = Query(..., description="Room name"),
    username: Optional[str] = Query(None, description="Participant name (optional)"),
    ttl_seconds: int = Query(3600, description="Token lifetime in seconds"),
    current_user: dict = Depends(get_current_user)
):
    """
    Generate LiveKit access token for authenticated user
    """
    user_username = current_user["username"]
    user_permissions = current_user["permissions"]
    participant_name = username or user_username
    
    # Check room permissions
    allowed_users = ROOM_PERMISSIONS.get(room, [])
    if not ('*' in allowed_users or 
            user_username in allowed_users or 
            'join_any_room' in user_permissions):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied to room: {room}"
        )
    
    try:
        # Create token with appropriate permissions
        at = api.AccessToken(API_KEY, API_SECRET)
        at.with_ttl(timedelta(seconds=ttl_seconds))
        at.with_identity(participant_name)
        at.with_name(current_user["name"])
        
        # Set up video grants
        grants = api.VideoGrants(
            room_join=True,
            room=room,
            can_publish=True,
            can_subscribe=True,
            can_publish_data=True,
        )
        
        # Add moderation permissions for admins
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
    """
    Create a new room (admin only)
    """
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
    
    # Add room to permissions (in production, save to database)
    ROOM_PERMISSIONS[room_name] = allowed_users
    
    return {
        "success": True,
        "room_name": room_name,
        "allowed_users": allowed_users
    }

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {"status": "healthy", "service": "livekit-auth-server"}

# Legacy endpoint for backwards compatibility
@app.get("/token-legacy")
async def get_token_legacy(
    room: str = Query(..., description="Room name"),
    username: str = Query(..., description="Participant name"),
    ttl_seconds: int = Query(60, description="Token lifetime in seconds")
):
    """
    Legacy token endpoint (no authentication - for testing only)
    WARNING: This bypasses authentication! Remove in production.
    """
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)