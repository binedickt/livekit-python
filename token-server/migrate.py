import asyncio
import asyncpg
import hashlib

async def migrate_data():
    DB_URL = "postgresql://user:password@postgres:5432/livekit"
    
    USERS = {
        'admin': {
            'password_hash': hashlib.sha256('admin123madin'.encode()).hexdigest(),
            'permissions': ['join_any_room', 'create_room', 'moderate', 'create_user', 'delete_user', 'delete_room', 'manage_permissions'],
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

    ROOM_PERMISSIONS = {
        'public-room': ['*'],
        'private-room': ['admin', 'user1'],
        'admin-room': ['admin'],
        'family': ['admin', 'mama']
    }

    conn = await asyncpg.connect(DB_URL)
    
    # Insert users
    for username, data in USERS.items():
        await conn.execute(
            '''
            INSERT INTO users (username, password_hash, name, permissions)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (username) DO NOTHING
            ''',
            username, data['password_hash'], data['name'], data['permissions']
        )
    
    # Insert rooms
    for room_name, allowed_users in ROOM_PERMISSIONS.items():
        await conn.execute(
            '''
            INSERT INTO rooms (room_name, allowed_users)
            VALUES ($1, $2)
            ON CONFLICT (room_name) DO NOTHING
            ''',
            room_name, allowed_users
        )
    
    await conn.close()

if __name__ == "__main__":
    asyncio.run(migrate_data())