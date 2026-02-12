from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import secrets
import hashlib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import os
import json
import bcrypt
import time

# Simple file-based storage (no database needed for quick start)
USERS_FILE = "users.json"
KEYS_FILE = "keys.json"
SESSIONS_FILE = "sessions.json"

# Environment setup
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
cipher = Fernet(ENCRYPTION_KEY.encode())

# Initialize storage files
for file in [USERS_FILE, KEYS_FILE, SESSIONS_FILE]:
    if not os.path.exists(file):
        with open(file, 'w') as f:
            json.dump({}, f)

def load_json(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2, default=str)

# FastAPI app
app = FastAPI(title="API Key Management Dashboard")

# CORS - Allow all origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper functions
def generate_key():
    return f"akm_{secrets.token_urlsafe(32)}"

def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

def encrypt_key(key):
    return cipher.encrypt(key.encode()).decode()

def decrypt_key(encrypted):
    return cipher.decrypt(encrypted.encode()).decode()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_session(user_id):
    session_id = secrets.token_urlsafe(32)
    sessions = load_json(SESSIONS_FILE)
    sessions[session_id] = {
        "user_id": user_id,
        "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat()
    }
    save_json(SESSIONS_FILE, sessions)
    return session_id

def verify_session(session_id):
    sessions = load_json(SESSIONS_FILE)
    session = sessions.get(session_id)
    if not session:
        return None
    if datetime.utcnow() > datetime.fromisoformat(session["expires_at"]):
        del sessions[session_id]
        save_json(SESSIONS_FILE, sessions)
        return None
    return session["user_id"]

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    session_id = authorization.replace("Bearer ", "")
    user_id = verify_session(session_id)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return user_id

# Routes
@app.post("/api/auth/register")
async def register(data: dict):
    email = data.get("email")
    password = data.get("password")
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")
    
    users = load_json(USERS_FILE)
    if email in users:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    users[email] = {
        "user_id": secrets.token_urlsafe(16),
        "email": email,
        "password_hash": hash_password(password),
        "created_at": datetime.utcnow().isoformat()
    }
    save_json(USERS_FILE, users)
    
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
async def login(data: dict):
    email = data.get("email")
    password = data.get("password")
    
    users = load_json(USERS_FILE)
    user = users.get(email)
    
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    session_id = create_session(user["user_id"])
    return {
        "sessionId": session_id,
        "userId": user["user_id"],
        "email": user["email"]
    }

@app.post("/api/auth/logout")
async def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        session_id = authorization.replace("Bearer ", "")
        sessions = load_json(SESSIONS_FILE)
        if session_id in sessions:
            del sessions[session_id]
            save_json(SESSIONS_FILE, sessions)
    return {"message": "Logged out successfully"}

@app.get("/api/keys")
async def list_keys(user_id: str = Header(None, alias="Authorization")):
    user_id = get_current_user(user_id)
    keys = load_json(KEYS_FILE)
    user_keys = [k for k in keys.values() if k["user_id"] == user_id]
    user_keys.sort(key=lambda x: x["created_at"], reverse=True)
    
    return {
        "keys": [
            {
                "keyId": k["key_id"],
                "label": k["label"],
                "provider": k["provider"],
                "status": k["status"],
                "createdAt": k["created_at"],
                "lastUsedAt": k.get("last_used_at"),
                "usageCount": k.get("usage_count", 0),
                "avgResponseTimeMs": round(
                    sum(r["response_time_ms"] for r in k.get("response_times", [])) / len(k.get("response_times", [])) 
                    if k.get("response_times") else 0, 
                    2
                )
            }
            for k in user_keys
        ]
    }

@app.post("/api/keys")
async def create_key(data: dict, user_id: str = Header(None, alias="Authorization")):
    user_id = get_current_user(user_id)
    
    key_value = generate_key()
    key_hash_value = hash_key(key_value)
    key_id = secrets.token_urlsafe(16)
    
    keys = load_json(KEYS_FILE)
    keys[key_id] = {
        "key_id": key_id,
        "user_id": user_id,
        "key_value_encrypted": encrypt_key(key_value),
        "key_hash": key_hash_value,
        "label": data.get("label", ""),
        "provider": data.get("provider", "internal"),
        "status": "active",
        "created_at": datetime.utcnow().isoformat(),
        "last_used_at": None
    }
    save_json(KEYS_FILE, keys)
    
    return {
        "keyId": key_id,
        "keyValue": key_value,
        "label": keys[key_id]["label"],
        "provider": keys[key_id]["provider"],
        "status": keys[key_id]["status"],
        "createdAt": keys[key_id]["created_at"]
    }

@app.patch("/api/keys/{key_id}")
async def update_key(key_id: str, data: dict, user_id: str = Header(None, alias="Authorization")):
    user_id = get_current_user(user_id)
    
    keys = load_json(KEYS_FILE)
    key = keys.get(key_id)
    
    if not key or key["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Key not found")
    
    if "label" in data:
        key["label"] = data["label"]
    if "status" in data:
        key["status"] = data["status"]
    
    save_json(KEYS_FILE, keys)
    return {"message": "Key updated successfully"}

@app.delete("/api/keys/{key_id}")
async def delete_key(key_id: str, user_id: str = Header(None, alias="Authorization")):
    user_id = get_current_user(user_id)
    
    keys = load_json(KEYS_FILE)
    key = keys.get(key_id)
    
    if not key or key["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Key not found")
    
    del keys[key_id]
    save_json(KEYS_FILE, keys)
    return {"message": "Key deleted successfully"}

@app.post("/api/validate")
async def validate_key(
    data: Optional[dict] = None,
    x_api_key: Optional[str] = Header(None),
    api_key: Optional[str] = Query(None)
):
    start_time = time.time()
    
    key_value = None
    if data and "apiKey" in data:
        key_value = data["apiKey"]
    elif x_api_key:
        key_value = x_api_key
    elif api_key:
        key_value = api_key
    
    if not key_value:
        raise HTTPException(status_code=400, detail="API key required")
    
    key_hash_value = hash_key(key_value)
    keys = load_json(KEYS_FILE)
    
    key = None
    for k in keys.values():
        if k["key_hash"] == key_hash_value:
            key = k
            break
    
    if not key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if key["status"] != "active":
        raise HTTPException(status_code=401, detail="API key is inactive")
    
    # Update last used and track performance
    key["last_used_at"] = datetime.utcnow().isoformat()
    
    # Track usage stats
    if "usage_count" not in key:
        key["usage_count"] = 0
    key["usage_count"] += 1
    
    # Track response times
    if "response_times" not in key:
        key["response_times"] = []
    
    response_time_ms = (time.time() - start_time) * 1000
    key["response_times"].append({
        "timestamp": datetime.utcnow().isoformat(),
        "response_time_ms": round(response_time_ms, 2)
    })
    
    # Keep only last 100 response times
    if len(key["response_times"]) > 100:
        key["response_times"] = key["response_times"][-100:]
    
    save_json(KEYS_FILE, keys)
    
    return {
        "valid": True,
        "userId": key["user_id"],
        "keyId": key["key_id"],
        "provider": key["provider"],
        "responseTimeMs": round(response_time_ms, 2)
    }

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/keys/{key_id}/stats")
async def get_key_stats(key_id: str, user_id: str = Header(None, alias="Authorization")):
    user_id = get_current_user(user_id)
    
    keys = load_json(KEYS_FILE)
    key = keys.get(key_id)
    
    if not key or key["user_id"] != user_id:
        raise HTTPException(status_code=404, detail="Key not found")
    
    # Calculate average response time
    response_times = key.get("response_times", [])
    avg_response_time = 0
    if response_times:
        avg_response_time = sum(r["response_time_ms"] for r in response_times) / len(response_times)
    
    return {
        "keyId": key_id,
        "usageCount": key.get("usage_count", 0),
        "avgResponseTimeMs": round(avg_response_time, 2),
        "lastUsedAt": key.get("last_used_at"),
        "recentResponseTimes": response_times[-10:] if response_times else []
    }

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting API Key Management Dashboard...")
    print("📍 Backend: http://localhost:8000")
    print("📍 Frontend: http://localhost:3000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
