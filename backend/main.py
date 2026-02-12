from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import secrets
import hashlib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import os
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import bcrypt
import httpx
from functools import lru_cache

# Environment setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./api_keys.db")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")

# Database setup
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Encryption
cipher = Fernet(ENCRYPTION_KEY.encode())

# Models
class User(Base):
    __tablename__ = "users"
    user_id = Column(String, primary_key=True)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class APIKey(Base):
    __tablename__ = "api_keys"
    key_id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False, index=True)
    key_value_encrypted = Column(String, nullable=False)
    key_hash = Column(String, unique=True, nullable=False, index=True)
    label = Column(String)
    provider = Column(String, default="internal")
    status = Column(String, default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index('idx_user_status', 'user_id', 'status'),
    )

# Create tables
Base.metadata.create_all(bind=engine)

# In-memory session store (for quick MVP - use Redis in production)
sessions = {}
failed_attempts = {}

# FastAPI app
app = FastAPI(title="API Key Management Dashboard")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class LoginRequest(BaseModel):
    email: str
    password: str

class CreateKeyRequest(BaseModel):
    label: Optional[str] = None
    provider: str = "internal"

class UpdateKeyRequest(BaseModel):
    label: Optional[str] = None
    status: Optional[str] = None

class ValidateKeyRequest(BaseModel):
    apiKey: str

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper functions
def generate_key() -> str:
    """Generate cryptographically secure API key with 256 bits entropy"""
    random_bytes = secrets.token_urlsafe(32)
    return f"akm_{random_bytes}"

def hash_key(key: str) -> str:
    """Generate SHA-256 hash of key for lookup"""
    return hashlib.sha256(key.encode()).hexdigest()

def encrypt_key(key: str) -> str:
    """Encrypt key value"""
    return cipher.encrypt(key.encode()).decode()

def decrypt_key(encrypted: str) -> str:
    """Decrypt key value"""
    return cipher.decrypt(encrypted.encode()).decode()

def hash_password(password: str) -> str:
    """Hash password with bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_session(user_id: str) -> str:
    """Create session with 24 hour expiration"""
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        "user_id": user_id,
        "expires_at": datetime.utcnow() + timedelta(hours=24)
    }
    return session_id

def verify_session(session_id: str) -> Optional[str]:
    """Verify session and return user_id"""
    session = sessions.get(session_id)
    if not session:
        return None
    if datetime.utcnow() > session["expires_at"]:
        del sessions[session_id]
        return None
    return session["user_id"]

# NVIDIA API validation with caching
@lru_cache(maxsize=1000)
def validate_nvidia_key_cached(api_key: str, cache_time: int) -> dict:
    """Validate NVIDIA API key with 5-minute cache"""
    try:
        # NVIDIA API validation endpoint
        response = httpx.get(
            "https://api.nvcf.nvidia.com/v2/nvcf/functions",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=2.0
        )
        return {
            "valid": response.status_code == 200,
            "error": None if response.status_code == 200 else f"NVIDIA API error: {response.status_code}"
        }
    except Exception as e:
        return {"valid": False, "error": f"NVIDIA API connection error: {str(e)}"}

def validate_nvidia_key(api_key: str) -> dict:
    """Validate NVIDIA key with 5-minute cache"""
    cache_time = int(datetime.utcnow().timestamp() / 300)  # 5-minute buckets
    return validate_nvidia_key_cached(api_key, cache_time)

# Auth dependency
async def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> str:
    """Get current user from session"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    session_id = authorization.replace("Bearer ", "")
    user_id = verify_session(session_id)
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    return user_id

# Routes
@app.post("/api/auth/register")
async def register(request: LoginRequest, db: Session = Depends(get_db)):
    """Register new user"""
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = User(
        user_id=secrets.token_urlsafe(16),
        email=request.email,
        password_hash=hash_password(request.password)
    )
    db.add(user)
    db.commit()
    
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Login and create session"""
    # Rate limiting check
    attempts_key = request.email
    if attempts_key in failed_attempts:
        attempts, last_attempt = failed_attempts[attempts_key]
        if attempts >= 5 and datetime.utcnow() - last_attempt < timedelta(minutes=15):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")
    
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.password_hash):
        # Track failed attempt
        if attempts_key in failed_attempts:
            attempts, _ = failed_attempts[attempts_key]
            failed_attempts[attempts_key] = (attempts + 1, datetime.utcnow())
        else:
            failed_attempts[attempts_key] = (1, datetime.utcnow())
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Clear failed attempts on success
    if attempts_key in failed_attempts:
        del failed_attempts[attempts_key]
    
    session_id = create_session(user.user_id)
    return {
        "sessionId": session_id,
        "userId": user.user_id,
        "email": user.email
    }

@app.post("/api/auth/logout")
async def logout(authorization: Optional[str] = Header(None)):
    """Logout and destroy session"""
    if authorization and authorization.startswith("Bearer "):
        session_id = authorization.replace("Bearer ", "")
        if session_id in sessions:
            del sessions[session_id]
    return {"message": "Logged out successfully"}

@app.get("/api/keys")
async def list_keys(user_id: str = Depends(get_current_user), db: Session = Depends(get_db)):
    """List all keys for authenticated user"""
    keys = db.query(APIKey).filter(APIKey.user_id == user_id).order_by(APIKey.created_at.desc()).all()
    
    return {
        "keys": [
            {
                "keyId": key.key_id,
                "label": key.label,
                "provider": key.provider,
                "status": key.status,
                "createdAt": key.created_at.isoformat(),
                "lastUsedAt": key.last_used_at.isoformat() if key.last_used_at else None
            }
            for key in keys
        ]
    }

@app.post("/api/keys")
async def create_key(request: CreateKeyRequest, user_id: str = Depends(get_current_user), db: Session = Depends(get_db)):
    """Create new API key"""
    key_value = generate_key()
    key_hash_value = hash_key(key_value)
    
    api_key = APIKey(
        key_id=secrets.token_urlsafe(16),
        user_id=user_id,
        key_value_encrypted=encrypt_key(key_value),
        key_hash=key_hash_value,
        label=request.label,
        provider=request.provider,
        status="active"
    )
    
    db.add(api_key)
    db.commit()
    
    return {
        "keyId": api_key.key_id,
        "keyValue": key_value,  # Only returned once!
        "label": api_key.label,
        "provider": api_key.provider,
        "status": api_key.status,
        "createdAt": api_key.created_at.isoformat()
    }

@app.patch("/api/keys/{key_id}")
async def update_key(key_id: str, request: UpdateKeyRequest, user_id: str = Depends(get_current_user), db: Session = Depends(get_db)):
    """Update key metadata"""
    key = db.query(APIKey).filter(APIKey.key_id == key_id, APIKey.user_id == user_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    if request.label is not None:
        key.label = request.label
    if request.status is not None:
        key.status = request.status
    
    db.commit()
    
    return {"message": "Key updated successfully"}

@app.delete("/api/keys/{key_id}")
async def delete_key(key_id: str, user_id: str = Depends(get_current_user), db: Session = Depends(get_db)):
    """Delete API key"""
    key = db.query(APIKey).filter(APIKey.key_id == key_id, APIKey.user_id == user_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    db.delete(key)
    db.commit()
    
    return {"message": "Key deleted successfully"}

@app.post("/api/validate")
async def validate_key(
    request: Optional[ValidateKeyRequest] = None,
    x_api_key: Optional[str] = Header(None),
    api_key: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Validate API key - supports header, query param, or body"""
    key_value = None
    if request and request.apiKey:
        key_value = request.apiKey
    elif x_api_key:
        key_value = x_api_key
    elif api_key:
        key_value = api_key
    
    if not key_value:
        raise HTTPException(status_code=400, detail="API key required")
    
    key_hash_value = hash_key(key_value)
    key = db.query(APIKey).filter(APIKey.key_hash == key_hash_value).first()
    
    if not key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if key.status != "active":
        raise HTTPException(status_code=401, detail="API key is inactive")
    
    # NVIDIA validation if provider is nvidia
    if key.provider == "nvidia":
        nvidia_result = validate_nvidia_key(key_value)
        if not nvidia_result["valid"]:
            raise HTTPException(status_code=401, detail=nvidia_result["error"])
    
    # Update last used timestamp asynchronously (simplified for MVP)
    key.last_used_at = datetime.utcnow()
    db.commit()
    
    return {
        "valid": True,
        "userId": key.user_id,
        "keyId": key.key_id,
        "provider": key.provider
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
