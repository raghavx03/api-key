import asyncio
"""
API Key Management Dashboard - Advanced Backend
================================================
Production-grade FastAPI backend with:
- JWT authentication (access + refresh tokens)
- Role-based access control (admin, user, viewer)
- API key scoping (read/write permissions)
- Rate limiting per IP
- Structured logging with loguru
- Request ID tracking middleware
- API versioning (/api/v1/)
- Key rotation, IP whitelisting, usage quotas
"""

from fastapi import FastAPI, Depends, HTTPException, Header, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
import secrets
import hashlib
import uuid
import re
import time
from datetime import datetime, timezone, timedelta
from cryptography.fernet import Fernet
import os
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, JSON, Index, Float, text, inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
import bcrypt
import httpx
from functools import lru_cache
from jose import jwt, JWTError
from loguru import logger
import sys

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./api_keys.db")
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")
SUPER_ADMIN_EMAIL = "ragsproai@gmail.com"
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(64))
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# ─────────────────────────────────────────────
# Logging Setup (loguru)
# ─────────────────────────────────────────────
logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{extra[request_id]}</cyan> | <level>{message}</level>",
    level="INFO",
    serialize=False,
)
logger.add(
    "logs/api_gateway.log",
    rotation="10 MB",
    retention="30 days",
    compression="gz",
    level="DEBUG",
    serialize=True,
)
logger = logger.bind(request_id="-")

# ─────────────────────────────────────────────
# Database Setup
# ─────────────────────────────────────────────
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

# Encryption
cipher = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

# ─────────────────────────────────────────────
# Database Models
# ─────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    user_id = Column(String, primary_key=True, default=lambda: secrets.token_urlsafe(16))
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user")  # admin, user, viewer
    plan = Column(String, default="free")  # free, pro
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class APIKey(Base):
    __tablename__ = "api_keys"
    key_id = Column(String, primary_key=True, default=lambda: secrets.token_urlsafe(16))
    user_id = Column(String, nullable=False, index=True)
    key_value_encrypted = Column(String, nullable=False)
    key_hash = Column(String, unique=True, nullable=False, index=True)
    label = Column(String, default="")
    provider = Column(String, default="internal")
    status = Column(String, default="active")
    scope = Column(String, default="read_write")  # read_only, read_write, full_access
    allowed_ips = Column(JSON, default=list)  # IP whitelisting
    usage_count = Column(Integer, default=0)
    usage_quota = Column(Integer, default=0)  # 0 = unlimited
    avg_response_time_ms = Column(Float, default=0.0)
    total_response_time_ms = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    rotated_from = Column(String, nullable=True)  # key_id of the key this was rotated from

    __table_args__ = (
        Index('idx_user_status', 'user_id', 'status'),
    )

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    token_id = Column(String, primary_key=True, default=lambda: secrets.token_urlsafe(16))
    user_id = Column(String, nullable=False, index=True)
    token_hash = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class AuditLog(Base):
    __tablename__ = "audit_logs"
    log_id = Column(String, primary_key=True, default=lambda: uuid.uuid4().hex)
    user_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

# Create tables
Base.metadata.create_all(bind=engine)

# ── Add 'plan' column if not exists (migration for existing DBs) ──
try:
    inspector = sa_inspect(engine)
    columns = [c["name"] for c in inspector.get_columns("users")]
    if "plan" not in columns:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN plan VARCHAR DEFAULT 'free'"))
            conn.commit()
            logger.info("Added 'plan' column to users table")
except Exception as e:
    logger.warning(f"Migration check: {e}")

# ── Super admin auto-setup ──
def setup_super_admin():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == SUPER_ADMIN_EMAIL).first()
        if admin:
            if admin.role != "admin" or admin.plan != "pro":
                admin.role = "admin"
                admin.plan = "pro"
                db.commit()
                logger.info(f"Super admin updated: {SUPER_ADMIN_EMAIL} -> admin + pro")
        else:
            logger.info(f"Super admin {SUPER_ADMIN_EMAIL} not registered yet, will be set on registration")
    finally:
        db.close()

setup_super_admin()

# ─────────────────────────────────────────────
# Rate Limiting (in-memory sliding window)
# ─────────────────────────────────────────────
rate_limit_store: dict = {}

def check_rate_limit(ip: str, max_requests: int = 60, window_seconds: int = 60) -> bool:
    """Sliding window rate limiter per IP. Returns True if allowed."""
    now = time.time()
    key = f"rate:{ip}"
    
    if key not in rate_limit_store:
        rate_limit_store[key] = []
    
    # Remove old entries
    rate_limit_store[key] = [t for t in rate_limit_store[key] if now - t < window_seconds]
    
    if len(rate_limit_store[key]) >= max_requests:
        return False
    
    rate_limit_store[key].append(now)
    return True

# Failed login tracking
failed_attempts: dict = {}

# ─────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────
app = FastAPI(
    title="API Key Management Gateway",
    description="Production-grade API key management with JWT auth, RBAC, and analytics",
    version="2.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
)

# CORS - Specific origins only
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,https://api-key-blush.vercel.app,https://api-key-backend-xsdo.onrender.com,https://api.ragspro.com,http://api.ragspro.com").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Request-Id", "X-Response-Time"],
)

# ─────────────────────────────────────────────
# Middleware: Request ID + Response Time + Rate Limiting
# ─────────────────────────────────────────────
@app.middleware("http")
async def add_tracking_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    start_time = time.time()
    
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        return Response(
            content='{"detail":"Rate limit exceeded. Try again later."}',
            status_code=429,
            media_type="application/json",
            headers={"X-Request-Id": request_id}
        )
    
    # Bind request context for logging
    with logger.contextualize(request_id=request_id):
        logger.info(f"{request.method} {request.url.path} from {client_ip}")
        
        response = await call_next(request)
        
        process_time = (time.time() - start_time) * 1000
        response.headers["X-Request-Id"] = request_id
        response.headers["X-Response-Time"] = f"{process_time:.2f}ms"
        
        logger.info(f"Completed {response.status_code} in {process_time:.2f}ms")
    
    return response

# ─────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid email format')
        return v.lower()
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one digit')
        return v

class LoginRequest(BaseModel):
    email: str
    password: str

class CreateKeyRequest(BaseModel):
    label: Optional[str] = ""
    provider: str = "internal"
    scope: str = "read_write"
    allowed_ips: Optional[List[str]] = []
    usage_quota: Optional[int] = 0
    expires_in_days: Optional[int] = None

class UpdateKeyRequest(BaseModel):
    label: Optional[str] = None
    status: Optional[str] = None
    scope: Optional[str] = None
    allowed_ips: Optional[List[str]] = None
    usage_quota: Optional[int] = None

class ValidateKeyRequest(BaseModel):
    apiKey: str

class RotateKeyRequest(BaseModel):
    label: Optional[str] = None

class UpdateUserRoleRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|user|viewer)$")

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshRequest(BaseModel):
    refresh_token: str

# ─────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_key() -> str:
    return f"akm_{secrets.token_urlsafe(32)}"

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def encrypt_key(key: str) -> str:
    return cipher.encrypt(key.encode()).decode()

def decrypt_key(encrypted: str) -> str:
    return cipher.decrypt(encrypted.encode()).decode()

def _hash_password_sync(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()

def _verify_password_sync(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

async def hash_password(password: str) -> str:
    return await asyncio.to_thread(_hash_password_sync, password)

async def verify_password(password: str, hashed: str) -> bool:
    return await asyncio.to_thread(_verify_password_sync, password, hashed)

# ─────────────────────────────────────────────
# JWT Token Functions
# ─────────────────────────────────────────────
def create_access_token(user_id: str, email: str, role: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "type": "access",
        "exp": expires,
        "iat": datetime.now(timezone.utc),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> tuple[str, str]:
    """Returns (raw_token, token_hash)"""
    raw_token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise JWTError("Invalid token type")
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

# ─────────────────────────────────────────────
# Auth Dependency
# ─────────────────────────────────────────────
async def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.replace("Bearer ", "")
    payload = decode_access_token(token)
    
    user = db.query(User).filter(User.user_id == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    
    return {"user_id": user.user_id, "email": user.email, "role": user.role, "plan": user.plan or "free"}

async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

async def require_write(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="Write access required")
    return current_user

# ─────────────────────────────────────────────
# Audit Logging Helper
# ─────────────────────────────────────────────
def log_audit(db: Session, user_id: str, action: str, resource_type: str = None, 
              resource_id: str = None, ip_address: str = None, details: dict = None):
    audit = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        details=details or {}
    )
    db.add(audit)
    db.commit()

# ─────────────────────────────────────────────
# NVIDIA Validation
# ─────────────────────────────────────────────
@lru_cache(maxsize=1000)
def validate_nvidia_key_cached(api_key: str, cache_time: int) -> dict:
    try:
        response = httpx.get(
            "https://api.nvcf.nvidia.com/v2/nvcf/functions",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=3.0
        )
        return {"valid": response.status_code == 200, "error": None if response.status_code == 200 else f"NVIDIA error: {response.status_code}"}
    except Exception as e:
        return {"valid": False, "error": f"NVIDIA connection error: {str(e)}"}

def validate_nvidia_key(api_key: str) -> dict:
    cache_time = int(datetime.now(timezone.utc).timestamp() / 300)
    return validate_nvidia_key_cached(api_key, cache_time)

# ═════════════════════════════════════════════
# API ROUTES — v1
# ═════════════════════════════════════════════

# ─────── Auth Routes ───────

@app.post("/api/v1/auth/register", tags=["Authentication"])
async def register(request: RegisterRequest, req: Request, db: Session = Depends(get_db)):
    """Register a new user with email validation and password policy."""
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # First user is admin
    user_count = db.query(User).count()
    role = "admin" if user_count == 0 else "user"
    
    # Super admin gets admin + pro automatically
    plan = "free"
    if request.email.lower() == SUPER_ADMIN_EMAIL:
        role = "admin"
        plan = "pro"
    
    user = User(
        user_id=secrets.token_urlsafe(16),
        email=request.email,
        password_hash=await hash_password(request.password),
        role=role,
        plan=plan,
    )
    db.add(user)
    db.commit()
    
    log_audit(db, user.user_id, "user.register", "user", user.user_id, 
              req.client.host if req.client else None)
    
    logger.info(f"New user registered: {request.email} (role: {role}, plan: {plan})")
    return {"message": "User registered successfully", "role": role, "plan": plan}

@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["Authentication"])
async def login(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    """Login and receive JWT access + refresh tokens."""
    client_ip = req.client.host if req.client else "unknown"
    attempts_key = request.email
    
    # Rate limiting for failed logins
    if attempts_key in failed_attempts:
        attempts, last_attempt = failed_attempts[attempts_key]
        if attempts >= 5 and datetime.now(timezone.utc) - last_attempt < timedelta(minutes=15):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")
    
    user = db.query(User).filter(User.email == request.email.lower()).first()
    if not user or not await verify_password(request.password, user.password_hash):
        if attempts_key in failed_attempts:
            attempts, _ = failed_attempts[attempts_key]
            failed_attempts[attempts_key] = (attempts + 1, datetime.now(timezone.utc))
        else:
            failed_attempts[attempts_key] = (1, datetime.now(timezone.utc))
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")
    
    # Clear failed attempts
    failed_attempts.pop(attempts_key, None)
    
    # Create tokens
    access_token = create_access_token(user.user_id, user.email, user.role)
    raw_refresh, refresh_hash = create_refresh_token(user.user_id)
    
    # Store refresh token
    refresh_record = RefreshToken(
        user_id=user.user_id,
        token_hash=refresh_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(refresh_record)
    db.commit()
    
    log_audit(db, user.user_id, "user.login", "user", user.user_id, client_ip)
    logger.info(f"User logged in: {user.email}")
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

@app.post("/api/v1/auth/refresh", response_model=TokenResponse, tags=["Authentication"])
async def refresh_token(request: RefreshRequest, db: Session = Depends(get_db)):
    """Get new access token using refresh token."""
    token_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()
    
    refresh_record = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash,
        RefreshToken.revoked == False,
    ).first()
    
    if not refresh_record:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    now = datetime.now(timezone.utc)
    expires = refresh_record.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now > expires:
        refresh_record.revoked = True
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token expired")
    
    user = db.query(User).filter(User.user_id == refresh_record.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    
    # Revoke old token, issue new pair
    refresh_record.revoked = True
    
    access_token = create_access_token(user.user_id, user.email, user.role)
    raw_refresh, new_refresh_hash = create_refresh_token(user.user_id)
    
    new_refresh_record = RefreshToken(
        user_id=user.user_id,
        token_hash=new_refresh_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(new_refresh_record)
    db.commit()
    
    logger.info(f"Token refreshed for user: {user.email}")
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

@app.post("/api/v1/auth/logout", tags=["Authentication"])
async def logout(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """Logout — revokes all refresh tokens for the user."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        try:
            payload = decode_access_token(token)
            db.query(RefreshToken).filter(
                RefreshToken.user_id == payload["sub"],
                RefreshToken.revoked == False,
            ).update({"revoked": True})
            db.commit()
            logger.info(f"User logged out: {payload.get('email')}")
        except Exception:
            pass
    return {"message": "Logged out successfully"}

@app.get("/api/v1/auth/me", tags=["Authentication"])
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile."""
    return {
        "userId": current_user["user_id"],
        "email": current_user["email"],
        "role": current_user["role"],
        "plan": current_user.get("plan", "free"),
    }

# ─────── Key Management Routes ───────

@app.get("/api/v1/keys", tags=["Key Management"])
async def list_keys(
    status: Optional[str] = None,
    provider: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    page: int = 1,
    per_page: int = 20,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List API keys with filtering, search, sorting, and pagination."""
    query = db.query(APIKey).filter(APIKey.user_id == current_user["user_id"])
    
    if status:
        query = query.filter(APIKey.status == status)
    if provider:
        query = query.filter(APIKey.provider == provider)
    if search:
        query = query.filter(APIKey.label.ilike(f"%{search}%"))
    
    # Count total
    total = query.count()
    
    # Sort
    sort_col = getattr(APIKey, sort_by, APIKey.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_col.desc())
    else:
        query = query.order_by(sort_col.asc())
    
    # Paginate
    keys = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return {
        "keys": [
            {
                "keyId": key.key_id,
                "label": key.label,
                "provider": key.provider,
                "status": key.status,
                "scope": key.scope,
                "allowedIps": key.allowed_ips or [],
                "usageCount": key.usage_count,
                "usageQuota": key.usage_quota,
                "avgResponseTimeMs": round(key.avg_response_time_ms, 2),
                "createdAt": key.created_at.isoformat() if key.created_at else None,
                "lastUsedAt": key.last_used_at.isoformat() if key.last_used_at else None,
                "expiresAt": key.expires_at.isoformat() if key.expires_at else None,
                "rotatedFrom": key.rotated_from,
            }
            for key in keys
        ],
        "pagination": {
            "page": page,
            "perPage": per_page,
            "total": total,
            "totalPages": (total + per_page - 1) // per_page,
        }
    }

@app.post("/api/v1/keys", tags=["Key Management"])
async def create_key(
    request: CreateKeyRequest,
    req: Request,
    current_user: dict = Depends(require_write),
    db: Session = Depends(get_db)
):
    """Create a new API key with scoping and optional IP whitelisting."""
    # Plan limit enforcement: Free users can have max 10 keys
    user_plan = current_user.get("plan", "free")
    if user_plan == "free":
        existing_count = db.query(APIKey).filter(APIKey.user_id == current_user["user_id"]).count()
        if existing_count >= 10:
            raise HTTPException(
                status_code=403,
                detail="Free plan limit reached (10 keys). Upgrade to Pro for unlimited keys."
            )
    
    key_value = generate_key()
    key_hash_value = hash_key(key_value)
    
    expires_at = None
    if request.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=request.expires_in_days)
    
    api_key = APIKey(
        key_id=secrets.token_urlsafe(16),
        user_id=current_user["user_id"],
        key_value_encrypted=encrypt_key(key_value),
        key_hash=key_hash_value,
        label=request.label or "",
        provider=request.provider,
        scope=request.scope,
        allowed_ips=request.allowed_ips or [],
        usage_quota=request.usage_quota or 0,
        expires_at=expires_at,
    )
    
    db.add(api_key)
    db.commit()
    
    log_audit(db, current_user["user_id"], "key.create", "api_key", api_key.key_id,
              req.client.host if req.client else None, {"label": request.label, "provider": request.provider})
    
    logger.info(f"API key created: {api_key.key_id} by {current_user['email']}")
    
    return {
        "keyId": api_key.key_id,
        "keyValue": key_value,  # Only shown once
        "label": api_key.label,
        "provider": api_key.provider,
        "scope": api_key.scope,
        "status": api_key.status,
        "createdAt": api_key.created_at.isoformat(),
        "expiresAt": api_key.expires_at.isoformat() if api_key.expires_at else None,
    }

@app.patch("/api/v1/keys/{key_id}", tags=["Key Management"])
async def update_key(
    key_id: str,
    request: UpdateKeyRequest,
    req: Request,
    current_user: dict = Depends(require_write),
    db: Session = Depends(get_db)
):
    """Update key metadata, scope, status, or IP whitelist."""
    key = db.query(APIKey).filter(APIKey.key_id == key_id, APIKey.user_id == current_user["user_id"]).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    if request.label is not None:
        key.label = request.label
    if request.status is not None:
        key.status = request.status
    if request.scope is not None:
        key.scope = request.scope
    if request.allowed_ips is not None:
        key.allowed_ips = request.allowed_ips
    if request.usage_quota is not None:
        key.usage_quota = request.usage_quota
    
    db.commit()
    
    log_audit(db, current_user["user_id"], "key.update", "api_key", key_id,
              req.client.host if req.client else None)
    
    return {"message": "Key updated successfully"}

@app.delete("/api/v1/keys/{key_id}", tags=["Key Management"])
async def delete_key(
    key_id: str,
    req: Request,
    current_user: dict = Depends(require_write),
    db: Session = Depends(get_db)
):
    """Delete an API key permanently."""
    key = db.query(APIKey).filter(APIKey.key_id == key_id, APIKey.user_id == current_user["user_id"]).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    db.delete(key)
    db.commit()
    
    log_audit(db, current_user["user_id"], "key.delete", "api_key", key_id,
              req.client.host if req.client else None)
    
    logger.info(f"API key deleted: {key_id} by {current_user['email']}")
    return {"message": "Key deleted successfully"}

@app.post("/api/v1/keys/{key_id}/rotate", tags=["Key Management"])
async def rotate_key(
    key_id: str,
    request: RotateKeyRequest,
    req: Request,
    current_user: dict = Depends(require_write),
    db: Session = Depends(get_db)
):
    """Rotate an API key — deactivates the old key and creates a new one."""
    old_key = db.query(APIKey).filter(APIKey.key_id == key_id, APIKey.user_id == current_user["user_id"]).first()
    if not old_key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    # Deactivate old key
    old_key.status = "rotated"
    
    # Create new key with same settings
    new_key_value = generate_key()
    new_key = APIKey(
        key_id=secrets.token_urlsafe(16),
        user_id=current_user["user_id"],
        key_value_encrypted=encrypt_key(new_key_value),
        key_hash=hash_key(new_key_value),
        label=request.label or old_key.label,
        provider=old_key.provider,
        scope=old_key.scope,
        allowed_ips=old_key.allowed_ips,
        usage_quota=old_key.usage_quota,
        rotated_from=old_key.key_id,
    )
    
    db.add(new_key)
    db.commit()
    
    log_audit(db, current_user["user_id"], "key.rotate", "api_key", key_id,
              req.client.host if req.client else None, {"new_key_id": new_key.key_id})
    
    logger.info(f"API key rotated: {key_id} → {new_key.key_id} by {current_user['email']}")
    
    return {
        "keyId": new_key.key_id,
        "keyValue": new_key_value,
        "label": new_key.label,
        "provider": new_key.provider,
        "scope": new_key.scope,
        "status": new_key.status,
        "createdAt": new_key.created_at.isoformat(),
        "rotatedFrom": old_key.key_id,
    }

@app.get("/api/v1/keys/{key_id}/stats", tags=["Key Management"])
async def get_key_stats(
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed usage statistics for a key."""
    key = db.query(APIKey).filter(APIKey.key_id == key_id, APIKey.user_id == current_user["user_id"]).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return {
        "keyId": key.key_id,
        "label": key.label,
        "usageCount": key.usage_count,
        "usageQuota": key.usage_quota,
        "avgResponseTimeMs": round(key.avg_response_time_ms, 2),
        "lastUsedAt": key.last_used_at.isoformat() if key.last_used_at else None,
        "status": key.status,
        "scope": key.scope,
        "quotaUsedPercent": round((key.usage_count / key.usage_quota) * 100, 1) if key.usage_quota > 0 else 0,
    }

# ─────── Validation Route ───────

@app.post("/api/v1/validate", tags=["Validation"])
async def validate_key(
    request: Optional[ValidateKeyRequest] = None,
    x_api_key: Optional[str] = Header(None),
    api_key: Optional[str] = Query(None),
    req: Request = None,
    db: Session = Depends(get_db)
):
    """Validate an API key — supports header, query param, or body. Checks IP whitelist, quotas, and expiry."""
    start_time = time.time()
    
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
        raise HTTPException(status_code=401, detail=f"API key is {key.status}")
    
    # Check expiry
    if key.expires_at:
        exp = key.expires_at if key.expires_at.tzinfo else key.expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp:
            key.status = "expired"
            db.commit()
            raise HTTPException(status_code=401, detail="API key has expired")
    
    # Check IP whitelist
    client_ip = req.client.host if req and req.client else None
    if key.allowed_ips and len(key.allowed_ips) > 0 and client_ip:
        if client_ip not in key.allowed_ips:
            raise HTTPException(status_code=403, detail=f"IP {client_ip} not whitelisted for this key")
    
    # Check usage quota
    if key.usage_quota > 0 and key.usage_count >= key.usage_quota:
        raise HTTPException(status_code=429, detail="Usage quota exceeded for this key")
    
    # NVIDIA validation
    if key.provider == "nvidia":
        nvidia_result = validate_nvidia_key(key_value)
        if not nvidia_result["valid"]:
            raise HTTPException(status_code=401, detail=nvidia_result["error"])
    
    # Update usage stats
    response_time_ms = (time.time() - start_time) * 1000
    key.usage_count += 1
    key.last_used_at = datetime.now(timezone.utc)
    key.total_response_time_ms += response_time_ms
    key.avg_response_time_ms = key.total_response_time_ms / key.usage_count
    db.commit()
    
    return {
        "valid": True,
        "userId": key.user_id,
        "keyId": key.key_id,
        "provider": key.provider,
        "scope": key.scope,
        "responseTimeMs": round(response_time_ms, 2),
        "usageCount": key.usage_count,
    }

# ─────── Admin Routes ───────

@app.get("/api/v1/admin/users", tags=["Admin"])
async def list_users(
    page: int = 1,
    per_page: int = 20,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """[Admin] List all users."""
    total = db.query(User).count()
    users = db.query(User).order_by(User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    
    return {
        "users": [
            {
                "userId": u.user_id,
                "email": u.email,
                "role": u.role,
                "isActive": u.is_active,
                "createdAt": u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ],
        "pagination": {"page": page, "perPage": per_page, "total": total, "totalPages": (total + per_page - 1) // per_page}
    }

@app.patch("/api/v1/admin/users/{user_id}/role", tags=["Admin"])
async def update_user_role(
    user_id: str,
    request: UpdateUserRoleRequest,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """[Admin] Update a user's role."""
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.role = request.role
    db.commit()
    
    logger.info(f"User {user.email} role changed to {request.role} by admin {current_user['email']}")
    return {"message": f"User role updated to {request.role}"}

@app.get("/api/v1/admin/audit-logs", tags=["Admin"])
async def get_audit_logs(
    page: int = 1,
    per_page: int = 50,
    action: Optional[str] = None,
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """[Admin] Get audit logs."""
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        query = query.filter(AuditLog.action == action)
    
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return {
        "logs": [
            {
                "logId": log.log_id,
                "userId": log.user_id,
                "action": log.action,
                "resourceType": log.resource_type,
                "resourceId": log.resource_id,
                "ipAddress": log.ip_address,
                "details": log.details,
                "createdAt": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ],
        "pagination": {"page": page, "perPage": per_page, "total": total, "totalPages": (total + per_page - 1) // per_page}
    }

@app.get("/api/v1/admin/stats", tags=["Admin"])
async def get_admin_stats(
    current_user: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """[Admin] Get system-wide statistics."""
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    total_keys = db.query(APIKey).count()
    active_keys = db.query(APIKey).filter(APIKey.status == "active").count()
    total_validations = db.query(APIKey).with_entities(
        db.query(APIKey).with_entities(APIKey.usage_count).subquery()
    ).count()
    
    # Sum usage counts safely
    from sqlalchemy import func
    total_usage = db.query(func.sum(APIKey.usage_count)).scalar() or 0
    avg_response = db.query(func.avg(APIKey.avg_response_time_ms)).filter(APIKey.usage_count > 0).scalar() or 0
    
    return {
        "totalUsers": total_users,
        "activeUsers": active_users,
        "totalKeys": total_keys,
        "activeKeys": active_keys,
        "totalValidations": total_usage,
        "avgResponseTimeMs": round(avg_response, 2),
    }

# ─────── Health Check ───────

@app.get("/api/v1/health", tags=["System"])
async def health_check(db: Session = Depends(get_db)):
    """Health check with dependency status."""
    checks = {"api": "healthy", "database": "unknown"}
    
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "healthy"
    except Exception as e:
        checks["database"] = f"unhealthy: {str(e)}"
    
    overall = "healthy" if all(v == "healthy" for v in checks.values()) else "degraded"
    
    return {
        "status": overall,
        "checks": checks,
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ─────── Billing / Razorpay Routes ───────

class CreateOrderRequest(BaseModel):
    plan: str = "pro"

class VerifyPaymentRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

PLAN_PRICES = {
    "pro": {"amount": 159900, "currency": "INR", "description": "RagsPro API Pro Plan — Monthly"},
}

@app.get("/api/v1/billing/plan", tags=["Billing"])
async def get_plan_info(current_user: dict = Depends(get_current_user)):
    """Get current user's plan information."""
    plan = current_user.get("plan", "free")
    limits = {
        "free": {"max_keys": 10, "rate_limit": 60, "features": ["Up to 10 API keys", "AES-256 encryption", "Basic analytics", "60 req/min", "Key rotation", "Community support"]},
        "pro": {"max_keys": -1, "rate_limit": 1000, "features": ["Unlimited API keys", "AES-256 encryption", "Advanced analytics", "1,000 req/min", "Key rotation", "Priority email support", "Custom providers", "Team management"]},
    }
    return {
        "plan": plan,
        "limits": limits.get(plan, limits["free"]),
        "is_pro": plan == "pro",
    }

@app.post("/api/v1/billing/create-order", tags=["Billing"])
async def create_razorpay_order(
    request: CreateOrderRequest,
    current_user: dict = Depends(get_current_user)
):
    """Create a Razorpay order for plan upgrade."""
    if current_user.get("plan") == "pro":
        raise HTTPException(status_code=400, detail="Already on Pro plan")
    
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise HTTPException(status_code=500, detail="Payment gateway not configured")
    
    plan_info = PLAN_PRICES.get(request.plan)
    if not plan_info:
        raise HTTPException(status_code=400, detail="Invalid plan")
    
    try:
        import hmac as hmac_mod
        # Create order via Razorpay API
        order_data = {
            "amount": plan_info["amount"],
            "currency": plan_info["currency"],
            "receipt": f"order_{current_user['user_id']}_{int(time.time())}",
            "notes": {
                "user_id": current_user["user_id"],
                "email": current_user["email"],
                "plan": request.plan,
            }
        }
        
        import base64
        auth_string = f"{RAZORPAY_KEY_ID}:{RAZORPAY_KEY_SECRET}"
        auth_header = base64.b64encode(auth_string.encode()).decode()
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.razorpay.com/v1/orders",
                json=order_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Basic {auth_header}",
                },
                timeout=10.0,
            )
        
        if resp.status_code != 200:
            logger.error(f"Razorpay order creation failed: {resp.text}")
            raise HTTPException(status_code=500, detail="Failed to create payment order")
        
        order = resp.json()
        return {
            "order_id": order["id"],
            "amount": order["amount"],
            "currency": order["currency"],
            "key_id": RAZORPAY_KEY_ID,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Razorpay error: {e}")
        raise HTTPException(status_code=500, detail="Payment service error")

@app.post("/api/v1/billing/verify-payment", tags=["Billing"])
async def verify_razorpay_payment(
    request: VerifyPaymentRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verify Razorpay payment and upgrade user to Pro."""
    import hmac as hmac_mod
    
    # Verify signature
    message = f"{request.razorpay_order_id}|{request.razorpay_payment_id}"
    expected_signature = hmac_mod.new(
        RAZORPAY_KEY_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    if expected_signature != request.razorpay_signature:
        raise HTTPException(status_code=400, detail="Payment verification failed")
    
    # Upgrade user to Pro
    user = db.query(User).filter(User.user_id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.plan = "pro"
    db.commit()
    
    log_audit(db, user.user_id, "billing.upgrade", "user", user.user_id, details={
        "plan": "pro",
        "payment_id": request.razorpay_payment_id,
        "order_id": request.razorpay_order_id,
    })
    
    logger.info(f"User upgraded to Pro: {user.email} (payment: {request.razorpay_payment_id})")
    
    return {
        "success": True,
        "plan": "pro",
        "message": "Successfully upgraded to Pro plan!",
    }

# ─────── Backward Compatibility (old routes redirect) ───────

@app.post("/api/auth/register", include_in_schema=False)
async def register_compat(request: RegisterRequest, req: Request, db: Session = Depends(get_db)):
    return await register(request, req, db)

@app.post("/api/auth/login", include_in_schema=False)
async def login_compat(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    return await login(request, req, db)

@app.post("/api/auth/logout", include_in_schema=False)
async def logout_compat(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    return await logout(authorization, db)

@app.get("/api/keys", include_in_schema=False)
async def list_keys_compat(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    return await list_keys(current_user=current_user, db=db)

@app.post("/api/keys", include_in_schema=False)
async def create_key_compat(request: CreateKeyRequest, req: Request, current_user: dict = Depends(require_write), db: Session = Depends(get_db)):
    return await create_key(request, req, current_user, db)

@app.patch("/api/keys/{key_id}", include_in_schema=False)
async def update_key_compat(key_id: str, request: UpdateKeyRequest, req: Request, current_user: dict = Depends(require_write), db: Session = Depends(get_db)):
    return await update_key(key_id, request, req, current_user, db)

@app.delete("/api/keys/{key_id}", include_in_schema=False)
async def delete_key_compat(key_id: str, req: Request, current_user: dict = Depends(require_write), db: Session = Depends(get_db)):
    return await delete_key(key_id, req, current_user, db)

@app.post("/api/validate", include_in_schema=False)
async def validate_key_compat(request: Optional[ValidateKeyRequest] = None, x_api_key: Optional[str] = Header(None), api_key: Optional[str] = Query(None), req: Request = None, db: Session = Depends(get_db)):
    return await validate_key(request, x_api_key, api_key, req, db)

@app.get("/api/health", include_in_schema=False)
async def health_check_compat(db: Session = Depends(get_db)):
    return await health_check(db)

# ─────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    logger.info(f"🚀 Starting API Key Gateway v2.0.0 on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
