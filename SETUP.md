# 🚀 Quick Setup Guide

## Backend Setup (Choose One Method)

### Method 1: Using pip (Recommended)
```bash
cd backend
pip3 install --break-system-packages fastapi uvicorn bcrypt cryptography
python3 simple_main.py
```

### Method 2: Using Virtual Environment
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # Mac/Linux
# OR
venv\Scripts\activate  # Windows
pip install fastapi uvicorn bcrypt cryptography
python simple_main.py
```

### Method 3: Using Homebrew Python (Mac)
```bash
brew install python@3.11
/opt/homebrew/bin/python3.11 -m pip install fastapi uvicorn bcrypt cryptography
/opt/homebrew/bin/python3.11 backend/simple_main.py
```

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

## Test Backend

```bash
curl http://localhost:8000/api/health
```

Should return: `{"status":"healthy"}`

## Access Dashboard

Open browser: http://localhost:3000

## First Time Use

1. Click "Don't have an account? Register"
2. Enter any username (e.g., "admin") and password (min 6 chars)
3. Click "Register"
4. Login with same credentials
5. Start creating API keys!

## Troubleshooting

**Backend not starting?**
- Install dependencies first
- Check if port 8000 is free: `lsof -i :8000`
- Check backend.log for errors

**Frontend not connecting?**
- Make sure backend is running on port 8000
- Clear browser cache
- Check browser console for errors

**"Module not found" error?**
- Install dependencies: `pip3 install --break-system-packages fastapi uvicorn bcrypt cryptography`

## Quick Commands

```bash
# Start backend
python3 backend/simple_main.py

# Start frontend (in another terminal)
cd frontend && npm run dev

# Test API
curl http://localhost:8000/api/health

# Register user
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin","password":"admin123"}'

# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin","password":"admin123"}'
```

## Features

✅ No database needed - uses JSON files
✅ Simple setup - minimal dependencies
✅ Fast - < 10ms validation
✅ Secure - AES-256 encryption
✅ Works offline - no external dependencies

Enjoy! 🎉
