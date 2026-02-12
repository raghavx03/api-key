"""
Python Example: API Key ko kaise use karein
"""

import requests
from openai import OpenAI

# ============================================
# 1. SIMPLE API VALIDATION
# ============================================

def validate_api_key(api_key):
    """Check if API key is valid"""
    response = requests.post(
        "http://localhost:8000/api/validate",
        json={"apiKey": api_key}
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Valid API Key!")
        print(f"   User ID: {data['userId']}")
        print(f"   Key ID: {data['keyId']}")
        print(f"   Provider: {data['provider']}")
        return True
    else:
        print(f"❌ Invalid API Key: {response.json()['detail']}")
        return False


# ============================================
# 2. MIDDLEWARE FOR FLASK APP
# ============================================

from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

def require_api_key(f):
    """Decorator to protect Flask routes with API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # API key header se ya query param se le sakte ho
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        
        # Validate against your API key service
        response = requests.post(
            "http://localhost:8000/api/validate",
            json={"apiKey": api_key}
        )
        
        if response.status_code != 200:
            return jsonify({"error": "Invalid API key"}), 401
        
        # Valid key - add user info to request
        request.user_info = response.json()
        return f(*args, **kwargs)
    
    return decorated_function


@app.route('/api/protected')
@require_api_key
def protected_route():
    """Protected route - API key required"""
    return jsonify({
        "message": "Success! You have access",
        "user": request.user_info
    })


# ============================================
# 3. FASTAPI MIDDLEWARE
# ============================================

from fastapi import FastAPI, HTTPException, Header, Depends
import httpx

fastapi_app = FastAPI()

async def verify_api_key(x_api_key: str = Header(None)):
    """FastAPI dependency for API key validation"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/validate",
            json={"apiKey": x_api_key}
        )
    
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return response.json()


@fastapi_app.get("/api/data")
async def get_data(user_info: dict = Depends(verify_api_key)):
    """Protected endpoint"""
    return {
        "message": "Here's your data",
        "user": user_info
    }


# ============================================
# 4. OPENAI WITH YOUR API KEY
# ============================================

def use_openai_with_validation(your_api_key, openai_api_key):
    """First validate your API key, then use OpenAI"""
    
    # Step 1: Validate your API key
    if not validate_api_key(your_api_key):
        print("Access denied!")
        return
    
    # Step 2: Use OpenAI
    client = OpenAI(api_key=openai_api_key)
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "user", "content": "Hello!"}
        ]
    )
    
    print(response.choices[0].message.content)


# ============================================
# 5. RATE LIMITING WITH API KEYS
# ============================================

from collections import defaultdict
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.limits = {
            "free": 10,      # 10 requests per minute
            "premium": 100   # 100 requests per minute
        }
    
    def check_rate_limit(self, api_key):
        """Check if API key has exceeded rate limit"""
        # Validate key first
        response = requests.post(
            "http://localhost:8000/api/validate",
            json={"apiKey": api_key}
        )
        
        if response.status_code != 200:
            return False, "Invalid API key"
        
        user_info = response.json()
        user_id = user_info['userId']
        
        # Check rate limit
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        
        # Remove old requests
        self.requests[user_id] = [
            req_time for req_time in self.requests[user_id]
            if req_time > minute_ago
        ]
        
        # Check limit
        tier = "premium" if user_info.get('tier') == 'premium' else "free"
        if len(self.requests[user_id]) >= self.limits[tier]:
            return False, f"Rate limit exceeded: {self.limits[tier]}/min"
        
        # Add current request
        self.requests[user_id].append(now)
        return True, "OK"


# ============================================
# 6. USAGE EXAMPLES
# ============================================

if __name__ == "__main__":
    # Example 1: Simple validation
    print("\n=== Example 1: Simple Validation ===")
    api_key = "akm_your_key_here"  # Dashboard se copy karo
    validate_api_key(api_key)
    
    # Example 2: Use in requests
    print("\n=== Example 2: API Request with Key ===")
    response = requests.get(
        "http://your-api.com/data",
        headers={"X-API-Key": api_key}
    )
    print(response.json())
    
    # Example 3: Query parameter
    print("\n=== Example 3: Query Parameter ===")
    response = requests.get(
        f"http://your-api.com/data?api_key={api_key}"
    )
    print(response.json())
    
    # Example 4: Rate limiting
    print("\n=== Example 4: Rate Limiting ===")
    limiter = RateLimiter()
    allowed, message = limiter.check_rate_limit(api_key)
    print(f"Allowed: {allowed}, Message: {message}")


# ============================================
# 7. ASYNC VALIDATION (for high performance)
# ============================================

import asyncio
import aiohttp

async def validate_api_key_async(api_key):
    """Async validation for better performance"""
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "http://localhost:8000/api/validate",
            json={"apiKey": api_key}
        ) as response:
            if response.status == 200:
                return await response.json()
            return None


async def process_multiple_requests(api_keys):
    """Validate multiple API keys concurrently"""
    tasks = [validate_api_key_async(key) for key in api_keys]
    results = await asyncio.gather(*tasks)
    return results


# ============================================
# 8. CACHING FOR PERFORMANCE
# ============================================

from functools import lru_cache
from time import time

class CachedValidator:
    def __init__(self, cache_ttl=300):  # 5 minutes cache
        self.cache = {}
        self.cache_ttl = cache_ttl
    
    def validate(self, api_key):
        """Validate with caching"""
        now = time()
        
        # Check cache
        if api_key in self.cache:
            cached_time, cached_result = self.cache[api_key]
            if now - cached_time < self.cache_ttl:
                print("✅ Using cached validation")
                return cached_result
        
        # Validate
        response = requests.post(
            "http://localhost:8000/api/validate",
            json={"apiKey": api_key}
        )
        
        result = response.status_code == 200
        
        # Cache result
        self.cache[api_key] = (now, result)
        
        return result
