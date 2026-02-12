# 🔑 API Key Usage Guide

Complete guide on how to use your API keys in different scenarios.

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Python Examples](#python-examples)
3. [JavaScript/Node.js Examples](#javascript-examples)
4. [cURL Examples](#curl-examples)
5. [Real-World Use Cases](#real-world-use-cases)
6. [Best Practices](#best-practices)

---

## 🚀 Quick Start

### Step 1: Create API Key

1. Login to dashboard: http://localhost:3000
2. Click "Create New Key"
3. Give it a label (e.g., "Production API")
4. Copy the key (shows only once!)
5. Save it securely

### Step 2: Validate Your Key

```bash
curl -X POST http://localhost:8000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"apiKey": "akm_your_key_here"}'
```

Response:
```json
{
  "valid": true,
  "userId": "abc123",
  "keyId": "xyz789",
  "provider": "internal"
}
```

---

## 🐍 Python Examples

### 1. Simple Validation

```python
import requests

api_key = "akm_your_key_here"

response = requests.post(
    "http://localhost:8000/api/validate",
    json={"apiKey": api_key}
)

if response.status_code == 200:
    print("✅ Valid key!")
    print(response.json())
else:
    print("❌ Invalid key!")
```

### 2. Protect Flask Routes

```python
from flask import Flask, request, jsonify
from functools import wraps
import requests

app = Flask(__name__)

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        
        # Validate
        response = requests.post(
            "http://localhost:8000/api/validate",
            json={"apiKey": api_key}
        )
        
        if response.status_code != 200:
            return jsonify({"error": "Invalid API key"}), 401
        
        request.user_info = response.json()
        return f(*args, **kwargs)
    
    return decorated

@app.route('/api/data')
@require_api_key
def get_data():
    return jsonify({
        "message": "Success!",
        "user": request.user_info
    })
```

### 3. Use with OpenAI

```python
from openai import OpenAI
import requests

def call_openai_with_validation(your_api_key, openai_key):
    # First validate your key
    response = requests.post(
        "http://localhost:8000/api/validate",
        json={"apiKey": your_api_key}
    )
    
    if response.status_code != 200:
        print("Access denied!")
        return
    
    # Use OpenAI
    client = OpenAI(api_key=openai_key)
    completion = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello!"}]
    )
    
    print(completion.choices[0].message.content)
```

### 4. FastAPI Middleware

```python
from fastapi import FastAPI, HTTPException, Header, Depends
import httpx

app = FastAPI()

async def verify_api_key(x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(401, "API key required")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/validate",
            json={"apiKey": x_api_key}
        )
    
    if response.status_code != 200:
        raise HTTPException(401, "Invalid API key")
    
    return response.json()

@app.get("/api/data")
async def get_data(user_info: dict = Depends(verify_api_key)):
    return {"message": "Success!", "user": user_info}
```

---

## 🟨 JavaScript Examples

### 1. Node.js with Axios

```javascript
const axios = require('axios');

async function validateApiKey(apiKey) {
  try {
    const response = await axios.post('http://localhost:8000/api/validate', {
      apiKey: apiKey
    });
    
    console.log('✅ Valid key!', response.data);
    return true;
  } catch (error) {
    console.log('❌ Invalid key!');
    return false;
  }
}

// Use it
validateApiKey('akm_your_key_here');
```

### 2. Express.js Middleware

```javascript
const express = require('express');
const axios = require('axios');

const app = express();

async function requireApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  try {
    const response = await axios.post('http://localhost:8000/api/validate', {
      apiKey: apiKey
    });
    
    req.userInfo = response.data;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
}

app.get('/api/data', requireApiKey, (req, res) => {
  res.json({ message: 'Success!', user: req.userInfo });
});

app.listen(3001, () => console.log('Server running on port 3001'));
```

### 3. React Component

```javascript
import React, { useState, useEffect } from 'react';

function DataComponent() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    async function fetchData() {
      const apiKey = localStorage.getItem('apiKey');
      
      try {
        // Validate key
        const validateRes = await fetch('http://localhost:8000/api/validate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ apiKey })
        });
        
        if (!validateRes.ok) throw new Error('Invalid API key');
        
        // Fetch data
        const dataRes = await fetch('http://your-api.com/data', {
          headers: { 'X-API-Key': apiKey }
        });
        
        const result = await dataRes.json();
        setData(result);
      } catch (err) {
        setError(err.message);
      }
    }
    
    fetchData();
  }, []);
  
  if (error) return <div>Error: {error}</div>;
  if (!data) return <div>Loading...</div>;
  
  return <div>Data: {JSON.stringify(data)}</div>;
}
```

### 4. Fetch API (Browser)

```javascript
// Method 1: Header
fetch('http://your-api.com/data', {
  headers: {
    'X-API-Key': 'akm_your_key_here'
  }
})
.then(res => res.json())
.then(data => console.log(data));

// Method 2: Query parameter
fetch('http://your-api.com/data?api_key=akm_your_key_here')
.then(res => res.json())
.then(data => console.log(data));
```

---

## 💻 cURL Examples

### 1. Header Method

```bash
curl -X POST http://localhost:8000/api/validate \
  -H "X-API-Key: akm_your_key_here"
```

### 2. Query Parameter

```bash
curl "http://localhost:8000/api/validate?api_key=akm_your_key_here"
```

### 3. Request Body

```bash
curl -X POST http://localhost:8000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"apiKey": "akm_your_key_here"}'
```

### 4. Get Protected Data

```bash
curl http://your-api.com/data \
  -H "X-API-Key: akm_your_key_here"
```

---

## 🎯 Real-World Use Cases

### 1. API Gateway

```python
# Validate all incoming requests
from fastapi import FastAPI, Request
import httpx

app = FastAPI()

@app.middleware("http")
async def validate_api_key_middleware(request: Request, call_next):
    api_key = request.headers.get("x-api-key")
    
    if not api_key:
        return JSONResponse({"error": "API key required"}, status_code=401)
    
    # Validate
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/api/validate",
            json={"apiKey": api_key}
        )
    
    if response.status_code != 200:
        return JSONResponse({"error": "Invalid API key"}, status_code=401)
    
    # Add user info to request state
    request.state.user = response.json()
    
    return await call_next(request)
```

### 2. Microservices Authentication

```javascript
// Service A validates, Service B trusts
const axios = require('axios');

// Service A
async function validateAndForward(apiKey, targetService) {
  // Validate
  const validation = await axios.post('http://localhost:8000/api/validate', {
    apiKey: apiKey
  });
  
  // Forward with user info
  return await axios.post(targetService, {
    data: 'some data',
    user: validation.data
  });
}
```

### 3. Rate Limiting by API Key

```python
from collections import defaultdict
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
    
    def check_limit(self, user_id, limit=100):
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        
        # Clean old requests
        self.requests[user_id] = [
            t for t in self.requests[user_id] if t > minute_ago
        ]
        
        # Check limit
        if len(self.requests[user_id]) >= limit:
            return False
        
        self.requests[user_id].append(now)
        return True

# Use in your API
limiter = RateLimiter()

@app.get("/api/data")
async def get_data(user_info: dict = Depends(verify_api_key)):
    if not limiter.check_limit(user_info['userId']):
        raise HTTPException(429, "Rate limit exceeded")
    
    return {"data": "your data"}
```

### 4. Multi-Tenant Application

```javascript
// Different API keys for different tenants
const tenantConfigs = {
  'user-123': { tier: 'premium', features: ['feature-a', 'feature-b'] },
  'user-456': { tier: 'free', features: ['feature-a'] }
};

async function getTenantConfig(apiKey) {
  const validation = await axios.post('http://localhost:8000/api/validate', {
    apiKey: apiKey
  });
  
  const userId = validation.data.userId;
  return tenantConfigs[userId] || { tier: 'free', features: [] };
}
```

---

## ✅ Best Practices

### 1. Store Keys Securely

```bash
# ❌ DON'T: Hardcode in code
api_key = "akm_abc123..."

# ✅ DO: Use environment variables
import os
api_key = os.getenv('API_KEY')
```

```javascript
// ❌ DON'T: Commit to git
const apiKey = "akm_abc123...";

// ✅ DO: Use .env file
require('dotenv').config();
const apiKey = process.env.API_KEY;
```

### 2. Cache Validations

```python
from functools import lru_cache
from time import time

@lru_cache(maxsize=1000)
def validate_cached(api_key, cache_time):
    # cache_time changes every 5 minutes
    response = requests.post(
        "http://localhost:8000/api/validate",
        json={"apiKey": api_key}
    )
    return response.status_code == 200

# Use it
cache_time = int(time() / 300)  # 5-minute buckets
is_valid = validate_cached(api_key, cache_time)
```

### 3. Handle Errors Gracefully

```javascript
async function safeValidate(apiKey) {
  try {
    const response = await axios.post('http://localhost:8000/api/validate', {
      apiKey: apiKey
    }, {
      timeout: 5000  // 5 second timeout
    });
    return { valid: true, data: response.data };
  } catch (error) {
    if (error.response) {
      // Invalid key
      return { valid: false, error: 'Invalid API key' };
    } else if (error.request) {
      // Network error
      return { valid: false, error: 'Validation service unavailable' };
    } else {
      // Other error
      return { valid: false, error: 'Unknown error' };
    }
  }
}
```

### 4. Rotate Keys Regularly

```python
# Create new key
new_key = create_api_key(label="Production-2024-02")

# Update your services
update_services_with_new_key(new_key)

# Deactivate old key after migration
deactivate_api_key(old_key_id)

# Delete old key after grace period
delete_api_key(old_key_id)
```

### 5. Monitor Usage

```python
# Log every validation
import logging

def validate_with_logging(api_key):
    response = requests.post(
        "http://localhost:8000/api/validate",
        json={"apiKey": api_key}
    )
    
    logging.info(f"API Key validation: {response.status_code}")
    
    if response.status_code == 200:
        user_info = response.json()
        logging.info(f"User: {user_info['userId']}")
    
    return response.status_code == 200
```

---

## 🔒 Security Tips

1. **Never expose keys in client-side code**
2. **Use HTTPS in production**
3. **Rotate keys regularly**
4. **Monitor for suspicious activity**
5. **Set up rate limiting**
6. **Use different keys for different environments**
7. **Revoke compromised keys immediately**

---

## 📞 Support

Need help? Check:
- Dashboard: http://localhost:3000
- API Health: http://localhost:8000/api/health
- Examples: `/examples` folder

Happy coding! 🚀
