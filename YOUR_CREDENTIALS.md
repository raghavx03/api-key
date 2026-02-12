# Your Personal Credentials

## Account Details
- **Email**: raghav@test.com
- **Password**: raghav123

## Your First API Key
- **Key ID**: zE22fEFvStq6fLrWrJD-7w
- **API Key**: `akm_YAImOpm5ld5cQ6ZygaV2oh3mlVHs_lEU2e2CEoc51uM`
- **Label**: My First API Key
- **Provider**: internal
- **Status**: active
- **Created**: 2026-02-12

## How to Use Your API Key

### Python Example:
```python
import requests

api_key = "akm_YAImOpm5ld5cQ6ZygaV2oh3mlVHs_lEU2e2CEoc51uM"

# Validate the key
response = requests.post(
    "http://localhost:8000/api/validate",
    headers={"X-API-Key": api_key}
)

print(response.json())
# Output: {"valid": true, "responseTimeMs": 25.5, ...}
```

### JavaScript Example:
```javascript
const apiKey = "akm_YAImOpm5ld5cQ6ZygaV2oh3mlVHs_lEU2e2CEoc51uM";

const response = await fetch("http://localhost:8000/api/validate", {
  method: "POST",
  headers: {
    "X-API-Key": apiKey
  }
});

const data = await response.json();
console.log(data);
```

### cURL Example:
```bash
curl -X POST http://localhost:8000/api/validate \
  -H "X-API-Key: akm_YAImOpm5ld5cQ6ZygaV2oh3mlVHs_lEU2e2CEoc51uM"
```

## Dashboard Access

**Local Backend**: http://localhost:8000
**Frontend**: Update to use local backend (see below)

## Current Status

✅ Backend running locally on port 8000
✅ Account created and working
✅ API key generated and ready to use
⏳ Railway deployment fixing (will update frontend URL once fixed)

## Next Steps

1. Use the API key in your applications
2. Test validation endpoint
3. Check performance metrics
4. Once Railway is fixed, frontend will connect automatically

---

**Keep this file secure! Your API key is like a password.**
