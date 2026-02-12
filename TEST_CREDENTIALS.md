# Test Credentials

## Demo Account
- **Email**: demo@test.com
- **Password**: demo123

## Production URLs
- **Frontend**: https://api-key-blush.vercel.app
- **Backend**: https://api-key-production.up.railway.app

## How to Test

1. Go to https://api-key-blush.vercel.app/login
2. Click "Register" if you want to create a new account, or use the demo account above
3. Login with your credentials
4. Create API keys in the dashboard
5. See real-time performance metrics:
   - Usage count (how many times the key was used)
   - Average response time (speed in milliseconds)
   - Color-coded speed indicators:
     - 🟢 Green (< 50ms) = Super fast
     - 🟡 Yellow (50-200ms) = Good
     - 🔴 Red (> 200ms) = Slow

## Performance Features

The dashboard now shows:
- **Usage Count**: Total number of API calls made with each key
- **Average Speed**: Average response time in milliseconds
- **Speed Indicator**: Color-coded to show performance
  - Fast (< 50ms): Green
  - Medium (50-200ms): Yellow
  - Slow (> 200ms): Red

## API Key Usage

Once you create an API key, you can use it in your applications:

```python
import requests

response = requests.post(
    "https://api-key-production.up.railway.app/api/validate",
    headers={"X-API-Key": "your_key_here"}
)

print(response.json())
# Output: {"valid": true, "responseTimeMs": 25.5, ...}
```

## NVIDIA API Key

Your NVIDIA API key is already configured in the backend:
```
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
```

When you create a key with provider "NVIDIA", it will use this key internally.
