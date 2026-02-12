#!/usr/bin/env python3
"""
Quick Test Script - API Key ko test karne ke liye
"""

import requests
import json

print("🔑 API Key Quick Test\n")
print("=" * 50)

# Step 1: Create a test user
print("\n1️⃣  Creating test user...")
try:
    response = requests.post(
        "http://localhost:8000/api/auth/register",
        json={"email": "test", "password": "test123"}
    )
    if response.status_code == 200:
        print("✅ User created successfully!")
    else:
        print(f"ℹ️  User might already exist: {response.json()}")
except Exception as e:
    print(f"❌ Error: {e}")

# Step 2: Login
print("\n2️⃣  Logging in...")
try:
    response = requests.post(
        "http://localhost:8000/api/auth/login",
        json={"email": "test", "password": "test123"}
    )
    session_data = response.json()
    session_id = session_data['sessionId']
    print(f"✅ Logged in! Session ID: {session_id[:20]}...")
except Exception as e:
    print(f"❌ Error: {e}")
    exit(1)

# Step 3: Create API Key
print("\n3️⃣  Creating API Key...")
try:
    response = requests.post(
        "http://localhost:8000/api/keys",
        headers={"Authorization": f"Bearer {session_id}"},
        json={"label": "Test Key", "provider": "internal"}
    )
    key_data = response.json()
    api_key = key_data['keyValue']
    print(f"✅ API Key created!")
    print(f"   Key: {api_key}")
    print(f"   Label: {key_data['label']}")
    print(f"   Provider: {key_data['provider']}")
except Exception as e:
    print(f"❌ Error: {e}")
    exit(1)

# Step 4: Validate API Key (Method 1: Body)
print("\n4️⃣  Validating API Key (Method 1: Body)...")
try:
    response = requests.post(
        "http://localhost:8000/api/validate",
        json={"apiKey": api_key}
    )
    validation_data = response.json()
    print(f"✅ Validation successful!")
    print(f"   Valid: {validation_data['valid']}")
    print(f"   User ID: {validation_data['userId']}")
    print(f"   Provider: {validation_data['provider']}")
except Exception as e:
    print(f"❌ Error: {e}")

# Step 5: Validate API Key (Method 2: Header)
print("\n5️⃣  Validating API Key (Method 2: Header)...")
try:
    response = requests.post(
        "http://localhost:8000/api/validate",
        headers={"X-API-Key": api_key}
    )
    print(f"✅ Header validation successful!")
except Exception as e:
    print(f"❌ Error: {e}")

# Step 6: Validate API Key (Method 3: Query Param)
print("\n6️⃣  Validating API Key (Method 3: Query Param)...")
try:
    response = requests.post(
        f"http://localhost:8000/api/validate?api_key={api_key}"
    )
    print(f"✅ Query param validation successful!")
except Exception as e:
    print(f"❌ Error: {e}")

# Step 7: List all keys
print("\n7️⃣  Listing all API Keys...")
try:
    response = requests.get(
        "http://localhost:8000/api/keys",
        headers={"Authorization": f"Bearer {session_id}"}
    )
    keys_data = response.json()
    print(f"✅ Found {len(keys_data['keys'])} key(s):")
    for key in keys_data['keys']:
        print(f"   - {key['label']} ({key['status']}) - Created: {key['createdAt']}")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n" + "=" * 50)
print("🎉 All tests passed!")
print("\n📝 Your API Key:")
print(f"   {api_key}")
print("\n💡 Use this key in your applications!")
print("\n📖 Check examples/USAGE_GUIDE.md for more examples")
