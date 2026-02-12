#!/bin/bash

echo "Testing backend..."

# Test health
echo "1. Health check:"
curl -s http://localhost:8000/api/health
echo ""

# Test registration
echo -e "\n2. Testing registration:"
curl -s -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test","password":"test123"}'
echo ""

echo -e "\nIf you see 'User registered successfully', backend is working!"
