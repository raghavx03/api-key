#!/bin/bash

echo "🔍 Checking Deployment Status..."
echo ""

# Check Frontend
echo "📱 Frontend (Vercel):"
FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://api-key-blush.vercel.app)
if [ "$FRONTEND_STATUS" = "200" ]; then
    echo "✅ Frontend is LIVE - https://api-key-blush.vercel.app"
else
    echo "❌ Frontend is DOWN (Status: $FRONTEND_STATUS)"
fi

echo ""

# Check Backend
echo "🔧 Backend (Railway):"
BACKEND_RESPONSE=$(curl -s https://api-key-production.up.railway.app/api/health)
if echo "$BACKEND_RESPONSE" | grep -q "healthy"; then
    echo "✅ Backend is LIVE - https://api-key-production.up.railway.app"
    echo "   Response: $BACKEND_RESPONSE"
else
    echo "❌ Backend is DOWN or deploying..."
    echo "   Response: $BACKEND_RESPONSE"
    echo ""
    echo "💡 If backend is deploying, wait 2-3 minutes and run this script again"
fi

echo ""
echo "🎯 Test Credentials:"
echo "   Email: demo@test.com"
echo "   Password: demo123"
