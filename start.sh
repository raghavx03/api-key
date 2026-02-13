#!/bin/bash

echo "🔑 Starting API Key Management Gateway v2.0..."
echo ""

# Check if .env exists
if [ ! -f "backend/.env" ]; then
    echo "⚠️  Creating .env file..."
    ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
    
    cat > backend/.env << EOF
DATABASE_URL=sqlite:///./api_keys.db
ENCRYPTION_KEY=$ENCRYPTION_KEY
JWT_SECRET_KEY=$JWT_SECRET
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
NVIDIA_API_KEY=your-nvidia-api-key-here
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
EOF
    
    echo "✅ .env file created with secure keys!"
fi

# Install backend deps if needed
if [ ! -d "backend/venv" ]; then
    echo "📦 Setting up Python virtual environment..."
    cd backend && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && cd ..
fi

# Install frontend deps if needed
if [ ! -d "frontend/node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    cd frontend && npm install && cd ..
fi

# Start backend
echo "🚀 Starting backend on http://localhost:8000..."
cd backend && source venv/bin/activate && python main.py &
BACKEND_PID=$!
cd ..

# Wait for backend
sleep 3

# Start frontend
echo "🚀 Starting frontend on http://localhost:3000..."
cd frontend && npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "✅ API Key Gateway v2.0 is running!"
echo "   🌐 Frontend:  http://localhost:3000"
echo "   🔧 Backend:   http://localhost:8000"
echo "   📖 API Docs:  http://localhost:8000/api/v1/docs"
echo ""
echo "Press Ctrl+C to stop..."

trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait
