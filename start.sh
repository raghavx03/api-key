#!/bin/bash

echo "🔑 Starting API Key Management Dashboard..."
echo ""

# Check if .env exists
if [ ! -f "backend/.env" ]; then
    echo "⚠️  Creating .env file..."
    cd backend
    
    # Generate encryption key
    ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    
    cat > .env << EOF
DATABASE_URL=sqlite:///./api_keys.db
ENCRYPTION_KEY=$ENCRYPTION_KEY
NVIDIA_API_KEY=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
EOF
    
    echo "✅ .env file created!"
    cd ..
fi

# Start backend
echo "🚀 Starting backend on http://localhost:8000..."
cd backend
python3 main.py &
BACKEND_PID=$!
cd ..

# Wait for backend to start
sleep 3

# Start frontend
echo "🚀 Starting frontend on http://localhost:3000..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "✅ Dashboard is running!"
echo "   Frontend: http://localhost:3000"
echo "   Backend:  http://localhost:8000"
echo ""
echo "Press Ctrl+C to stop..."

# Wait for Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait
