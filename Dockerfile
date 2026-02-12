FROM python:3.11-slim

WORKDIR /app

# Copy requirements
COPY backend/simple_requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY backend/ /app/backend/
COPY users.json keys.json sessions.json /app/ 2>/dev/null || true

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "backend/simple_main.py"]
