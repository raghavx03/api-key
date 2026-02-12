FROM python:3.11-slim

WORKDIR /app

# Copy requirements
COPY backend/simple_requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY backend/ /app/backend/

# Create empty JSON files if they don't exist
RUN touch /app/users.json /app/keys.json /app/sessions.json && \
    echo '{}' > /app/users.json && \
    echo '{}' > /app/keys.json && \
    echo '{}' > /app/sessions.json

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "backend/simple_main.py"]
