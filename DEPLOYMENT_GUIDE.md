# 🚀 Deployment Guide - Live Kaise Karein

Apne API Key Management Dashboard ko internet pe live karne ke liye.

---

## 🎯 Deployment Options

### Option 1: Railway (Easiest - Free Tier Available)

#### Backend Deploy:

1. **Railway account banao**: https://railway.app
2. **New Project** → **Deploy from GitHub**
3. **Backend setup:**
   ```bash
   # railway.json banao
   {
     "build": {
       "builder": "NIXPACKS"
     },
     "deploy": {
       "startCommand": "python backend/simple_main.py",
       "restartPolicyType": "ON_FAILURE"
     }
   }
   ```

4. **Environment Variables set karo:**
   - `ENCRYPTION_KEY`: Generate karo
   - `PORT`: 8000

5. **Deploy!** Railway automatically URL dega: `https://your-app.railway.app`

#### Frontend Deploy:

1. **Vercel account banao**: https://vercel.com
2. **Import Git Repository**
3. **Build settings:**
   - Framework: Vite
   - Root Directory: `frontend`
   - Build Command: `npm run build`
   - Output Directory: `dist`

4. **Environment Variables:**
   - `VITE_API_URL`: Your Railway backend URL

5. **Deploy!** Vercel URL milega: `https://your-app.vercel.app`

---

### Option 2: Heroku (Popular)

#### Backend:

```bash
# Heroku CLI install karo
brew install heroku/brew/heroku  # Mac
# ya https://devcenter.heroku.com/articles/heroku-cli

# Login
heroku login

# Create app
heroku create your-api-key-backend

# Set environment variables
heroku config:set ENCRYPTION_KEY=your-key-here

# Deploy
git push heroku main

# URL milega: https://your-api-key-backend.herokuapp.com
```

#### Frontend:

```bash
# Frontend ke liye alag app
heroku create your-api-key-frontend

# Build settings
heroku buildpacks:set heroku/nodejs

# Deploy
git subtree push --prefix frontend heroku main
```

---

### Option 3: DigitalOcean App Platform

1. **Account banao**: https://www.digitalocean.com
2. **Create App** → **GitHub se connect**
3. **Backend component:**
   - Type: Web Service
   - Run Command: `python backend/simple_main.py`
   - Port: 8000

4. **Frontend component:**
   - Type: Static Site
   - Build Command: `cd frontend && npm run build`
   - Output Directory: `frontend/dist`

5. **Deploy!** URLs milenge automatically

---

### Option 4: AWS (Advanced)

#### Backend (EC2):

```bash
# EC2 instance launch karo
# SSH karo
ssh -i your-key.pem ubuntu@your-ec2-ip

# Setup
sudo apt update
sudo apt install python3-pip nginx

# Clone repo
git clone your-repo
cd your-repo

# Install dependencies
pip3 install -r backend/simple_requirements.txt

# Run with systemd
sudo nano /etc/systemd/system/apikey.service
```

**apikey.service:**
```ini
[Unit]
Description=API Key Management Backend
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/your-repo
ExecStart=/usr/bin/python3 backend/simple_main.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Start service
sudo systemctl start apikey
sudo systemctl enable apikey

# Setup nginx reverse proxy
sudo nano /etc/nginx/sites-available/apikey
```

**nginx config:**
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/apikey /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

#### Frontend (S3 + CloudFront):

```bash
# Build frontend
cd frontend
npm run build

# Upload to S3
aws s3 sync dist/ s3://your-bucket-name --acl public-read

# Setup CloudFront distribution
# Point to S3 bucket
```

---

### Option 5: Docker + Any Cloud

#### Create Dockerfile for Backend:

```dockerfile
# backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY backend/simple_requirements.txt .
RUN pip install --no-cache-dir -r simple_requirements.txt

COPY backend/ .

EXPOSE 8000

CMD ["python", "simple_main.py"]
```

#### Create Dockerfile for Frontend:

```dockerfile
# frontend/Dockerfile
FROM node:18-alpine as build

WORKDIR /app

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

#### Docker Compose:

```yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    build:
      context: .
      dockerfile: backend/Dockerfile
    ports:
      - "8000:8000"
    environment:
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
    restart: always

  frontend:
    build:
      context: .
      dockerfile: frontend/Dockerfile
    ports:
      - "80:80"
    depends_on:
      - backend
    restart: always
```

**Deploy to any cloud:**
```bash
# Build and run
docker-compose up -d

# Ya push to Docker Hub and deploy
docker-compose push
```

---

## 🔒 Production Checklist

### Security:

- [ ] HTTPS enable karo (Let's Encrypt free hai)
- [ ] Environment variables secure rakho
- [ ] CORS properly configure karo
- [ ] Rate limiting add karo
- [ ] Database backup setup karo

### Performance:

- [ ] Redis add karo for caching
- [ ] PostgreSQL use karo (SQLite ki jagah)
- [ ] CDN setup karo for frontend
- [ ] Load balancer add karo (if needed)

### Monitoring:

- [ ] Logging setup karo (Sentry, LogRocket)
- [ ] Uptime monitoring (UptimeRobot, Pingdom)
- [ ] Error tracking
- [ ] Analytics

---

## 🎯 Quick Deploy - Railway (Recommended)

**Sabse easy aur free:**

1. **Backend:**
   ```bash
   # Railway CLI install
   npm i -g @railway/cli
   
   # Login
   railway login
   
   # Deploy
   railway init
   railway up
   
   # URL milega: https://your-app.railway.app
   ```

2. **Frontend:**
   ```bash
   # Vercel CLI install
   npm i -g vercel
   
   # Deploy
   cd frontend
   vercel
   
   # URL milega: https://your-app.vercel.app
   ```

3. **Update frontend API URL:**
   ```javascript
   // frontend/src/api.ts
   const API_BASE = 'https://your-app.railway.app/api'
   ```

4. **Done!** Ab kahi se bhi access karo! 🎉

---

## 💰 Cost Comparison

| Platform | Backend | Frontend | Total/Month |
|----------|---------|----------|-------------|
| Railway + Vercel | Free | Free | $0 |
| Heroku | $7 | Free | $7 |
| DigitalOcean | $5 | $0 | $5 |
| AWS | ~$10 | ~$1 | ~$11 |

**Recommendation:** Start with Railway + Vercel (Free!)

---

## 🚀 After Deployment

### Update your code:

```python
# Instead of localhost
API_URL = "http://localhost:8000"

# Use production URL
API_URL = "https://your-app.railway.app"
```

### Test:

```bash
# Test backend
curl https://your-app.railway.app/api/health

# Test validation
curl -X POST https://your-app.railway.app/api/validate \
  -H "Content-Type: application/json" \
  -d '{"apiKey": "akm_your_key"}'
```

### Use anywhere:

```python
import requests

# Ab kahi se bhi use karo!
response = requests.post(
    "https://your-app.railway.app/api/validate",
    json={"apiKey": "akm_your_key"}
)
```

---

## 📞 Need Help?

- Railway Docs: https://docs.railway.app
- Vercel Docs: https://vercel.com/docs
- Heroku Docs: https://devcenter.heroku.com

Happy Deploying! 🚀
