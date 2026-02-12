# 🚀 Complete Deployment Guide - Railway + Vercel

## 📋 Overview

- **Backend**: Railway (Python/FastAPI)
- **Frontend**: Vercel (React/Vite)

---

## 🔧 Step 1: Get Railway Backend URL

1. Go to Railway dashboard: https://railway.app/dashboard
2. Click on your backend project
3. Go to **Settings** → **Domains**
4. Copy the URL (e.g., `https://api-key-backend-production.up.railway.app`)

---

## 🔧 Step 2: Update Frontend Configuration

### Option A: Update .env.production file

Edit `frontend/.env.production`:

```bash
VITE_API_URL=https://your-railway-backend-url.railway.app
```

### Option B: Set in Vercel Dashboard

1. Go to Vercel dashboard: https://vercel.com/dashboard
2. Select your project
3. Go to **Settings** → **Environment Variables**
4. Add:
   - **Name**: `VITE_API_URL`
   - **Value**: `https://your-railway-backend-url.railway.app`
   - **Environment**: Production

---

## 🔧 Step 3: Push to GitHub

```bash
git add .
git commit -m "Configure production backend URL"
git push origin main
```

This will automatically trigger:
- ✅ Vercel redeploy (frontend)
- ✅ Railway redeploy (backend)

---

## 🔧 Step 4: Verify Deployment

### Backend (Railway):

```bash
# Test health endpoint
curl https://your-railway-backend-url.railway.app/api/health

# Should return:
# {"status":"healthy","timestamp":"..."}
```

### Frontend (Vercel):

1. Open your Vercel URL
2. Should see login page
3. Try registering and logging in
4. Create an API key

---

## 🐛 Troubleshooting

### Issue 1: Vercel still shows 404

**Solution:**
1. Go to Vercel dashboard
2. **Settings** → **General**
3. Set:
   - Root Directory: `frontend`
   - Build Command: `npm run build`
   - Output Directory: `dist`
4. **Deployments** → **Redeploy**

### Issue 2: Backend not responding

**Solution:**
1. Check Railway logs
2. Make sure `ENCRYPTION_KEY` is set in Railway environment variables
3. Redeploy backend

### Issue 3: CORS errors

**Solution:**
Backend already has CORS configured. If still getting errors, update `backend/simple_main.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-vercel-url.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Issue 4: API calls failing

**Solution:**
1. Check browser console for errors
2. Verify `VITE_API_URL` is set correctly
3. Test backend URL directly in browser

---

## 📝 Quick Commands

### Redeploy Everything:

```bash
# Trigger both deployments
git commit --allow-empty -m "Redeploy"
git push origin main
```

### Test Backend:

```bash
# Health check
curl https://your-backend.railway.app/api/health

# Register user
curl -X POST https://your-backend.railway.app/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test","password":"test123"}'

# Login
curl -X POST https://your-backend.railway.app/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test","password":"test123"}'
```

### Check Vercel Build:

```bash
# Install Vercel CLI
npm i -g vercel

# Check deployment
vercel ls

# View logs
vercel logs
```

---

## ✅ Final Checklist

- [ ] Railway backend is deployed and responding
- [ ] Railway backend URL is copied
- [ ] Frontend `.env.production` is updated OR Vercel env var is set
- [ ] Code is pushed to GitHub
- [ ] Vercel has redeployed
- [ ] Frontend loads without 404
- [ ] Can register/login on frontend
- [ ] Can create API keys
- [ ] API keys can be validated

---

## 🎯 Expected URLs

After successful deployment:

- **Frontend**: `https://your-project.vercel.app`
- **Backend**: `https://your-backend.railway.app`
- **API Health**: `https://your-backend.railway.app/api/health`
- **GitHub**: `https://github.com/raghavx03/api-key`

---

## 🔐 Environment Variables

### Railway (Backend):

```
ENCRYPTION_KEY=<generate-with-python>
PORT=8000
```

Generate encryption key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Vercel (Frontend):

```
VITE_API_URL=https://your-backend.railway.app
```

---

## 📞 Need Help?

1. Check Railway logs: Railway Dashboard → Your Project → Logs
2. Check Vercel logs: Vercel Dashboard → Your Project → Deployments → View Logs
3. Test locally first: `./start.sh`

---

Happy Deploying! 🚀
