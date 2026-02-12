# 🚀 Vercel Deployment Guide

## ✅ Files Added

- `vercel.json` - Root configuration
- `frontend/vercel.json` - Frontend routing configuration

## 📝 Vercel Dashboard Settings

### Option 1: Redeploy (Automatic)

Vercel will automatically redeploy after the GitHub push. Wait 1-2 minutes and refresh your Vercel URL.

### Option 2: Manual Configuration

If still showing 404, update these settings in Vercel Dashboard:

1. **Go to your project**: https://vercel.com/dashboard
2. **Click on your project** (api-key)
3. **Settings** → **General**

#### Build & Development Settings:

```
Framework Preset: Vite
Root Directory: frontend
Build Command: npm run build
Output Directory: dist
Install Command: npm install
```

#### Environment Variables (if needed):

```
VITE_API_URL=https://your-backend-url.railway.app
```

4. **Save** and **Redeploy**

## 🔄 Redeploy Steps

### Method 1: From Dashboard

1. Go to **Deployments** tab
2. Click **...** (three dots) on latest deployment
3. Click **Redeploy**

### Method 2: From CLI

```bash
# Install Vercel CLI
npm i -g vercel

# Login
vercel login

# Deploy
cd frontend
vercel --prod
```

### Method 3: Push to GitHub

```bash
# Any push triggers auto-deploy
git commit --allow-empty -m "Trigger Vercel deployment"
git push origin main
```

## ✅ Verify Deployment

After deployment, check:

1. **Homepage**: Should show login page
2. **Console**: No 404 errors
3. **Network**: Check if assets are loading

## 🐛 Still Getting 404?

### Check Build Logs:

1. Go to **Deployments** tab
2. Click on latest deployment
3. Check **Build Logs**
4. Look for errors

### Common Issues:

**Issue 1: Wrong Root Directory**
- Solution: Set Root Directory to `frontend` in settings

**Issue 2: Build Failed**
- Solution: Check if `package.json` exists in `frontend/`
- Run locally: `cd frontend && npm run build`

**Issue 3: Output Directory Wrong**
- Solution: Set Output Directory to `dist`

**Issue 4: Routing Issues**
- Solution: `vercel.json` should have rewrites (already added)

## 📞 Quick Fix Commands

```bash
# Test build locally
cd frontend
npm install
npm run build
# Check if dist/ folder is created

# If build works locally, push to GitHub
git add .
git commit -m "Fix Vercel deployment"
git push origin main
```

## 🎯 Expected Result

After successful deployment:
- ✅ Homepage loads (login page)
- ✅ No 404 errors
- ✅ React app works
- ✅ Routing works (dashboard, login)

## 🔗 Useful Links

- Vercel Dashboard: https://vercel.com/dashboard
- Vercel Docs: https://vercel.com/docs
- Vite Deployment: https://vitejs.dev/guide/static-deploy.html

---

**Note**: Backend needs to be deployed separately on Railway/Heroku. Frontend on Vercel only shows the UI.
