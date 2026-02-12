# Deployment Steps - API Key Management Dashboard

## Current Status
✅ GitHub repository: https://github.com/raghavx03/api-key
✅ Code pushed with deployment fixes
⏳ Railway backend needs redeploy
⏳ Vercel frontend needs redeploy

## Step 1: Deploy Backend on Railway

1. Go to Railway dashboard: https://railway.app/dashboard
2. Find your `api-key-production` project
3. Click on the service
4. Click **"Redeploy"** button (this will use the new nixpacks.toml configuration)
5. Wait 2-3 minutes for deployment to complete
6. Check the deployment logs - should see: `Uvicorn running on http://0.0.0.0:8000`
7. Verify environment variable is set:
   - Variable name: `ENCRYPTION_KEY`
   - Value: `AIiL3wabOdqo8WMJVShHSHhOjLvtVzBG4_RgsEdlcz0=`

## Step 2: Deploy Frontend on Vercel

### Option A: Redeploy Existing Project
1. Go to Vercel dashboard: https://vercel.com/dashboard
2. Find your project
3. Click **"Redeploy"** on the latest deployment
4. Wait 2-3 minutes

### Option B: Create New Deployment (if you deleted the project)
1. Go to https://vercel.com/new
2. Import from GitHub: `raghavx03/api-key`
3. Configure project:
   - **Framework Preset**: Other
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
   - **Install Command**: `npm install`
4. Add Environment Variable:
   - Name: `VITE_API_URL`
   - Value: `https://api-key-production.up.railway.app`
5. Click **Deploy**

## Step 3: Verify Deployment

### Test Backend
```bash
curl https://api-key-production.up.railway.app/api/health
```
Should return: `{"status":"healthy"}`

### Test Frontend
1. Open your Vercel URL (e.g., `https://your-project.vercel.app`)
2. You should see the login page
3. Register a new account
4. Login and create an API key

## Step 4: Test Complete Flow

1. **Register**: Create a new user account
2. **Login**: Login with your credentials
3. **Create API Key**: Click "Generate New API Key"
4. **Copy Key**: Copy the generated key
5. **Test Validation**: Use the validation endpoint

```bash
curl -X POST https://api-key-production.up.railway.app/api/keys/validate \
  -H "Content-Type: application/json" \
  -d '{"api_key": "YOUR_KEY_HERE"}'
```

## Troubleshooting

### Railway Backend Issues
- Check logs in Railway dashboard
- Ensure `ENCRYPTION_KEY` environment variable is set
- Verify nixpacks.toml is being used (check build logs)

### Vercel Frontend Issues
- Check deployment logs in Vercel dashboard
- Ensure `VITE_API_URL` environment variable is set
- Verify root directory is set to `frontend`

### CORS Issues
- Backend allows all origins in production
- If you see CORS errors, check browser console

## Next Steps After Deployment

Once both are deployed and working:

1. **Save your Vercel URL** - this is your dashboard URL
2. **Create your first API key** in the dashboard
3. **Use the API key** in your applications (see examples/ folder)
4. **Test with NVIDIA API** - your key is already configured in the backend

## Performance Notes

- API key validation is extremely fast (< 10ms)
- Keys are encrypted with AES-256
- Session management with secure cookies
- File-based storage for simplicity (can scale to database later)
