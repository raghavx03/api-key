import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Key, AlertCircle, Info } from 'lucide-react'
import './Docs.css'

type Section = 'intro' | 'auth' | 'keys' | 'validate' | 'admin' | 'errors' | 'examples'

const BASE_URL = 'https://api.ragspro.com'

export default function Docs() {
    const [section, setSection] = useState<Section>('intro')

    return (
        <div className="docs-page">
            {/* Reuse landing nav */}
            <nav className="landing-nav">
                <Link to="/" className="nav-logo">
                    <div className="logo-icon"><Key size={18} color="#fff" /></div>
                    RagsPro API
                </Link>
                <div className="nav-links">
                    <Link to="/">Home</Link>
                    <Link to="/docs">Docs</Link>
                    <Link to="/login" className="nav-cta">Dashboard</Link>
                </div>
            </nav>

            <div className="docs-layout">
                {/* Sidebar */}
                <aside className="docs-sidebar">
                    <h4>Getting Started</h4>
                    <button className={`sidebar-link ${section === 'intro' ? 'active' : ''}`} onClick={() => setSection('intro')}>Introduction</button>
                    <button className={`sidebar-link ${section === 'auth' ? 'active' : ''}`} onClick={() => setSection('auth')}>Authentication</button>

                    <h4>API Reference</h4>
                    <button className={`sidebar-link ${section === 'keys' ? 'active' : ''}`} onClick={() => setSection('keys')}>Key Management</button>
                    <button className={`sidebar-link ${section === 'validate' ? 'active' : ''}`} onClick={() => setSection('validate')}>Validation</button>
                    <button className={`sidebar-link ${section === 'admin' ? 'active' : ''}`} onClick={() => setSection('admin')}>Admin</button>

                    <h4>Resources</h4>
                    <button className={`sidebar-link ${section === 'examples' ? 'active' : ''}`} onClick={() => setSection('examples')}>Code Examples</button>
                    <button className={`sidebar-link ${section === 'errors' ? 'active' : ''}`} onClick={() => setSection('errors')}>Errors & Limits</button>
                </aside>

                {/* Content */}
                <main className="docs-content">
                    {section === 'intro' && <IntroSection />}
                    {section === 'auth' && <AuthSection />}
                    {section === 'keys' && <KeysSection />}
                    {section === 'validate' && <ValidateSection />}
                    {section === 'admin' && <AdminSection />}
                    {section === 'examples' && <ExamplesSection />}
                    {section === 'errors' && <ErrorsSection />}
                </main>
            </div>
        </div>
    )
}

function IntroSection() {
    return (
        <>
            <h1>RagsPro API Documentation</h1>
            <p className="docs-intro">
                RagsPro API Gateway provides enterprise-grade API key management with encryption,
                role-based access control, and real-time analytics. This documentation covers all
                17 endpoints available in the REST API.
            </p>

            <h2>Base URL</h2>
            <div className="doc-code-block">{BASE_URL}/api/v1</div>

            <h2>Quick Start</h2>
            <h3>1. Create an Account</h3>
            <div className="doc-code-block">{`curl -X POST ${BASE_URL}/api/v1/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{"email": "you@example.com", "password": "SecurePass123"}'`}</div>

            <h3>2. Login and Get Token</h3>
            <div className="doc-code-block">{`curl -X POST ${BASE_URL}/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email": "you@example.com", "password": "SecurePass123"}'

# Response:
{
  "access_token": "eyJhbGciOiJIUzI1...",
  "refresh_token": "eyJhbGciOiJIUzI1...",
  "token_type": "bearer"
}`}</div>

            <h3>3. Create an API Key</h3>
            <div className="doc-code-block">{`curl -X POST ${BASE_URL}/api/v1/keys \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"label": "My First Key", "provider": "internal"}'

# Response includes raw_key — save it! Not shown again.`}</div>

            <h3>4. Validate a Key</h3>
            <div className="doc-code-block">{`curl -X POST ${BASE_URL}/api/v1/validate \\
  -H "Content-Type: application/json" \\
  -d '{"apiKey": "akm_your_key_here"}'

# Response: {"valid": true, "key_id": "...", "scope": "read_write"}`}</div>

            <div className="docs-alert info">
                <Info size={18} />
                <span>All endpoints return JSON. Use <code>Content-Type: application/json</code> for request bodies.</span>
            </div>
        </>
    )
}

function AuthSection() {
    return (
        <>
            <h1>Authentication</h1>
            <p className="docs-intro">
                The API uses JWT (JSON Web Tokens) for authentication. After login, include
                the access token in the <code>Authorization</code> header of all protected requests.
            </p>

            <div className="docs-alert info">
                <Info size={18} />
                <span>Access tokens expire in <strong>15 minutes</strong>. Use the refresh token to get a new one without re-logging in.</span>
            </div>

            <h2>Register</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/api/v1/auth/register</span>
                    <span className="endpoint-desc">Create a new account</span>
                </div>
                <div className="endpoint-body">
                    <h4>Request Body</h4>
                    <table className="params-table">
                        <thead><tr><th>Field</th><th>Type</th><th>Rules</th></tr></thead>
                        <tbody>
                            <tr><td><code>email</code></td><td>string</td><td>Valid email, 5-255 chars</td></tr>
                            <tr><td><code>password</code></td><td>string</td><td>8-128 chars, 1 uppercase, 1 lowercase, 1 digit</td></tr>
                        </tbody>
                    </table>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "message": "User registered successfully",
  "user_id": "abc123...",
  "email": "you@example.com",
  "role": "admin"
}`}</div>
                </div>
            </div>

            <h2>Login</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/api/v1/auth/login</span>
                    <span className="endpoint-desc">Get JWT tokens</span>
                </div>
                <div className="endpoint-body">
                    <h4>Request Body</h4>
                    <table className="params-table">
                        <thead><tr><th>Field</th><th>Type</th></tr></thead>
                        <tbody>
                            <tr><td><code>email</code></td><td>string</td></tr>
                            <tr><td><code>password</code></td><td>string</td></tr>
                        </tbody>
                    </table>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "access_token": "eyJhbGciOiJIUzI1...",
  "refresh_token": "eyJhbGciOiJIUzI1...",
  "token_type": "bearer",
  "user": {
    "user_id": "abc123",
    "email": "you@example.com",
    "role": "admin"
  }
}`}</div>
                </div>
            </div>

            <h2>Refresh Token</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/api/v1/auth/refresh</span>
                    <span className="endpoint-desc">Get new access token</span>
                </div>
                <div className="endpoint-body">
                    <h4>Request Body</h4>
                    <div className="doc-code-block">{`{"refresh_token": "eyJhbGciOiJIUzI1..."}`}</div>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{"access_token": "new_access_token...", "token_type": "bearer"}`}</div>
                </div>
            </div>

            <h2>Get Profile</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge get">GET</span>
                    <span className="endpoint-path">/api/v1/auth/me</span>
                    <span className="endpoint-desc">Current user info</span>
                </div>
                <div className="endpoint-body">
                    <h4>Headers</h4>
                    <div className="doc-code-block">Authorization: Bearer YOUR_ACCESS_TOKEN</div>
                </div>
            </div>

            <h2>Logout</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/api/v1/auth/logout</span>
                    <span className="endpoint-desc">Revoke refresh token</span>
                </div>
                <div className="endpoint-body">
                    <h4>Request Body</h4>
                    <div className="doc-code-block">{`{"refresh_token": "eyJhbGciOiJIUzI1..."}`}</div>
                </div>
            </div>
        </>
    )
}

function KeysSection() {
    return (
        <>
            <h1>Key Management</h1>
            <p className="docs-intro">
                Create, list, update, delete, and rotate API keys. All endpoints require
                authentication via JWT token.
            </p>

            <h2>Create Key</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/api/v1/keys</span>
                    <span className="endpoint-desc">Generate a new API key</span>
                </div>
                <div className="endpoint-body">
                    <h4>Request Body</h4>
                    <table className="params-table">
                        <thead><tr><th>Field</th><th>Type</th><th>Default</th><th>Description</th></tr></thead>
                        <tbody>
                            <tr><td><code>label</code></td><td>string</td><td>required</td><td>Human-readable name</td></tr>
                            <tr><td><code>provider</code></td><td>string</td><td>"internal"</td><td>internal, nvidia, openai, custom</td></tr>
                            <tr><td><code>scope</code></td><td>string</td><td>"read_write"</td><td>read_only, read_write, full_access</td></tr>
                            <tr><td><code>usage_quota</code></td><td>integer</td><td>0</td><td>Max API calls (0 = unlimited)</td></tr>
                            <tr><td><code>expires_in_days</code></td><td>integer</td><td>null</td><td>Days until expiry (null = never)</td></tr>
                            <tr><td><code>allowed_ips</code></td><td>string[]</td><td>[]</td><td>Whitelist IPs</td></tr>
                        </tbody>
                    </table>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "key_id": "abc123...",
  "label": "Production Key",
  "provider": "nvidia",
  "scope": "read_write",
  "status": "active",
  "raw_key": "akm_5QQ2yIRqVWAs..."   ← Save this! Not shown again.
}`}</div>
                    <div className="docs-alert warning">
                        <AlertCircle size={18} />
                        <span>The <code>raw_key</code> is only returned once during creation. Store it securely — you cannot retrieve it again.</span>
                    </div>
                </div>
            </div>

            <h2>List Keys</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge get">GET</span>
                    <span className="endpoint-path">/api/v1/keys</span>
                    <span className="endpoint-desc">List all your keys</span>
                </div>
                <div className="endpoint-body">
                    <h4>Query Parameters</h4>
                    <table className="params-table">
                        <thead><tr><th>Param</th><th>Type</th><th>Description</th></tr></thead>
                        <tbody>
                            <tr><td><code>provider</code></td><td>string</td><td>Filter by provider</td></tr>
                            <tr><td><code>status</code></td><td>string</td><td>active, inactive, expired</td></tr>
                            <tr><td><code>search</code></td><td>string</td><td>Search by label</td></tr>
                            <tr><td><code>page</code></td><td>integer</td><td>Page number (default: 1)</td></tr>
                            <tr><td><code>per_page</code></td><td>integer</td><td>Items per page (default: 12)</td></tr>
                            <tr><td><code>sort_by</code></td><td>string</td><td>created_at, label, last_used_at</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <h2>Update Key</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge patch">PATCH</span>
                    <span className="endpoint-path">/api/v1/keys/:key_id</span>
                    <span className="endpoint-desc">Update label, status, or scope</span>
                </div>
                <div className="endpoint-body">
                    <h4>Request Body</h4>
                    <div className="doc-code-block">{`{
  "label": "New Label",      // optional
  "status": "inactive",      // optional: active / inactive
  "scope": "read_only"       // optional
}`}</div>
                </div>
            </div>

            <h2>Delete Key</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge delete">DELETE</span>
                    <span className="endpoint-path">/api/v1/keys/:key_id</span>
                    <span className="endpoint-desc">Permanently delete a key</span>
                </div>
            </div>

            <h2>Rotate Key</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/api/v1/keys/:key_id/rotate</span>
                    <span className="endpoint-desc">Replace with new key</span>
                </div>
                <div className="endpoint-body">
                    <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        Disables the old key and generates a new one with the same settings.
                        Returns the new <code>raw_key</code>.
                    </p>
                </div>
            </div>

            <h2>Key Stats</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge get">GET</span>
                    <span className="endpoint-path">/api/v1/keys/:key_id/stats</span>
                    <span className="endpoint-desc">Usage analytics for a key</span>
                </div>
                <div className="endpoint-body">
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "key_id": "abc123",
  "total_validations": 1547,
  "successful_validations": 1520,
  "failed_validations": 27,
  "avg_response_time_ms": 8.3,
  "last_used_at": "2026-02-13T18:00:00Z"
}`}</div>
                </div>
            </div>
        </>
    )
}

function ValidateSection() {
    return (
        <>
            <h1>Key Validation</h1>
            <p className="docs-intro">
                The validate endpoint is the core of your integration. Call it from your apps
                to check if an API key is valid before processing requests.
            </p>

            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/api/v1/validate</span>
                    <span className="endpoint-desc">Check if a key is valid</span>
                </div>
                <div className="endpoint-body">
                    <h4>Methods to Pass the Key</h4>
                    <table className="params-table">
                        <thead><tr><th>Method</th><th>How</th></tr></thead>
                        <tbody>
                            <tr><td>Request Body</td><td><code>{`{"apiKey": "akm_..."}`}</code></td></tr>
                            <tr><td>Header</td><td><code>X-API-Key: akm_...</code></td></tr>
                            <tr><td>Query Param</td><td><code>?api_key=akm_...</code></td></tr>
                        </tbody>
                    </table>

                    <h4>Success Response</h4>
                    <div className="doc-code-block">{`{
  "valid": true,
  "key_id": "abc123",
  "label": "Production Key",
  "provider": "nvidia",
  "scope": "read_write",
  "usage_count": 1547,
  "owner_email": "you@example.com"
}`}</div>

                    <h4>Invalid Key Response</h4>
                    <div className="doc-code-block">{`{
  "valid": false,
  "error": "Invalid API key"
}`}</div>
                </div>
            </div>

            <h2>Integration Example</h2>
            <p>Add this middleware to your Express.js app:</p>
            <div className="doc-code-block">{`// Express.js middleware
async function validateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing API key' });

  const response = await fetch('${BASE_URL}/api/v1/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey })
  });
  const { valid } = await response.json();

  if (!valid) return res.status(403).json({ error: 'Invalid API key' });
  next();
}

app.use('/api', validateApiKey);`}</div>

            <p>Or in Python FastAPI:</p>
            <div className="doc-code-block">{`import httpx
from fastapi import Header, HTTPException

async def validate_key(x_api_key: str = Header(...)):
    async with httpx.AsyncClient() as client:
        res = await client.post(
            "${BASE_URL}/api/v1/validate",
            json={"apiKey": x_api_key}
        )
    if not res.json().get("valid"):
        raise HTTPException(403, "Invalid API key")

@app.get("/protected", dependencies=[Depends(validate_key)])
async def protected_route():
    return {"message": "Access granted!"}`}</div>
        </>
    )
}

function AdminSection() {
    return (
        <>
            <h1>Admin Endpoints</h1>
            <p className="docs-intro">
                Admin endpoints are only accessible to users with the <code>admin</code> role.
                The first registered user automatically becomes admin.
            </p>

            <h2>Dashboard Stats</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge get">GET</span>
                    <span className="endpoint-path">/api/v1/admin/stats</span>
                    <span className="endpoint-desc">System-wide statistics</span>
                </div>
                <div className="endpoint-body">
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "total_users": 42,
  "total_keys": 156,
  "active_keys": 128,
  "total_validations": 45_230,
  "providers": {"nvidia": 45, "openai": 32, "internal": 79}
}`}</div>
                </div>
            </div>

            <h2>List Users</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge get">GET</span>
                    <span className="endpoint-path">/api/v1/admin/users</span>
                    <span className="endpoint-desc">All registered users</span>
                </div>
            </div>

            <h2>Audit Logs</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge get">GET</span>
                    <span className="endpoint-path">/api/v1/admin/audit-logs</span>
                    <span className="endpoint-desc">Security event trail</span>
                </div>
                <div className="endpoint-body">
                    <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        Returns all actions: key creation, deletion, rotation, login attempts, etc.
                        Pagination supported with <code>?page=1&per_page=50</code>.
                    </p>
                </div>
            </div>

            <h2>Health Check</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge get">GET</span>
                    <span className="endpoint-path">/api/v1/health</span>
                    <span className="endpoint-desc">API + DB health (no auth required)</span>
                </div>
                <div className="endpoint-body">
                    <div className="doc-code-block">{`{
  "status": "healthy",
  "checks": {"api": "healthy", "database": "healthy"},
  "version": "2.0.0",
  "timestamp": "2026-02-13T18:09:19Z"
}`}</div>
                </div>
            </div>
        </>
    )
}

function ExamplesSection() {
    return (
        <>
            <h1>Code Examples</h1>
            <p className="docs-intro">
                Complete examples showing how to integrate RagsPro API into your applications.
            </p>

            <h2>Python — Full Workflow</h2>
            <div className="doc-code-block">{`import requests

BASE = "${BASE_URL}/api/v1"

# 1. Register
requests.post(f"{BASE}/auth/register", json={
    "email": "dev@myapp.com",
    "password": "SecurePass123"
})

# 2. Login
tokens = requests.post(f"{BASE}/auth/login", json={
    "email": "dev@myapp.com",
    "password": "SecurePass123"
}).json()

headers = {"Authorization": f"Bearer {tokens['access_token']}"}

# 3. Create a key
key = requests.post(f"{BASE}/keys", json={
    "label": "Production NVIDIA",
    "provider": "nvidia",
    "scope": "read_write",
    "usage_quota": 10000,
    "expires_in_days": 90
}, headers=headers).json()

print(f"Key created: {key['raw_key']}")

# 4. Validate the key (from any service)
result = requests.post(f"{BASE}/validate", json={
    "apiKey": key["raw_key"]
}).json()

print(f"Valid: {result['valid']}")  # True

# 5. List all keys
keys = requests.get(f"{BASE}/keys", headers=headers).json()
print(f"Total keys: {len(keys['keys'])}")

# 6. Rotate a key
new_key = requests.post(
    f"{BASE}/keys/{key['key_id']}/rotate",
    headers=headers
).json()
print(f"New key: {new_key['raw_key']}")`}</div>

            <h2>JavaScript — Express Middleware</h2>
            <div className="doc-code-block">{`const express = require('express');
const app = express();

// Middleware: Validate API key on every request
async function requireApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  try {
    const response = await fetch('${BASE_URL}/api/v1/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey })
    });
    const data = await response.json();
    
    if (!data.valid) {
      return res.status(403).json({ error: 'Invalid API key' });
    }
    
    req.apiKeyInfo = data; // Attach key info to request
    next();
  } catch (err) {
    return res.status(500).json({ error: 'Validation service unavailable' });
  }
}

// Protected routes
app.get('/api/data', requireApiKey, (req, res) => {
  res.json({
    message: 'Access granted!',
    scope: req.apiKeyInfo.scope,
    provider: req.apiKeyInfo.provider
  });
});

app.listen(3001, () => console.log('Server running on :3001'));`}</div>

            <h2>React — API Client</h2>
            <div className="doc-code-block">{`// apiClient.ts
const API_KEY = import.meta.env.VITE_API_KEY;

async function fetchWithKey(url: string, options: RequestInit = {}) {
  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json',
    },
  });
}

// Usage in component
const data = await fetchWithKey('https://your-api.com/data');`}</div>
        </>
    )
}

function ErrorsSection() {
    return (
        <>
            <h1>Errors & Rate Limits</h1>

            <h2>HTTP Status Codes</h2>
            <table className="params-table">
                <thead><tr><th>Code</th><th>Meaning</th></tr></thead>
                <tbody>
                    <tr><td><code>200</code></td><td>Success</td></tr>
                    <tr><td><code>400</code></td><td>Bad request — validation error</td></tr>
                    <tr><td><code>401</code></td><td>Unauthorized — missing or expired JWT</td></tr>
                    <tr><td><code>403</code></td><td>Forbidden — insufficient permissions</td></tr>
                    <tr><td><code>404</code></td><td>Not found — resource doesn't exist</td></tr>
                    <tr><td><code>422</code></td><td>Unprocessable — invalid request body</td></tr>
                    <tr><td><code>429</code></td><td>Rate limited — too many requests</td></tr>
                    <tr><td><code>500</code></td><td>Server error</td></tr>
                </tbody>
            </table>

            <h2>Error Response Format</h2>
            <div className="doc-code-block">{`{
  "detail": "Error message describing what went wrong"
}`}</div>

            <h2>Rate Limits</h2>
            <table className="params-table">
                <thead><tr><th>Limit</th><th>Value</th></tr></thead>
                <tbody>
                    <tr><td>Requests per minute (per IP)</td><td><code>60</code></td></tr>
                    <tr><td>Failed login attempts</td><td><code>5 per 15 min</code></td></tr>
                </tbody>
            </table>

            <div className="docs-alert info">
                <Info size={18} />
                <span>
                    Rate limit info is tracked via the <code>X-Request-Id</code> and <code>X-Response-Time</code> response headers on every request.
                </span>
            </div>

            <h2>Token Expiry</h2>
            <table className="params-table">
                <thead><tr><th>Token</th><th>Lifetime</th></tr></thead>
                <tbody>
                    <tr><td>Access Token</td><td><code>15 minutes</code></td></tr>
                    <tr><td>Refresh Token</td><td><code>7 days</code></td></tr>
                </tbody>
            </table>

            <div className="docs-alert warning">
                <AlertCircle size={18} />
                <span>
                    When your access token expires, use the <code>/auth/refresh</code> endpoint
                    with your refresh token to get a new access token without re-logging in.
                </span>
            </div>
        </>
    )
}
