import { useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertCircle, Info } from 'lucide-react'
import './LandingPage.css'
import './Docs.css'

type Section = 'intro' | 'auth' | 'keys' | 'validate' | 'ai-proxy' | 'admin' | 'errors' | 'examples'

const API_URL = 'https://api-key-backend-xsdo.onrender.com'

export default function Docs() {
    const [section, setSection] = useState<Section>('intro')

    return (
        <div className="docs-page">
            {/* Reuse landing nav */}
            <nav className="landing-nav">
                <Link to="/" className="nav-logo">
                    <img src="/logo.png" alt="RagsPro" />
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
                    <button className={`sidebar-link ${section === 'ai-proxy' ? 'active' : ''}`} onClick={() => setSection('ai-proxy')}>AI Proxy</button>
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
                    {section === 'ai-proxy' && <AIProxySection />}
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
                role-based access control, real-time analytics, and an <strong>OpenAI-compatible AI proxy</strong>.
                This documentation covers all endpoints available in the REST API.
            </p>

            <h2>API Base URL</h2>
            <div className="doc-code-block">{API_URL}/api/v1</div>

            <h2>AI Proxy Base URL</h2>
            <div className="doc-code-block">{API_URL}/v1</div>

            <div className="docs-alert info">
                <Info size={18} />
                <span>The API management endpoints use <code>/api/v1</code> prefix. The AI Proxy endpoints use <code>/v1</code> prefix (OpenAI-compatible).</span>
            </div>

            <h2>Quick Start</h2>
            <h3>1. Create an Account</h3>
            <div className="doc-code-block">{`curl -X POST ${API_URL}/api/v1/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{"email": "you@example.com", "password": "SecurePass123"}'

# Response:
{
  "message": "User registered successfully",
  "role": "admin",
  "plan": "pro"
}`}</div>

            <h3>2. Login and Get Token</h3>
            <div className="doc-code-block">{`curl -X POST ${API_URL}/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email": "you@example.com", "password": "SecurePass123"}'

# Response:
{
  "access_token": "eyJhbGciOiJIUzI1...",
  "refresh_token": "eyJhbGciOiJIUzI1...",
  "token_type": "bearer"
}`}</div>

            <h3>3. Create an API Key</h3>
            <div className="doc-code-block">{`curl -X POST ${API_URL}/api/v1/keys \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"label": "My First Key", "provider": "internal"}'

# Response:
{
  "keyId": "abc123...",
  "keyValue": "akm_5QQ2yIRqVWAs...",  ← Save this! Not shown again.
  "label": "My First Key",
  "provider": "internal",
  "scope": "read_write",
  "status": "active"
}`}</div>

            <h3>4. Use the Key for AI Chat</h3>
            <div className="doc-code-block">{`curl -X POST ${API_URL}/v1/chat/completions \\
  -H "Authorization: Bearer akm_your_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "meta/llama-3.1-8b-instruct",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Response (OpenAI-compatible):
{
  "id": "chatcmpl-...",
  "choices": [{
    "message": {"role": "assistant", "content": "Hello! How can I help?"},
    "finish_reason": "stop"
  }],
  "model": "meta/llama-3.1-8b-instruct",
  "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18}
}`}</div>

            <div className="docs-alert warning">
                <AlertCircle size={18} />
                <span>The <code>keyValue</code> (starting with <code>akm_</code>) is only returned once during creation. Store it securely!</span>
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
                    <h4>Example</h4>
                    <div className="doc-code-block">{`curl -X POST ${API_URL}/api/v1/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{"email": "you@example.com", "password": "SecurePass123"}'`}</div>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "message": "User registered successfully",
  "role": "admin",
  "plan": "pro"
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
                    <h4>Example</h4>
                    <div className="doc-code-block">{`curl -X POST ${API_URL}/api/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email": "you@example.com", "password": "SecurePass123"}'`}</div>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
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
                authentication via JWT token in the <code>Authorization</code> header.
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
                    <h4>Example</h4>
                    <div className="doc-code-block">{`curl -X POST ${API_URL}/api/v1/keys \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"label": "Production Key", "provider": "nvidia", "scope": "full_access"}'`}</div>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "keyId": "VQPxtKvu0Wiu...",
  "keyValue": "akm_hsulDWo_ZaW3JbV...",   ← Save this! Not shown again.
  "label": "Production Key",
  "provider": "nvidia",
  "scope": "full_access",
  "status": "active",
  "createdAt": "2026-02-14T04:00:00Z",
  "expiresAt": null
}`}</div>
                    <div className="docs-alert warning">
                        <AlertCircle size={18} />
                        <span>The <code>keyValue</code> (starts with <code>akm_</code>) is only returned once during creation. Store it securely — you cannot retrieve it again.</span>
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
                        Returns the new <code>keyValue</code>.
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
  "last_used_at": "2026-02-14T04:00:00Z"
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

                    <h4>Example</h4>
                    <div className="doc-code-block">{`curl -X POST ${API_URL}/api/v1/validate \\
  -H "Content-Type: application/json" \\
  -d '{"apiKey": "akm_your_key_here"}'`}</div>

                    <h4>Success Response</h4>
                    <div className="doc-code-block">{`{
  "valid": true,
  "userId": "FZ_NaofX21FB...",
  "keyId": "VQPxtKvu0Wiu...",
  "provider": "internal",
  "scope": "full_access",
  "responseTimeMs": 4.21,
  "usageCount": 1
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

  const response = await fetch('${API_URL}/api/v1/validate', {
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
            "${API_URL}/api/v1/validate",
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

function AIProxySection() {
    return (
        <>
            <h1>AI Proxy (OpenAI-Compatible)</h1>
            <p className="docs-intro">
                RagsPro includes an OpenAI-compatible AI proxy. Use your <code>akm_</code> API key to call
                chat completions, list models, and generate images. The proxy validates your key, forwards
                to upstream AI providers (NVIDIA, OpenAI), and tracks usage automatically.
            </p>

            <div className="docs-alert info">
                <Info size={18} />
                <span>AI Proxy endpoints use <code>/v1</code> prefix (no <code>/api</code>). Authenticate with your <code>akm_</code> key in the <code>Authorization: Bearer</code> header.</span>
            </div>

            <h2>List Models</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge get">GET</span>
                    <span className="endpoint-path">/v1/models</span>
                    <span className="endpoint-desc">List available AI models</span>
                </div>
                <div className="endpoint-body">
                    <h4>Example</h4>
                    <div className="doc-code-block">{`curl ${API_URL}/v1/models \\
  -H "Authorization: Bearer akm_your_key_here"`}</div>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "object": "list",
  "data": [
    {"id": "meta/llama-3.1-8b-instruct", "object": "model", "owned_by": "nvidia"},
    {"id": "meta/llama-3.1-70b-instruct", "object": "model", "owned_by": "nvidia"},
    {"id": "nvidia/llama-3.1-nemotron-70b-instruct", "object": "model", "owned_by": "nvidia"},
    {"id": "google/gemma-2-9b-it", "object": "model", "owned_by": "nvidia"},
    {"id": "mistralai/mistral-7b-instruct-v0.3", "object": "model", "owned_by": "nvidia"},
    {"id": "moonshotai/kimi-k2.5", "object": "model", "owned_by": "nvidia"},
    {"id": "stabilityai/stable-diffusion-xl", "object": "model", "owned_by": "nvidia"}
  ]
}`}</div>
                </div>
            </div>

            <h2>Chat Completions</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/v1/chat/completions</span>
                    <span className="endpoint-desc">Chat with AI models (OpenAI-compatible)</span>
                </div>
                <div className="endpoint-body">
                    <h4>Request Body</h4>
                    <table className="params-table">
                        <thead><tr><th>Field</th><th>Type</th><th>Required</th><th>Description</th></tr></thead>
                        <tbody>
                            <tr><td><code>model</code></td><td>string</td><td>Yes</td><td>Model ID from /v1/models</td></tr>
                            <tr><td><code>messages</code></td><td>array</td><td>Yes</td><td>Chat messages (role + content)</td></tr>
                            <tr><td><code>max_tokens</code></td><td>integer</td><td>No</td><td>Max tokens to generate</td></tr>
                            <tr><td><code>temperature</code></td><td>float</td><td>No</td><td>Creativity (0.0 - 2.0)</td></tr>
                            <tr><td><code>stream</code></td><td>boolean</td><td>No</td><td>Enable streaming (SSE)</td></tr>
                        </tbody>
                    </table>
                    <h4>Example</h4>
                    <div className="doc-code-block">{`curl -X POST ${API_URL}/v1/chat/completions \\
  -H "Authorization: Bearer akm_your_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "meta/llama-3.1-8b-instruct",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "What is an API gateway?"}
    ],
    "max_tokens": 200,
    "temperature": 0.7
  }'`}</div>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "id": "chatcmpl-abc123",
  "object": "chat.completion",
  "created": 1707868800,
  "model": "meta/llama-3.1-8b-instruct",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "An API gateway is a server that acts as..."
    },
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 25,
    "completion_tokens": 150,
    "total_tokens": 175
  },
  "_gateway": {
    "keyId": "VQPxtKvu0Wiu...",
    "provider": "nvidia",
    "responseTimeMs": 457.97
  }
}`}</div>
                </div>
            </div>

            <h2>Streaming</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/v1/chat/completions</span>
                    <span className="endpoint-desc">Stream responses via Server-Sent Events</span>
                </div>
                <div className="endpoint-body">
                    <h4>Example (curl)</h4>
                    <div className="doc-code-block">{`curl -X POST ${API_URL}/v1/chat/completions \\
  -H "Authorization: Bearer akm_your_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "meta/llama-3.1-8b-instruct",
    "messages": [{"role": "user", "content": "Hello!"}],
    "stream": true
  }'

# Response: Server-Sent Events
data: {"choices":[{"delta":{"content":"Hello"}}]}
data: {"choices":[{"delta":{"content":"!"}}]}
data: {"choices":[{"delta":{"content":" How"}}]}
data: [DONE]`}</div>
                    <h4>JavaScript Streaming</h4>
                    <div className="doc-code-block">{`const response = await fetch('${API_URL}/v1/chat/completions', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer akm_your_key_here',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    model: 'meta/llama-3.1-8b-instruct',
    messages: [{ role: 'user', content: 'Hello!' }],
    stream: true
  })
});

const reader = response.body.getReader();
const decoder = new TextDecoder();

while (true) {
  const { value, done } = await reader.read();
  if (done) break;
  const chunk = decoder.decode(value);
  // Parse SSE: each line starts with "data: "
  const lines = chunk.split('\\n').filter(l => l.startsWith('data: '));
  for (const line of lines) {
    const data = line.slice(6);
    if (data === '[DONE]') break;
    const parsed = JSON.parse(data);
    process.stdout.write(parsed.choices[0]?.delta?.content || '');
  }
}`}</div>
                </div>
            </div>

            <h2>Image Generation</h2>
            <div className="endpoint-card">
                <div className="endpoint-header">
                    <span className="method-badge post">POST</span>
                    <span className="endpoint-path">/v1/images/generations</span>
                    <span className="endpoint-desc">Generate images from text</span>
                </div>
                <div className="endpoint-body">
                    <h4>Example</h4>
                    <div className="doc-code-block">{`curl -X POST ${API_URL}/v1/images/generations \\
  -H "Authorization: Bearer akm_your_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "stabilityai/stable-diffusion-xl",
    "prompt": "A futuristic city skyline at sunset"
  }'`}</div>
                </div>
            </div>

            <h2>Available Models</h2>
            <table className="params-table">
                <thead><tr><th>Model ID</th><th>Type</th><th>Best For</th></tr></thead>
                <tbody>
                    <tr><td><code>meta/llama-3.1-8b-instruct</code></td><td>Chat</td><td>Fast responses, general tasks</td></tr>
                    <tr><td><code>meta/llama-3.1-70b-instruct</code></td><td>Chat</td><td>Complex reasoning, coding</td></tr>
                    <tr><td><code>nvidia/llama-3.1-nemotron-70b-instruct</code></td><td>Chat</td><td>High quality, instruction following</td></tr>
                    <tr><td><code>google/gemma-2-9b-it</code></td><td>Chat</td><td>Lightweight, efficient</td></tr>
                    <tr><td><code>mistralai/mistral-7b-instruct-v0.3</code></td><td>Chat</td><td>Fast, multilingual</td></tr>
                    <tr><td><code>moonshotai/kimi-k2.5</code></td><td>Chat</td><td>Advanced reasoning</td></tr>
                    <tr><td><code>stabilityai/stable-diffusion-xl</code></td><td>Image</td><td>Image generation</td></tr>
                </tbody>
            </table>
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
  "total_validations": 45230,
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
                    <h4>Example</h4>
                    <div className="doc-code-block">{`curl ${API_URL}/api/v1/health`}</div>
                    <h4>Response</h4>
                    <div className="doc-code-block">{`{
  "status": "healthy",
  "checks": {"api": "healthy", "database": "healthy"},
  "version": "2.0.0",
  "timestamp": "2026-02-14T04:00:00Z"
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

API = "${API_URL}/api/v1"

# 1. Register
requests.post(f"{API}/auth/register", json={
    "email": "dev@myapp.com",
    "password": "SecurePass123"
})

# 2. Login
tokens = requests.post(f"{API}/auth/login", json={
    "email": "dev@myapp.com",
    "password": "SecurePass123"
}).json()

headers = {"Authorization": f"Bearer {tokens['access_token']}"}

# 3. Create a key
key = requests.post(f"{API}/keys", json={
    "label": "Production NVIDIA",
    "provider": "nvidia",
    "scope": "full_access"
}, headers=headers).json()

api_key = key["keyValue"]  # Save this! Starts with akm_
print(f"Key: {api_key}")

# 4. Use the key for AI chat
response = requests.post(f"${API_URL}/v1/chat/completions",
    headers={"Authorization": f"Bearer {api_key}"},
    json={
        "model": "meta/llama-3.1-8b-instruct",
        "messages": [{"role": "user", "content": "Hello!"}]
    }
).json()

print(response["choices"][0]["message"]["content"])

# 5. Validate the key (from any service)
result = requests.post(f"{API}/validate", json={
    "apiKey": api_key
}).json()
print(f"Valid: {result['valid']}")  # True`}</div>

            <h2>JavaScript — AI Chatbot</h2>
            <div className="doc-code-block">{`const API_KEY = 'akm_your_key_here';
const API_URL = '${API_URL}';

async function chat(message) {
  const response = await fetch(API_URL + '/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': \`Bearer \${API_KEY}\`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'meta/llama-3.1-8b-instruct',
      messages: [
        { role: 'system', content: 'You are a helpful assistant.' },
        { role: 'user', content: message }
      ],
      max_tokens: 500
    })
  });

  const data = await response.json();
  return data.choices[0].message.content;
}

// Usage
const reply = await chat('What is an API gateway?');
console.log(reply);`}</div>

            <h2>Python — AI Chatbot</h2>
            <div className="doc-code-block">{`import requests

API_KEY = "akm_your_key_here"
API_URL = "${API_URL}"

def chat(message, history=[]):
    history.append({"role": "user", "content": message})
    response = requests.post(
        f"{API_URL}/v1/chat/completions",
        headers={"Authorization": f"Bearer {API_KEY}"},
        json={
            "model": "meta/llama-3.1-8b-instruct",
            "messages": history,
            "max_tokens": 500
        }
    ).json()
    reply = response["choices"][0]["message"]["content"]
    history.append({"role": "assistant", "content": reply})
    return reply

# Interactive chatbot
print("RagsPro AI Chatbot (type 'quit' to exit)")
history = [{"role": "system", "content": "You are a helpful assistant."}]
while True:
    user_input = input("You: ")
    if user_input.lower() == "quit":
        break
    print(f"AI: {chat(user_input, history)}")`}</div>

            <h2>React — Express Middleware</h2>
            <div className="doc-code-block">{`const express = require('express');
const app = express();

// Middleware: Validate API key on every request
async function requireApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  try {
    const response = await fetch('${API_URL}/api/v1/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey })
    });
    const data = await response.json();
    
    if (!data.valid) {
      return res.status(403).json({ error: 'Invalid API key' });
    }
    
    req.apiKeyInfo = data;
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
                    <tr><td><code>401</code></td><td>Unauthorized — missing or expired JWT / API key</td></tr>
                    <tr><td><code>403</code></td><td>Forbidden — insufficient permissions or invalid key</td></tr>
                    <tr><td><code>404</code></td><td>Not found — resource doesn't exist</td></tr>
                    <tr><td><code>422</code></td><td>Unprocessable — invalid request body</td></tr>
                    <tr><td><code>429</code></td><td>Rate limited — too many requests</td></tr>
                    <tr><td><code>500</code></td><td>Server error</td></tr>
                    <tr><td><code>502</code></td><td>Upstream AI provider error</td></tr>
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
