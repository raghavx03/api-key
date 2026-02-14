import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
    Shield, Zap, BarChart3, RotateCw, Users,
    Globe, ArrowRight, Check, BookOpen, Menu, X, Minus,
} from 'lucide-react'
import './LandingPage.css'

const codeExamples = {
    python: {
        label: 'Python',
        code: `<span class="code-keyword">import</span> requests

<span class="code-comment"># Create an API key</span>
<span class="code-variable">headers</span> = {"Authorization": <span class="code-string">"Bearer YOUR_JWT_TOKEN"</span>}
<span class="code-variable">res</span> = requests.<span class="code-function">post</span>(
    <span class="code-string">"https://api-key-backend-xsdo.onrender.com/api/v1/keys"</span>,
    json={"label": <span class="code-string">"Production"</span>, "provider": <span class="code-string">"nvidia"</span>},
    headers=headers
)
<span class="code-variable">api_key</span> = res.json()[<span class="code-string">"raw_key"</span>]

<span class="code-comment"># Validate a key</span>
<span class="code-variable">valid</span> = requests.<span class="code-function">post</span>(
    <span class="code-string">"https://api-key-backend-xsdo.onrender.com/api/v1/validate"</span>,
    json={"apiKey": api_key}
).json()[<span class="code-string">"valid"</span>]  <span class="code-comment"># True</span>`,
    },
    javascript: {
        label: 'JavaScript',
        code: `<span class="code-comment">// Create an API key</span>
<span class="code-keyword">const</span> res = <span class="code-keyword">await</span> <span class="code-function">fetch</span>(<span class="code-string">"https://api-key-backend-xsdo.onrender.com/api/v1/keys"</span>, {
  method: <span class="code-string">"POST"</span>,
  headers: {
    <span class="code-string">"Authorization"</span>: <span class="code-string">\`Bearer \${token}\`</span>,
    <span class="code-string">"Content-Type"</span>: <span class="code-string">"application/json"</span>
  },
  body: JSON.<span class="code-function">stringify</span>({
    label: <span class="code-string">"Production"</span>,
    provider: <span class="code-string">"nvidia"</span>
  })
});
<span class="code-keyword">const</span> { <span class="code-variable">raw_key</span> } = <span class="code-keyword">await</span> res.<span class="code-function">json</span>();

<span class="code-comment">// Validate a key</span>
<span class="code-keyword">const</span> { <span class="code-variable">valid</span> } = <span class="code-keyword">await</span> <span class="code-function">fetch</span>(
  <span class="code-string">"https://api-key-backend-xsdo.onrender.com/api/v1/validate"</span>,
  { method: <span class="code-string">"POST"</span>, body: JSON.<span class="code-function">stringify</span>({ apiKey: raw_key }) }
).<span class="code-function">then</span>(r => r.<span class="code-function">json</span>());</span>`,
    },
    curl: {
        label: 'cURL',
        code: `<span class="code-comment"># Create an API key</span>
<span class="code-function">curl</span> -X POST <span class="code-string">https://api-key-backend-xsdo.onrender.com/api/v1/keys</span> \\
  -H <span class="code-string">"Authorization: Bearer YOUR_JWT_TOKEN"</span> \\
  -H <span class="code-string">"Content-Type: application/json"</span> \\
  -d <span class="code-string">'{"label": "Production", "provider": "nvidia"}'</span>

<span class="code-comment"># Validate a key</span>
<span class="code-function">curl</span> -X POST <span class="code-string">https://api-key-backend-xsdo.onrender.com/api/v1/validate</span> \\
  -H <span class="code-string">"Content-Type: application/json"</span> \\
  -d <span class="code-string">'{"apiKey": "akm_your_key_here"}'</span>`,
    },
}

const features = [
    { icon: <Shield size={20} />, color: 'blue', title: 'AES-256 Encryption', desc: 'Every API key is encrypted at rest using Fernet symmetric encryption. Keys are never stored in plaintext.' },
    { icon: <Users size={20} />, color: 'purple', title: 'Role-Based Access', desc: 'Admin, User, and Viewer roles with granular permissions. Control who can create, read, or manage keys.' },
    { icon: <Zap size={20} />, color: 'green', title: 'Sub-10ms Validation', desc: 'Lightning-fast key validation endpoint. Integrate into your middleware for instant authentication.' },
    { icon: <BarChart3 size={20} />, color: 'pink', title: 'Real-time Analytics', desc: 'Track usage per key — total calls, average response time, last used timestamp, and provider breakdown.' },
    { icon: <RotateCw size={20} />, color: 'yellow', title: 'Key Rotation', desc: 'One-click key rotation. Old key is disabled, new key is generated. Zero downtime key management.' },
    { icon: <Globe size={20} />, color: 'cyan', title: 'Multi-Provider Support', desc: 'Manage keys for NVIDIA, OpenAI, internal services, and any custom provider — all in one dashboard.' },
]

export default function LandingPage() {
    const [activeTab, setActiveTab] = useState<'python' | 'javascript' | 'curl'>('python')
    const [mobileOpen, setMobileOpen] = useState(false)

    return (
        <div className="landing-page">
            {/* Floating Pill Navbar */}
            <nav className="landing-nav">
                <Link to="/" className="nav-logo">
                    <img src="/logo.png" alt="RagsPro" />
                    RagsPro API
                </Link>
                <div className="nav-links">
                    <a href="#features">Features</a>
                    <a href="#pricing">Pricing</a>
                    <Link to="/docs">Docs</Link>
                    <Link to="/login" className="nav-cta">Get Started</Link>
                </div>
                <button className="nav-hamburger" onClick={() => setMobileOpen(!mobileOpen)} aria-label="Menu">
                    {mobileOpen ? <X size={20} /> : <Menu size={20} />}
                </button>
            </nav>

            {/* Mobile Menu */}
            <div className={`mobile-menu ${mobileOpen ? 'open' : ''}`}>
                <a href="#features" onClick={() => setMobileOpen(false)}>Features</a>
                <a href="#pricing" onClick={() => setMobileOpen(false)}>Pricing</a>
                <Link to="/docs" onClick={() => setMobileOpen(false)}>Documentation</Link>
                <Link to="/login" className="nav-cta" onClick={() => setMobileOpen(false)}>Get Started</Link>
            </div>

            {/* Hero */}
            <section className="hero-section">
                <div className="hero-badge">
                    Now with NVIDIA + OpenAI support
                </div>
                <h1 className="hero-title">
                    Manage API Keys<br />
                    <span className="gradient-text">Like a Pro</span>
                </h1>
                <p className="hero-subtitle">
                    Enterprise-grade API key management with encryption, RBAC, analytics,
                    and instant validation. Built for developers who ship fast.
                </p>
                <div className="hero-buttons">
                    <Link to="/login" className="btn-hero-primary">
                        Start Free <ArrowRight size={16} />
                    </Link>
                    <Link to="/docs" className="btn-hero-secondary">
                        <BookOpen size={16} /> Read Docs
                    </Link>
                </div>

                {/* Code Preview */}
                <div className="hero-code">
                    <div className="code-header">
                        <span className="code-dot red" />
                        <span className="code-dot yellow" />
                        <span className="code-dot green" />
                        <div className="code-tabs">
                            {Object.entries(codeExamples).map(([key, val]) => (
                                <button
                                    key={key}
                                    className={`code-tab ${activeTab === key ? 'active' : ''}`}
                                    onClick={() => setActiveTab(key as 'python' | 'javascript' | 'curl')}
                                >
                                    {val.label}
                                </button>
                            ))}
                        </div>
                    </div>
                    <div className="code-body">
                        <pre dangerouslySetInnerHTML={{ __html: codeExamples[activeTab].code }} />
                    </div>
                </div>
            </section>

            {/* Stats */}
            <div className="stats-bar">
                {[
                    { num: '17', label: 'API Endpoints' },
                    { num: 'AES-256', label: 'Encryption' },
                    { num: '<10ms', label: 'Validation Speed' },
                    { num: '99.9%', label: 'Uptime SLA' },
                ].map((s, i) => (
                    <div key={i} className="stat-item">
                        <div className="stat-number">{s.num}</div>
                        <div className="stat-label">{s.label}</div>
                    </div>
                ))}
            </div>

            {/* Features */}
            <section className="features-section" id="features">
                <div className="section-label">Features</div>
                <h2 className="section-title">Everything You Need</h2>
                <p className="section-subtitle">
                    A complete API key lifecycle — from creation to rotation to analytics.
                </p>
                <div className="features-grid">
                    {features.map((f, i) => (
                        <div key={i} className="feature-card">
                            <div className={`feature-card-icon ${f.color}`}>{f.icon}</div>
                            <h3>{f.title}</h3>
                            <p>{f.desc}</p>
                        </div>
                    ))}
                </div>
            </section>

            {/* How It Works */}
            <section className="how-section" id="how-it-works">
                <div className="section-label">Quick Start</div>
                <h2 className="section-title">Up and Running in 3 Steps</h2>
                <div className="steps-list">
                    {[
                        { n: '1', title: 'Create an Account', desc: 'Sign up with your email. Get admin access to the dashboard instantly. No credit card required.' },
                        { n: '2', title: 'Generate API Keys', desc: 'Create keys for any provider — NVIDIA, OpenAI, or your internal services. Set scopes, quotas, and expiry.' },
                        { n: '3', title: 'Integrate and Ship', desc: 'Use the /validate endpoint in your apps. Track usage in real-time from your dashboard.' },
                    ].map((s, i) => (
                        <div key={i} className="step-card">
                            <div className="step-number">{s.n}</div>
                            <div>
                                <h3>{s.title}</h3>
                                <p>{s.desc}</p>
                            </div>
                        </div>
                    ))}
                </div>
            </section>

            {/* Pricing */}
            <section className="pricing-section" id="pricing">
                <div className="section-label">Pricing</div>
                <h2 className="section-title">Simple, Transparent Pricing</h2>
                <p className="section-subtitle">
                    Start free, scale when you need to.
                </p>
                <div className="pricing-grid">
                    {/* Free Plan */}
                    <div className="pricing-card">
                        <div className="pricing-name">Free</div>
                        <div className="pricing-price">$0</div>
                        <div className="pricing-period">Free forever</div>
                        <ul className="pricing-features">
                            {[
                                { text: 'Up to 10 API keys', active: true },
                                { text: 'AES-256 encryption', active: true },
                                { text: 'Basic analytics', active: true },
                                { text: '60 req/min rate limit', active: true },
                                { text: 'Key rotation', active: true },
                                { text: 'Community support', active: true },
                                { text: 'Custom providers', active: false },
                                { text: 'Priority support', active: false },
                            ].map((f, i) => (
                                <li key={i} className={f.active ? '' : 'disabled'}>
                                    {f.active ? <Check size={15} /> : <Minus size={15} />}
                                    {f.text}
                                </li>
                            ))}
                        </ul>
                        <Link to="/login" className="btn-pricing">Get Started</Link>
                    </div>

                    {/* Pro Plan */}
                    <div className="pricing-card popular">
                        <div className="pricing-badge">Most Popular</div>
                        <div className="pricing-name">Pro</div>
                        <div className="pricing-price">₹899<span>/mo</span></div>
                        <div className="pricing-period">Billed monthly</div>
                        <ul className="pricing-features">
                            {[
                                { text: 'Unlimited API keys', active: true },
                                { text: 'AES-256 encryption', active: true },
                                { text: 'Advanced analytics', active: true },
                                { text: '1,000 req/min rate limit', active: true },
                                { text: 'Key rotation', active: true },
                                { text: 'Priority email support', active: true },
                                { text: 'Custom providers', active: true },
                                { text: 'Team management', active: true },
                            ].map((f, i) => (
                                <li key={i} className={f.active ? '' : 'disabled'}>
                                    {f.active ? <Check size={15} /> : <Minus size={15} />}
                                    {f.text}
                                </li>
                            ))}
                        </ul>
                        <Link to="/login" className="btn-pricing primary">Start Free Trial</Link>
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="landing-footer">
                <div className="footer-brand">
                    <img src="/logo.png" alt="RagsPro" style={{ width: 28, height: 28, borderRadius: 6 }} />
                    <span style={{ fontWeight: 700, fontSize: 16 }}>RagsPro API Gateway</span>
                </div>
                <p className="footer-tagline">
                    Enterprise-grade API key management & AI proxy platform.
                    <br />
                    Built with ❤️ by <strong>Bhupender Pratap</strong> & <strong>Raghav Shah</strong> at{' '}
                    <a href="https://ragspro.com" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-purple)', textDecoration: 'none', fontWeight: 600 }}>
                        RagsPro
                    </a>
                </p>
                <div className="footer-links">
                    <Link to="/docs">Documentation</Link>
                    <a href="https://github.com/raghavx03/api-key" target="_blank" rel="noopener noreferrer">GitHub</a>
                    <Link to="/login">Dashboard</Link>
                    <a href="https://ragspro.com" target="_blank" rel="noopener noreferrer">RagsPro Agency</a>
                    <a href="/llms.txt">For AI</a>
                    <a href="/sitemap.xml">Sitemap</a>
                </div>
                <p className="footer-copy">
                    © {new Date().getFullYear()} RagsPro. All rights reserved. | api.ragspro.com
                </p>
            </footer>
        </div>
    )
}
