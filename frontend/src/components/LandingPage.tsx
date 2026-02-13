import { useState } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
    Key, Shield, Zap, BarChart3, RotateCw, Users,
    Globe, ArrowRight, Check, BookOpen,
} from 'lucide-react'
import './LandingPage.css'

const codeExamples = {
    python: {
        label: 'Python',
        code: `<span class="code-keyword">import</span> requests

<span class="code-comment"># Create an API key</span>
<span class="code-variable">headers</span> = {"Authorization": <span class="code-string">"Bearer YOUR_JWT_TOKEN"</span>}
<span class="code-variable">res</span> = requests.<span class="code-function">post</span>(
    <span class="code-string">"https://api.ragspro.com/api/v1/keys"</span>,
    json={"label": <span class="code-string">"Production"</span>, "provider": <span class="code-string">"nvidia"</span>},
    headers=headers
)
<span class="code-variable">api_key</span> = res.json()[<span class="code-string">"raw_key"</span>]

<span class="code-comment"># Validate a key</span>
<span class="code-variable">valid</span> = requests.<span class="code-function">post</span>(
    <span class="code-string">"https://api.ragspro.com/api/v1/validate"</span>,
    json={"apiKey": api_key}
).json()[<span class="code-string">"valid"</span>]  <span class="code-comment"># True ✅</span>`,
    },
    javascript: {
        label: 'JavaScript',
        code: `<span class="code-comment">// Create an API key</span>
<span class="code-keyword">const</span> res = <span class="code-keyword">await</span> <span class="code-function">fetch</span>(<span class="code-string">"https://api.ragspro.com/api/v1/keys"</span>, {
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
  <span class="code-string">"https://api.ragspro.com/api/v1/validate"</span>,
  { method: <span class="code-string">"POST"</span>, body: JSON.<span class="code-function">stringify</span>({ apiKey: raw_key }) }
).<span class="code-function">then</span>(r => r.<span class="code-function">json</span>()); <span class="code-comment">// true ✅</span>`,
    },
    curl: {
        label: 'cURL',
        code: `<span class="code-comment"># Create an API key</span>
<span class="code-function">curl</span> -X POST <span class="code-string">https://api.ragspro.com/api/v1/keys</span> \\
  -H <span class="code-string">"Authorization: Bearer YOUR_JWT_TOKEN"</span> \\
  -H <span class="code-string">"Content-Type: application/json"</span> \\
  -d <span class="code-string">'{"label": "Production", "provider": "nvidia"}'</span>

<span class="code-comment"># Validate a key</span>
<span class="code-function">curl</span> -X POST <span class="code-string">https://api.ragspro.com/api/v1/validate</span> \\
  -H <span class="code-string">"Content-Type: application/json"</span> \\
  -d <span class="code-string">'{"apiKey": "akm_your_key_here"}'</span>`,
    },
}

const features = [
    { icon: <Shield size={22} />, color: 'blue', title: 'AES-256 Encryption', desc: 'Every API key is encrypted at rest using Fernet symmetric encryption. Keys are never stored in plaintext.' },
    { icon: <Users size={22} />, color: 'purple', title: 'Role-Based Access', desc: 'Admin, User, and Viewer roles with granular permissions. Control who can create, read, or manage keys.' },
    { icon: <Zap size={22} />, color: 'green', title: 'Sub-10ms Validation', desc: 'Lightning-fast key validation endpoint. Integrate into your middleware for instant authentication.' },
    { icon: <BarChart3 size={22} />, color: 'pink', title: 'Real-time Analytics', desc: 'Track usage per key — total calls, average response time, last used timestamp, and provider breakdown.' },
    { icon: <RotateCw size={22} />, color: 'yellow', title: 'Key Rotation', desc: 'One-click key rotation. Old key is disabled, new key is generated. Zero downtime key management.' },
    { icon: <Globe size={22} />, color: 'cyan', title: 'Multi-Provider Support', desc: 'Manage keys for NVIDIA, OpenAI, internal services, and any custom provider. All in one dashboard.' },
]

export default function LandingPage() {
    const [activeTab, setActiveTab] = useState<'python' | 'javascript' | 'curl'>('python')

    return (
        <div className="landing-page">
            {/* Navbar */}
            <nav className="landing-nav">
                <Link to="/" className="nav-logo">
                    <div className="logo-icon"><Key size={18} color="#fff" /></div>
                    RagsPro API
                </Link>
                <div className="nav-links">
                    <a href="#features">Features</a>
                    <a href="#how-it-works">How It Works</a>
                    <Link to="/docs">Docs</Link>
                    <Link to="/login" className="nav-cta">Get Started</Link>
                </div>
            </nav>

            {/* Hero */}
            <motion.section
                className="hero-section"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6 }}
            >
                <div className="hero-badge">
                    <Zap size={14} /> Now with NVIDIA + OpenAI support
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
                        Start Free <ArrowRight size={18} />
                    </Link>
                    <Link to="/docs" className="btn-hero-secondary">
                        <BookOpen size={18} /> Read Docs
                    </Link>
                </div>

                {/* Code Preview */}
                <motion.div
                    className="hero-code"
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3, duration: 0.6 }}
                >
                    <div className="code-header">
                        <span className="code-dot red" />
                        <span className="code-dot yellow" />
                        <span className="code-dot green" />
                        <div className="code-tabs">
                            {Object.entries(codeExamples).map(([key, val]) => (
                                <button
                                    key={key}
                                    className={`code-tab ${activeTab === key ? 'active' : ''}`}
                                    onClick={() => setActiveTab(key as any)}
                                >
                                    {val.label}
                                </button>
                            ))}
                        </div>
                    </div>
                    <div className="code-body">
                        <pre dangerouslySetInnerHTML={{ __html: codeExamples[activeTab].code }} />
                    </div>
                </motion.div>
            </motion.section>

            {/* Stats */}
            <div className="stats-bar">
                {[
                    { num: '17', label: 'API Endpoints' },
                    { num: 'AES-256', label: 'Encryption' },
                    { num: '<10ms', label: 'Validation Speed' },
                    { num: '100%', label: 'Open Source' },
                ].map((s, i) => (
                    <motion.div
                        key={i}
                        className="stat-item"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.4 + i * 0.1 }}
                    >
                        <div className="stat-number">{s.num}</div>
                        <div className="stat-label">{s.label}</div>
                    </motion.div>
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
                        <motion.div
                            key={i}
                            className="feature-card"
                            initial={{ opacity: 0, y: 20 }}
                            whileInView={{ opacity: 1, y: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: i * 0.1 }}
                        >
                            <div className={`feature-card-icon ${f.color}`}>{f.icon}</div>
                            <h3>{f.title}</h3>
                            <p>{f.desc}</p>
                        </motion.div>
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
                        { n: '3', title: 'Integrate & Ship', desc: 'Use the /validate endpoint in your apps. Track usage in real-time from your dashboard.' },
                    ].map((s, i) => (
                        <motion.div
                            key={i}
                            className="step-card"
                            initial={{ opacity: 0, x: -20 }}
                            whileInView={{ opacity: 1, x: 0 }}
                            viewport={{ once: true }}
                            transition={{ delay: i * 0.15 }}
                        >
                            <div className="step-number">{s.n}</div>
                            <div>
                                <h3>{s.title}</h3>
                                <p>{s.desc}</p>
                            </div>
                        </motion.div>
                    ))}
                </div>
            </section>

            {/* Pricing */}
            <section className="pricing-section" id="pricing">
                <div className="section-label">Pricing</div>
                <h2 className="section-title">Simple & Free</h2>
                <p className="section-subtitle">
                    Everything included. No hidden fees.
                </p>
                <motion.div
                    className="pricing-card"
                    initial={{ opacity: 0, scale: 0.95 }}
                    whileInView={{ opacity: 1, scale: 1 }}
                    viewport={{ once: true }}
                >
                    <div className="pricing-badge">Free Forever</div>
                    <div className="pricing-price">$0</div>
                    <div className="pricing-period">No credit card required</div>
                    <ul className="pricing-features">
                        {[
                            'Unlimited API keys',
                            'AES-256 encryption at rest',
                            'Role-based access control',
                            'Real-time usage analytics',
                            'Key rotation & expiry',
                            'Multi-provider support',
                            '60 req/min rate limit',
                            'REST API access',
                        ].map((f, i) => (
                            <li key={i}><Check size={18} /> {f}</li>
                        ))}
                    </ul>
                    <Link to="/login" className="btn-pricing">
                        Get Started Free <ArrowRight size={18} style={{ display: 'inline', marginLeft: 6 }} />
                    </Link>
                </motion.div>
            </section>

            {/* Footer */}
            <footer className="landing-footer">
                <div className="footer-links">
                    <Link to="/docs">Documentation</Link>
                    <a href="https://github.com/raghavx03/api-key" target="_blank" rel="noopener noreferrer">GitHub</a>
                    <Link to="/login">Dashboard</Link>
                    <a href="https://ragspro.com" target="_blank" rel="noopener noreferrer">RagsPro</a>
                </div>
                <p className="footer-copy">
                    © {new Date().getFullYear()} RagsPro. Built with ❤️ for developers.
                </p>
            </footer>
        </div>
    )
}
