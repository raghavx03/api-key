import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Key, Plus, Trash2, Copy, LogOut, RefreshCw, Activity, Zap,
  Search, Moon, Sun, Shield, RotateCw,
  ChevronLeft, ChevronRight, BarChart3, Users, Globe, Lock, Clock,
  TrendingUp, AlertTriangle, Crown, X, Check, Sparkles,
} from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import toast from 'react-hot-toast'
import { formatDistanceToNow } from 'date-fns'
import { useAuthStore, useKeyStore, useThemeStore } from '../store'
import { APIKey, api } from '../api'
import './Dashboard.css'

export default function Dashboard() {
  const { user, logout } = useAuthStore()
  const {
    keys, pagination, loading, filterProvider, filterStatus,
    fetchKeys, createKey, updateKey, deleteKey, rotateKey,
    setSearch, setFilterProvider, setFilterStatus, setPage,
  } = useKeyStore()
  const { theme, toggleTheme } = useThemeStore()

  const [showCreateModal, setShowCreateModal] = useState(false)
  const [createdKey, setCreatedKey] = useState<APIKey | null>(null)
  const [showAnalytics, setShowAnalytics] = useState(false)
  const [showUpgradeModal, setShowUpgradeModal] = useState(false)
  const [upgrading, setUpgrading] = useState(false)
  const [newKey, setNewKey] = useState({ label: '', provider: 'internal', scope: 'read_write', quota: 0, expiry: 0 })
  const [searchInput, setSearchInput] = useState('')
  const [adminStats, setAdminStats] = useState<any>(null)

  useEffect(() => {
    fetchKeys()
  }, [filterProvider, filterStatus, pagination?.page])

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(searchInput)
      fetchKeys()
    }, 400)
    return () => clearTimeout(timer)
  }, [searchInput])

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        document.getElementById('search-input')?.focus()
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 'n') {
        e.preventDefault()
        setShowCreateModal(true)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  // Load admin stats
  useEffect(() => {
    if (user?.role === 'admin') {
      api.getAdminStats().then(setAdminStats).catch(() => { })
    }
  }, [user])

  const handleCreateKey = async () => {
    try {
      const result = await createKey({
        label: newKey.label,
        provider: newKey.provider,
        scope: newKey.scope,
        usage_quota: newKey.quota || 0,
        expires_in_days: newKey.expiry || undefined,
      })
      setCreatedKey(result)
      setShowCreateModal(false)
      setNewKey({ label: '', provider: 'internal', scope: 'read_write', quota: 0, expiry: 0 })
      toast.success('API key created!')
    } catch {
      toast.error('Failed to create key')
    }
  }

  const handleDelete = async (keyId: string) => {
    try {
      await deleteKey(keyId)
      toast.success('Key deleted')
    } catch {
      toast.error('Failed to delete key')
    }
  }

  const handleToggle = async (keyId: string, status: string) => {
    const newStatus = status === 'active' ? 'inactive' : 'active'
    try {
      await updateKey(keyId, { status: newStatus })
      toast.success(`Key ${newStatus}`)
    } catch {
      toast.error('Failed to update key')
    }
  }

  const handleRotate = async (keyId: string) => {
    try {
      const result = await rotateKey(keyId)
      setCreatedKey(result)
      toast.success('Key rotated! Save the new key.')
    } catch {
      toast.error('Failed to rotate key')
    }
  }

  const copyKey = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard!')
  }

  const handleLogout = () => {
    logout()
    toast.success('Logged out')
  }

  const handleUpgrade = async () => {
    setUpgrading(true)
    try {
      const order = await api.createOrder('pro')
      const options = {
        key: order.key_id,
        amount: order.amount,
        currency: order.currency,
        name: 'RagsPro API',
        description: 'Pro Plan — Monthly',
        order_id: order.order_id,
        handler: async (response: any) => {
          try {
            await api.verifyPayment({
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature,
            })
            toast.success('Upgraded to Pro! Refreshing...')
            setShowUpgradeModal(false)
            // Refresh user profile to get new plan
            const { fetchProfile } = useAuthStore.getState()
            await fetchProfile()
          } catch (err: any) {
            toast.error(err.message || 'Payment verification failed')
          }
        },
        prefill: { email: user?.email || '' },
        theme: { color: '#6366f1' },
      }
      const rzp = new (window as any).Razorpay(options)
      rzp.on('payment.failed', () => {
        toast.error('Payment failed. Please try again.')
      })
      rzp.open()
    } catch (err: any) {
      toast.error(err.message || 'Failed to initiate payment')
    } finally {
      setUpgrading(false)
    }
  }

  // Chart data
  const providerData = [
    { name: 'Internal', value: keys.filter(k => k.provider === 'internal').length, color: '#6366f1' },
    { name: 'NVIDIA', value: keys.filter(k => k.provider === 'nvidia').length, color: '#10b981' },
  ].filter(d => d.value > 0)

  const usageData = keys.slice(0, 8).map(k => ({
    name: k.label || k.keyId.slice(0, 8),
    calls: k.usageCount || 0,
    speed: k.avgResponseTimeMs || 0,
  }))

  // Stats
  const totalKeys = keys.length
  const activeKeys = keys.filter(k => k.status === 'active').length
  const totalCalls = keys.reduce((sum, k) => sum + (k.usageCount || 0), 0)
  const avgSpeed = keys.filter(k => k.avgResponseTimeMs > 0).length > 0
    ? keys.filter(k => k.avgResponseTimeMs > 0).reduce((sum, k) => sum + k.avgResponseTimeMs, 0) / keys.filter(k => k.avgResponseTimeMs > 0).length
    : 0

  return (
    <div className="dash">
      {/* ─── Sidebar/Header ─── */}
      <header className="dash-header">
        <div className="header-left">
          <div className="logo-mark">
            <img src="/logo.png" alt="RagsPro" style={{ width: 24, height: 24, borderRadius: 6 }} />
          </div>
          <div>
            <h1 className="app-title">RagsPro API</h1>
            <span className="version-badge">v2.0</span>
          </div>
        </div>
        <div className="header-right">
          <button className="icon-btn" onClick={toggleTheme} title="Toggle theme">
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
          </button>
          <button className="icon-btn" onClick={() => setShowAnalytics(!showAnalytics)} title="Analytics">
            <BarChart3 size={18} />
          </button>
          <button className="icon-btn" onClick={() => fetchKeys()} title="Refresh">
            <RefreshCw size={18} className={loading ? 'spinning' : ''} />
          </button>
          <div className="user-badge">
            <span className="user-email">{user?.email}</span>
            <span className={`plan-tag plan-${user?.plan || 'free'}`}>
              {user?.plan === 'pro' ? <><Crown size={12} /> Pro</> : 'Free'}
            </span>
            {user?.role !== 'user' && <span className={`role-tag role-${user?.role}`}>{user?.role}</span>}
          </div>
          {user?.plan !== 'pro' && (
            <button className="upgrade-btn" onClick={() => setShowUpgradeModal(true)}>
              <Sparkles size={14} /> Upgrade
            </button>
          )}
          <button className="icon-btn logout-btn" onClick={handleLogout} title="Logout">
            <LogOut size={18} />
          </button>
        </div>
      </header>

      <main className="dash-main">
        {/* ─── Stats Cards ─── */}
        <motion.div
          className="stats-row"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="stat-card">
            <div className="stat-icon blue"><Key size={20} /></div>
            <div>
              <div className="stat-value">{totalKeys}</div>
              <div className="stat-label">Total Keys</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon green"><Shield size={20} /></div>
            <div>
              <div className="stat-value">{activeKeys}</div>
              <div className="stat-label">Active</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon purple"><Activity size={20} /></div>
            <div>
              <div className="stat-value">{totalCalls.toLocaleString()}</div>
              <div className="stat-label">Total Calls</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon yellow"><Zap size={20} /></div>
            <div>
              <div className="stat-value">{avgSpeed > 0 ? `${avgSpeed.toFixed(1)}ms` : 'N/A'}</div>
              <div className="stat-label">Avg Speed</div>
            </div>
          </div>
          {adminStats && (
            <>
              <div className="stat-card">
                <div className="stat-icon teal"><Users size={20} /></div>
                <div>
                  <div className="stat-value">{adminStats.totalUsers}</div>
                  <div className="stat-label">Users</div>
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-icon orange"><TrendingUp size={20} /></div>
                <div>
                  <div className="stat-value">{adminStats.totalValidations?.toLocaleString()}</div>
                  <div className="stat-label">Validations</div>
                </div>
              </div>
            </>
          )}
        </motion.div>

        {/* ─── Analytics Panel ─── */}
        <AnimatePresence>
          {showAnalytics && keys.length > 0 && (
            <motion.div
              className="analytics-panel"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <div className="charts-grid">
                <div className="chart-card glass-card">
                  <h3><Activity size={16} /> Usage by Key</h3>
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={usageData}>
                      <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                      <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                      <Tooltip
                        contentStyle={{
                          background: 'var(--bg-card)',
                          border: '1px solid var(--border-primary)',
                          borderRadius: 8,
                          color: 'var(--text-primary)',
                          fontSize: 13,
                        }}
                      />
                      <Bar dataKey="calls" fill="#6366f1" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="chart-card glass-card">
                  <h3><Globe size={16} /> By Provider</h3>
                  {providerData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={220}>
                      <PieChart>
                        <Pie
                          data={providerData}
                          cx="50%" cy="50%"
                          outerRadius={80}
                          innerRadius={50}
                          paddingAngle={4}
                          dataKey="value"
                          label={({ name, value }) => `${name}: ${value}`}
                        >
                          {providerData.map((d, i) => (
                            <Cell key={i} fill={d.color} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="chart-empty">No data yet</div>
                  )}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ─── Actions Bar ─── */}
        <div className="actions-bar">
          <button className="btn-create" onClick={() => setShowCreateModal(true)}>
            <Plus size={16} /> New Key
            <kbd className="kbd">⌘N</kbd>
          </button>

          <div className="search-box">
            <Search size={16} />
            <input
              id="search-input"
              type="text"
              placeholder="Search keys..."
              value={searchInput}
              onChange={e => setSearchInput(e.target.value)}
            />
            <kbd className="kbd">⌘K</kbd>
          </div>

          <div className="filter-pills">
            <select value={filterProvider} onChange={e => setFilterProvider(e.target.value)}>
              <option value="all">All Providers</option>
              <option value="internal">Internal</option>
              <option value="nvidia">NVIDIA</option>
            </select>
            <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="rotated">Rotated</option>
              <option value="expired">Expired</option>
            </select>
          </div>
        </div>

        {/* ─── Keys Grid ─── */}
        {loading ? (
          <div className="keys-grid">
            {[1, 2, 3, 4, 5, 6].map(i => (
              <div key={i} className="key-card-skeleton">
                <div className="skeleton" style={{ height: 20, width: '60%', marginBottom: 16 }} />
                <div className="skeleton" style={{ height: 14, width: '40%', marginBottom: 12 }} />
                <div className="skeleton" style={{ height: 14, width: '80%', marginBottom: 8 }} />
                <div className="skeleton" style={{ height: 14, width: '50%' }} />
              </div>
            ))}
          </div>
        ) : keys.length === 0 ? (
          <motion.div
            className="empty-state"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="empty-icon"><Key size={48} /></div>
            <h2>No API keys yet</h2>
            <p>Create your first API key to get started</p>
            <button className="btn-create" onClick={() => setShowCreateModal(true)}>
              <Plus size={16} /> Create First Key
            </button>
          </motion.div>
        ) : (
          <>
            <div className="keys-grid">
              {keys.map((key, i) => (
                <motion.div
                  key={key.keyId}
                  className="key-card glass-card"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}
                >
                  <div className="card-top">
                    <div className="card-label">
                      <span className="key-name">{key.label || 'Unnamed Key'}</span>
                      {key.provider === 'nvidia' && <span className="badge nvidia">NVIDIA</span>}
                      {key.rotatedFrom && <span className="badge rotated">Rotated</span>}
                    </div>
                    <button
                      className={`status-pill ${key.status}`}
                      onClick={() => handleToggle(key.keyId, key.status)}
                    >
                      {key.status}
                    </button>
                  </div>

                  <div className="card-meta">
                    <div className="meta-row">
                      <span><Lock size={12} /> Scope</span>
                      <span className="scope-val">{key.scope?.replace('_', ' ')}</span>
                    </div>
                    <div className="meta-row">
                      <span><Clock size={12} /> Created</span>
                      <span>{key.createdAt ? formatDistanceToNow(new Date(key.createdAt), { addSuffix: true }) : 'N/A'}</span>
                    </div>
                    <div className="meta-row">
                      <span><Activity size={12} /> Usage</span>
                      <span className="usage-val">
                        {key.usageCount || 0}
                        {key.usageQuota > 0 && <span className="quota">/ {key.usageQuota}</span>}
                      </span>
                    </div>
                    <div className="meta-row">
                      <span><Zap size={12} /> Speed</span>
                      <span className={`speed ${(key.avgResponseTimeMs || 0) < 50 ? 'fast' : (key.avgResponseTimeMs || 0) < 200 ? 'medium' : 'slow'}`}>
                        {key.avgResponseTimeMs > 0 ? `${key.avgResponseTimeMs.toFixed(1)}ms` : 'N/A'}
                      </span>
                    </div>
                    {key.expiresAt && (
                      <div className="meta-row">
                        <span><AlertTriangle size={12} /> Expires</span>
                        <span>{formatDistanceToNow(new Date(key.expiresAt), { addSuffix: true })}</span>
                      </div>
                    )}
                    {key.allowedIps && key.allowedIps.length > 0 && (
                      <div className="meta-row">
                        <span><Globe size={12} /> IPs</span>
                        <span>{key.allowedIps.length} whitelisted</span>
                      </div>
                    )}
                  </div>

                  <div className="card-actions">
                    <button className="action-btn rotate" onClick={() => handleRotate(key.keyId)} title="Rotate key">
                      <RotateCw size={14} />
                    </button>
                    <button className="action-btn danger" onClick={() => handleDelete(key.keyId)} title="Delete key">
                      <Trash2 size={14} />
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>

            {/* Pagination */}
            {pagination && pagination.totalPages > 1 && (
              <div className="pagination">
                <button
                  disabled={pagination.page <= 1}
                  onClick={() => setPage(pagination.page - 1)}
                >
                  <ChevronLeft size={16} />
                </button>
                <span>Page {pagination.page} of {pagination.totalPages}</span>
                <button
                  disabled={pagination.page >= pagination.totalPages}
                  onClick={() => setPage(pagination.page + 1)}
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            )}
          </>
        )}
      </main>

      {/* ─── Create Modal ─── */}
      <AnimatePresence>
        {showCreateModal && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowCreateModal(false)}
          >
            <motion.div
              className="modal glass-card"
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={e => e.stopPropagation()}
            >
              <h2>Create New API Key</h2>

              <div className="modal-field">
                <label>Label</label>
                <input
                  type="text"
                  value={newKey.label}
                  onChange={e => setNewKey({ ...newKey, label: e.target.value })}
                  placeholder="e.g. Production API"
                />
              </div>

              <div className="modal-row">
                <div className="modal-field">
                  <label>Provider</label>
                  <select value={newKey.provider} onChange={e => setNewKey({ ...newKey, provider: e.target.value })}>
                    <option value="internal">Internal</option>
                    <option value="nvidia">NVIDIA</option>
                  </select>
                </div>
                <div className="modal-field">
                  <label>Scope</label>
                  <select value={newKey.scope} onChange={e => setNewKey({ ...newKey, scope: e.target.value })}>
                    <option value="read_only">Read Only</option>
                    <option value="read_write">Read & Write</option>
                    <option value="full_access">Full Access</option>
                  </select>
                </div>
              </div>

              <div className="modal-row">
                <div className="modal-field">
                  <label>Usage Quota (0 = unlimited)</label>
                  <input
                    type="number"
                    value={newKey.quota}
                    onChange={e => setNewKey({ ...newKey, quota: parseInt(e.target.value) || 0 })}
                    min={0}
                  />
                </div>
                <div className="modal-field">
                  <label>Expires in (days, 0 = never)</label>
                  <input
                    type="number"
                    value={newKey.expiry}
                    onChange={e => setNewKey({ ...newKey, expiry: parseInt(e.target.value) || 0 })}
                    min={0}
                  />
                </div>
              </div>

              <div className="modal-actions">
                <button className="btn-secondary" onClick={() => setShowCreateModal(false)}>Cancel</button>
                <button className="btn-primary" onClick={handleCreateKey}>Create Key</button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ─── Key Created Modal ─── */}
      <AnimatePresence>
        {createdKey && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setCreatedKey(null)}
          >
            <motion.div
              className="modal glass-card modal-success"
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={e => e.stopPropagation()}
            >
              <div className="success-icon">✅</div>
              <h2>API Key Created!</h2>
              <p className="warning-text">
                <AlertTriangle size={14} /> Save this key now — it won't be shown again!
              </p>
              <div className="key-reveal">
                <code>{createdKey.keyValue}</code>
                <button onClick={() => copyKey(createdKey.keyValue!)}>
                  <Copy size={16} />
                </button>
              </div>
              <button className="btn-primary full" onClick={() => setCreatedKey(null)}>
                I've saved it
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ─── Upgrade Modal ─── */}
      <AnimatePresence>
        {showUpgradeModal && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowUpgradeModal(false)}
          >
            <motion.div
              className="modal glass-card upgrade-modal"
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={e => e.stopPropagation()}
            >
              <button className="modal-close" onClick={() => setShowUpgradeModal(false)}>
                <X size={20} />
              </button>
              <div className="upgrade-header">
                <div className="upgrade-icon-wrap">
                  <Crown size={28} />
                </div>
                <h2>Upgrade to <span className="gradient-text">Pro</span></h2>
                <p>Unlock the full power of RagsPro API Gateway</p>
              </div>
              <div className="upgrade-features">
                {['Unlimited API keys', 'Advanced analytics dashboard', '1,000 req/min rate limit', 'Custom providers', 'Team management', 'Priority email support', 'Key rotation & IP whitelisting', 'Audit logs'].map(f => (
                  <div key={f} className="upgrade-feature-item">
                    <Check size={16} className="check-icon" />
                    <span>{f}</span>
                  </div>
                ))}
              </div>
              <div className="upgrade-price">
                <span className="price-amount">₹1,599</span>
                <span className="price-period">/month</span>
              </div>
              <button
                className="btn-primary full upgrade-pay-btn"
                onClick={handleUpgrade}
                disabled={upgrading}
              >
                {upgrading ? 'Processing...' : 'Pay & Upgrade Now'}
              </button>
              <p className="secure-text">Secure payment via Razorpay</p>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
