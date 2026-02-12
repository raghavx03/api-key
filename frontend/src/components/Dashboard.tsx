import { useState, useEffect } from 'react'
import { api, APIKey } from '../api'
import { formatDistanceToNow } from 'date-fns'
import { Key, Plus, Trash2, Copy, Eye, EyeOff, LogOut, RefreshCw } from 'lucide-react'
import './Dashboard.css'

interface DashboardProps {
  sessionId: string
  onLogout: () => void
}

export default function Dashboard({ sessionId, onLogout }: DashboardProps) {
  const [keys, setKeys] = useState<APIKey[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newKeyLabel, setNewKeyLabel] = useState('')
  const [newKeyProvider, setNewKeyProvider] = useState('internal')
  const [createdKey, setCreatedKey] = useState<APIKey | null>(null)
  const [visibleKeys, setVisibleKeys] = useState<Set<string>>(new Set())
  const [filterProvider, setFilterProvider] = useState<string>('all')

  const loadKeys = async () => {
    try {
      const result = await api.listKeys(sessionId)
      setKeys(result.keys)
    } catch (err) {
      console.error('Failed to load keys:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadKeys()
  }, [sessionId])

  const handleCreateKey = async () => {
    try {
      const newKey = await api.createKey(sessionId, newKeyLabel, newKeyProvider)
      setCreatedKey(newKey)
      setNewKeyLabel('')
      setNewKeyProvider('internal')
      await loadKeys()
    } catch (err) {
      alert('Failed to create key')
    }
  }

  const handleDeleteKey = async (keyId: string) => {
    if (!confirm('Are you sure you want to delete this API key?')) return
    
    try {
      await api.deleteKey(sessionId, keyId)
      setKeys(keys.filter(k => k.keyId !== keyId))
    } catch (err) {
      alert('Failed to delete key')
    }
  }

  const handleToggleStatus = async (keyId: string, currentStatus: string) => {
    const newStatus = currentStatus === 'active' ? 'inactive' : 'active'
    try {
      await api.updateKey(sessionId, keyId, { status: newStatus })
      setKeys(keys.map(k => k.keyId === keyId ? { ...k, status: newStatus } : k))
    } catch (err) {
      alert('Failed to update key status')
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    alert('Copied to clipboard!')
  }

  const toggleKeyVisibility = (keyId: string) => {
    const newVisible = new Set(visibleKeys)
    if (newVisible.has(keyId)) {
      newVisible.delete(keyId)
    } else {
      newVisible.add(keyId)
    }
    setVisibleKeys(newVisible)
  }

  const handleLogout = async () => {
    await api.logout(sessionId)
    onLogout()
  }

  const filteredKeys = filterProvider === 'all' 
    ? keys 
    : keys.filter(k => k.provider === filterProvider)

  if (loading) {
    return (
      <div className="dashboard-container">
        <div className="loading">Loading...</div>
      </div>
    )
  }

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div>
          <h1>🔑 API Key Dashboard</h1>
          <p>Manage your API keys securely</p>
        </div>
        <button onClick={handleLogout} className="btn-logout">
          <LogOut size={18} />
          Logout
        </button>
      </header>

      <div className="dashboard-actions">
        <button onClick={() => setShowCreateModal(true)} className="btn-create">
          <Plus size={18} />
          Create New Key
        </button>
        
        <div className="filter-group">
          <label>Filter:</label>
          <select value={filterProvider} onChange={(e) => setFilterProvider(e.target.value)}>
            <option value="all">All Providers</option>
            <option value="internal">Internal</option>
            <option value="nvidia">NVIDIA</option>
          </select>
        </div>

        <button onClick={loadKeys} className="btn-refresh">
          <RefreshCw size={18} />
        </button>
      </div>

      {filteredKeys.length === 0 ? (
        <div className="empty-state">
          <Key size={48} />
          <h2>No API keys yet</h2>
          <p>Create your first API key to get started</p>
        </div>
      ) : (
        <div className="keys-grid">
          {filteredKeys.map((key) => (
            <div key={key.keyId} className="key-card">
              <div className="key-header">
                <div className="key-label">
                  {key.label || 'Unnamed Key'}
                  {key.provider === 'nvidia' && <span className="nvidia-badge">NVIDIA</span>}
                </div>
                <button
                  onClick={() => handleToggleStatus(key.keyId, key.status)}
                  className={`status-toggle ${key.status}`}
                >
                  {key.status}
                </button>
              </div>

              <div className="key-info">
                <div className="info-row">
                  <span className="label">Created:</span>
                  <span>{formatDistanceToNow(new Date(key.createdAt), { addSuffix: true })}</span>
                </div>
                <div className="info-row">
                  <span className="label">Last used:</span>
                  <span>
                    {key.lastUsedAt 
                      ? formatDistanceToNow(new Date(key.lastUsedAt), { addSuffix: true })
                      : 'Never used'}
                  </span>
                </div>
              </div>

              <div className="key-actions">
                <button
                  onClick={() => handleDeleteKey(key.keyId)}
                  className="btn-icon btn-danger"
                  title="Delete key"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>Create New API Key</h2>
            
            <div className="form-group">
              <label>Label (optional)</label>
              <input
                type="text"
                value={newKeyLabel}
                onChange={(e) => setNewKeyLabel(e.target.value)}
                placeholder="My API Key"
              />
            </div>

            <div className="form-group">
              <label>Provider</label>
              <select value={newKeyProvider} onChange={(e) => setNewKeyProvider(e.target.value)}>
                <option value="internal">Internal</option>
                <option value="nvidia">NVIDIA</option>
              </select>
            </div>

            <div className="modal-actions">
              <button onClick={() => setShowCreateModal(false)} className="btn-secondary">
                Cancel
              </button>
              <button onClick={handleCreateKey} className="btn-primary">
                Create Key
              </button>
            </div>
          </div>
        </div>
      )}

      {createdKey && (
        <div className="modal-overlay" onClick={() => setCreatedKey(null)}>
          <div className="modal modal-success" onClick={(e) => e.stopPropagation()}>
            <h2>✅ API Key Created!</h2>
            <p className="warning">⚠️ Save this key now - it won't be shown again!</p>
            
            <div className="key-display">
              <code>{createdKey.keyValue}</code>
              <button
                onClick={() => copyToClipboard(createdKey.keyValue!)}
                className="btn-copy"
              >
                <Copy size={16} />
              </button>
            </div>

            <button onClick={() => setCreatedKey(null)} className="btn-primary">
              I've saved it
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
