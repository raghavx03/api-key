const API_BASE = import.meta.env.VITE_API_URL || '/api'

export interface APIKey {
  keyId: string
  label: string
  provider: string
  status: string
  createdAt: string
  lastUsedAt: string | null
  keyValue?: string
  usageCount?: number
  avgResponseTimeMs?: number
}

export const api = {
  async register(email: string, password: string) {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    })
    if (!res.ok) {
      const error = await res.json()
      throw new Error(error.detail || 'Registration failed')
    }
    return res.json()
  },

  async login(email: string, password: string) {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    })
    if (!res.ok) {
      const error = await res.json()
      throw new Error(error.detail || 'Login failed')
    }
    return res.json()
  },

  async logout(sessionId: string) {
    await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionId}` }
    })
  },

  async listKeys(sessionId: string): Promise<{ keys: APIKey[] }> {
    const res = await fetch(`${API_BASE}/keys`, {
      headers: { Authorization: `Bearer ${sessionId}` }
    })
    if (!res.ok) throw new Error('Failed to fetch keys')
    return res.json()
  },

  async createKey(sessionId: string, label: string, provider: string): Promise<APIKey> {
    const res = await fetch(`${API_BASE}/keys`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionId}`
      },
      body: JSON.stringify({ label, provider })
    })
    if (!res.ok) throw new Error('Failed to create key')
    return res.json()
  },

  async updateKey(sessionId: string, keyId: string, updates: { label?: string; status?: string }) {
    const res = await fetch(`${API_BASE}/keys/${keyId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sessionId}`
      },
      body: JSON.stringify(updates)
    })
    if (!res.ok) throw new Error('Failed to update key')
    return res.json()
  },

  async deleteKey(sessionId: string, keyId: string) {
    const res = await fetch(`${API_BASE}/keys/${keyId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${sessionId}` }
    })
    if (!res.ok) throw new Error('Failed to delete key')
    return res.json()
  },

  async validateKey(apiKey: string) {
    const res = await fetch(`${API_BASE}/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey })
    })
    return { valid: res.ok, status: res.status }
  }
}
