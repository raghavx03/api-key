const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

export interface APIKey {
  keyId: string
  label: string
  provider: string
  status: string
  scope: string
  allowedIps: string[]
  usageCount: number
  usageQuota: number
  avgResponseTimeMs: number
  createdAt: string
  lastUsedAt: string | null
  expiresAt: string | null
  rotatedFrom: string | null
  keyValue?: string
}

export interface Pagination {
  page: number
  perPage: number
  total: number
  totalPages: number
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export interface UserProfile {
  userId: string
  email: string
  role: string
  plan: string
}

export interface AdminStats {
  totalUsers: number
  activeUsers: number
  totalKeys: number
  activeKeys: number
  totalValidations: number
  avgResponseTimeMs: number
}

// Token helpers
const getAccessToken = () => localStorage.getItem('accessToken')
const getRefreshToken = () => localStorage.getItem('refreshToken')
const setTokens = (access: string, refresh: string) => {
  localStorage.setItem('accessToken', access)
  localStorage.setItem('refreshToken', refresh)
}
const clearTokens = () => {
  localStorage.removeItem('accessToken')
  localStorage.removeItem('refreshToken')
}

// Auto-refresh wrapper
async function fetchWithAuth(url: string, options: RequestInit = {}): Promise<Response> {
  const token = getAccessToken()
  const headers = {
    ...options.headers as Record<string, string>,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }

  let res = await fetch(url, { ...options, headers })

  // If 401, try refresh
  if (res.status === 401 && getRefreshToken()) {
    const refreshRes = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: getRefreshToken() }),
    })

    if (refreshRes.ok) {
      const data: TokenResponse = await refreshRes.json()
      setTokens(data.access_token, data.refresh_token)
      // Retry original request
      headers.Authorization = `Bearer ${data.access_token}`
      res = await fetch(url, { ...options, headers })
    } else {
      clearTokens()
      window.location.href = '/login'
      throw new Error('Session expired. Please login again.')
    }
  }

  return res
}

export const api = {
  // ─── Auth ───
  async register(email: string, password: string) {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    if (!res.ok) {
      const err = await res.json()
      throw new Error(err.detail || 'Registration failed')
    }
    return res.json()
  },

  async login(email: string, password: string): Promise<TokenResponse> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    if (!res.ok) {
      const err = await res.json()
      throw new Error(err.detail || 'Login failed')
    }
    const data: TokenResponse = await res.json()
    setTokens(data.access_token, data.refresh_token)
    return data
  },

  async logout() {
    try {
      await fetchWithAuth(`${API_BASE}/auth/logout`, { method: 'POST' })
    } finally {
      clearTokens()
    }
  },

  async getMe(): Promise<UserProfile> {
    const res = await fetchWithAuth(`${API_BASE}/auth/me`)
    if (!res.ok) throw new Error('Failed to get profile')
    return res.json()
  },

  // ─── Keys ───
  async listKeys(params?: {
    status?: string
    provider?: string
    search?: string
    sort_by?: string
    sort_order?: string
    page?: number
    per_page?: number
  }): Promise<{ keys: APIKey[]; pagination: Pagination }> {
    const query = new URLSearchParams()
    if (params?.status) query.set('status', params.status)
    if (params?.provider) query.set('provider', params.provider)
    if (params?.search) query.set('search', params.search)
    if (params?.sort_by) query.set('sort_by', params.sort_by)
    if (params?.sort_order) query.set('sort_order', params.sort_order)
    if (params?.page) query.set('page', params.page.toString())
    if (params?.per_page) query.set('per_page', params.per_page.toString())

    const res = await fetchWithAuth(`${API_BASE}/keys?${query}`)
    if (!res.ok) throw new Error('Failed to fetch keys')
    return res.json()
  },

  async createKey(data: {
    label?: string
    provider?: string
    scope?: string
    allowed_ips?: string[]
    usage_quota?: number
    expires_in_days?: number
  }): Promise<APIKey> {
    const res = await fetchWithAuth(`${API_BASE}/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!res.ok) throw new Error('Failed to create key')
    return res.json()
  },

  async updateKey(keyId: string, updates: {
    label?: string
    status?: string
    scope?: string
    allowed_ips?: string[]
    usage_quota?: number
  }) {
    const res = await fetchWithAuth(`${API_BASE}/keys/${keyId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    })
    if (!res.ok) throw new Error('Failed to update key')
    return res.json()
  },

  async deleteKey(keyId: string) {
    const res = await fetchWithAuth(`${API_BASE}/keys/${keyId}`, { method: 'DELETE' })
    if (!res.ok) throw new Error('Failed to delete key')
    return res.json()
  },

  async rotateKey(keyId: string, label?: string): Promise<APIKey> {
    const res = await fetchWithAuth(`${API_BASE}/keys/${keyId}/rotate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label }),
    })
    if (!res.ok) throw new Error('Failed to rotate key')
    return res.json()
  },

  async getKeyStats(keyId: string) {
    const res = await fetchWithAuth(`${API_BASE}/keys/${keyId}/stats`)
    if (!res.ok) throw new Error('Failed to get stats')
    return res.json()
  },

  // ─── Validation ───
  async validateKey(apiKey: string) {
    const res = await fetch(`${API_BASE}/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey }),
    })
    return { valid: res.ok, status: res.status, data: await res.json() }
  },

  // ─── Admin ───
  async getAdminStats(): Promise<AdminStats> {
    const res = await fetchWithAuth(`${API_BASE}/admin/stats`)
    if (!res.ok) throw new Error('Failed to get admin stats')
    return res.json()
  },

  async listUsers(page = 1) {
    const res = await fetchWithAuth(`${API_BASE}/admin/users?page=${page}`)
    if (!res.ok) throw new Error('Failed to list users')
    return res.json()
  },

  async getAuditLogs(page = 1) {
    const res = await fetchWithAuth(`${API_BASE}/admin/audit-logs?page=${page}`)
    if (!res.ok) throw new Error('Failed to get audit logs')
    return res.json()
  },

  // ─── Helpers ───
  isAuthenticated: () => !!getAccessToken(),
  clearAuth: clearTokens,

  // ─── Billing ───
  async createOrder(plan: string = 'pro') {
    const res = await fetchWithAuth(`${API_BASE}/billing/create-order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan }),
    })
    if (!res.ok) {
      const err = await res.json()
      throw new Error(err.detail || 'Failed to create order')
    }
    return res.json()
  },

  async verifyPayment(data: { razorpay_order_id: string; razorpay_payment_id: string; razorpay_signature: string }) {
    const res = await fetchWithAuth(`${API_BASE}/billing/verify-payment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!res.ok) {
      const err = await res.json()
      throw new Error(err.detail || 'Payment verification failed')
    }
    return res.json()
  },

  async getPlanInfo() {
    const res = await fetchWithAuth(`${API_BASE}/billing/plan`)
    if (!res.ok) throw new Error('Failed to get plan info')
    return res.json()
  },
}
