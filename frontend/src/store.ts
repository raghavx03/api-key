import { create } from 'zustand'
import { api, APIKey, UserProfile, Pagination } from './api'

interface AuthState {
    isAuthenticated: boolean
    user: UserProfile | null
    loading: boolean
    login: (email: string, password: string) => Promise<void>
    register: (email: string, password: string) => Promise<void>
    logout: () => Promise<void>
    fetchProfile: () => Promise<void>
    checkAuth: () => void
}

interface KeyState {
    keys: APIKey[]
    pagination: Pagination | null
    loading: boolean
    search: string
    filterProvider: string
    filterStatus: string
    sortBy: string
    sortOrder: string
    page: number
    fetchKeys: () => Promise<void>
    createKey: (data: {
        label?: string; provider?: string; scope?: string;
        allowed_ips?: string[]; usage_quota?: number; expires_in_days?: number
    }) => Promise<APIKey>
    updateKey: (keyId: string, updates: { label?: string; status?: string; scope?: string }) => Promise<void>
    deleteKey: (keyId: string) => Promise<void>
    rotateKey: (keyId: string, label?: string) => Promise<APIKey>
    setSearch: (s: string) => void
    setFilterProvider: (p: string) => void
    setFilterStatus: (s: string) => void
    setSortBy: (s: string) => void
    setSortOrder: (s: string) => void
    setPage: (p: number) => void
}

interface ThemeState {
    theme: 'dark' | 'light'
    toggleTheme: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
    isAuthenticated: api.isAuthenticated(),
    user: null,
    loading: false,

    login: async (email, password) => {
        set({ loading: true })
        try {
            await api.login(email, password)
            const user = await api.getMe()
            set({ isAuthenticated: true, user, loading: false })
        } catch (e) {
            set({ loading: false })
            throw e
        }
    },

    register: async (email, password) => {
        set({ loading: true })
        try {
            await api.register(email, password)
            set({ loading: false })
        } catch (e) {
            set({ loading: false })
            throw e
        }
    },

    logout: async () => {
        await api.logout()
        set({ isAuthenticated: false, user: null })
    },

    fetchProfile: async () => {
        try {
            const user = await api.getMe()
            set({ user, isAuthenticated: true })
        } catch {
            set({ isAuthenticated: false, user: null })
            api.clearAuth()
        }
    },

    checkAuth: () => {
        set({ isAuthenticated: api.isAuthenticated() })
    },
}))

export const useKeyStore = create<KeyState>((set, get) => ({
    keys: [],
    pagination: null,
    loading: false,
    search: '',
    filterProvider: 'all',
    filterStatus: 'all',
    sortBy: 'created_at',
    sortOrder: 'desc',
    page: 1,

    fetchKeys: async () => {
        set({ loading: true })
        try {
            const { search, filterProvider, filterStatus, sortBy, sortOrder, page } = get()
            const result = await api.listKeys({
                search: search || undefined,
                provider: filterProvider !== 'all' ? filterProvider : undefined,
                status: filterStatus !== 'all' ? filterStatus : undefined,
                sort_by: sortBy,
                sort_order: sortOrder,
                page,
                per_page: 12,
            })
            set({ keys: result.keys, pagination: result.pagination, loading: false })
        } catch {
            set({ loading: false })
        }
    },

    createKey: async (data) => {
        const result = await api.createKey(data)
        await get().fetchKeys()
        return result
    },

    updateKey: async (keyId, updates) => {
        await api.updateKey(keyId, updates)
        await get().fetchKeys()
    },

    deleteKey: async (keyId) => {
        await api.deleteKey(keyId)
        await get().fetchKeys()
    },

    rotateKey: async (keyId, label) => {
        const result = await api.rotateKey(keyId, label)
        await get().fetchKeys()
        return result
    },

    setSearch: (s) => set({ search: s, page: 1 }),
    setFilterProvider: (p) => set({ filterProvider: p, page: 1 }),
    setFilterStatus: (s) => set({ filterStatus: s, page: 1 }),
    setSortBy: (s) => set({ sortBy: s }),
    setSortOrder: (s) => set({ sortOrder: s }),
    setPage: (p) => set({ page: p }),
}))

export const useThemeStore = create<ThemeState>((set, get) => ({
    theme: (localStorage.getItem('theme') as 'dark' | 'light') || 'dark',

    toggleTheme: () => {
        const next = get().theme === 'dark' ? 'light' : 'dark'
        localStorage.setItem('theme', next)
        document.documentElement.setAttribute('data-theme', next)
        set({ theme: next })
    },
}))
