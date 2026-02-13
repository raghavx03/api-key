import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { motion, AnimatePresence } from 'framer-motion'
import { Eye, EyeOff, Sparkles, Shield, Zap } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuthStore } from '../store'
import './Login.css'

const loginSchema = z.object({
  email: z.string().email('Please enter a valid email'),
  password: z.string().min(1, 'Password is required'),
})

const registerSchema = z.object({
  email: z.string().email('Please enter a valid email'),
  password: z.string()
    .min(8, 'At least 8 characters')
    .regex(/[A-Z]/, 'Need one uppercase letter')
    .regex(/[a-z]/, 'Need one lowercase letter')
    .regex(/[0-9]/, 'Need one digit'),
})

type FormData = z.infer<typeof registerSchema>

export default function Login() {
  const [isRegister, setIsRegister] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const { login, register: registerUser, loading } = useAuthStore()

  const schema = isRegister ? registerSchema : loginSchema
  const { register, handleSubmit, formState: { errors }, reset } = useForm<FormData>({
    resolver: zodResolver(schema),
  })

  const onSubmit = async (data: FormData) => {
    try {
      if (isRegister) {
        await registerUser(data.email, data.password)
        toast.success('Account created! Please login.')
        setIsRegister(false)
        reset()
      } else {
        await login(data.email, data.password)
        toast.success('Welcome back!')
      }
    } catch (err: any) {
      toast.error(err.message || 'Something went wrong')
    }
  }

  const features = [
    { icon: <Shield size={20} />, title: 'AES-256 Encryption', desc: 'Keys encrypted at rest' },
    { icon: <Zap size={20} />, title: 'Sub-10ms Validation', desc: 'Lightning fast key checks' },
    { icon: <Sparkles size={20} />, title: 'JWT Authentication', desc: 'Secure token-based auth' },
  ]

  return (
    <div className="login-page">
      {/* Floating orbs */}
      <div className="orb orb-1" />
      <div className="orb orb-2" />
      <div className="orb orb-3" />

      <div className="login-layout">
        {/* Left side — branding */}
        <motion.div
          className="login-hero"
          initial={{ opacity: 0, x: -30 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="hero-content">
            <div className="hero-icon">
              <img src="/logo.png" alt="RagsPro" style={{ width: 40, height: 40, borderRadius: 10 }} />
            </div>
            <h1>RagsPro<br /><span className="gradient-text">API Gateway</span></h1>
            <p>Enterprise-grade API key management with advanced security, RBAC, and real-time analytics.</p>

            <div className="feature-list">
              {features.map((f, i) => (
                <motion.div
                  key={i}
                  className="feature-item"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.3 + i * 0.1 }}
                >
                  <div className="feature-icon">{f.icon}</div>
                  <div>
                    <strong>{f.title}</strong>
                    <span>{f.desc}</span>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* Right side — form */}
        <motion.div
          className="login-form-side"
          initial={{ opacity: 0, x: 30 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <div className="login-card glass-card">
            <AnimatePresence mode="wait">
              <motion.div
                key={isRegister ? 'register' : 'login'}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
              >
                <h2>{isRegister ? 'Create Account' : 'Welcome Back'}</h2>
                <p className="form-subtitle">
                  {isRegister ? 'Start managing your API keys' : 'Login to your dashboard'}
                </p>

                <form onSubmit={handleSubmit(onSubmit)}>
                  <div className="field">
                    <label>Email</label>
                    <input
                      type="email"
                      {...register('email')}
                      placeholder="you@company.com"
                      className={errors.email ? 'error' : ''}
                    />
                    {errors.email && <span className="field-error">{errors.email.message}</span>}
                  </div>

                  <div className="field">
                    <label>Password</label>
                    <div className="password-wrapper">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        {...register('password')}
                        placeholder={isRegister ? 'Min 8 chars, A-z, 0-9' : '••••••••'}
                        className={errors.password ? 'error' : ''}
                      />
                      <button
                        type="button"
                        className="toggle-pw"
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                    {errors.password && <span className="field-error">{errors.password.message}</span>}
                  </div>

                  <button type="submit" className="btn-submit" disabled={loading}>
                    {loading ? (
                      <div className="spinner" />
                    ) : (
                      isRegister ? 'Create Account' : 'Sign In'
                    )}
                  </button>
                </form>

                <div className="switch-mode">
                  <button onClick={() => { setIsRegister(!isRegister); reset() }}>
                    {isRegister ? 'Already have an account? Sign in' : "Don't have an account? Create one"}
                  </button>
                </div>
              </motion.div>
            </AnimatePresence>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
