import { useState } from 'react'
import { Shield, X, User, Mail, Lock, ArrowRight } from 'lucide-react'
import api from '../../api/index'
import { API } from '../../api/endpoints'
import { useAuthStore } from '../../store/authStore'
import { Button } from '../common/Button'
import { Input } from '../common/Input'
import { Card } from '../common/Card'

export function AuthModal({ open, onClose }) {
  const [mode, setMode] = useState('register') // Default to register mode as per requirements
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [tenantName, setTenantName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const store = useAuthStore()

  async function submit(e) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const body =
        mode === 'login'
          ? { email, password }
          : { email, password, tenant_name: tenantName, role: 'investigator' }
      const res = await api.post(API.auth[mode === 'login' ? 'login' : 'register'], body)
      store.setAuth(res.data.user ?? { email }, res.data.access_token)
      setEmail(''); setPassword(''); setTenantName('')
      onClose()
    } catch (err) {
      const msg = err?.response?.data?.detail || err.message
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg))
    } finally {
      setLoading(false)
    }
  }

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-canvas/80 backdrop-blur-sm"
        onClick={onClose}
        style={{ pointerEvents: 'auto' }}
      />
      <Card className="relative w-full max-w-md p-6 sm:p-8 space-y-6 bg-canvas-card border-border-strong shadow-elevated z-51">
        <button 
          onClick={onClose} 
          className="absolute top-5 right-5 text-parchment-dim hover:text-parchment transition-colors"
          aria-label="Close Modal"
        >
          <X size={18} />
        </button>

        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-md bg-canvas-subtle border border-border flex items-center justify-center text-ochre">
            <Shield size={18} />
          </div>
          <div>
            <h3 className="editorial-heading text-lg text-parchment">
              {mode === 'login' ? 'Investigator Sign In' : 'Register Organization'}
            </h3>
            <p className="text-xs text-parchment-dim font-mono">
              Secure Credential Authentication
            </p>
          </div>
        </div>

        <form onSubmit={submit} className="space-y-4" style={{ pointerEvents: 'auto' }}>
          {mode === 'register' && (
            <div className="space-y-1.5">
              <label className="block text-xs font-mono uppercase text-parchment-dim">
                Organization Name
              </label>
              <div className="relative">
                <User size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-parchment-dim" />
                <input
                  value={tenantName}
                  onChange={(e) => setTenantName(e.target.value)}
                  placeholder="National Fraud Bureau"
                  required
                  className="w-full pl-9 pr-3 py-2 bg-canvas-subtle border border-border rounded-md text-xs font-mono text-parchment placeholder:text-parchment-dim focus:outline-none focus:border-ochre"
                />
              </div>
            </div>
          )}

          <div className="space-y-1.5">
            <label className="block text-xs font-mono uppercase text-parchment-dim">
              Operator Email
            </label>
            <div className="relative">
              <Mail size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-parchment-dim" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="investigator@agency.gov"
                className="w-full pl-9 pr-3 py-2 bg-canvas-subtle border border-border rounded-md text-xs font-mono text-parchment placeholder:text-parchment-dim focus:outline-none focus:border-ochre"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-mono uppercase text-parchment-dim">
              Passphrase
            </label>
            <div className="relative">
              <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-parchment-dim" />
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 bg-canvas-subtle border border-border rounded-md text-xs font-mono text-parchment placeholder:text-parchment-dim focus:outline-none focus:border-ochre"
              />
            </div>
          </div>

          {error && (
            <div className="p-3 rounded-md bg-risk-critical-dim border border-risk-critical-border text-xs text-risk-critical font-mono">
              {error}
            </div>
          )}

          <Button
            type="submit"
            disabled={loading}
            className="w-full"
          >
            <span>{loading ? 'Authenticating...' : mode === 'login' ? 'Sign In to Workspace' : 'Create Organization Unit'}</span>
            <ArrowRight size={14} />
          </Button>
        </form>

        <div className="pt-2 text-center text-xs font-mono text-parchment-dim">
          <span>{mode === 'login' ? 'Need an investigator unit?' : 'Already have credentials?'}</span>
          <button
            onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(null) }}
            className="ml-2 text-ochre hover:underline font-semibold"
          >
            {mode === 'login' ? 'Register' : 'Sign In'}
          </button>
        </div>
      </Card>
    </div>
  )
}

export default AuthModal
