import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, X, User, Mail, Lock, ArrowRight } from 'lucide-react'
import api from '../../api/index'
import { API } from '../../api/endpoints'
import { useAuthStore } from '../../store/authStore'

export function AuthModal({ open, onClose }) {
  const [mode, setMode] = useState('login') // login | register
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
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md cyber-panel p-6">
        <button onClick={onClose} className="absolute top-4 right-4 text-slate-500 hover:text-[#b7ff38]">
          <X size={18} />
        </button>

        <div className="flex items-center gap-3 mb-5">
          <div className="w-9 h-9 border border-[#b7ff38]/50 bg-[#b7ff38]/5 text-[#b7ff38] flex items-center justify-center">
            <Shield size={18} />
          </div>
          <div>
            <div className="font-display text-xl tracking-wider text-slate-100">
              {mode === 'login' ? 'ACCESS CONSOLE' : 'REGISTER UNIT'}
            </div>
            <div className="cyber-kicker">SECURE AUTH GATEWAY</div>
          </div>
        </div>

        <form onSubmit={submit} className="space-y-3">
          {mode === 'register' && (
            <label className="block">
              <span className="cyber-kicker mb-1.5 inline-block">ORGANIZATION</span>
              <div className="relative">
                <User size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  value={tenantName}
                  onChange={(e) => setTenantName(e.target.value)}
                  placeholder="Acme Corp"
                  className="w-full pl-9 pr-3 py-2.5 bg-[#070c12] border border-[#b7ff38]/20 rounded text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-[#b7ff38]"
                />
              </div>
            </label>
          )}
          <label className="block">
            <span className="cyber-kicker mb-1.5 inline-block">CREDENTIAL EMAIL</span>
            <div className="relative">
              <Mail size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@acme.io"
                className="w-full pl-9 pr-3 py-2.5 bg-[#070c12] border border-[#b7ff38]/20 rounded text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-[#b7ff38]"
              />
            </div>
          </label>
          <label className="block">
            <span className="cyber-kicker mb-1.5 inline-block">PASSPHRASE</span>
            <div className="relative">
              <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full pl-9 pr-3 py-2.5 bg-[#070c12] border border-[#b7ff38]/20 rounded text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-[#b7ff38]"
              />
            </div>
          </label>

          {error && (
            <div className="text-xs text-[#ff416c] border border-[#ff416c]/30 bg-[#ff416c]/10 rounded px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="cyber-button w-full disabled:opacity-50"
          >
            {loading ? 'AUTHENTICATING…' : mode === 'login' ? 'LOGIN' : 'CREATE ACCOUNT'}
            <ArrowRight size={15} />
          </button>
        </form>

        <div className="mt-5 text-center text-xs text-slate-500 font-mono-tech tracking-wider">
          {mode === 'login' ? 'NO CREDENTIALS?' : 'ALREADY ENLISTED?'}
          <button
            onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(null) }}
            className="ml-2 text-[#b7ff38] hover:underline"
          >
            {mode === 'login' ? 'REGISTER' : 'LOGIN'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default AuthModal