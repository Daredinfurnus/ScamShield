import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield, Activity, Menu, Crosshair, LogOut, User } from 'lucide-react'
import { AuthModal } from '../auth/AuthModal'
import { useAuthStore } from '../../store/authStore'
import api from '../../api/index'

export function Navbar() {
  const location = useLocation()
  const [modalOpen, setModalOpen] = useState(false)
  const { user, accessToken, clearAuth } = useAuthStore()
  const active = location.pathname === '/' ? 'PUBLIC GATEWAY' : 'OPERATIONS CONSOLE'

  function handleLogout() {
    clearAuth()
    // Best-effort server-side cookie revocation.
    api.post('/api/auth/logout').catch(() => {})
  }

  return (
    <>
      <header className="sticky top-0 z-40 border-b border-cyan-300/10 bg-[#070c12]/90 backdrop-blur-xl">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8 h-[68px] flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 group">
            <span className="relative flex items-center justify-center w-9 h-9 border border-lime-300/50 bg-lime-300/5 text-[#b7ff38]">
              <Shield size={20} strokeWidth={2.2}/>
              <span className="absolute -right-1 -top-1 w-2 h-2 bg-[#b7ff38] shadow-[0_0_10px_#b7ff38]"/>
            </span>
            <span>
              <span className="block font-display text-[25px] leading-5 tracking-wider text-slate-100">SCAM<span className="text-[#b7ff38]">SHIELD</span></span>
              <span className="block mt-1 font-mono-tech text-[9px] tracking-[.22em] text-slate-500">FRAUD INTELLIGENCE SYSTEM</span>
            </span>
          </Link>
          <div className="hidden md:flex items-center gap-2 text-[10px] font-mono-tech tracking-[.14em] text-slate-500">
            <span className="w-1.5 h-1.5 rounded-full bg-[#b7ff38] shadow-[0_0_8px_#b7ff38] pulse-glow"/>
            <span>UI {active}</span>
            <span className="mx-2 text-slate-700">/</span>
            <Activity size={13} className="text-cyan-300"/>
            <span>LOCAL INSTANCE</span>
          </div>
          <div className="hidden sm:flex items-center gap-2">
            {accessToken ? (
              <>
                <span className="flex items-center gap-2 px-3 py-2 border border-[#b7ff38]/30 bg-[#b7ff38]/[.05] text-[#b7ff38] font-mono-tech text-[10px] tracking-wider">
                  <User size={13} /> {(user?.email || 'OPERATOR').slice(0, 24)}
                </span>
                <button
                  onClick={handleLogout}
                  className="inline-flex items-center gap-2 px-3 py-2 border border-[#ff416c]/40 text-[#ff416c] font-mono-tech text-[10px] tracking-wider hover:bg-[#ff416c]/10 transition-colors"
                >
                  <LogOut size={14} /> LOGOUT
                </button>
              </>
            ) : (
              <button
                onClick={() => setModalOpen(true)}
                className="inline-flex items-center gap-2 px-3 py-2 border border-[#b7ff38]/40 bg-[#b7ff38]/[.07] text-[#b7ff38] font-mono-tech text-[10px] tracking-wider hover:bg-[#b7ff38]/15 transition-colors"
              >
                <User size={14} /> ACCESS
              </button>
            )}
            <Link to="/investigations/new" className="inline-flex items-center gap-2 px-3 py-2 border border-[#b7ff38]/40 bg-[#b7ff38]/[.07] text-[#b7ff38] font-mono-tech text-[10px] tracking-wider hover:bg-[#b7ff38]/15 transition-colors">
              <Crosshair size={14}/> NEW CASE
            </Link>
          </div>
          <span className="sm:hidden text-[#b7ff38]"><Menu size={21}/></span>
        </div>
      </header>
      <AuthModal open={modalOpen} onClose={() => setModalOpen(false)} />
    </>
  )
}