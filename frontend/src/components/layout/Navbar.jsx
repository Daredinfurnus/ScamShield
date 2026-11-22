import { Link, useLocation } from 'react-router-dom'
import { Shield, PlusCircle, LayoutDashboard, History, Info, Menu, X, Terminal, ExternalLink, User, LogOut } from 'lucide-react'
import { useState } from 'react'
import { AuthModal } from '../auth/AuthModal'
import { useAuthStore } from '../../store/authStore'
import api from '../../api/index'

export function Navbar() {
  const location = useLocation()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const { user, accessToken, clearAuth, authModalOpen, openAuthModal, closeAuthModal } = useAuthStore()

  function handleLogout() {
    clearAuth()
    // Best-effort server-side cookie revocation.
    api.post('/api/auth/logout').catch(() => {})
  }

  const navLinks = [
    { to: '/', label: 'Overview' },
    { to: '/dashboard', label: 'Intelligence Desk' },
    { to: '/investigations/new', label: 'New Investigation', highlight: true },
    { to: '/investigations/history', label: 'Case Archive' },
    { to: '/about', label: 'Methodology' },
  ]

  return (
    <>
      <header className="sticky top-0 z-40 w-full border-b border-border bg-canvas/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <Link to="/" className="flex items-center gap-3 group">
          <div className="w-8 h-8 rounded-md bg-canvas-card border border-border-strong flex items-center justify-center text-ochre group-hover:border-ochre/50 transition-colors">
            <Shield size={18} strokeWidth={2.2} />
          </div>
          <div className="flex flex-col">
            <span className="font-serif text-lg leading-tight tracking-tight text-parchment font-semibold">
              ScamShield
            </span>
            <span className="text-[10px] font-mono tracking-widest text-parchment-dim uppercase">
              Investigation Platform
            </span>
          </div>
        </Link>

        {/* Desktop Nav */}
        <nav className="hidden md:flex items-center gap-1">
          {navLinks.map((item) => {
            const active = location.pathname === item.to
            if (item.highlight) {
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className="ml-2 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-medium rounded-md bg-ochre/15 text-ochre-light border border-ochre/30 hover:bg-ochre hover:text-canvas transition-colors"
                >
                  <PlusCircle size={14} />
                  <span>{item.label}</span>
                </Link>
              )
            }
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                  active
                    ? 'text-parchment bg-canvas-card border border-border'
                    : 'text-parchment-muted hover:text-parchment hover:bg-canvas-subtle'
                }`}
              >
                {item.label}
              </Link>
            )
          })}
        </nav>

        {/* Right side indicators */}
        <div className="hidden sm:flex items-center gap-3">
          <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-canvas-subtle border border-border-subtle font-mono text-[11px] text-parchment-dim">
            <span className="w-2 h-2 rounded-full bg-olive-light"></span>
            <span>ENGINE: DETERMINISTIC</span>
          </div>
          {accessToken ? (
            <>
              <span className="flex items-center gap-2 px-3 py-1.5 rounded bg-canvas-card border border-border font-mono text-[11px] text-parchment">
                <User size={13} /> {(user?.email || 'OPERATOR').slice(0, 24)}
              </span>
              <button
                onClick={handleLogout}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-risk-critical-border text-risk-critical font-mono text-[11px] hover:bg-risk-critical-dim transition-colors"
              >
                <LogOut size={13} /> LOGOUT
              </button>
            </>
          ) : (
            <button
              onClick={openAuthModal}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-ochre/40 bg-ochre/10 text-ochre font-mono text-[11px] hover:bg-ochre/20 transition-colors"
            >
              <User size={13} /> ACCESS
            </button>
          )}
        </div>

        {/* Mobile menu button */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="md:hidden p-2 text-parchment-muted hover:text-parchment rounded-md hover:bg-canvas-subtle"
          aria-label="Toggle Navigation"
        >
          {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Mobile drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-border bg-canvas-card px-4 py-4 space-y-2">
          {navLinks.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              onClick={() => setMobileMenuOpen(false)}
              className={`block px-3 py-2 text-sm rounded-md ${
                location.pathname === item.to
                  ? 'bg-canvas-elevated text-parchment font-medium'
                  : 'text-parchment-muted hover:text-parchment hover:bg-canvas-subtle'
              }`}
            >
              {item.label}
            </Link>
          ))}
        </div>
      )}
    </header>
      <AuthModal open={authModalOpen} onClose={closeAuthModal} />
    </>
  )
}
