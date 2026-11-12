import { Link } from 'react-router-dom'

export function Navbar() {
  return (
    <nav className="border-b border-border-color bg-noir-secondary/90 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 font-bold text-brand tracking-tight no-underline">
          <span className="w-2.5 h-2.5 bg-brand rounded-full"></span>
          <span>ScamShield</span>
        </Link>
        <div className="hidden md:flex gap-6 text-sm text-text-secondary">
          <Link to="/dashboard" className="hover:text-brand transition-colors">Dashboard</Link>
          <Link to="/investigations/new" className="hover:text-brand transition-colors">New Investigation</Link>
          <Link to="/investigations/history" className="hover:text-brand transition-colors">History</Link>
          <Link to="/about" className="hover:text-brand transition-colors">About</Link>
        </div>
      </div>
    </nav>
  )
}