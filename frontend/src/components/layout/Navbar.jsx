import { Link } from 'react-router-dom'

export function Navbar() {
  return (
    <nav className="border-b border-white/10 bg-navy-900/50 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 font-bold text-teal-400 tracking-tight no-underline">
          <span className="w-2.5 h-2.5 bg-cyan-500 rounded-full"></span>
          <span>ScamShield</span>
        </Link>
        <div className="hidden md:flex gap-6 text-sm text-slate-300">
          <Link to="/dashboard" className="hover:text-teal-400 transition-colors">Dashboard</Link>
          <Link to="/investigations/new" className="hover:text-teal-400 transition-colors">New Investigation</Link>
          <Link to="/investigations/history" className="hover:text-teal-400 transition-colors">History</Link>
          <Link to="/about" className="hover:text-teal-400 transition-colors">About</Link>
        </div>
      </div>
    </nav>
  )
}