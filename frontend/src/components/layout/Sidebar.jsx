import { Link } from 'react-router-dom'

export function Sidebar() {
  return (
    <aside className="hidden lg:flex lg:w-64 flex-col border-r border-white/10 bg-navy-900 p-4">
      <nav className="space-y-2">
        <Link to="/dashboard" className="flex items-center gap-3 px-3 py-2 rounded-lg bg-teal-500/10 text-teal-400">
          Dashboard
        </Link>
        <Link to="/investigations/new" className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/5 text-slate-300 hover:text-white transition-colors">
          New Investigation
        </Link>
        <Link to="/investigations/history" className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/5 text-slate-300 hover:text-white transition-colors">
          History
        </Link>
        <Link to="/about" className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/5 text-slate-300 hover:text-white transition-colors">
          About
        </Link>
      </nav>
    </aside>
  )
}