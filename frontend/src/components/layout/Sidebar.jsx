import { Link } from 'react-router-dom'

export function Sidebar() {
  return (
    <aside className="hidden lg:flex lg:w-64 flex-col border-r border-border-color bg-noir-secondary p-4">
      <nav className="space-y-2">
        <Link to="/dashboard" className="flex items-center gap-3 px-3 py-2 rounded-lg bg-brand/10 text-brand border border-brand/20">
          Dashboard
        </Link>
        <Link to="/investigations/new" className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-border-color/20 text-text-primary hover:text-white transition-colors">
          New Investigation
        </Link>
        <Link to="/investigations/history" className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-border-color/20 text-text-secondary hover:text-text-primary transition-colors">
          History
        </Link>
        <Link to="/about" className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-border-color/20 text-text-secondary hover:text-text-primary transition-colors">
          About
        </Link>
      </nav>
    </aside>
  )
}