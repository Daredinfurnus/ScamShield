export function Badge({ className = '', variant = 'default', children }) {
  const variants = {
    default: 'bg-white/10 text-slate-300 border border-white/10',
    low: 'bg-green-500/10 text-green-400 border border-green-500/30',
    medium: 'bg-amber-500/10 text-amber-400 border border-amber-500/30',
    high: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
    critical: 'bg-red-500/10 text-red-400 border border-red-500/30',
  }
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium border ${variants[variant]} ${className}`}>
      {children}
    </span>
  )
}