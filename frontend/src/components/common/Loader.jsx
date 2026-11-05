export function Loader({ className = '' }) {
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className="w-5 h-5 border-2 border-white/20 border-t-teal-400 rounded-full animate-spin"></div>
      <span className="text-sm text-slate-400">Analyzing...</span>
    </div>
  )
}