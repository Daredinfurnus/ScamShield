export function Loader({ className = '' }) {
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className="w-5 h-5 border-2 border-border-color border-t-brand rounded-full animate-spin"></div>
      <span className="text-sm text-text-secondary">Analyzing...</span>
    </div>
  )
}