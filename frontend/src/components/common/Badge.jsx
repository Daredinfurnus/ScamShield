export function Badge({ className = '', variant = 'default', children }) {
  const variants = {
    default: 'card border border-border-color text-text-secondary',
    low: 'bg-risk-low/10 border border-risk-low/30 text-risk-low',
    medium: 'bg-risk-medium/10 border border-risk-medium/30 text-risk-medium',
    high: 'bg-risk-high/10 border border-risk-high/30 text-risk-high',
    critical: 'bg-risk-critical/10 border border-risk-critical/30 text-risk-critical',
  }
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium border ${variants[variant]} ${className}`}>
      {children}
    </span>
  )
}