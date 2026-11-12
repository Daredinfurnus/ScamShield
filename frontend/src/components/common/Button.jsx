import { forwardRef } from 'react'

export const Button = forwardRef(({ className = '', variant = 'primary', disabled, children, ...props }, ref) => {
  const base = 'inline-flex items-center justify-center rounded-lg font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none'
  const variants = {
    primary: 'bg-brand text-text-primary hover:bg-brand/90 focus:outline-none',
    secondary: 'card border border-border-color text-text-primary hover:bg-border-color/20',
    danger: 'bg-risk-critical/10 border border-risk/critical/30 text-risk/critical hover:bg-risk/critical/20',
  }
  return (
    <button ref={ref} className={`${base} ${variants[variant]} ${className}`} disabled={disabled} {...props}>
      {children}
    </button>
  )
})
Button.displayName = 'Button'