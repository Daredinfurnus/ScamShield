import { forwardRef } from 'react'

export const Button = forwardRef(({ className = '', variant = 'primary', disabled, children, ...props }, ref) => {
  const base = 'inline-flex items-center justify-center rounded-lg font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none'
  const variants = {
    primary: 'bg-teal-500 text-white hover:bg-teal-400',
    secondary: 'bg-white/10 border border-white/20 text-slate-200 hover:bg-white/5',
    danger: 'bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20',
  }
  return (
    <button ref={ref} className={`${base} ${variants[variant]} ${className}`} disabled={disabled} {...props}>
      {children}
    </button>
  )
})
Button.displayName = 'Button'