export function Input({ className = '', ...props }) {
  return (
    <input
      className={`block w-full rounded-lg border border-border-color card px-4 py-2.5 text-text-primary placeholder-text-secondary focus:outline-none focus:border-brand focus:ring-1 focus:ring-brand transition-colors ${className}`}
      {...props}
    />
  )
}