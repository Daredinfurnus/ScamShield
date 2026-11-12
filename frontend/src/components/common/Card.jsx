export function Card({ className = '', children }) {
  return (
    <div className={`card border border-border-color rounded-xl p-6 ${className}`}>
      {children}
    </div>
  )
}