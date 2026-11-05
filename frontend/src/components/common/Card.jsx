export function Card({ className = '', children }) {
  return (
    <div className={`bg-white/5 border border-white/10 rounded-xl p-6 ${className}`}>
      {children}
    </div>
  )
}