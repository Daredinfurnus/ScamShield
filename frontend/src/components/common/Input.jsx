export function Input({ className = '', ...props }) {
  return (
    <input
      className={`block w-full rounded-lg border border-white/10 bg-white/5 px-4 py-2.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-teal-500 focus:ring-1 focus:ring-teal-500 transition-colors ${className}`}
      {...props}
    />
  )
}