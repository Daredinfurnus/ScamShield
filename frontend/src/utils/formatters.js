export function formatDate(iso) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString()
}

export function riskColor(band) {
  const map = {
    low: 'text-green-400',
    medium: 'text-amber-400',
    high: 'text-orange-400',
    critical: 'text-red-400',
  }
  return map[band] || 'text-slate-400'
}