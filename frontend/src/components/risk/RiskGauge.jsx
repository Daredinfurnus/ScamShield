import { useEffect, useState } from 'react'

const RISK_COLORS = {
  low: '#22c55e',
  medium: '#f59e0b',
  high: '#fb923c',
  critical: '#ef4444',
}

export function RiskGauge({ score, className = '' }) {
  const [displayScore, setDisplayScore] = useState(0)

  useEffect(() => {
    const timer = setTimeout(() => setDisplayScore(score), 100)
    return () => clearTimeout(timer)
  }, [score])

  let band = 'low'
  let color = RISK_COLORS.low
  if (score >= 75) {
    band = 'critical'
    color = RISK_COLORS.critical
  } else if (score >= 50) {
    band = 'high'
    color = RISK_COLORS.high
  } else if (score >= 25) {
    band = 'medium'
    color = RISK_COLORS.medium
  }

  return (
    <div className={`card ${className}`}>
      <div className="flex flex-col items-center justify-center py-8">
        <div className="relative w-32 h-32">
          <svg className="w-full h-full" viewBox="0 0 60 60">
            <circle
              cx="30"
              cy="30"
              r="24"
              fill="none"
              stroke="white/10"
              strokeWidth="8"
              strokeLinecap="round"
            />
            <circle
              cx="30"
              cy="30"
              r="24"
              fill="none"
              stroke={color}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray="150.8"
              strokeDashoffset={150.8 - (score / 100) * 150.8}
              transform="rotate(-90 30 30)"
              className="transition-all duration-700 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-bold text-white">{Math.round(displayScore)}</span>
            <span className="text-xs text-slate-400 uppercase tracking-wider">/ 100</span>
          </div>
        </div>
        <div className="mt-4">
          <span className={`text-xs font-semibold uppercase tracking-wider ${color}`}>
            {band.toUpperCase()}
          </span>
        </div>
      </div>
    </div>
  )
}