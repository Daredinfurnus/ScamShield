import { Badge } from './Badge'

export function RiskChip({ score, className = '' }) {
  let band = 'low'
  if (score >= 75) band = 'critical'
  else if (score >= 50) band = 'high'
  else if (score >= 25) band = 'medium'
  return (
    <Badge variant={band} className={className}>
      {band.toUpperCase()} {score}/100
    </Badge>
  )
}