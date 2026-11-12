import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const SIGNAL_COLORS = ['#C78332', '#CA9E48', '#CD6C4A', '#B25C60']

export function RiskBreakdown({ signals, findings }) {
  // If we have signals, display them as signal breakdown
  if (!!signals && signals.length > 0) {
    const data = signals.map((s, i) => ({
      name: s.name,
      value: s.score,
      color: SIGNAL_COLORS[i % SIGNAL_COLORS.length],
    }))

    return (
      <div className="card">
        <h3 className="font-display font-semibold text-text-primary mb-4">Risk Breakdown</h3>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 20, right: 20, bottom: 40, left: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="white/10" vertical={false} />
              <XAxis dataKey="name" stroke="white/10" tickLine={false} fontSize="10" />
              <YAxis stroke="white/10" tickLine={false} fontSize="10" domain={[0, 100]} />
              <Tooltip
                contentStyle={{ backgroundColor: '#201F1B', border: '1px solid #393831' }}
                labelStyle={{ color: '#A9A18F' }}
                itemStyle={{ color: '#E9DFCC' }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="mt-4 space-y-2">
          {data.map((d) => (
            <div key={d.name} className="flex items-center justify-between text-sm px-2 py-1 rounded bg-card-elevated border border-border-color">
              <span className="text-text-secondary">{d.name}</span>
              <span className="font-mono-tech text-xs">{d.value}</span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  // If we have findings but no signals, display findings-based breakdown
  if (!!findings && findings.length > 0) {
    const findingData = findings.map((f, i) => ({
      name: f.title || f.finding_type,
      value: f.score || 0,
      color: SIGNAL_COLORS[i % SIGNAL_COLORS.length],
      evidence: f.evidence_snippet || '',
      source: f.evidence_source || '',
    }))

    return (
      <div className="card">
        <h3 className="font-display font-semibold text-text-primary mb-4">Risk Breakdown</h3>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={findingData} margin={{ top: 20, right: 20, bottom: 40, left: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="white/10" vertical={false} />
              <XAxis dataKey="name" stroke="white/10" tickLine={false} fontSize="10" />
              <YAxis stroke="white/10" tickLine={false} fontSize="10" domain={[0, 100]} />
              <Tooltip
                contentStyle={{ backgroundColor: '#201F1B', border: '1px solid #393831' }}
                labelStyle={{ color: '#A9A18F' }}
                itemStyle={{ color: '#E9DFCC' }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {findingData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="mt-4 space-y-2">
          {findingData.map((d) => (
            <div key={d.name} className="flex items-center justify-between text-sm px-2 py-1 rounded bg-card-elevated border border-border-color">
              <span className="text-text-secondary">{d.name}</span>
              <span className="font-mono-tech text-xs">{d.value}</span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  // Truly no signals or findings
  return (
    <div className="card">
      <h3 className="font-display font-semibold text-text-primary mb-4">Risk Breakdown</h3>
      <p className="text-sm text-text-secondary">No risk signals detected.</p>
    </div>
  )
}

  