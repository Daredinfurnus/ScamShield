import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const SIGNAL_COLORS = ['#22d3ee', '#14b8a6', '#2dd4bf', '#06b6d4']

export function RiskBreakdown({ signals }) {
  if (!signals || signals.length === 0) {
    return (
      <div className="card">
        <h3 className="font-semibold text-white mb-4">Risk Breakdown</h3>
        <p className="text-sm text-slate-400">No risk signals detected.</p>
      </div>
    )
  }

  const data = signals.map((s, i) => ({
    name: s.name,
    value: s.score,
    color: SIGNAL_COLORS[i % SIGNAL_COLORS.length],
  }))

  return (
    <div className="card">
      <h3 className="font-semibold text-white mb-4">Risk Breakdown</h3>
      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 20, right: 20, bottom: 40, left: 10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="white/10" vertical={false} />
            <XAxis dataKey="name" stroke="white/30" tickLine={false} fontSize="10" />
            <YAxis stroke="white/30" tickLine={false} fontSize="10" domain={[0, 100]} />
            <Tooltip
              contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155' }}
              labelStyle={{ color: '#94a3b8' }}
              itemStyle={{ color: '#e2e8f0' }}
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
          <div key={d.name} className="flex items-center justify-between text-sm px-2 py-1 rounded bg-white/5">
            <span className="text-slate-300">{d.name}</span>
            <span className="text-teal-400 font-mono">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}