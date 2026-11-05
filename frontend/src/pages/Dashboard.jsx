import { useEffect, useState } from 'react'
import { Shield, AlertCircle, TrendingUp, LayoutList } from 'lucide-react'
import api from '../api/index'
import { API } from '../api/endpoints'
import { RiskChip } from '../components/common/RiskChip'

export default function Dashboard() {
  const [investigations, setInvestigations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    api
      .get(API.investigations)
      .then((res) => setInvestigations(res.data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const total = investigations.length
  const critical = investigations.filter((i) => i.risk_band === 'critical').length
  const avgScore =
    total > 0
      ? Math.round(
          investigations.reduce((sum, i) => sum + i.risk_score, 0) / total
        )
      : 0

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-slate-400">Loading dashboard...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="card p-8 text-center">
        <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-3" />
        <h3 className="font-semibold text-white mb-2">Unable to load dashboard</h3>
        <p className="text-sm text-slate-400">{error}</p>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-slate-400">Overview of your investigations and risk posture.</p>
      </div>

      <div className="grid md:grid-cols-3 gap-6">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Total Investigations</p>
              <p className="text-3xl font-bold text-white">{total}</p>
            </div>
            <Shield className="w-8 h-8 text-teal-400" />
          </div>
        </div>
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Critical Risk Cases</p>
              <p className="text-3xl font-bold text-red-400">{critical}</p>
            </div>
            <AlertCircle className="w-8 h-8 text-red-400" />
          </div>
        </div>
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Avg Risk Score</p>
              <p className="text-3xl font-bold text-teal-400">{avgScore}</p>
            </div>
            <TrendingUp className="w-8 h-8 text-teal-400" />
          </div>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold text-white">Recent Investigations</h3>
          <a
            href="/investigations/history"
            className="text-sm text-teal-400 hover:text-teal-300"
          >
            View all
          </a>
        </div>
        {investigations.length === 0 ? (
          <p className="text-sm text-slate-400 text-center py-4">
            No investigations yet. Start one from the New Investigation page.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/10 text-xs text-slate-400 uppercase">
                  <th className="pb-3">ID</th>
                  <th className="pb-3">Type</th>
                  <th className="pb-3">Risk Score</th>
                  <th className="pb-3">Band</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3">Created</th>
                </tr>
              </thead>
              <tbody>
                {investigations.slice(0, 5).map((inv) => (
                  <tr key={inv.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                    <td className="py-3 text-sm text-slate-300 font-mono">#{inv.id}</td>
                    <td className="py-3 text-sm text-slate-300">{inv.input_type}</td>
                    <td className="py-3 text-sm text-slate-300 font-mono">
                      {inv.risk_score}
                    </td>
                    <td className="py-3">
                      <RiskChip score={inv.risk_score} className="text-xs" />
                    </td>
                    <td className="py-3 text-sm text-slate-300">
                      {inv.status}
                    </td>
                    <td className="py-3 text-sm text-slate-400 font-mono">
                      {new Date(inv.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}