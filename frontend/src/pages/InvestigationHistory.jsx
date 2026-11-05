import { useEffect, useState } from 'react'
import api from '../api/index'
import { API } from '../api/endpoints'
import { RiskChip } from '../components/common/RiskChip'

export default function InvestigationHistory() {
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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-slate-400">Loading history...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="card p-8 text-center">
        <p className="text-sm text-slate-400">{error}</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Investigation History</h1>
        <p className="text-slate-400">Previously submitted investigations and their outcomes.</p>
      </div>
      <div className="card">
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
                <th className="pb-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {investigations.length === 0 ? (
                <tr>
                  <td className="py-4 text-slate-300 text-center" colSpan="7">
                    No investigations found.
                  </td>
                </tr>
              ) : (
                investigations.map((inv) => (
                  <tr key={inv.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                    <td className="py-3 text-sm text-slate-300 font-mono">#{inv.id}</td>
                    <td className="py-3 text-sm text-slate-300 capitalize">{inv.input_type}</td>
                    <td className="py-3 text-sm text-slate-300 font-mono">{inv.risk_score}</td>
                    <td className="py-3">
                      <RiskChip score={inv.risk_score} className="text-xs" />
                    </td>
                    <td className="py-3 text-sm text-slate-300 capitalize">{inv.status}</td>
                    <td className="py-3 text-sm text-slate-400 font-mono">
                      {new Date(inv.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 text-right">
                      <a
                        href={`/investigations/${inv.id}/report`}
                        className="text-sm text-teal-400 hover:text-teal-300 underline"
                      >
                        View Report
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}