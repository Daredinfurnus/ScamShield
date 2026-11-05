import { useParams } from 'react-router-dom'
import { useEffect, useState } from 'react'
import api from '../api/index'
import { InvestigationResult } from '../components/investigation/InvestigationResult'

export default function InvestigationReport() {
  const { id } = useParams()
  const [investigation, setInvestigation] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    api
      .get(`/api/investigations/${id}`)
      .then((res) => setInvestigation(res.data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-slate-400">Loading report...</p>
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

  if (!investigation) {
    return (
      <div className="card p-8 text-center">
        <p className="text-sm text-slate-400">Investigation not found.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Investigation Report</h1>
        <p className="text-slate-400">Case #{investigation.id}</p>
      </div>
      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <p className="text-sm text-slate-400 capitalize">{investigation.input_type}</p>
            <p className="text-sm text-slate-400 font-mono">{investigation.input_content}</p>
          </div>
          <div className="text-right">
            <p className="text-xs text-slate-400 uppercase">Created</p>
            <p className="text-sm font-mono text-white">
              {new Date(investigation.created_at).toLocaleString()}
            </p>
          </div>
        </div>
      </div>
      <InvestigationResult result={{ ...investigation, risk_score: investigation.risk_score || 0, risk_band: investigation.risk_band || 'low', status: investigation.status || 'pending' }} />
    </div>
  )
}