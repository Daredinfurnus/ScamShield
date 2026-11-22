import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  ShieldAlert,
  AlertTriangle,
  FileText,
  TrendingUp,
  ArrowUpRight,
  Clock,
  FolderOpen,
  Filter,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Plus
} from 'lucide-react'
import api from '../api/index'
import { API } from '../api/endpoints'
import { Card } from '../components/common/Card'
import { Badge } from '../components/common/Badge'
import { RiskChip } from '../components/common/RiskChip'
import { Loader } from '../components/common/Loader'
import { useAuthStore } from '../store/authStore'

export default function Dashboard() {
  const [investigations, setInvestigations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const { user, accessToken, authModalOpen, openAuthModal, closeAuthModal } = useAuthStore()
  const navigate = useNavigate()

  useEffect(() => {
    // Require authentication before fetching investigations
    if (!user || !accessToken) {
      setLoading(false)
      return
    }

    api
      .get(API.investigations)
      .then((res) => {
        setInvestigations(Array.isArray(res.data) ? res.data : [])
      })
      .catch((err) => {
        if (err.response?.status === 401) {
          // Unauthorized - show error instead of redirecting
          setError('Authentication required')
          return
        }
        setError(err.response?.data?.detail || err.message)
      })
      .finally(() => setLoading(false))
  }, [user, accessToken])

  // Show authentication required message when not logged in
  if (!loading && (!user || !accessToken)) {
    return (
      <div className="max-w-2xl mx-auto py-12 text-center space-y-6">
        <Card className="p-8 border-ochre-border bg-ochre-dim">
          <ShieldAlert className="w-8 h-8 text-ochre mx-auto mb-2" />
          <h3 className="font-semibold text-parchment">Authentication Required</h3>
          <p className="text-xs text-parchment-muted mt-1 font-mono">
            Please sign in to access the Intelligence Desk.
          </p>
          <button
            onClick={openAuthModal}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-ochre text-canvas font-semibold text-xs font-mono mt-4"
          >
            <span>ACCESS</span>
            <ChevronRight size={14} />
          </button>
        </Card>
      </div>
    )
  }

  if (loading) {
    return <Loader text="Loading Intelligence Telemetry..." className="h-64" />
  }

  // Real aggregate statistics
  const total = investigations.length
  const critical = investigations.filter((i) => (i.risk_band || '').toLowerCase() === 'critical').length
  const high = investigations.filter((i) => (i.risk_band || '').toLowerCase() === 'high').length
  const medium = investigations.filter((i) => (i.risk_band || '').toLowerCase() === 'medium').length
  const low = investigations.filter((i) => (i.risk_band || '').toLowerCase() === 'low').length
  const avgScore = total > 0 ? (investigations.reduce((sum, i) => sum + (i.risk_score || 0), 0) / total).toFixed(1) : 0

  const recentCases = [...investigations].slice(0, 7)

  return (
    <div className="space-y-8 fade-in max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-border pb-6">
        <div>
          <div className="flex items-center gap-2 mb-2 font-mono text-xs text-ochre uppercase tracking-wider">
            <ShieldAlert size={14} />
            <span>Case Telemetry & Operations</span>
          </div>
          <h1 className="editorial-heading text-3xl sm:text-4xl text-parchment">
            Intelligence Desk
          </h1>
          <p className="mt-1 text-sm text-parchment-muted">
            Live overview of examined threat cases, risk distributions, and forensic findings.
          </p>
        </div>
        <Link
          to="/investigations/new"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-ochre hover:bg-ochre-light text-canvas font-semibold text-xs font-mono transition-colors self-start sm:self-auto"
        >
          <Plus size={14} />
          <span>NEW INTAKE</span>
        </Link>
      </div>

      {error ? (
        <Card className="p-8 text-center border-risk-critical-border bg-risk-critical-dim">
          <AlertTriangle className="w-8 h-8 text-risk-critical mx-auto mb-2" />
          <h3 className="font-semibold text-parchment">Telemetry Uplink Failed</h3>
          <p className="text-xs text-parchment-muted mt-1 font-mono">{error}</p>
        </Card>
      ) : total === 0 ? (
        <Card className="p-12 text-center space-y-4">
          <FolderOpen className="w-10 h-10 text-parchment-dim mx-auto" />
          <div className="max-w-md mx-auto">
            <h3 className="editorial-heading text-xl text-parchment">No Case Files Recorded</h3>
            <p className="text-sm text-parchment-muted mt-1">
              Your platform instance has not yet ingested any investigations.
              Submit a suspicious message or phishing URL to populate live telemetry.
            </p>
          </div>
          <Link
            to="/investigations/new"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-ochre text-canvas font-semibold text-xs font-mono"
          >
            <span>Open First Case</span>
            <ChevronRight size={14} />
          </Link>
        </Card>
      ) : (
        <>
          {/* Key Metrics */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <Card className="p-5 space-y-2">
              <div className="text-[11px] font-mono text-parchment-dim uppercase tracking-wider">
                Total Examined
              </div>
              <div className="text-3xl font-bold font-mono text-parchment">{total}</div>
              <div className="text-[11px] text-parchment-dim">Recorded case files</div>
            </Card>

            <Card className="p-5 space-y-2 border-l-2 border-l-risk-critical">
              <div className="text-[11px] font-mono text-risk-critical uppercase tracking-wider">
                Critical Threats
              </div>
              <div className="text-3xl font-bold font-mono text-risk-critical">{critical}</div>
              <div className="text-[11px] text-parchment-dim">Score &ge; 75.0 / 100</div>
            </Card>

            <Card className="p-5 space-y-2 border-l-2 border-l-risk-high">
              <div className="text-[11px] font-mono text-risk-high uppercase tracking-wider">
                High Risk Cases
              </div>
              <div className="text-3xl font-bold font-mono text-risk-high">{high}</div>
              <div className="text-[11px] text-parchment-dim">Score 50.0 – 74.9</div>
            </Card>

            <Card className="p-5 space-y-2">
              <div className="text-[11px] font-mono text-ochre uppercase tracking-wider">
                Average Risk Score
              </div>
              <div className="text-3xl font-bold font-mono text-ochre">{avgScore}</div>
              <div className="text-[11px] text-parchment-dim">Across all investigations</div>
            </Card>
          </div>

          {/* Risk Band Distribution Bar */}
          <Card className="p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-semibold text-sm text-parchment">
                  Risk Classification Spectrum
                </h3>
                <p className="text-xs text-parchment-dim">
                  Proportional breakdown of examined evidence records.
                </p>
              </div>
              <span className="font-mono text-xs text-parchment-dim">{total} total</span>
            </div>

            {/* Distribution Visual Bar */}
            <div className="w-full h-3 rounded-full overflow-hidden bg-canvas-subtle flex">
              {critical > 0 && (
                <div
                  style={{ width: `${(critical / total) * 100}%` }}
                  className="bg-risk-critical h-full"
                  title={`Critical: ${critical}`}
                />
              )}
              {high > 0 && (
                <div
                  style={{ width: `${(high / total) * 100}%` }}
                  className="bg-risk-high h-full"
                  title={`High: ${high}`}
                />
              )}
              {medium > 0 && (
                <div
                  style={{ width: `${(medium / total) * 100}%` }}
                  className="bg-risk-medium h-full"
                  title={`Medium: ${medium}`}
                />
              )}
              {low > 0 && (
                <div
                  style={{ width: `${(low / total) * 100}%` }}
                  className="bg-risk-low h-full"
                  title={`Low: ${low}`}
                />
              )}
            </div>

            {/* Legend */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 font-mono text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-sm bg-risk-critical shrink-0" />
                <span className="text-parchment-dim">Critical:</span>
                <span className="text-parchment font-semibold">{critical}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-sm bg-risk-high shrink-0" />
                <span className="text-parchment-dim">High:</span>
                <span className="text-parchment font-semibold">{high}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-sm bg-risk-medium shrink-0" />
                <span className="text-parchment-dim">Medium:</span>
                <span className="text-parchment font-semibold">{medium}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-sm bg-risk-low shrink-0" />
                <span className="text-parchment-dim">Low / Benign:</span>
                <span className="text-parchment font-semibold">{low}</span>
              </div>
            </div>
          </Card>

          {/* Recent Investigations Table */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="editorial-heading text-xl text-parchment">
                  Recent Case Dossiers
                </h3>
                <p className="text-xs text-parchment-dim">
                  Most recent investigation records submitted to the platform.
                </p>
              </div>
              <Link
                to="/investigations/history"
                className="text-xs font-mono text-ochre hover:text-ochre-light flex items-center gap-1"
              >
                <span>Full Archive</span>
                <ChevronRight size={14} />
              </Link>
            </div>

            <Card className="overflow-hidden p-0 border border-border">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-border bg-canvas-subtle/60 text-parchment-dim font-mono uppercase tracking-wider">
                      <th className="py-3 px-4">Case ID</th>
                      <th className="py-3 px-4">Input Vector</th>
                      <th className="py-3 px-4">Threat Summary</th>
                      <th className="py-3 px-4">Deterministic Risk</th>
                      <th className="py-3 px-4">Timestamp</th>
                      <th className="py-3 px-4 text-right">Dossier</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle">
                    {recentCases.map((c) => (
                      <tr key={c.id} className="hover:bg-canvas-cardHover transition-colors">
                        <td className="py-3 px-4 font-mono text-parchment font-medium">
                          #{c.id}
                        </td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded bg-canvas-subtle border border-border-subtle font-mono text-[10px] uppercase text-parchment-muted">
                            {c.input_type}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-sans text-parchment max-w-xs truncate">
                          {c.title || c.input_content || 'Untitled Examination'}
                        </td>
                        <td className="py-3 px-4">
                          <RiskChip score={c.risk_score || 0} band={c.risk_band} />
                        </td>
                        <td className="py-3 px-4 font-mono text-parchment-dim">
                          {c.created_at ? new Date(c.created_at).toLocaleString('en-US', {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          }) : '—'}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <Link
                            to={`/investigations/${c.id}/report`}
                            className="text-ochre hover:text-ochre-light font-mono font-medium inline-flex items-center gap-1"
                          >
                            <span>Inspect</span>
                            <ChevronRight size={12} />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}