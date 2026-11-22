import { useEffect, useState } from 'react'
import { Sparkles, Bot, AlertCircle, FileText, CheckCircle2, RefreshCw } from 'lucide-react'
import api from '../../api/index'
import { API } from '../../api/endpoints'
import { Card } from '../common/Card'
import { Badge } from '../common/Badge'
import { Button } from '../common/Button'
import { Loader } from '../common/Loader'

export function AIInvestigationAssistant({ investigationId }) {
  const [status, setStatus] = useState(null)
  const [explanation, setExplanation] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [reportLoading, setReportLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    // 1. Fetch AI provider status
    api
      .get(API.aiStatus)
      .then((res) => setStatus(res.data))
      .catch(() => setStatus({ provider: 'none', available: false, fallback_available: true }))

    // 2. Fetch AI / Deterministic Explanation
    api
      .get(API.aiExplain(investigationId))
      .then((res) => {
        // Handle both wrapped and unwrapped response formats
        const data = res.data.data || res.data
        setExplanation({
          summary: data.summary || data.explanation || '',
          observations: data.supporting_evidence || data.observations || [],
          recommendations: data.recommended_actions || data.recommendations || [],
          limitations: data.limitations || [],
          provider: res.data.provider || 'deterministic',
          fallback_used: res.data.fallback_used || false,
          risk_score: res.data.risk_score,
          risk_band: res.data.risk_band,
        })
      })
      .catch((err) => {
        // If 404 or missing, keep explanation null
      })
      .finally(() => setLoading(false))
  }, [investigationId])

  const handleGenerateReport = async () => {
    setReportLoading(true)
    setError(null)
    try {
      const res = await api.get(API.aiReport(investigationId))
      setReport(res.data)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Report generation failed.')
    } finally {
      setReportLoading(false)
    }
  }

  if (loading) {
    return <Loader text="Synthesizing Investigative Explanation..." className="p-4" />
  }

  const isLLM = status?.provider === 'openai' && status?.available

  return (
    <Card className="p-6 space-y-6 border border-border bg-canvas-card">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded bg-ochre-dim border border-ochre/30 text-ochre">
            <Bot size={18} />
          </div>
          <div>
            <h3 className="font-semibold text-sm text-parchment">
              Investigative Intelligence Narrative
            </h3>
            <p className="text-[11px] font-mono text-parchment-dim">
              Provider: {status?.provider ? status.provider.toUpperCase() : 'DETERMINISTIC FALLBACK'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isLLM ? (
            <Badge variant="ochre">LLM Synthesized</Badge>
          ) : (
            <Badge variant="neutral">Deterministic Baseline</Badge>
          )}
        </div>
      </div>

      {/* Explanation Content */}
      {explanation ? (
        <div className="space-y-4">
          <div className="p-4 rounded-md bg-canvas-subtle border border-border space-y-2">
            <div className="font-mono text-xs text-ochre uppercase tracking-wider font-semibold">
              Forensic Synthesis
            </div>
            <p className="text-xs text-parchment leading-relaxed whitespace-pre-wrap font-sans">
              {explanation.summary || 'No narrative synthesis generated.'}
            </p>
          </div>

          {explanation.recommendations && explanation.recommendations.length > 0 && (
            <div className="space-y-2">
              <span className="font-mono text-[10px] uppercase text-parchment-dim tracking-wider">
                Investigative Guidance
              </span>
              <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                {explanation.recommendations.map((act, i) => (
                  <li key={i} className="p-2.5 rounded bg-canvas-subtle border border-border text-parchment-muted flex items-start gap-2">
                    <CheckCircle2 size={14} className="text-olive-light shrink-0 mt-0.5" />
                    <span>{act}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : (
        <p className="text-xs text-parchment-dim">
          No automated explanation could be synthesized for this case record.
        </p>
      )}

      {/* Structured Comprehensive Report */}
      {report ? (
        <div className="pt-4 border-t border-border space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="font-mono text-xs text-ochre uppercase font-semibold">
              Formal Investigative Report
            </h4>
            <Badge variant="safe">Generated</Badge>
          </div>
          <div className="p-4 rounded-md bg-canvas-subtle border border-border font-mono text-xs text-parchment leading-relaxed whitespace-pre-wrap max-h-96 overflow-y-auto">
            {typeof report === 'string' ? report : report.report_markdown || JSON.stringify(report, null, 2)}
          </div>
        </div>
      ) : (
        <div className="pt-2 border-t border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <span className="text-xs text-parchment-dim">
            Compile formal investigative findings dossier for export or archive.
          </span>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={reportLoading}
            onClick={handleGenerateReport}
          >
            {reportLoading ? (
              <Loader text="Generating..." className="p-0 text-ochre" />
            ) : (
              <>
                <FileText size={14} />
                <span>Generate Dossier Report</span>
              </>
            )}
          </Button>
        </div>
      )}

      {error && (
        <p className="text-xs text-risk-critical font-mono">{error}</p>
      )}
    </Card>
  )
}
