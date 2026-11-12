import { useParams } from 'react-router-dom'
import { useEffect, useState } from 'react'
import api from '../api/index'
import { Button } from '../components/common/Button'
import { InvestigationResult } from '../components/investigation/InvestigationResult'
import { AIInvestigationAssistant } from '../components/ai/AIInvestigationAssistant'
import { Loader } from '../components/common/Loader'
import { RiskChip } from '../components/common/RiskChip'
import { RiskGauge } from '../components/risk/RiskGauge'

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
      <div className="flex items-center justify-center h-[600px]">
        <Loader />
      </div>
    )
  }

  if (error) {
    return (
      <div className="card p-12 text-center max-w-md mx-auto">
        <h2 className="font-display font-semibold text-text-primary mb-2">Unable to Load Report</h2>
        <p className="text-sm text-text-secondary mb-4">{error}</p>
        <Button variant="primary" className="px-6 py-2">
          Try Again
        </Button>
      </div>
    )
  }

  if (!investigation) {
    return (
      <div className="card p-12 text-center max-w-md mx-auto">
        <h2 className="font-display font-semibold text-text-primary mb-2">Case Not Found</h2>
        <p className="text-sm text-text-secondary mb-4">
          Investigation #{id} does not exist.
        </p>
      </div>
    )
  }

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-10">
      <header className="card border border-brand/30">
        <div className="p-8">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-6">
            <div>
              <span className="inline-block px-3 py-1 rounded-lg bg-brand/10 border border-brand/20 text-brand font-mono-tech text-xs font-bold uppercase tracking-wider mb-3">
                CASE #{investigation.id}
              </span>
              <h1 className="font-display font-bold text-text-primary text-3xl tracking-tight mb-1">
                {investigation.title || 'Untitled Investigation'}
              </h1>
              <p className="text-sm text-text-secondary">
                {investigation.input_type} investigation &bull; Status: {investigation.status}
              </p>
            </div>
            <div className="text-right md:text-left">
              <p className="text-xs text-text-secondary uppercase tracking-wider mb-1">Opened</p>
              <p className="font-mono-tech text-sm text-text-primary">
                {new Date(investigation.created_at).toLocaleDateString('en-US', {
                  weekday: 'long',
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric',
                })}
              </p>
              <p className="font-mono-tech text-xs text-text-secondary">
                {new Date(investigation.created_at).toLocaleTimeString('en-US', {
                  hour: '2-digit',
                  minute: '2-digit',
                })}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap gap-3 border-t border-border-color pt-6">
            <span className="Badge Badge--default text-xs px-3 py-1">
              Input: {investigation.input_type}
            </span>
            <span className={`Badge Badge--${investigation.risk_band || 'low'} text-xs px-3 py-1`}>
              Band: {(investigation.risk_band || 'low').toUpperCase()}
            </span>
            <span className="Badge Badge--default text-xs px-3 py-1">
              Score: {investigation.risk_score || 0}/100
            </span>
          </div>
        </div>
        </header>
      {/* THREAT ASSESSMENT */}
      <section className="grid md:grid-cols-2 gap-8">
        <div className="card p-8">
          <h2 className="font-display font-semibold text-text-primary mb-6">Threat Assessment</h2>
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-xs text-text-secondary uppercase tracking-wider mb-1">
                Risk Score
              </p>
              <span className="text-4xl font-bold font-mono-tech text-text-primary">
                {investigation.risk_score || 0}
              </span>
              <span className="text-xl text-text-secondary font-mono-tech">/ 100</span>
            </div>
            <RiskChip score={investigation.risk_score || 0} />
          </div>
          <RiskGauge score={investigation.risk_score || 0} />
        </div>

        <div className="card p-8">
          <h2 className="font-display font-semibold text-text-primary mb-6">Classification</h2>
          <div className="space-y-3">
            <div className="p-4 rounded-lg bg-card-elevated border border-border-color">
              <h3 className="font-display font-bold text-brand mb-1">
                {investigation.risk_band ? investigation.risk_band.toUpperCase() : 'LOW'}
              </h3>
              <p className="text-sm text-text-secondary">
                Classification determined by the backend detection engine. This score reflects
                aggregated detection signals and is not altered by AI interpretation.
              </p>
            </div>
            <div className="p-4 rounded-lg bg-card-elevated border border-border-color">
              <h3 className="font-display font-bold text-text-primary mb-1">Confidence Notes</h3>
              <p className="text-sm text-text-secondary">
                Risk bands: Critical (75-100), High (50-74), Medium (25-49), Low (0-24).
                Individual detection signals and findings contribute to this assessment.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ORIGINAL SUBMISSION */}
      <section className="card p-8">
        <h2 className="font-display font-semibold text-text-primary mb-6">Original Submission</h2>
        <div className="bg-card-elevated border border-border-color rounded-lg p-6 font-mono-tech text-sm text-text-secondary whitespace-pre-wrap break-words">
          {investigation.input_content || ''}
        </div>
        <p className="text-xs text-text-secondary mt-4">
          Submitted content is preserved as evidence. URLs within the text are preserved exactly
          as provided and have not been modified or validated by this platform.
        </p>
      </section>

      {/* FINDINGS AND EVIDENCE */}
      <section>
        <h2 className="font-display font-semibold text-text-primary mb-6">Findings &amp; Evidence</h2>
        <InvestigationResult result={investigation} />
      </section>

      {/* AI INVESTIGATION ASSISTANT */}
      <AIInvestigationAssistant investigationId={id} />

      {/* RECOMMENDED ACTIONS */}
      <section className="card p-8 border border-brand/20">
        <h2 className="font-display font-semibold text-text-primary mb-6">Recommended Actions</h2>
        <div className="space-y-4">
          <div className="flex items-start gap-3 p-4 rounded-lg bg-bg-elevated border border-brand/20">
            <span className="mt-0.5 text-brand">•</span>
            <div>
              <p className="text-sm text-text-primary font-medium">Do not interact with suspicious URLs</p>
              <p className="text-sm text-text-secondary">
                Do not click links or enter credentials on unverified sites referenced in this
                submission.
              </p>
            </div>
          </div>
          {investigation.risk_score && investigation.risk_score >= 50 && (
            <div className="flex items-start gap-3 p-4 rounded-lg bg-bg-elevated border border-brand/20">
              <span className="mt-0.5 text-brand">•</span>
              <div>
                <p className="text-sm text-text-primary font-medium">Report to your security team</p>
                <p className="text-sm text-text-secondary">
                  Escalate this investigation to your organization's security or fraud team for
                  further review.
                </p>
              </div>
            </div>
          )}
          <div className="flex items-start gap-3 p-4 rounded-lg bg-card-elevated border border-border-color">
            <span className="mt-0.5 text-text-secondary">•</span>
            <div>
              <p className="text-sm text-text-primary font-medium">Preserve evidence</p>
              <p className="text-sm text-text-secondary">
                Retain screenshots, message logs, and transaction references related to this case.
              </p>
            </div>
          </div>
        </div>
        <p className="text-xs text-text-secondary mt-6">
          Recommendations are based on detected findings and existing risk classification. They do
          not constitute legal advice or a determination of criminal activity.
        </p>
      </section>
    </div>
  )
}


