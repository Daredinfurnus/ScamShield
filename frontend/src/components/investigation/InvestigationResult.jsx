import { RiskChip } from '../common/RiskChip'
import { RiskGauge } from '../risk/RiskGauge'
import { RiskBreakdown } from '../risk/RiskBreakdown'

export function InvestigationResult({ result }) {
  if (!result) return null

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <h3 className="font-display font-semibold text-text-primary mb-1">Investigation Result</h3>
            <p className="text-sm text-text-secondary font-mono-tech">
              Case #{result.id ?? result.investigation_id} &bull; {result.status}
            </p>
          </div>
          <RiskChip score={result.risk_score} />
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <RiskGauge score={result.risk_score} />
        <RiskBreakdown signals={result.signals || []} findings={result.findings || []} />
      </div>

      <div className="card">
        <h3 className="font-display font-semibold text-text-primary mb-4">Findings &amp; Evidence</h3>
        {result.findings && result.findings.length > 0 ? (
          <div className="space-y-4">
            {result.findings.map((finding, i) => (
              <div key={i} className="p-4 card-elevated border border-border-color">
                <div className="flex justify-between items-start mb-2">
                  <span className="font-mono-tech font-medium text-text-primary">{finding.title}</span>
                  <span className="text-xs text-text-secondary">{finding.finding_type}</span>
                </div>
                {finding.description && (
                  <p className="text-sm text-text-secondary mb-2">{finding.description}</p>
                )}
                <div className="flex items-start gap-3">
                  <span className="text-xs text-text-secondary">Evidence:</span>
                  <p className="text-sm text-text-secondary truncate max-w-[200px]">
                    "{finding.evidence_snippet}"
                  </p>
                </div>
                <p className="text-xs text-text-secondary mt-2">
                  Source: {finding.evidence_source}&nbsp;|&nbsp;Score: {finding.score}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-text-secondary">No findings recorded.</p>
        )}
      </div>

      {result.analysis_summary && (
        <div className="card">
          <h3 className="font-display font-semibold text-text-primary mb-2">Analysis Summary</h3>
          <p className="text-sm text-text-secondary">{result.analysis_summary}</p>
        </div>
      )}
    </div>
  )
}