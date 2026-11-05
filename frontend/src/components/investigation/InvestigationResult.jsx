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
            <h3 className="font-semibold text-white mb-1">Investigation Result</h3>
            <p className="text-sm text-slate-400">
              Case #{result.investigation_id} &bull; {result.status}
            </p>
          </div>
          <RiskChip score={result.risk_score} />
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <RiskGauge score={result.risk_score} />
        <RiskBreakdown signals={result.signals || []} />
      </div>

      <div className="card">
        <h3 className="font-semibold text-white mb-4">Findings &amp; Evidence</h3>
        {result.findings && result.findings.length > 0 ? (
          <div className="space-y-4">
            {result.findings.map((finding, i) => (
              <div key={i} className="p-4 rounded-lg bg-white/5 border border-white/10">
                <div className="flex justify-between items-start mb-2">
                  <span className="font-medium text-white">{finding.title}</span>
                  <span className="text-xs text-teal-400">{finding.finding_type}</span>
                </div>
                {finding.description && (
                  <p className="text-sm text-slate-300 mb-2">{finding.description}</p>
                )}
                <div className="flex items-start gap-3">
                  <span className="text-xs text-slate-500">Evidence:</span>
                  <p className="text-sm text-slate-300 truncate max-w-[200px]">
                    "{finding.evidence_snippet}"
                  </p>
                </div>
                <p className="text-xs text-slate-500 mt-2">
                  Source: {finding.evidence_source}&nbsp;|&nbsp;Score: {finding.score}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-400">No findings recorded.</p>
        )}
      </div>

      {result.analysis_summary && (
        <div className="card">
          <h3 className="font-semibold text-white mb-2">Analysis Summary</h3>
          <p className="text-sm text-slate-300">{result.analysis_summary}</p>
        </div>
      )}
    </div>
  )
}