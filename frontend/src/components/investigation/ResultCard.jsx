export function ResultCard({ result }) {
  return (
    <div className="card">
      <h3 className="font-semibold text-white mb-4">Analysis Result</h3>
      <p className="text-sm text-slate-400">{result ? JSON.stringify(result) : 'No result yet.'}</p>
    </div>
  )
}