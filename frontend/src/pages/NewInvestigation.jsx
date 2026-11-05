import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/index'
import { API } from '../api/endpoints'
import { InvestigationResult } from '../components/investigation/InvestigationResult'

export default function NewInvestigation() {
  const navigate = useNavigate()
  const [inputType, setInputType] = useState('text')
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      let endpoint
      let body
      if (inputType === 'text') {
        endpoint = API.analyzeText
        body = { text: content }
      } else if (inputType === 'url') {
        endpoint = API.analyzeUrl
        body = { url: content }
      } else {
        setError('Image analysis requires a file upload (Phase 6).')
        setLoading(false)
        return
      }
      const res = await api.post(endpoint, body)
      setResult(res.data)
      if (res.data.investigation_id) {
        navigate(`/investigations/${res.data.investigation_id}/report`)
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Analysis failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">New Investigation</h1>
        <p className="text-slate-400">Submit a message, URL, or screenshot to investigate.</p>
      </div>
      <form onSubmit={handleSubmit} className="card space-y-4">
        <div className="grid md:grid-cols-2 gap-4">
          <label className="text-sm font-medium text-slate-300">Input type</label>
          <select
            value={inputType}
            onChange={(e) => setInputType(e.target.value)}
            className="w-full rounded-lg border border-white/10 bg-white/5 px-4 py-2.5 text-slate-200 focus:outline-none focus:border-teal-500"
          >
            <option value="text">Message Text</option>
            <option value="url">URL</option>
            <option value="image">Screenshot (Image)</option>
          </select>
        </div>
        <label className="text-sm font-medium text-slate-300 block mb-1">Content</label>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Paste a suspicious message or URL here..."
          rows={5}
          className="w-full rounded-lg border border-white/10 bg-white/5 px-4 py-2.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-teal-500"
        ></textarea>
        <button
          type="submit"
          disabled={loading || !content.trim()}
          className="w-full py-3 bg-teal-500 text-white rounded-xl font-semibold hover:bg-teal-400 disabled:opacity-50 transition-colors"
        >
          {loading ? 'Analyzing...' : 'Start Investigation'}
        </button>
      </form>
      {error && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          {error}
        </div>
      )}
      {result && (
        <div>
          <h2 className="text-xl font-bold text-white mb-4">Results</h2>
          <InvestigationResult result={result} />
          <div className="card mt-4 p-6">
            <h3 className="font-semibold text-white mb-3">Raw API Response</h3>
            <pre className="text-xs text-slate-400 bg-white/5 p-3 rounded overflow-x-auto font-mono">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}