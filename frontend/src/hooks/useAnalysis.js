import { useState } from 'react'
import api from '../api/index'
import { API } from '../api/endpoints'

export function useAnalysis() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const analyze = async (endpoint, body) => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.post(endpoint, body)
      setResult(res.data)
      return res.data
    } catch (err) {
      setError(err.response?.data?.detail || 'Analysis failed')
      throw err
    } finally {
      setLoading(false)
    }
  }

  return { analyze, result, loading, error }
}