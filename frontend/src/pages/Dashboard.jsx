import { useEffect, useState } from 'react'
import { Shield, AlertCircle, TrendingUp, LayoutList, Activity, ArrowUpRight, Lock } from 'lucide-react'
import { Link } from 'react-router-dom'
import api from '../api/index'
import { API } from '../api/endpoints'
import { RiskChip } from '../components/common/RiskChip'
import { AuthModal } from '../components/auth/AuthModal'
import { useAuthStore } from '../store/authStore'

export default function Dashboard() {
  const [investigations, setInvestigations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [authOpen, setAuthOpen] = useState(false)
  const { accessToken } = useAuthStore()

  useEffect(() => {
    api.get(API.investigations)
      .then((res) => setInvestigations(res.data))
      .catch((err) => {
        const status = err?.response?.status
        setError(status === 401 ? 'AUTH_REQUIRED' : (err.message || 'UPLINK FAILED'))
      })
      .finally(() => setLoading(false))
  }, [])

  const total = investigations.length
  const critical = investigations.filter((i) => i.risk_band === 'critical').length
  const avgScore = total > 0 ? Math.round(investigations.reduce((sum, i) => sum + i.risk_score, 0) / total) : 0

  if (loading) return <div className="cyber-panel scanline flex items-center justify-center h-64"><p className="font-mono-tech text-xs tracking-widest text-cyan-300 animate-pulse">INITIALIZING COMMAND CENTER...</p></div>
  if (error) return (
    <div className="card p-8 text-center">
      {error === 'AUTH_REQUIRED' ? (
        <>
          <Lock className="w-8 h-8 text-[#b7ff38] mx-auto mb-3" />
          <h3 className="font-semibold text-white mb-2">SECURE CONSOLE</h3>
          <p className="text-sm text-slate-400">Authenticated access required to view case telemetry.</p>
          <button onClick={() => setAuthOpen(true)} className="cyber-button mt-5">ACCESS CONSOLE</button>
        </>
      ) : (
        <>
          <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-3" />
          <h3 className="font-semibold text-white mb-2">UPLINK UNAVAILABLE</h3>
          <p className="text-sm text-slate-400">{error}</p>
          <p className="mt-3 font-mono-tech text-[10px] text-slate-600">CHECK API SERVICE / NETWORK / CORS</p>
        </>
      )}
    </div>
  )

  const metrics = [
    {label:'TOTAL INVESTIGATIONS',value:total,icon:Shield,color:'text-cyan-300',foot:'RECORDED CASE FILES'},
    {label:'CRITICAL RISK CASES',value:critical,icon:AlertCircle,color:'text-[#ff416c]',foot:'REQUIRES PRIORITY REVIEW'},
    {label:'AVERAGE RISK SCORE',value:avgScore,icon:TrendingUp,color:'text-[#b7ff38]',foot:'ACROSS ALL CASES'},
  ]
  return (
    <div className="space-y-7">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div><div className="cyber-kicker flex items-center gap-2"><Activity size={13}/> Operations / Overview</div><h1 className="mt-2 text-5xl sm:text-6xl">COMMAND CENTER</h1><p className="mt-2 text-xs text-slate-500">Investigation telemetry and case activity overview.</p></div>
        <Link to="/investigations/new" className="cyber-button"><span>+</span> NEW INVESTIGATION <ArrowUpRight size={14}/></Link>
      </div>
      <div className="grid sm:grid-cols-2 xl:grid-cols-3 gap-4">
        {metrics.map(({label,value,icon:Icon,color,foot},i) => (
          <div key={label} className="card">
            <div className="flex justify-between items-start"><span className="font-mono-tech text-[9px] tracking-[.14em] text-slate-500">{`METRIC / 0${i+1}`}</span><Icon size={18} className={color}/></div>
            <div className="mt-5 font-display text-5xl tracking-wide text-slate-100">{value}</div>
            <div className={`mt-1 font-mono-tech text-[10px] tracking-wider ${color}`}>{label}</div>
            <div className="mt-5 pt-3 border-t border-white/[.07] font-mono-tech text-[8px] tracking-widest text-slate-600">{foot}</div>
          </div>
        ))}
      </div>
      <div className="card">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
          <div><div className="cyber-kicker">Case Management / Feed</div><h2 className="text-3xl mt-1">RECENT INVESTIGATIONS</h2></div>
          <Link to="/investigations/history" className="font-mono-tech text-[10px] text-cyan-300 hover:text-[#b7ff38] flex items-center gap-2">ACCESS ARCHIVE <ArrowUpRight size={13}/></Link>
        </div>
        {investigations.length === 0 ? (
          <div className="border border-dashed border-white/10 py-12 text-center">
            <LayoutList className="mx-auto text-slate-600 mb-3" size={26}/>
            <p className="font-mono-tech text-xs text-slate-400">NO CASE FILES FOUND</p>
            <p className="text-xs text-slate-600 mt-2">Start a new investigation to populate this feed.</p>
            <Link to="/investigations/new" className="inline-flex mt-5 cyber-button">INITIATE CASE</Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse min-w-[680px]">
              <thead><tr className="border-b border-cyan-300/15 font-mono-tech text-[9px] tracking-widest text-slate-500"><th className="pb-3">CASE ID</th><th className="pb-3">INPUT TYPE</th><th className="pb-3">RISK SCORE</th><th className="pb-3">CLASSIFICATION</th><th className="pb-3">STATUS</th><th className="pb-3">DATE</th></tr></thead>
              <tbody>{investigations.slice(0,5).map((inv) => (
                <tr key={inv.id} className="border-b border-white/[.055] hover:bg-cyan-300/[.025] transition-colors">
                  <td className="py-4 font-mono-tech text-xs text-cyan-300">#{inv.id}</td>
                  <td className="py-4 text-xs text-slate-300">{inv.input_type}</td>
                  <td className="py-4 font-mono-tech text-xs text-slate-200">{inv.risk_score}</td>
                  <td className="py-4"><RiskChip score={inv.risk_score} className="text-xs" /></td>
                  <td className="py-4 font-mono-tech text-[10px] text-slate-400">{inv.status}</td>
                  <td className="py-4 font-mono-tech text-[10px] text-slate-500">{new Date(inv.created_at).toLocaleDateString()}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
