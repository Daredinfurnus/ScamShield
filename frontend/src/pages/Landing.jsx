import { Link } from 'react-router-dom'
import { Shield, Zap, BarChart3, Network } from 'lucide-react'

export default function Landing() {
  const features = [
    { icon: <Shield className="w-6 h-6" />, title: 'Text Analysis', desc: 'ML-powered scam classification of suspicious messages.' },
    { icon: <Zap className="w-6 h-6" />, title: 'URL Intelligence', desc: 'Heuristics and reputation checks for dangerous links.' },
    { icon: <BarChart3 className="w-6 h-6" />, title: 'Explainable Risk Scoring', desc: 'Backend-calculated 0-100 risk scores with evidence.' },
    { icon: <Network className="w-6 h-6" />, title: 'Entity Relationship Graph', desc: 'Map connected actors and infrastructure.' },
  ]

  return (
    <div className="space-y-12">
      <section className="py-12 text-center">
        <h1 className="text-4xl md:text-6xl font-bold text-white tracking-tight mb-6">
          Don&rsquo;t Just Detect Scams.<br />
          <span className="text-teal-400">Investigate Them.</span>
        </h1>
        <p className="text-lg text-slate-400 max-w-2xl mx-auto">
          AI-powered digital fraud investigation across messages, URLs, and screenshots.
        </p>
        <div className="mt-10 flex flex-col sm:flex-row gap-4 justify-center">
          <Link to="/investigations/new">
            <button className="px-8 py-3 bg-teal-500 text-white rounded-xl font-semibold hover:bg-teal-400 transition-colors">
              Start Investigation
            </button>
          </Link>
          <Link to="/dashboard">
            <button className="px-8 py-3 bg-white/10 border border-white/10 text-slate-200 rounded-xl font-semibold hover:bg-white/5 transition-colors">
              View Dashboard
            </button>
          </Link>
        </div>
      </section>

      <section className="py-12">
        <h2 className="text-2xl font-bold text-white mb-10 text-center">Capabilities</h2>
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((f, i) => (
            <div key={i} className="card">
              <div className="w-10 h-10 rounded-lg bg-teal-500/10 flex items-center justify-center text-teal-400 mb-4">
                {f.icon}
              </div>
              <h3 className="font-semibold text-white mb-2">{f.title}</h3>
              <p className="text-sm text-slate-400">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}