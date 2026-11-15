import { Link } from 'react-router-dom'
import { Shield, Zap, BarChart3, Network, ArrowUpRight, ScanLine, Fingerprint, Radar, TerminalSquare } from 'lucide-react'

export default function Landing() {
  const features = [
    { icon: <ScanLine className="w-5 h-5" />, code:'MOD_01', title:'Message Forensics', desc:'Inspect suspicious messages for manipulation patterns, pressure tactics and fraud indicators.' },
    { icon: <Radar className="w-5 h-5" />, code:'MOD_02', title:'URL Intelligence', desc:'Examine suspicious links and surface risk signals with traceable evidence.' },
    { icon: <BarChart3 className="w-5 h-5" />, code:'MOD_03', title:'Explainable Risk Engine', desc:'Deterministic backend scoring with transparent signals and evidence references.' },
    { icon: <Network className="w-5 h-5" />, code:'MOD_04', title:'Entity Mapping', desc:'Explore relationships between identifiers, accounts, domains and reported entities.' },
  ]
  return (
    <div className="space-y-16 sm:space-y-20">
      <section className="relative overflow-hidden border border-cyan-300/15 bg-[#0a1119]/80 scanline">
        <div className="absolute inset-0 opacity-40 pointer-events-none" style={{backgroundImage:'radial-gradient(circle at 80% 48%, rgba(0,229,255,.15), transparent 25%), linear-gradient(90deg, transparent 49.8%, rgba(0,229,255,.07) 50%, transparent 50.2%)'}}/>
        <div className="relative grid lg:grid-cols-[1.25fr_.75fr] gap-10 items-center px-6 py-12 sm:px-10 sm:py-16 lg:px-14">
          <div>
            <div className="inline-flex items-center gap-2 border border-[#b7ff38]/30 bg-[#b7ff38]/[.06] px-3 py-2 cyber-kicker">
              <span className="w-1.5 h-1.5 rounded-full bg-[#b7ff38] pulse-glow"/> DIGITAL THREAT INVESTIGATION PLATFORM
            </div>
            <h1 className="mt-7 text-6xl sm:text-7xl lg:text-[88px] leading-[.88] font-black tracking-wide text-slate-100">
              DON'T JUST<br/>DETECT <span className="text-[#b7ff38]">SCAMS.</span><br/>
              <span className="text-transparent" style={{WebkitTextStroke:'1px rgba(0,229,255,.8)'}}>INVESTIGATE.</span>
            </h1>
            <p className="mt-7 max-w-xl text-sm sm:text-base leading-7 text-slate-400">
              An evidence-first digital fraud intelligence workspace. Analyze suspicious messages and URLs, understand risk signals, and build a clearer picture of the threat.
            </p>
            <div className="mt-9 flex flex-wrap gap-3">
              <Link to="/investigations/new" className="cyber-button"><ScanLine size={16}/> INITIATE INVESTIGATION <ArrowUpRight size={15}/></Link>
              <Link to="/dashboard" className="cyber-button-secondary">OPEN COMMAND CENTER</Link>
            </div>
            <div className="mt-9 flex flex-wrap gap-x-7 gap-y-3 font-mono-tech text-[9px] tracking-widest text-slate-600">
              <span className="flex items-center gap-2"><span className="w-1.5 h-1.5 bg-[#b7ff38] rounded-full"/> EVIDENCE FIRST</span>
              <span className="flex items-center gap-2"><span className="w-1.5 h-1.5 bg-cyan-300 rounded-full"/> EXPLAINABLE SCORING</span>
              <span className="flex items-center gap-2"><span className="w-1.5 h-1.5 bg-[#ff416c] rounded-full"/> TRACEABLE SIGNALS</span>
            </div>
          </div>
          <div className="relative hidden lg:block">
            <div className="absolute inset-0 blur-3xl bg-cyan-400/10 rounded-full"/>
            <div className="relative border border-cyan-300/20 bg-[#071018]/90 p-5 shadow-[0_0_60px_rgba(0,229,255,.08)]">
              <div className="flex justify-between items-center border-b border-white/10 pb-3">
                <span className="cyber-kicker">LIVE / ANALYSIS INTERFACE</span>
                <span className="font-mono-tech text-[9px] text-cyan-300">SYS.00A</span>
              </div>
              <div className="py-8 flex items-center justify-center">
                <div className="relative w-56 h-56 rounded-full border border-cyan-300/20 flex items-center justify-center">
                  <div className="absolute inset-4 rounded-full border border-dashed border-[#b7ff38]/35 animate-spin" style={{animationDuration:'32s'}}/>
                  <div className="absolute inset-9 rounded-full border border-cyan-300/25"/>
                  <div className="absolute inset-0 rounded-full" style={{background:'conic-gradient(from 30deg, transparent 0 65%, rgba(0,229,255,.18) 75%, transparent 88%)'}}/>
                  <div className="relative flex flex-col items-center">
                    <Shield size={43} className="text-[#b7ff38] drop-shadow-[0_0_14px_rgba(183,255,56,.65)]"/>
                    <span className="mt-3 font-mono-tech text-[9px] tracking-[.2em] text-cyan-200">THREAT RADAR</span>
                    <span className="mt-1 font-mono-tech text-[8px] text-slate-600">AWAITING INPUT</span>
                  </div>
                  <span className="absolute top-7 right-10 w-2 h-2 bg-[#ff416c] rounded-full shadow-[0_0_12px_#ff416c]"/>
                  <span className="absolute bottom-12 left-7 w-1.5 h-1.5 bg-[#b7ff38] rounded-full shadow-[0_0_10px_#b7ff38]"/>
                </div>
              </div>
              <div className="space-y-2 font-mono-tech text-[9px]">
                <div className="flex justify-between text-slate-500"><span><TerminalSquare size={11} className="inline mr-2"/>CORE STATUS</span><span className="text-[#b7ff38]">READY FOR INPUT</span></div>
                <div className="h-px bg-white/10"/>
                <div className="flex justify-between text-slate-500"><span>ANALYSIS MODE</span><span className="text-cyan-300">EVIDENCE-LED</span></div>
                <div className="flex justify-between text-slate-500"><span>INTELLIGENCE</span><span className="text-slate-300">MULTI-SIGNAL</span></div>
              </div>
            </div>
          </div>
        </div>
        <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-[#b7ff38]/70 to-transparent"/>
      </section>

      <section>
        <div className="flex items-end justify-between gap-4 mb-7">
          <div><div className="cyber-kicker">Capabilities / 04 Modules</div><h2 className="mt-2 text-4xl sm:text-5xl">INTELLIGENCE TOOLKIT</h2></div>
          <span className="hidden sm:block font-mono-tech text-[9px] text-slate-600">SCAMSHIELD // MODULE INDEX</span>
        </div>
        <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {features.map((f) => (
            <div key={f.code} className="card group hover:border-cyan-300/35 transition-colors">
              <div className="flex justify-between items-center">
                <div className="w-10 h-10 flex items-center justify-center border border-[#b7ff38]/25 bg-[#b7ff38]/[.06] text-[#b7ff38]">{f.icon}</div>
                <span className="font-mono-tech text-[9px] text-slate-600">{f.code}</span>
              </div>
              <h3 className="mt-6 text-2xl text-slate-100">{f.title}</h3>
              <p className="mt-2 text-xs leading-6 text-slate-500">{f.desc}</p>
              <div className="mt-6 h-px bg-gradient-to-r from-[#b7ff38]/40 to-transparent"/>
            </div>
          ))}
        </div>
      </section>
      <section className="cyber-panel p-6 sm:p-8 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
        <div className="flex gap-4 items-start">
          <Fingerprint className="text-cyan-300 mt-1" size={25}/>
          <div><div className="cyber-kicker">Ready to examine evidence?</div><h2 className="mt-1 text-3xl">OPEN A NEW CASE FILE</h2><p className="text-xs text-slate-500 mt-1">Start with a suspicious message or URL. Review the evidence and risk signals.</p></div>
        </div>
        <Link to="/investigations/new" className="cyber-button shrink-0">CREATE CASE <ArrowUpRight size={15}/></Link>
      </section>
    </div>
  )
}
